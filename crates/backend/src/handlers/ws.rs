use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use common::models::UserClaims;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::broadcast::{self, error::RecvError};
use tracing::{info, warn};

use crate::{error::AppError, state::AppState};

/// How often an open socket re-validates its token (expiry / logout).
const TOKEN_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    pub token: Option<String>,
}

async fn verify_ws_token(token_str: &str, state: &AppState) -> Result<UserClaims, AppError> {
    let claims = crate::auth::jwt::verify_token(token_str, &state.jwt_secret).map_err(|e| {
        warn!("WebSocket token authentication failed: {}", e);
        e
    })?;

    if claims.token_type != "access" {
        return Err(AppError::Unauthorized(
            "Invalid token type for WebSocket (access token required)".to_string(),
        ));
    }

    if let Some(jti) = claims.jti {
        if state.is_token_revoked(jti).await {
            return Err(AppError::Unauthorized(
                "WebSocket token has been revoked".to_string(),
            ));
        }
    }

    Ok(claims)
}

async fn still_authorized(claims: &UserClaims, state: &AppState) -> bool {
    let now = chrono::Utc::now().timestamp() as usize;
    if claims.exp <= now {
        return false;
    }
    match claims.jti {
        Some(jti) => !state.is_token_revoked(jti).await,
        None => true,
    }
}

/// Streams every message of `rx` to the socket until the client disconnects or its token
/// stops being valid. Slow clients skip missed messages instead of being disconnected.
async fn stream_to_socket<T: Clone + Serialize>(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<T>,
    claims: UserClaims,
    state: AppState,
    stream_name: &str,
) {
    info!("{} connected to {} stream", claims.username, stream_name);
    let mut recheck = tokio::time::interval(TOKEN_RECHECK_INTERVAL);
    recheck.tick().await;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(item) => {
                    let Ok(json) = serde_json::to_string(&item) else { continue };
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    warn!("{} stream client lagging, skipped {} messages", stream_name, skipped);
                }
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                // Clients only ever send pings/closes; anything else is ignored.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                if !still_authorized(&claims, &state).await {
                    info!("Closing {} stream for {}: token expired or revoked", stream_name, claims.username);
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }

    info!("{} disconnected from {} stream", claims.username, stream_name);
}

pub async fn ws_alerts_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let token = query.token.ok_or_else(|| {
        AppError::Unauthorized("Missing authentication token for WebSocket".to_string())
    })?;
    let claims = verify_ws_token(&token, &state).await?;
    let rx = state.alert_broadcast.subscribe();
    Ok(ws.on_upgrade(move |socket| stream_to_socket(socket, rx, claims, state, "alerts")))
}

pub async fn ws_traffic_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let token = query.token.ok_or_else(|| {
        AppError::Unauthorized("Missing authentication token for WebSocket".to_string())
    })?;
    let claims = verify_ws_token(&token, &state).await?;
    let rx = state.traffic_broadcast.subscribe();
    Ok(ws.on_upgrade(move |socket| stream_to_socket(socket, rx, claims, state, "traffic")))
}
