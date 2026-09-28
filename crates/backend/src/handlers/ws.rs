use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{error::AppError, state::AppState};

#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    pub token: Option<String>,
}

fn verify_ws_token(token_str: &str, state: &AppState) -> Result<(), AppError> {
    let claims = crate::auth::jwt::verify_token(token_str, &state.jwt_secret).map_err(|e| {
        warn!("WebSocket token authentication failed: {}", e);
        e
    })?;

    if claims.token_type != "access" {
        return Err(AppError::Unauthorized(
            "Invalid token type for WebSocket (access token required)".to_string(),
        ));
    }

    if let Some(ref jti) = claims.jti {
        if state.revoked_tokens.contains_key(jti) {
            return Err(AppError::Unauthorized(
                "WebSocket token has been revoked".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn ws_alerts_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let token = query.token.ok_or_else(|| {
        AppError::Unauthorized("Missing authentication token for WebSocket".to_string())
    })?;
    verify_ws_token(&token, &state)?;
    Ok(ws.on_upgrade(|socket| handle_alerts_socket(socket, state)))
}

async fn handle_alerts_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.alert_broadcast.subscribe();
    info!("Client connected to /ws/alerts stream");

    while let Ok(alert) = rx.recv().await {
        if let Ok(json) = serde_json::to_string(&alert) {
            if socket.send(Message::Text(json)).await.is_err() {
                // Client disconnected
                break;
            }
        }
    }

    info!("Client disconnected from /ws/alerts stream");
}

pub async fn ws_traffic_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let token = query.token.ok_or_else(|| {
        AppError::Unauthorized("Missing authentication token for WebSocket".to_string())
    })?;
    verify_ws_token(&token, &state)?;
    Ok(ws.on_upgrade(|socket| handle_traffic_socket(socket, state)))
}

async fn handle_traffic_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.traffic_broadcast.subscribe();
    info!("Client connected to /ws/traffic live feed");

    while let Ok(event) = rx.recv().await {
        if let Ok(json) = serde_json::to_string(&event) {
            if socket.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    }

    info!("Client disconnected from /ws/traffic live feed");
}
