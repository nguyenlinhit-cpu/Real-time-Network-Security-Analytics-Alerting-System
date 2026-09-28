use axum::{extract::State, Json};
use common::models::{AuthResponseDto, CreateUserDto, LoginDto, User, UserPublicDto, UserRole};
use common::ApiResponse;
use std::time::Instant;
use validator::Validate;

use crate::{
    audit,
    auth::{
        jwt::generate_tokens,
        middleware::CurrentUser,
        password::{hash_password, verify_password},
    },
    error::AppError,
    middleware::ClientIp,
    state::{AppState, LOCKOUT_WINDOW},
};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const REFRESH_TOKEN_TTL_SECS: u64 = 7 * 24 * 3600;

/// Argon2id hash used to keep the response time of unknown usernames indistinguishable from
/// wrong passwords (username enumeration via timing). Generated once per process.
fn dummy_password_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        hash_password(&uuid::Uuid::new_v4().to_string()).unwrap_or_default()
    })
}

/// Lockout counters are scoped to (account, client IP): an attacker cannot lock a legitimate
/// user out from another address, and logging in via username or e-mail shares one counter.
fn lockout_key(user: Option<&User>, login: &str, ip: &ClientIp) -> String {
    match user {
        Some(u) => format!("secnet:lockout:{}:{}", u.id, ip.0),
        None => format!("secnet:lockout:unknown:{}:{}", login.to_lowercase(), ip.0),
    }
}

async fn is_locked_out(state: &AppState, key: &str) -> bool {
    if let Some(ref redis) = state.redis {
        match redis.get_int(key).await {
            Ok(v) => return v.unwrap_or(0) >= MAX_FAILED_ATTEMPTS as i64,
            Err(e) => tracing::warn!("Redis lockout check failed, using memory: {}", e),
        }
    }
    state
        .failed_logins
        .get(key)
        .map(|e| {
            let (attempts, last) = *e;
            attempts >= MAX_FAILED_ATTEMPTS && last.elapsed() < LOCKOUT_WINDOW
        })
        .unwrap_or(false)
}

async fn record_failed_attempt(state: &AppState, key: &str) {
    if let Some(ref redis) = state.redis {
        if redis
            .incr_with_expire(key, LOCKOUT_WINDOW.as_secs())
            .await
            .is_ok()
        {
            return;
        }
    }
    let now = Instant::now();
    let mut entry = state.failed_logins.entry(key.to_string()).or_insert((0, now));
    let (count, last) = entry.value_mut();
    if now.duration_since(*last) > LOCKOUT_WINDOW {
        *count = 1;
    } else {
        *count += 1;
    }
    *last = now;
}

async fn clear_failed_attempts(state: &AppState, key: &str) {
    if let Some(ref redis) = state.redis {
        let _ = redis.del(key).await;
    }
    state.failed_logins.remove(key);
}

#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = CreateUserDto,
    responses(
        (status = 200, description = "User registered successfully", body = ApiResponse<AuthResponseDto>),
        (status = 400, description = "Validation or duplicate error", body = ApiResponse<()>)
    ),
    tag = "Auth"
)]
pub async fn register(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(payload): Json<CreateUserDto>,
) -> Result<Json<ApiResponse<AuthResponseDto>>, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let hashed_password = hash_password(&payload.password)?;
    // Public self-registration ALWAYS defaults to Viewer to prevent privilege escalation (Mục 9)
    let role = UserRole::Viewer;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, email, password_hash, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, email, password_hash, role, created_at, updated_at
        "#,
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&hashed_password)
    .bind(role)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
            AppError::BadRequest("Username or email already exists".to_string())
        }
        _ => AppError::DatabaseError(e),
    })?;

    audit::record(
        &state.pool,
        Some(user.id),
        "USER_REGISTERED",
        &user.username,
        Some(client_ip.network()),
    )
    .await;

    let (token, refresh_token) =
        generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

    Ok(Json(ApiResponse::ok(AuthResponseDto {
        token,
        refresh_token,
        user: UserPublicDto::from(user),
    })))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginDto,
    responses(
        (status = 200, description = "Login successful", body = ApiResponse<AuthResponseDto>),
        (status = 401, description = "Invalid credentials", body = ApiResponse<()>),
        (status = 403, description = "Account temporarily locked", body = ApiResponse<()>)
    ),
    tag = "Auth"
)]
pub async fn login(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(payload): Json<LoginDto>,
) -> Result<Json<ApiResponse<AuthResponseDto>>, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let ip = Some(client_ip.network());

    let user_opt = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE username = $1 OR lower(email) = lower($1)
        "#,
    )
    .bind(&payload.username)
    .fetch_optional(&state.pool)
    .await?;

    let key = lockout_key(user_opt.as_ref(), &payload.username, &client_ip);

    if is_locked_out(&state, &key).await {
        audit::record(
            &state.pool,
            user_opt.as_ref().map(|u| u.id),
            "ACCOUNT_LOCKED_ATTEMPT",
            &payload.username,
            ip,
        )
        .await;
        return Err(AppError::Forbidden(
            "Too many failed login attempts from this address. Please try again after 15 minutes."
                .to_string(),
        ));
    }

    let is_valid = match &user_opt {
        Some(user) => verify_password(&payload.password, &user.password_hash)?,
        None => {
            let _ = verify_password(&payload.password, dummy_password_hash());
            false
        }
    };

    let user = match (is_valid, user_opt) {
        (true, Some(user)) => user,
        (_, user_opt) => {
            record_failed_attempt(&state, &key).await;
            audit::record(
                &state.pool,
                user_opt.as_ref().map(|u| u.id),
                "LOGIN_FAILED",
                &payload.username,
                ip,
            )
            .await;
            return Err(AppError::Unauthorized(
                "Invalid username or password".to_string(),
            ));
        }
    };

    clear_failed_attempts(&state, &key).await;
    audit::record(&state.pool, Some(user.id), "LOGIN_SUCCESS", &user.username, ip).await;

    let (token, refresh_token) =
        generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

    Ok(Json(ApiResponse::ok(AuthResponseDto {
        token,
        refresh_token,
        user: UserPublicDto::from(user),
    })))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct RefreshTokenPayload {
    pub refresh_token: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    request_body = RefreshTokenPayload,
    responses(
        (status = 200, description = "Token refreshed successfully", body = ApiResponse<AuthResponseDto>),
        (status = 401, description = "Invalid refresh token", body = ApiResponse<()>)
    ),
    tag = "Auth"
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenPayload>,
) -> Result<Json<ApiResponse<AuthResponseDto>>, AppError> {
    let claims = crate::auth::jwt::verify_token(&payload.refresh_token, &state.jwt_secret)?;

    // Security Hardening: Enforce token is of type 'refresh'
    if claims.token_type != "refresh" {
        return Err(AppError::Unauthorized(
            "Invalid token type: refresh token expected".to_string(),
        ));
    }

    let jti = claims
        .jti
        .ok_or_else(|| AppError::Unauthorized("Refresh token has no identifier".to_string()))?;

    // Rotation: consume the refresh token atomically so it can be used exactly once.
    if !state
        .try_consume_refresh_token(jti, REFRESH_TOKEN_TTL_SECS)
        .await
    {
        return Err(AppError::Unauthorized(
            "Refresh token has been revoked".to_string(),
        ));
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, created_at, updated_at FROM users WHERE id = $1"
    )
    .bind(claims.sub)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let (token, refresh_token) =
        generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

    Ok(Json(ApiResponse::ok(AuthResponseDto {
        token,
        refresh_token,
        user: UserPublicDto::from(user),
    })))
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    responses(
        (status = 200, description = "Logged out successfully", body = ApiResponse<String>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>)
    ),
    tag = "Auth",
    security(("bearer_auth" = []))
)]
pub async fn logout(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    payload: Option<Json<RefreshTokenPayload>>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;

    // 1. Revoke access token
    if let Some(jti) = current_user.0.jti {
        let ttl = current_user.0.exp.saturating_sub(now).max(1) as u64;
        state.revoke_token(jti, ttl).await;
    }

    // 2. Revoke refresh token if provided — only when it belongs to the same user (Mục 16)
    if let Some(Json(p)) = payload {
        if let Ok(claims) = crate::auth::jwt::verify_token(&p.refresh_token, &state.jwt_secret) {
            if claims.sub == current_user.0.sub && claims.token_type == "refresh" {
                if let Some(refresh_jti) = claims.jti {
                    let ttl = claims.exp.saturating_sub(now).max(1) as u64;
                    state.revoke_token(refresh_jti, ttl).await;
                }
            }
        }
    }

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "USER_LOGOUT",
        &current_user.0.username,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok("Logged out successfully".to_string())))
}
