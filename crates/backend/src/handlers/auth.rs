use axum::{extract::State, Json};
use common::models::{AuthResponseDto, CreateUserDto, LoginDto, User, UserPublicDto, UserRole};
use common::ApiResponse;
use validator::Validate;

use crate::{
    auth::{
        jwt::generate_tokens,
        middleware::CurrentUser,
        password::{hash_password, verify_password},
    },
    error::AppError,
    state::AppState,
};


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
    Json(payload): Json<CreateUserDto>,
) -> Result<Json<ApiResponse<AuthResponseDto>>, AppError> {
    payload.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;

    let hashed_password = hash_password(&payload.password)?;
    let role = payload.role.unwrap_or(UserRole::Viewer);

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

    // Record audit log for user registration
    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        user.id,
        "USER_REGISTERED",
        user.username
    )
    .execute(&state.pool)
    .await;

    let (token, refresh_token) = generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

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
    Json(payload): Json<LoginDto>,
) -> Result<Json<ApiResponse<AuthResponseDto>>, AppError> {
    payload.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;

    let lockout_window_secs = 900u64; // 15 minutes lockout
    let max_failed_attempts = 5i64;
    let lockout_key = format!("secnet:lockout:{}", payload.username);
    let now = std::time::Instant::now();

    // 1. Check account lockout (distributed via Redis if active, fallback to DashMap)
    let mut is_locked_out = false;
    if let Some(ref redis) = state.redis {
        if let Ok(Some(attempts)) = redis.get_int(&lockout_key).await {
            if attempts >= max_failed_attempts {
                is_locked_out = true;
            }
        }
    } else if let Some(entry) = state.failed_logins.get(&payload.username) {
        let (attempts, last_time) = *entry;
        if attempts >= 5 && now.duration_since(last_time) < std::time::Duration::from_secs(lockout_window_secs) {
            is_locked_out = true;
        }
    }

    if is_locked_out {
        let _ = sqlx::query!(
            "INSERT INTO audit_logs (action, target) VALUES ($1, $2)",
            "ACCOUNT_LOCKED_ATTEMPT",
            payload.username
        )
        .execute(&state.pool)
        .await;

        return Err(AppError::Forbidden(
            "Account is temporarily locked due to excessive failed login attempts. Please try again after 15 minutes.".to_string(),
        ));
    }

    let user_opt = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE username = $1 OR email = $1
        "#,
    )
    .bind(&payload.username)
    .fetch_optional(&state.pool)
    .await?;

    let user = match user_opt {
        Some(u) => u,
        None => {
            // Track failed attempt in Redis & DashMap
            if let Some(ref redis) = state.redis {
                let _ = redis.incr_with_expire(&lockout_key, lockout_window_secs).await;
            } else {
                let mut entry = state.failed_logins.entry(payload.username.clone()).or_insert((0, now));
                let (count, last_time) = entry.value_mut();
                if now.duration_since(*last_time) > std::time::Duration::from_secs(lockout_window_secs) {
                    *count = 1;
                } else {
                    *count += 1;
                }
                *last_time = now;
            }

            let _ = sqlx::query!(
                "INSERT INTO audit_logs (action, target) VALUES ($1, $2)",
                "LOGIN_FAILED",
                payload.username
            )
            .execute(&state.pool)
            .await;

            return Err(AppError::Unauthorized("Invalid username or password".to_string()));
        }
    };

    let is_valid = verify_password(&payload.password, &user.password_hash)?;
    if !is_valid {
        // Track failed attempt in Redis & DashMap
        if let Some(ref redis) = state.redis {
            let _ = redis.incr_with_expire(&lockout_key, lockout_window_secs).await;
        } else {
            let mut entry = state.failed_logins.entry(payload.username.clone()).or_insert((0, now));
            let (count, last_time) = entry.value_mut();
            if now.duration_since(*last_time) > std::time::Duration::from_secs(lockout_window_secs) {
                *count = 1;
            } else {
                *count += 1;
            }
            *last_time = now;
        }

        let _ = sqlx::query!(
            "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
            user.id,
            "LOGIN_FAILED",
            payload.username
        )
        .execute(&state.pool)
        .await;

        return Err(AppError::Unauthorized("Invalid username or password".to_string()));
    }

    // Success: reset failed logins counter in Redis and in-memory
    if let Some(ref redis) = state.redis {
        let _ = redis.del(&lockout_key).await;
    }
    state.failed_logins.remove(&payload.username);

    // Record audit log for successful login
    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        user.id,
        "LOGIN_SUCCESS",
        user.username
    )
    .execute(&state.pool)
    .await;

    let (token, refresh_token) = generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

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

    // Check if refresh token has been revoked
    if let Some(jti) = claims.jti {
        if state.is_token_revoked(jti).await {
            return Err(AppError::Unauthorized("Refresh token has been revoked".to_string()));
        }
        // Rotate: revoke old refresh token so it cannot be re-used
        state.revoke_token(jti, 7 * 24 * 3600).await;
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, created_at, updated_at FROM users WHERE id = $1"
    )
    .bind(claims.sub)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let (token, refresh_token) = generate_tokens(&user, &state.jwt_secret, state.jwt_expiration_hours)?;

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
) -> Result<Json<ApiResponse<String>>, AppError> {
    if let Some(jti) = current_user.0.jti {
        let now = chrono::Utc::now().timestamp() as usize;
        let ttl = if current_user.0.exp > now {
            (current_user.0.exp - now) as u64
        } else {
            3600
        };
        state.revoke_token(jti, ttl).await;
    }

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        "USER_LOGOUT",
        current_user.0.username
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok("Logged out successfully".to_string())))
}

