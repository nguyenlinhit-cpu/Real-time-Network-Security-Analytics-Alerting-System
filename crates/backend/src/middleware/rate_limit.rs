use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::time::{Duration, Instant};

use crate::{error::AppError, state::AppState};

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim())
        .unwrap_or("127.0.0.1")
        .to_string();

    let path = request.uri().path().to_string();
    let is_auth_sensitive = path.contains("/api/auth/login") || path.contains("/api/auth/register");

    let max_requests = if is_auth_sensitive { 10 } else { 200 };
    let window = Duration::from_secs(60);

    let key = format!("ratelimit:{}:{}", client_ip, if is_auth_sensitive { "auth" } else { "api" });

    // 1. Distributed rate limiting via Redis if available
    let mut handled_by_redis = false;
    if let Some(ref redis) = state.redis {
        match redis.incr_with_expire(&key, window.as_secs()).await {
            Ok(count) => {
                handled_by_redis = true;
                if count > max_requests as i64 {
                    return Err(AppError::RateLimitExceeded);
                }
            }
            Err(e) => {
                tracing::warn!("Redis rate limiter failed, falling back to local memory: {}", e);
            }
        }
    }

    // 2. Fallback to in-memory DashMap rate limiter
    if !handled_by_redis {
        let now = Instant::now();
        let mut entry = state.rate_limiter.entry(key).or_insert((now, 0));
        let (window_start, count) = entry.value_mut();

        if now.duration_since(*window_start) > window {
            *window_start = now;
            *count = 1;
        } else {
            *count += 1;
            if *count > max_requests {
                return Err(AppError::RateLimitExceeded);
            }
        }
    }

    Ok(next.run(request).await)
}
