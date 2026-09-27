use common::models::{User, UserClaims};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::error::AppError;

pub fn generate_tokens(
    user: &User,
    secret: &str,
    exp_hours: i64,
) -> Result<(String, String), AppError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let access_exp = now + (exp_hours * 3600) as usize;
    let refresh_exp = now + (7 * 24 * 3600) as usize;

    let access_claims = UserClaims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role,
        exp: access_exp,
        token_type: "access".to_string(),
        jti: Some(Uuid::new_v4()),
    };

    let refresh_claims = UserClaims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role,
        exp: refresh_exp,
        token_type: "refresh".to_string(),
        jti: Some(Uuid::new_v4()),
    };


    let token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to sign JWT: {}", e)))?;

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to sign refresh JWT: {}", e)))?;

    Ok((token, refresh_token))
}

pub fn verify_token(token: &str, secret: &str) -> Result<UserClaims, AppError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<UserClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("Invalid or expired token: {}", e)))?;

    Ok(token_data.claims)
}
