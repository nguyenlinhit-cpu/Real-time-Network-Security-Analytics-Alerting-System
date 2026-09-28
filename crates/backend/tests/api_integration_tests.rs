use backend::auth::jwt::{generate_tokens, verify_token};
use backend::auth::password::{hash_password, verify_password};
use backend::auth::rbac::{require_admin, require_analyst_or_admin};
use backend::auth::CurrentUser;
use common::models::{User, UserClaims, UserRole};
use uuid::Uuid;

#[test]
fn test_password_hashing_and_verification() {
    let raw_password = "SuperSecurePassword987!";
    let hashed = hash_password(raw_password).expect("Hashing should succeed");

    assert!(verify_password(raw_password, &hashed).expect("Verification should succeed"));
    assert!(!verify_password("WrongPassword123!", &hashed)
        .expect("Wrong password verification should return false"));
}

#[test]
fn test_jwt_generation_and_validation() {
    let secret = "test_super_secret_jwt_key_at_least_32_bytes_long";
    let user = User {
        id: Uuid::new_v4(),
        username: "test_analyst".to_string(),
        email: "analyst@test.local".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Analyst,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let (token, refresh_token) =
        generate_tokens(&user, secret, 24).expect("Token generation should succeed");
    assert!(!token.is_empty());
    assert!(!refresh_token.is_empty());

    let claims = verify_token(&token, secret).expect("Token verification should succeed");
    assert_eq!(claims.username, "test_analyst");
    assert_eq!(claims.role, UserRole::Analyst);
}

#[test]
fn test_rbac_permission_enforcement() {
    let admin_user = CurrentUser(UserClaims {
        sub: Uuid::new_v4(),
        username: "admin_user".to_string(),
        role: UserRole::Admin,
        exp: 9999999999,
        token_type: "access".to_string(),
        jti: Some(Uuid::new_v4()),
    });

    let analyst_user = CurrentUser(UserClaims {
        sub: Uuid::new_v4(),
        username: "analyst_user".to_string(),
        role: UserRole::Analyst,
        exp: 9999999999,
        token_type: "access".to_string(),
        jti: Some(Uuid::new_v4()),
    });

    let viewer_user = CurrentUser(UserClaims {
        sub: Uuid::new_v4(),
        username: "viewer_user".to_string(),
        role: UserRole::Viewer,
        exp: 9999999999,
        token_type: "access".to_string(),
        jti: Some(Uuid::new_v4()),
    });

    // Admin should have access to both admin-only and analyst endpoints
    assert!(require_admin(&admin_user).is_ok());
    assert!(require_analyst_or_admin(&admin_user).is_ok());

    // Analyst should be allowed for analyst endpoints, but blocked from admin endpoints
    assert!(require_analyst_or_admin(&analyst_user).is_ok());
    assert!(
        require_admin(&analyst_user).is_err(),
        "Analyst must be denied for admin-only actions"
    );

    // Viewer should be denied from both
    assert!(
        require_analyst_or_admin(&viewer_user).is_err(),
        "Viewer must be denied for analyst actions"
    );
    assert!(
        require_admin(&viewer_user).is_err(),
        "Viewer must be denied for admin actions"
    );
}

#[test]
fn test_token_type_segregation() {
    let secret = "test_super_secret_jwt_key_at_least_32_bytes_long";
    let user = User {
        id: Uuid::new_v4(),
        username: "test_analyst".to_string(),
        email: "analyst@test.local".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Analyst,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let (token, refresh_token) =
        generate_tokens(&user, secret, 24).expect("Token generation should succeed");

    let access_claims =
        verify_token(&token, secret).expect("Access token verification should succeed");
    assert_eq!(access_claims.token_type, "access");
    assert!(access_claims.jti.is_some());

    let refresh_claims =
        verify_token(&refresh_token, secret).expect("Refresh token verification should succeed");
    assert_eq!(refresh_claims.token_type, "refresh");
    assert!(refresh_claims.jti.is_some());
    assert_ne!(access_claims.jti, refresh_claims.jti);
}
