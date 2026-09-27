use common::models::*;
use common::ApiResponse;
use gloo_net::http::{Request, RequestBuilder};
use web_sys::window;

const TOKEN_STORAGE_KEY: &str = "secnet_jwt_token";
const USER_STORAGE_KEY: &str = "secnet_user_info";

pub struct ApiClient;

#[allow(dead_code)]
impl ApiClient {
    pub fn get_token() -> Option<String> {
        window()?
            .local_storage()
            .ok()??
            .get_item(TOKEN_STORAGE_KEY)
            .ok()?
    }

    pub fn set_token(token: &str) {
        if let Some(storage) = window().and_then(|w| w.local_storage().ok().flatten()) {
            let _ = storage.set_item(TOKEN_STORAGE_KEY, token);
        }
    }

    pub fn get_current_user() -> Option<UserPublicDto> {
        let storage = window().and_then(|w| w.local_storage().ok().flatten())?;
        let user_str = storage.get_item(USER_STORAGE_KEY).ok()??;
        serde_json::from_str(&user_str).ok()
    }

    pub fn set_current_user(user: &UserPublicDto) {
        if let Some(storage) = window().and_then(|w| w.local_storage().ok().flatten()) {
            if let Ok(json) = serde_json::to_string(user) {
                let _ = storage.set_item(USER_STORAGE_KEY, &json);
            }
        }
    }

    pub fn logout() {
        if let Some(storage) = window().and_then(|w| w.local_storage().ok().flatten()) {
            let _ = storage.remove_item(TOKEN_STORAGE_KEY);
            let _ = storage.remove_item(USER_STORAGE_KEY);
        }
    }

    pub async fn api_logout() {
        let _ = Self::auth_request("POST", "/api/auth/logout").send().await;
        Self::logout();
    }

    pub fn is_authenticated() -> bool {
        Self::get_token().is_some()
    }

    fn auth_request(method: &str, url: &str) -> RequestBuilder {
        let mut req = match method {
            "POST" => Request::post(url),
            "PATCH" => Request::patch(url),
            "DELETE" => Request::delete(url),
            _ => Request::get(url),
        };

        if let Some(token) = Self::get_token() {
            req = req.header("Authorization", &format!("Bearer {}", token));
        }

        req
    }


    pub async fn login(dto: &LoginDto) -> Result<AuthResponseDto, String> {
        let res = Request::post("/api/auth/login")
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let body: ApiResponse<AuthResponseDto> = res.json().await.map_err(|e| e.to_string())?;
        if body.success {
            if let Some(data) = body.data {
                Self::set_token(&data.token);
                Self::set_current_user(&data.user);
                return Ok(data);
            }
        }
        Err(body.error.unwrap_or_else(|| "Login failed".to_string()))
    }

    pub async fn get_dashboard_summary() -> Result<TrafficSummaryDto, String> {
        let res = Self::auth_request("GET", "/api/dashboard/summary")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<TrafficSummaryDto> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load summary".to_string()))
    }

    pub async fn get_alerts() -> Result<Vec<Alert>, String> {
        let res = Self::auth_request("GET", "/api/alerts")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<Alert>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load alerts".to_string()))
    }

    pub async fn update_alert_status(id: uuid::Uuid, status: AlertStatus) -> Result<Alert, String> {
        let dto = UpdateAlertDto { status };
        let res = Self::auth_request("PATCH", &format!("/api/alerts/{}", id))
            .json(&dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Alert> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to update alert".to_string()))
    }

    pub async fn get_traffic() -> Result<Vec<TrafficEvent>, String> {
        let res = Self::auth_request("GET", "/api/traffic?limit=50")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<TrafficEvent>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load traffic".to_string()))
    }

    pub async fn get_rules() -> Result<Vec<DetectionRule>, String> {
        let res = Self::auth_request("GET", "/api/rules")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<DetectionRule>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load rules".to_string()))
    }

    pub async fn get_devices() -> Result<Vec<Device>, String> {
        let res = Self::auth_request("GET", "/api/devices")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<Device>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load devices".to_string()))
    }

    pub async fn get_device_history(id: uuid::Uuid) -> Result<Vec<TrafficEvent>, String> {
        let res = Self::auth_request("GET", &format!("/api/devices/{}/history", id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<TrafficEvent>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load device history".to_string()))
    }


    pub async fn register(dto: &CreateUserDto) -> Result<AuthResponseDto, String> {
        let res = Request::post("/api/auth/register")
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let body: ApiResponse<AuthResponseDto> = res.json().await.map_err(|e| e.to_string())?;
        if body.success {
            if let Some(data) = body.data {
                Self::set_token(&data.token);
                Self::set_current_user(&data.user);
                return Ok(data);
            }
        }
        Err(body.error.unwrap_or_else(|| "Registration failed".to_string()))
    }

    pub async fn create_rule(dto: &CreateRuleDto) -> Result<DetectionRule, String> {
        let res = Self::auth_request("POST", "/api/rules")
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<DetectionRule> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to create rule".to_string()))
    }

    pub async fn update_rule(id: uuid::Uuid, dto: &UpdateRuleDto) -> Result<DetectionRule, String> {
        let res = Self::auth_request("PATCH", &format!("/api/rules/{}", id))
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<DetectionRule> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to update rule".to_string()))
    }

    pub async fn delete_rule(id: uuid::Uuid) -> Result<(), String> {
        let res = Self::auth_request("DELETE", &format!("/api/rules/{}", id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<()> = res.json().await.map_err(|e| e.to_string())?;
        if body.success {
            Ok(())
        } else {
            Err(body.error.unwrap_or_else(|| "Failed to delete rule".to_string()))
        }
    }

    pub async fn get_blocklist() -> Result<Vec<BlockedIp>, String> {
        let res = Self::auth_request("GET", "/api/blocklist")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<BlockedIp>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load blocklist".to_string()))
    }

    pub async fn add_to_blocklist(dto: &CreateBlockedIpDto) -> Result<BlockedIp, String> {
        let res = Self::auth_request("POST", "/api/blocklist")
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<BlockedIp> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to block IP".to_string()))
    }

    pub async fn remove_from_blocklist(id: uuid::Uuid) -> Result<(), String> {
        let res = Self::auth_request("DELETE", &format!("/api/blocklist/{}", id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<()> = res.json().await.map_err(|e| e.to_string())?;
        if body.success {
            Ok(())
        } else {
            Err(body.error.unwrap_or_else(|| "Failed to remove IP from blocklist".to_string()))
        }
    }

    pub async fn get_notification_channels() -> Result<Vec<NotificationChannel>, String> {
        let res = Self::auth_request("GET", "/api/notifications/channels")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Vec<NotificationChannel>> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to load channels".to_string()))
    }

    pub async fn create_notification_channel(dto: &CreateNotificationChannelDto) -> Result<NotificationChannel, String> {
        let res = Self::auth_request("POST", "/api/notifications/channels")
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<NotificationChannel> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to create channel".to_string()))
    }

    pub async fn update_notification_channel(id: uuid::Uuid, dto: &UpdateNotificationChannelDto) -> Result<NotificationChannel, String> {
        let res = Self::auth_request("PATCH", &format!("/api/notifications/channels/{}", id))
            .json(dto)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<NotificationChannel> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to update channel".to_string()))
    }

    pub async fn delete_notification_channel(id: uuid::Uuid) -> Result<(), String> {
        let res = Self::auth_request("DELETE", &format!("/api/notifications/channels/{}", id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<()> = res.json().await.map_err(|e| e.to_string())?;
        if body.success {
            Ok(())
        } else {
            Err(body.error.unwrap_or_else(|| "Failed to delete channel".to_string()))
        }
    }

    pub async fn test_notification_channel(id: uuid::Uuid) -> Result<String, String> {
        let res = Self::auth_request("POST", &format!("/api/notifications/test/{}", id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<String> = res.json().await.map_err(|e| e.to_string())?;
        body.data.ok_or_else(|| body.error.unwrap_or_else(|| "Failed to send test alert".to_string()))
    }

    pub async fn export_csv_file() -> Result<(), String> {
        let res = Self::auth_request("GET", "/api/reports/export")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.ok() {
            return Err(format!("Export request failed with status: {}", res.status()));
        }

        let csv_text = res.text().await.map_err(|e| e.to_string())?;

        let _ = js_sys::eval(&format!(
            r#"(function() {{
                const blob = new Blob([`{}`], {{ type: 'text/csv;charset=utf-8;' }});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'security_incidents_report.csv';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(url), 1000);
            }})()"#,
            csv_text.replace('\\', "\\\\").replace('`', "\\`").replace('$', "\\$")
        ));

        Ok(())
    }
}

