use common::models::*;
use common::ApiResponse;
use futures::future::{FutureExt, LocalBoxFuture, Shared};
use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use std::cell::RefCell;
use web_sys::window;

type RefreshFuture = Shared<LocalBoxFuture<'static, Result<String, String>>>;

thread_local! {
    /// Refresh tokens are single-use (rotation), so concurrent 401s must share one refresh.
    static REFRESH_IN_FLIGHT: RefCell<Option<RefreshFuture>> = const { RefCell::new(None) };
}

const TOKEN_STORAGE_KEY: &str = "secnet_jwt_token";
const REFRESH_TOKEN_STORAGE_KEY: &str = "secnet_refresh_token";
const USER_STORAGE_KEY: &str = "secnet_user_info";

/// Filters for the paginated alert list.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AlertQuery {
    pub severity: Option<AlertSeverity>,
    pub status: Option<AlertStatus>,
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

fn enum_param<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn encode_component(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_default()
}

pub struct ApiClient;

impl ApiClient {
    fn storage() -> Option<web_sys::Storage> {
        window().and_then(|w| w.local_storage().ok().flatten())
    }

    pub fn get_token() -> Option<String> {
        Self::storage()?
            .get_item(TOKEN_STORAGE_KEY)
            .ok()?
            .filter(|t| !t.is_empty())
    }

    fn get_refresh_token() -> Option<String> {
        Self::storage()?
            .get_item(REFRESH_TOKEN_STORAGE_KEY)
            .ok()?
            .filter(|t| !t.is_empty())
    }

    fn store_session(data: &AuthResponseDto) {
        if let Some(storage) = Self::storage() {
            let _ = storage.set_item(TOKEN_STORAGE_KEY, &data.token);
            let _ = storage.set_item(REFRESH_TOKEN_STORAGE_KEY, &data.refresh_token);
            if let Ok(json) = serde_json::to_string(&data.user) {
                let _ = storage.set_item(USER_STORAGE_KEY, &json);
            }
        }
    }

    pub fn get_current_user() -> Option<UserPublicDto> {
        let user_str = Self::storage()?.get_item(USER_STORAGE_KEY).ok()??;
        serde_json::from_str(&user_str).ok()
    }

    pub fn is_admin() -> bool {
        Self::get_current_user()
            .map(|u| u.role == UserRole::Admin)
            .unwrap_or(false)
    }

    pub fn is_analyst_or_admin() -> bool {
        Self::get_current_user()
            .map(|u| matches!(u.role, UserRole::Admin | UserRole::Analyst))
            .unwrap_or(false)
    }

    pub fn clear_session() {
        if let Some(storage) = Self::storage() {
            let _ = storage.remove_item(TOKEN_STORAGE_KEY);
            let _ = storage.remove_item(REFRESH_TOKEN_STORAGE_KEY);
            let _ = storage.remove_item(USER_STORAGE_KEY);
        }
    }

    /// The session can no longer be refreshed: drop it and return to the login screen.
    fn session_expired() {
        Self::clear_session();
        if let Some(w) = window() {
            let _ = w.location().set_hash("login");
            let _ = w.location().reload();
        }
    }

    /// Revokes the tokens server-side, then clears the local session.
    pub async fn api_logout() {
        let payload = serde_json::json!({
            "refresh_token": Self::get_refresh_token().unwrap_or_default()
        });
        if let Some(token) = Self::get_token() {
            if let Ok(req) = Request::post("/api/auth/logout")
                .header("Authorization", &format!("Bearer {}", token))
                .json(&payload)
            {
                let _ = req.send().await;
            }
        }
        Self::clear_session();
    }

    /// Exchanges the refresh token for a new token pair (rotation).
    pub async fn try_refresh_token() -> Result<String, String> {
        let refresh =
            Self::get_refresh_token().ok_or_else(|| "No refresh token available".to_string())?;
        let res = Request::post("/api/auth/refresh")
            .json(&serde_json::json!({ "refresh_token": refresh }))
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        let body: ApiResponse<AuthResponseDto> = res.json().await.map_err(|e| e.to_string())?;
        match body.data {
            Some(data) if body.success => {
                Self::store_session(&data);
                Ok(data.token)
            }
            _ => Err("Session expired, please login again".to_string()),
        }
    }

    async fn refresh_shared() -> Result<String, String> {
        let fut = REFRESH_IN_FLIGHT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(f) = slot.as_ref() {
                return f.clone();
            }
            let f = Self::try_refresh_token().boxed_local().shared();
            *slot = Some(f.clone());
            f
        });
        let result = fut.await;
        REFRESH_IN_FLIGHT.with(|slot| *slot.borrow_mut() = None);
        result
    }

    /// Refreshes the session proactively (e.g. after WebSocket handshake failures). Logs the
    /// user out if the refresh token is no longer valid.
    pub async fn refresh_session() -> bool {
        match Self::refresh_shared().await {
            Ok(_) => true,
            Err(e) if e.starts_with("Network error") => false,
            Err(_) => {
                Self::session_expired();
                false
            }
        }
    }

    pub fn is_authenticated() -> bool {
        Self::get_token().is_some()
    }

    fn builder(method: &str, url: &str) -> RequestBuilder {
        let req = match method {
            "POST" => Request::post(url),
            "PATCH" => Request::patch(url),
            "DELETE" => Request::delete(url),
            _ => Request::get(url),
        };
        match Self::get_token() {
            Some(token) => req.header("Authorization", &format!("Bearer {}", token)),
            None => req,
        }
    }

    async fn send_once(
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Response, String> {
        let builder = Self::builder(method, url);
        let result = match body {
            Some(b) => builder.json(b).map_err(|e| e.to_string())?.send().await,
            None => builder.send().await,
        };
        result.map_err(|e| format!("Network error: {}", e))
    }

    /// Sends an authenticated request; on 401 the access token is refreshed once and the request
    /// retried. If the refresh fails the user is logged out.
    async fn send(
        method: &str,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Response, String> {
        let res = Self::send_once(method, url, body.as_ref()).await?;
        if res.status() != 401 {
            return Ok(res);
        }
        match Self::refresh_shared().await {
            Ok(_) => Self::send_once(method, url, body.as_ref()).await,
            // A transient network failure is not a reason to drop the session.
            Err(e) if e.starts_with("Network error") => Err(e),
            Err(e) => {
                Self::session_expired();
                Err(e)
            }
        }
    }

    async fn parse<T: DeserializeOwned>(res: Response) -> Result<ApiResponse<T>, String> {
        let status = res.status();
        res.json::<ApiResponse<T>>()
            .await
            .map_err(|_| format!("Unexpected server response (HTTP {})", status))
    }

    /// Request whose response carries data.
    async fn request<T: DeserializeOwned>(
        method: &str,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, String> {
        let body = Self::parse::<T>(Self::send(method, url, body).await?).await?;
        match body.data {
            Some(data) if body.success => Ok(data),
            _ => Err(body.error.unwrap_or_else(|| "Request failed".to_string())),
        }
    }

    /// Request whose success response has no meaningful data.
    async fn request_ok(method: &str, url: &str) -> Result<(), String> {
        let body = Self::parse::<serde_json::Value>(Self::send(method, url, None).await?).await?;
        if body.success {
            Ok(())
        } else {
            Err(body.error.unwrap_or_else(|| "Request failed".to_string()))
        }
    }

    fn to_value<T: serde::Serialize>(dto: &T) -> Result<serde_json::Value, String> {
        serde_json::to_value(dto).map_err(|e| e.to_string())
    }

    async fn authenticate(url: &str, body: serde_json::Value) -> Result<AuthResponseDto, String> {
        let res = Request::post(url)
            .json(&body)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;
        let body = Self::parse::<AuthResponseDto>(res).await?;
        match body.data {
            Some(data) if body.success => {
                Self::store_session(&data);
                Ok(data)
            }
            _ => Err(body
                .error
                .unwrap_or_else(|| "Authentication failed".to_string())),
        }
    }

    pub async fn login(dto: &LoginDto) -> Result<AuthResponseDto, String> {
        Self::authenticate("/api/auth/login", Self::to_value(dto)?).await
    }

    pub async fn register(dto: &CreateUserDto) -> Result<AuthResponseDto, String> {
        Self::authenticate("/api/auth/register", Self::to_value(dto)?).await
    }

    pub async fn get_dashboard_summary() -> Result<TrafficSummaryDto, String> {
        Self::request("GET", "/api/dashboard/summary", None).await
    }

    pub async fn get_alerts(query: &AlertQuery) -> Result<Vec<Alert>, String> {
        let mut url = format!(
            "/api/alerts?limit={}&offset={}",
            query.limit.clamp(1, 200),
            query.offset.max(0)
        );
        if let Some(sev) = &query.severity {
            url.push_str(&format!("&severity={}", enum_param(sev)));
        }
        if let Some(st) = &query.status {
            url.push_str(&format!("&status={}", enum_param(st)));
        }
        if let Some(search) = query.search.as_deref().filter(|s| !s.trim().is_empty()) {
            url.push_str(&format!("&search={}", encode_component(search.trim())));
        }
        Self::request("GET", &url, None).await
    }

    pub async fn update_alert_status(id: uuid::Uuid, status: AlertStatus) -> Result<Alert, String> {
        let body = Self::to_value(&UpdateAlertDto { status })?;
        Self::request("PATCH", &format!("/api/alerts/{}", id), Some(body)).await
    }

    pub async fn get_traffic() -> Result<Vec<TrafficEvent>, String> {
        Self::request("GET", "/api/traffic?limit=50", None).await
    }

    pub async fn get_rules() -> Result<Vec<DetectionRule>, String> {
        Self::request("GET", "/api/rules", None).await
    }

    pub async fn get_devices() -> Result<Vec<Device>, String> {
        Self::request("GET", "/api/devices", None).await
    }

    pub async fn get_device_history(id: uuid::Uuid) -> Result<Vec<TrafficEvent>, String> {
        Self::request("GET", &format!("/api/devices/{}/history", id), None).await
    }

    pub async fn get_alert_traffic(id: uuid::Uuid) -> Result<Vec<TrafficEvent>, String> {
        Self::request("GET", &format!("/api/alerts/{}/traffic", id), None).await
    }

    pub async fn get_audit_logs() -> Result<Vec<AuditLog>, String> {
        Self::request("GET", "/api/audit-logs?limit=200", None).await
    }

    pub async fn get_sensor_status() -> Result<Vec<SensorStatusDto>, String> {
        Self::request("GET", "/api/sensor/status", None).await
    }

    pub async fn create_rule(dto: &CreateRuleDto) -> Result<DetectionRule, String> {
        Self::request("POST", "/api/rules", Some(Self::to_value(dto)?)).await
    }

    pub async fn update_rule(id: uuid::Uuid, dto: &UpdateRuleDto) -> Result<DetectionRule, String> {
        Self::request(
            "PATCH",
            &format!("/api/rules/{}", id),
            Some(Self::to_value(dto)?),
        )
        .await
    }

    pub async fn delete_rule(id: uuid::Uuid) -> Result<(), String> {
        Self::request_ok("DELETE", &format!("/api/rules/{}", id)).await
    }

    pub async fn get_blocklist() -> Result<Vec<BlockedIp>, String> {
        Self::request("GET", "/api/blocklist", None).await
    }

    pub async fn add_to_blocklist(dto: &CreateBlockedIpDto) -> Result<BlockedIp, String> {
        Self::request("POST", "/api/blocklist", Some(Self::to_value(dto)?)).await
    }

    pub async fn remove_from_blocklist(id: uuid::Uuid) -> Result<(), String> {
        Self::request_ok("DELETE", &format!("/api/blocklist/{}", id)).await
    }

    pub async fn get_notification_channels() -> Result<Vec<NotificationChannel>, String> {
        Self::request("GET", "/api/notifications/channels", None).await
    }

    pub async fn create_notification_channel(
        dto: &CreateNotificationChannelDto,
    ) -> Result<NotificationChannel, String> {
        Self::request(
            "POST",
            "/api/notifications/channels",
            Some(Self::to_value(dto)?),
        )
        .await
    }

    pub async fn update_notification_channel(
        id: uuid::Uuid,
        dto: &UpdateNotificationChannelDto,
    ) -> Result<NotificationChannel, String> {
        Self::request(
            "PATCH",
            &format!("/api/notifications/channels/{}", id),
            Some(Self::to_value(dto)?),
        )
        .await
    }

    pub async fn delete_notification_channel(id: uuid::Uuid) -> Result<(), String> {
        Self::request_ok("DELETE", &format!("/api/notifications/channels/{}", id)).await
    }

    pub async fn test_notification_channel(id: uuid::Uuid) -> Result<String, String> {
        Self::request("POST", &format!("/api/notifications/test/{}", id), None).await
    }

    pub async fn export_csv_file() -> Result<(), String> {
        let res = Self::send("GET", "/api/reports/export?format=csv", None).await?;
        if !res.ok() {
            return Err(format!(
                "Export request failed with status: {}",
                res.status()
            ));
        }
        let csv_text = res.text().await.map_err(|e| e.to_string())?;

        // Client-side file download via a Blob URL (Mục 53)
        let blob_parts = js_sys::Array::new();
        blob_parts.push(&wasm_bindgen::JsValue::from_str(&csv_text));
        let blob_props = web_sys::BlobPropertyBag::new();
        blob_props.set_type("text/csv;charset=utf-8;");
        let blob = web_sys::Blob::new_with_str_sequence_and_options(&blob_parts, &blob_props)
            .map_err(|_| "Could not create CSV file".to_string())?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)
            .map_err(|_| "Could not create download link".to_string())?;

        if let Some(doc) = window().and_then(|w| w.document()) {
            if let Ok(elem) = doc.create_element("a") {
                if let Ok(a) = wasm_bindgen::JsCast::dyn_into::<web_sys::HtmlAnchorElement>(elem) {
                    a.set_href(&url);
                    a.set_download("security_incidents_report.csv");
                    if let Some(body) = doc.body() {
                        let _ = body.append_child(&a);
                        a.click();
                        let _ = body.remove_child(&a);
                    }
                }
            }
        }
        // The download has started; release the blob memory.
        let _ = web_sys::Url::revoke_object_url(&url);
        Ok(())
    }
}
