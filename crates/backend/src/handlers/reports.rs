use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use common::models::Alert;

use crate::{auth::middleware::CurrentUser, error::AppError, state::AppState};

#[derive(serde::Deserialize)]
pub struct ReportExportQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub format: Option<String>,
    pub limit: Option<i64>,
}

const MAX_EXPORT_ROWS: i64 = 10_000;

/// Sanitize text against CSV / Formula Injection (CWE-1236) (Mục 20)
fn sanitize_csv_cell(val: &str) -> String {
    let escaped = val.replace('\"', "\"\"");
    let trimmed = escaped.trim_start();
    if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r')
    {
        format!("'{}", escaped)
    } else {
        escaped
    }
}

#[utoipa::path(
    get,
    path = "/api/reports/export",
    params(
        ("from" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Start of the detection time range"),
        ("to" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "End of the detection time range"),
        ("format" = Option<String>, Query, description = "Export format (only `csv` is supported)"),
        ("limit" = Option<i64>, Query, description = "Maximum rows (default and max 10000)")
    ),
    responses(
        (status = 200, description = "CSV incident report; header X-Report-Truncated=true when the limit was reached", body = String),
        (status = 400, description = "Unsupported format", body = common::ApiResponse<()>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn export_reports(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(query): Query<ReportExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(fmt) = query.format.as_deref() {
        if !fmt.eq_ignore_ascii_case("csv") {
            return Err(AppError::BadRequest(format!(
                "Unsupported export format '{}' (only 'csv' is available)",
                fmt
            )));
        }
    }
    let limit = query.limit.unwrap_or(MAX_EXPORT_ROWS).clamp(1, MAX_EXPORT_ROWS);

    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
        FROM alerts
        WHERE ($1::TIMESTAMPTZ IS NULL OR detected_at >= $1)
          AND ($2::TIMESTAMPTZ IS NULL OR detected_at <= $2)
        ORDER BY detected_at DESC
        LIMIT $3
        "#,
    )
    .bind(query.from)
    .bind(query.to)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let truncated = alerts.len() as i64 >= limit;
    let mut csv_output =
        String::from("id,detected_at,severity,status,src_ip,dst_ip,title,description,mitre_tactic,mitre_technique\n");
    for a in alerts {
        csv_output.push_str(&format!(
            "\"{}\",\"{}\",\"{:?}\",\"{:?}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            a.id,
            a.detected_at.to_rfc3339(),
            a.severity,
            a.status,
            a.src_ip,
            a.dst_ip,
            sanitize_csv_cell(&a.title),
            sanitize_csv_cell(&a.description),
            sanitize_csv_cell(a.mitre_tactic.as_deref().unwrap_or("")),
            sanitize_csv_cell(a.mitre_technique.as_deref().unwrap_or(""))
        ));
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"security_incidents_report.csv\""),
    );
    headers.insert(
        "x-report-truncated",
        HeaderValue::from_static(if truncated { "true" } else { "false" }),
    );

    Ok((StatusCode::OK, headers, csv_output))
}
