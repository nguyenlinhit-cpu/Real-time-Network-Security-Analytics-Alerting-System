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
}

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

pub async fn export_reports(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(query): Query<ReportExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at
        FROM alerts
        WHERE ($1::TIMESTAMPTZ IS NULL OR detected_at >= $1)
          AND ($2::TIMESTAMPTZ IS NULL OR detected_at <= $2)
        ORDER BY detected_at DESC
        LIMIT 1000
        "#,
    )
    .bind(query.from)
    .bind(query.to)
    .fetch_all(&state.pool)
    .await?;

    let mut csv_output =
        String::from("id,detected_at,severity,status,src_ip,dst_ip,title,description\n");
    for a in alerts {
        csv_output.push_str(&format!(
            "\"{}\",\"{}\",\"{:?}\",\"{:?}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            a.id,
            a.detected_at.to_rfc3339(),
            a.severity,
            a.status,
            a.src_ip,
            a.dst_ip,
            sanitize_csv_cell(&a.title),
            sanitize_csv_cell(&a.description)
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

    Ok((StatusCode::OK, headers, csv_output))
}
