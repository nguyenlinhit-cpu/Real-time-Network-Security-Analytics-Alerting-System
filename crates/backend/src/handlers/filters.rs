use ipnetwork::IpNetwork;

use crate::error::AppError;

/// Parses an optional IP filter. An invalid value is rejected instead of silently ignored,
/// which would otherwise return the unfiltered data set.
pub fn parse_ip_filter(name: &str, value: Option<&str>) -> Result<Option<IpNetwork>, AppError> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => s
            .parse::<IpNetwork>()
            .map(Some)
            .map_err(|_| AppError::BadRequest(format!("Invalid IP address for '{}': {}", name, s))),
    }
}

/// Builds a `%term%` ILIKE pattern with `%`, `_` and `\` escaped so user input matches literally.
pub fn like_pattern(term: Option<&str>) -> Option<String> {
    term.map(str::trim).filter(|s| !s.is_empty()).map(|s| {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{}%", escaped)
    })
}
