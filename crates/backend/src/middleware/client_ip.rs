use axum::{
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{request::Parts, HeaderMap},
    middleware::Next,
    response::Response,
};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

/// Resolved client address, inserted into request extensions by `client_ip_middleware`.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    pub fn network(&self) -> IpNetwork {
        IpNetwork::from(self.0)
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .unwrap_or(ClientIp(IpAddr::V4(Ipv4Addr::LOCALHOST))))
    }
}

/// Proxies whose `X-Real-IP` / `X-Forwarded-For` headers are trusted.
/// Configurable via `TRUSTED_PROXIES` (comma-separated CIDRs); defaults to loopback and
/// private ranges, which is where the bundled nginx reverse proxies live.
fn trusted_proxies() -> &'static Vec<IpNetwork> {
    static PROXIES: OnceLock<Vec<IpNetwork>> = OnceLock::new();
    PROXIES.get_or_init(|| {
        let raw = std::env::var("TRUSTED_PROXIES")
            .unwrap_or_else(|_| "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16".into());
        raw.split(',')
            .filter_map(|s| s.trim().parse::<IpNetwork>().ok())
            .collect()
    })
}

/// Determine the real client IP. Forwarding headers are only honoured when the TCP peer is a
/// trusted proxy, so clients connecting directly cannot spoof their address.
pub fn resolve_client_ip(peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
    let peer_ip = match peer {
        Some(ip) => ip,
        // No connection info (e.g. in-process tests): nothing to trust.
        None => return IpAddr::V4(Ipv4Addr::LOCALHOST),
    };

    if !trusted_proxies().iter().any(|net| net.contains(peer_ip)) {
        return peer_ip;
    }

    if let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }

    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }

    peer_ip
}

pub async fn client_ip_middleware(mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let ip = resolve_client_ip(peer, request.headers());
    request.extensions_mut().insert(ClientIp(ip));
    next.run(request).await
}
