use axum::http::HeaderMap;
use backend::middleware::resolve_client_ip;
use std::net::IpAddr;

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, v.parse().unwrap());
    }
    h
}

#[test]
fn forwarded_headers_are_ignored_from_untrusted_peers() {
    // A client connecting directly from the Internet cannot choose its rate-limit identity.
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    let h = headers(&[("x-real-ip", "9.9.9.9"), ("x-forwarded-for", "8.8.8.8")]);
    assert_eq!(resolve_client_ip(Some(peer), &h), peer);
}

#[test]
fn forwarded_headers_are_used_behind_trusted_proxy() {
    // nginx inside the docker network (private range) forwards the real client address.
    let proxy: IpAddr = "172.18.0.5".parse().unwrap();
    let h = headers(&[("x-real-ip", "198.51.100.23")]);
    assert_eq!(
        resolve_client_ip(Some(proxy), &h),
        "198.51.100.23".parse::<IpAddr>().unwrap()
    );

    // X-Forwarded-For: the right-most entry is the one appended by the trusted proxy.
    let h = headers(&[("x-forwarded-for", "1.2.3.4, 198.51.100.99")]);
    assert_eq!(
        resolve_client_ip(Some(proxy), &h),
        "198.51.100.99".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn garbage_forwarded_header_falls_back_to_peer() {
    let proxy: IpAddr = "127.0.0.1".parse().unwrap();
    let h = headers(&[("x-real-ip", "not-an-ip")]);
    assert_eq!(resolve_client_ip(Some(proxy), &h), proxy);
}
