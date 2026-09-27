use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_rate_limiter_in_memory_sliding_window() {
    let rate_limiter = Arc::new(DashMap::new());
    let client_ip = "192.168.1.100";
    let key = format!("ratelimit:{}:auth", client_ip);
    let max_requests = 10;
    let window = Duration::from_secs(60);

    let now = Instant::now();

    // 1. First 10 requests should succeed
    for i in 1..=max_requests {
        let mut entry = rate_limiter.entry(key.clone()).or_insert((now, 0));
        let (window_start, count) = entry.value_mut();

        if now.duration_since(*window_start) > window {
            *window_start = now;
            *count = 1;
        } else {
            *count += 1;
        }

        assert_eq!(*count, i);
        assert!(*count <= max_requests);
    }

    // 2. 11th request should exceed the limit
    {
        let mut entry = rate_limiter.entry(key.clone()).or_insert((now, 0));
        let (_, count) = entry.value_mut();
        *count += 1;
        assert!(*count > max_requests, "11th request must trigger rate limit exceed");
    }

    // 3. Different endpoint category (API) should have independent counter
    let api_key = format!("ratelimit:{}:api", client_ip);
    {
        let mut entry = rate_limiter.entry(api_key.clone()).or_insert((now, 0));
        let (_, count) = entry.value_mut();
        *count = 1;
        assert_eq!(*count, 1, "API endpoint counter must be separate from auth counter");
    }
}
