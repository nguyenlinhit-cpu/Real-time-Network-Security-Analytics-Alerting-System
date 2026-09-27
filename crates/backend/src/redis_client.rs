use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Lightweight, async RESP-compatible Redis client for distributed rate limiting and alert deduplication
pub struct SimpleRedisClient {
    address: Option<String>,
    connection: Mutex<Option<BufReader<TcpStream>>>,
    connected: AtomicBool,
}

impl SimpleRedisClient {
    pub fn new(address: Option<String>) -> Self {
        let has_addr = address.is_some();
        Self {
            address,
            connection: Mutex::new(None),
            connected: AtomicBool::new(has_addr),
        }
    }

    /// Check if Redis address is configured
    pub fn is_configured(&self) -> bool {
        self.address.is_some()
    }

    /// Helper to parse host and port from various URL formats (redis://host:port or host:port)
    fn get_host_port(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        let stripped = addr.trim_start_matches("redis://");
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        if host_port.contains(':') {
            Some(host_port.to_string())
        } else {
            Some(format!("{}:6379", host_port))
        }
    }

    /// Acquire or establish connection
    async fn get_connection<'a>(
        &'a self,
        guard: &'a mut tokio::sync::MutexGuard<'_, Option<BufReader<TcpStream>>>,
    ) -> Result<&'a mut BufReader<TcpStream>, String> {
        if guard.is_none() {
            let host_port = self
                .get_host_port()
                .ok_or_else(|| "Redis address not configured".to_string())?;

            match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&host_port)).await {
                Ok(Ok(stream)) => {
                    info!("Connected to distributed Redis instance at {}", host_port);
                    **guard = Some(BufReader::new(stream));
                    self.connected.store(true, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(format!("Failed to connect to Redis at {}: {}", host_port, e));
                }
                Err(_) => {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(format!("Connection timeout to Redis at {}", host_port));
                }
            }
        }

        Ok(guard.as_mut().unwrap())
    }

    /// Atomically increments a key and sets TTL on creation (distributed rate limiting)
    pub async fn incr_with_expire(&self, key: &str, ttl_seconds: u64) -> Result<i64, String> {
        let mut guard = self.connection.lock().await;
        let reader = match self.get_connection(&mut guard).await {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        // Command 1: INCR key
        let cmd = format!("*2\r\n$4\r\nINCR\r\n${}\r\n{}\r\n", key.len(), key);
        if let Err(e) = reader.get_mut().write_all(cmd.as_bytes()).await {
            *guard = None;
            return Err(format!("Write error to Redis: {}", e));
        }

        let mut line = String::new();
        if let Err(e) = reader.read_line(&mut line).await {
            *guard = None;
            return Err(format!("Read error from Redis: {}", e));
        }

        let count: i64 = if line.starts_with(':') {
            line[1..].trim().parse().map_err(|e| format!("Invalid INCR response: {}", e))?
        } else {
            *guard = None;
            return Err(format!("Unexpected INCR response from Redis: {}", line.trim()));
        };

        // If newly created counter (count == 1), set expiration TTL
        if count == 1 {
            let ttl_str = ttl_seconds.to_string();
            let expire_cmd = format!(
                "*3\r\n$6\r\nEXPIRE\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                key.len(),
                key,
                ttl_str.len(),
                ttl_str
            );
            if let Err(e) = reader.get_mut().write_all(expire_cmd.as_bytes()).await {
                *guard = None;
                return Err(format!("Write EXPIRE error to Redis: {}", e));
            }

            let mut exp_line = String::new();
            let _ = reader.read_line(&mut exp_line).await;
        }

        Ok(count)
    }

    /// Sets key only if not exists with TTL (distributed alert deduplication / cooldown)
    /// Returns Ok(true) if newly set (i.e. NOT throttled), Ok(false) if key already exists (throttled)
    pub async fn set_nx_ex(&self, key: &str, val: &str, ttl_seconds: u64) -> Result<bool, String> {
        let mut guard = self.connection.lock().await;
        let reader = match self.get_connection(&mut guard).await {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let ttl_str = ttl_seconds.to_string();
        let cmd = format!(
            "*6\r\n$3\r\nSET\r\n${}\r\n{}\r\n${}\r\n{}\r\n$2\r\nEX\r\n${}\r\n{}\r\n$2\r\nNX\r\n",
            key.len(),
            key,
            val.len(),
            val,
            ttl_str.len(),
            ttl_str
        );

        if let Err(e) = reader.get_mut().write_all(cmd.as_bytes()).await {
            *guard = None;
            return Err(format!("Write SET NX EX error to Redis: {}", e));
        }

        let mut line = String::new();
        if let Err(e) = reader.read_line(&mut line).await {
            *guard = None;
            return Err(format!("Read SET NX EX error from Redis: {}", e));
        }

        let trimmed = line.trim();
        if trimmed == "+OK" {
            Ok(true) // Acquired slot
        } else if trimmed == "$-1" {
            Ok(false) // Already exists
        } else {
            debug!("SET NX EX unexpected response: {}", trimmed);
            Ok(false)
        }
    }
}
