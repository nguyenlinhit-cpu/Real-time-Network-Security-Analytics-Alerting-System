use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::info;

/// Every Redis round-trip (connect + write + read) must finish within this budget, so a hung
/// Redis instance degrades to the in-memory fallbacks instead of stalling every API request.
const REDIS_OP_TIMEOUT: Duration = Duration::from_millis(500);

/// Minimal RESP reply representation (only the reply types the commands below produce).
#[derive(Debug, Clone, PartialEq)]
pub enum RespValue {
    Simple(String),
    Integer(i64),
    Bulk(Option<String>),
    Error(String),
}

/// Lightweight, async RESP-compatible Redis client for distributed rate limiting and alert deduplication
pub struct SimpleRedisClient {
    address: Option<String>,
    connection: Mutex<Option<BufReader<TcpStream>>>,
}

impl SimpleRedisClient {
    pub fn new(address: Option<String>) -> Self {
        Self {
            address,
            connection: Mutex::new(None),
        }
    }

    /// Check if Redis address is configured
    pub fn is_configured(&self) -> bool {
        self.address.is_some()
    }

    /// Password from `redis://:password@host:port` (or `redis://user:password@…`).
    fn get_password(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        let rest = addr.trim_start_matches("redis://");
        let (creds, _) = rest.split_once('@')?;
        let password = creds.split_once(':').map(|(_, p)| p).unwrap_or(creds);
        (!password.is_empty()).then(|| password.to_string())
    }

    /// Helper to parse host and port from various URL formats (redis://host:port or host:port)
    fn get_host_port(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        let stripped = addr.trim_start_matches("redis://");
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        let host_port = host_port.rsplit('@').next().unwrap_or(host_port);
        if host_port.contains(':') {
            Some(host_port.to_string())
        } else {
            Some(format!("{}:6379", host_port))
        }
    }

    fn encode(args: &[&str]) -> Vec<u8> {
        let mut out = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            out.extend_from_slice(a.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    async fn read_reply(reader: &mut BufReader<TcpStream>) -> Result<RespValue, String> {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("Read error from Redis: {}", e))?;
        if n == 0 {
            return Err("Redis closed the connection".to_string());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let (prefix, rest) = line.split_at(1.min(line.len()));
        match prefix {
            "+" => Ok(RespValue::Simple(rest.to_string())),
            "-" => Ok(RespValue::Error(rest.to_string())),
            ":" => rest
                .parse()
                .map(RespValue::Integer)
                .map_err(|e| format!("Invalid integer reply: {}", e)),
            "$" => {
                let len: i64 = rest
                    .parse()
                    .map_err(|e| format!("Invalid bulk length: {}", e))?;
                if len < 0 {
                    return Ok(RespValue::Bulk(None));
                }
                let mut buf = vec![0u8; len as usize + 2];
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| format!("Read error from Redis: {}", e))?;
                buf.truncate(len as usize);
                Ok(RespValue::Bulk(Some(
                    String::from_utf8_lossy(&buf).into_owned(),
                )))
            }
            _ => Err(format!("Unexpected Redis reply: {}", line)),
        }
    }

    /// Sends one command and reads its reply. Any failure drops the connection so the next call
    /// reconnects cleanly instead of reading a stale, out-of-sync reply.
    pub async fn command(&self, args: &[&str]) -> Result<RespValue, String> {
        let host_port = self
            .get_host_port()
            .ok_or_else(|| "Redis address not configured".to_string())?;
        let mut guard = self.connection.lock().await;

        let result = tokio::time::timeout(REDIS_OP_TIMEOUT, async {
            if guard.is_none() {
                let stream = TcpStream::connect(&host_port)
                    .await
                    .map_err(|e| format!("Failed to connect to Redis at {}: {}", host_port, e))?;
                let mut reader = BufReader::new(stream);
                if let Some(password) = self.get_password() {
                    reader
                        .get_mut()
                        .write_all(&Self::encode(&["AUTH", &password]))
                        .await
                        .map_err(|e| format!("Write error to Redis: {}", e))?;
                    match Self::read_reply(&mut reader).await? {
                        RespValue::Simple(ok) if ok == "OK" => {}
                        other => return Err(format!("Redis AUTH failed: {:?}", other)),
                    }
                }
                info!("Connected to distributed Redis instance at {}", host_port);
                *guard = Some(reader);
            }
            let reader = guard.as_mut().expect("connection initialised above");
            reader
                .get_mut()
                .write_all(&Self::encode(args))
                .await
                .map_err(|e| format!("Write error to Redis: {}", e))?;
            Self::read_reply(reader).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "Redis operation timed out ({:?})",
                REDIS_OP_TIMEOUT
            ))
        });

        match result {
            Ok(RespValue::Error(e)) => Err(format!("Redis error: {}", e)),
            Ok(v) => Ok(v),
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }

    /// Atomically increments a key and sets TTL on creation (distributed rate limiting)
    pub async fn incr_with_expire(&self, key: &str, ttl_seconds: u64) -> Result<i64, String> {
        let count = match self.command(&["INCR", key]).await? {
            RespValue::Integer(n) => n,
            other => return Err(format!("Unexpected INCR reply: {:?}", other)),
        };
        if count == 1 {
            self.command(&["EXPIRE", key, &ttl_seconds.to_string()])
                .await?;
        }
        Ok(count)
    }

    /// Sets key only if not exists with TTL (distributed alert deduplication / cooldown)
    /// Returns Ok(true) if newly set (i.e. NOT throttled), Ok(false) if key already exists (throttled)
    pub async fn set_nx_ex(&self, key: &str, val: &str, ttl_seconds: u64) -> Result<bool, String> {
        match self
            .command(&["SET", key, val, "EX", &ttl_seconds.to_string(), "NX"])
            .await?
        {
            RespValue::Simple(s) if s == "OK" => Ok(true),
            RespValue::Bulk(None) => Ok(false),
            other => Err(format!("Unexpected SET NX reply: {:?}", other)),
        }
    }

    /// Checks if a key exists in Redis
    pub async fn exists(&self, key: &str) -> Result<bool, String> {
        match self.command(&["EXISTS", key]).await? {
            RespValue::Integer(n) => Ok(n > 0),
            other => Err(format!("Unexpected EXISTS reply: {:?}", other)),
        }
    }

    /// Sets key with TTL
    pub async fn set_ex(&self, key: &str, val: &str, ttl_seconds: u64) -> Result<(), String> {
        self.command(&["SET", key, val, "EX", &ttl_seconds.max(1).to_string()])
            .await
            .map(|_| ())
    }

    /// Deletes a key from Redis
    pub async fn del(&self, key: &str) -> Result<bool, String> {
        match self.command(&["DEL", key]).await? {
            RespValue::Integer(n) => Ok(n > 0),
            other => Err(format!("Unexpected DEL reply: {:?}", other)),
        }
    }

    /// Gets integer value of key (e.g. for failed login counter)
    pub async fn get_int(&self, key: &str) -> Result<Option<i64>, String> {
        match self.command(&["GET", key]).await? {
            RespValue::Bulk(Some(s)) => Ok(s.trim().parse().ok()),
            RespValue::Bulk(None) => Ok(None),
            other => Err(format!("Unexpected GET reply: {:?}", other)),
        }
    }
}
