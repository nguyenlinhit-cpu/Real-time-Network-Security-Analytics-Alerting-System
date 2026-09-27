use common::models::TrafficEvent;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// Decoupled event sink interface for capture-to-detection pipelines
pub trait EventSink: Send + Sync {
    fn emit<'a>(
        &'a self,
        event: &'a TrafficEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// In-memory MPSC channel sink (high performance, local single-node mode)
pub struct LocalChannelSink {
    tx: Sender<TrafficEvent>,
}

impl LocalChannelSink {
    pub fn new(tx: Sender<TrafficEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for LocalChannelSink {
    fn emit<'a>(
        &'a self,
        event: &'a TrafficEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.tx
                .send(event.clone())
                .await
                .map_err(|e| format!("Channel send error: {}", e))
        })
    }
}

/// Distributed Redis Stream broker sink (for multi-node capture-engine deployments)
pub struct RedisStreamBrokerSink {
    redis_address: String,
    stream_key: String,
    stream: Mutex<Option<BufReader<TcpStream>>>,
}

impl RedisStreamBrokerSink {
    pub fn new(redis_address: String, stream_key: String) -> Self {
        Self {
            redis_address,
            stream_key,
            stream: Mutex::new(None),
        }
    }
}

impl EventSink for RedisStreamBrokerSink {
    fn emit<'a>(
        &'a self,
        event: &'a TrafficEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let json_payload = serde_json::to_string(event).map_err(|e| e.to_string())?;

            let mut guard = self.stream.lock().await;
            if guard.is_none() {
                let stripped = self.redis_address.trim_start_matches("redis://");
                let host_port = if stripped.contains(':') {
                    stripped.to_string()
                } else {
                    format!("{}:6379", stripped)
                };

                match TcpStream::connect(&host_port).await {
                    Ok(s) => {
                        info!("Connected to Redis Stream message broker at {}", host_port);
                        *guard = Some(BufReader::new(s));
                    }
                    Err(e) => return Err(format!("Could not connect to Redis Stream: {}", e)),
                }
            }

            let reader = guard.as_mut().unwrap();

            // RESP command: XADD <stream_key> * event <json>
            let cmd = format!(
                "*5\r\n$4\r\nXADD\r\n${}\r\n{}\r\n$1\r\n*\r\n$5\r\nevent\r\n${}\r\n{}\r\n",
                self.stream_key.len(),
                self.stream_key,
                json_payload.len(),
                json_payload
            );

            if let Err(e) = reader.get_mut().write_all(cmd.as_bytes()).await {
                *guard = None;
                return Err(format!("Error writing to Redis Stream: {}", e));
            }

            let mut line = String::new();
            if let Err(e) = reader.read_line(&mut line).await {
                *guard = None;
                return Err(format!("Error reading from Redis Stream: {}", e));
            }

            Ok(())
        })
    }
}
