use common::models::{Alert, TrafficBatchDto, TrafficEvent};
use futures::{future::Either, StreamExt};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

use crate::api::client::ApiClient;

const MAX_BACKOFF_MS: u32 = 30_000;
const TOKEN_CHECK_MS: u32 = 2_000;

fn ws_url(path: &str, token: &str) -> Option<String> {
    let window = web_sys::window()?;
    let location = window.location();
    let host = location.host().ok()?;
    let scheme = if location.protocol().unwrap_or_default() == "https:" {
        "wss:"
    } else {
        "ws:"
    };
    let token = js_sys::encode_uri_component(token).as_string()?;
    Some(format!("{}//{}{}?token={}", scheme, host, path, token))
}

/// Keeps one authenticated WebSocket to `path` open for as long as the user is logged in.
/// Reconnects with exponential backoff (reset after every successful connection), closes the
/// socket when the user logs out or the token changes, and releases its JS callbacks on close.
fn run_stream(
    path: &'static str,
    on_message: Rc<dyn Fn(String)>,
    set_connected: Option<WriteSignal<bool>>,
) {
    leptos::task::spawn_local(async move {
        let mut backoff_ms = 1_000u32;
        let mut failed_attempts = 0u32;
        loop {
            let Some(token) = ApiClient::get_token() else {
                // Not logged in: wait quietly (no backoff growth) until a token appears.
                if let Some(s) = set_connected {
                    s.set(false);
                }
                failed_attempts = 0;
                backoff_ms = 1_000;
                TimeoutFuture::new(1_000).await;
                continue;
            };
            let Some(url) = ws_url(path, &token) else {
                TimeoutFuture::new(backoff_ms).await;
                continue;
            };

            let opened = Rc::new(Cell::new(false));
            if let Ok(ws) = WebSocket::new(&url) {
                let (close_tx, mut close_rx) = futures::channel::mpsc::unbounded::<()>();

                let opened_cb = opened.clone();
                let onopen = Closure::<dyn FnMut()>::new(move || {
                    opened_cb.set(true);
                    if let Some(s) = set_connected {
                        s.set(true);
                    }
                });
                let handler = on_message.clone();
                let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                    if let Some(txt) = e.data().as_string() {
                        handler(txt);
                    }
                });
                let tx_close = close_tx.clone();
                let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |_| {
                    let _ = tx_close.unbounded_send(());
                });
                let onerror = Closure::<dyn FnMut(Event)>::new(move |_| {
                    let _ = close_tx.unbounded_send(());
                });
                ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
                ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
                ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
                ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

                loop {
                    let tick = TimeoutFuture::new(TOKEN_CHECK_MS);
                    match futures::future::select(close_rx.next(), tick).await {
                        Either::Left(_) => break,
                        Either::Right(_) => {
                            // Logged out or token rotated: reconnect with the current credentials.
                            if ApiClient::get_token().as_deref() != Some(token.as_str()) {
                                let _ = ws.close();
                                break;
                            }
                        }
                    }
                }

                ws.set_onopen(None);
                ws.set_onmessage(None);
                ws.set_onclose(None);
                ws.set_onerror(None);
                let _ = ws.close();
                drop((onopen, onmessage, onclose, onerror));
            }

            if let Some(s) = set_connected {
                s.set(false);
            }
            if opened.get() {
                backoff_ms = 1_000;
                failed_attempts = 0;
            } else {
                failed_attempts += 1;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                // Repeated handshake failures usually mean the access token expired.
                if failed_attempts == 2 && ApiClient::get_token().as_deref() == Some(token.as_str())
                {
                    ApiClient::refresh_session().await;
                }
            }
            TimeoutFuture::new(backoff_ms).await;
        }
    });
}

pub fn init_alerts_websocket(
    alerts_signal: WriteSignal<Vec<Alert>>,
    latest_alert: WriteSignal<Option<Alert>>,
    is_connected: WriteSignal<bool>,
) {
    let handler: Rc<dyn Fn(String)> = Rc::new(move |txt: String| {
        let Ok(alert) = serde_json::from_str::<Alert>(&txt) else {
            return;
        };
        let mut is_new = true;
        alerts_signal.update(|list| {
            if let Some(existing) = list.iter_mut().find(|a| a.id == alert.id) {
                *existing = alert.clone();
                is_new = false;
            } else {
                list.insert(0, alert.clone());
                list.truncate(200);
            }
        });
        if is_new {
            latest_alert.set(Some(alert));
        }
    });
    run_stream("/ws/alerts", handler, Some(is_connected));
}

pub fn init_traffic_websocket(
    traffic_signal: WriteSignal<Vec<TrafficEvent>>,
    total_bytes_signal: WriteSignal<u64>,
) {
    let handler: Rc<dyn Fn(String)> = Rc::new(move |txt: String| {
        let Ok(batch) = serde_json::from_str::<TrafficBatchDto>(&txt) else {
            return;
        };
        total_bytes_signal.update(|v| *v += batch.total_bytes.max(0) as u64);
        traffic_signal.update(|list| {
            for event in batch.events.into_iter().rev() {
                list.insert(0, event);
            }
            list.truncate(100);
        });
    });
    run_stream("/ws/traffic", handler, None);
}
