use common::models::{Alert, TrafficEvent};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

fn get_token_query() -> String {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        if let Ok(Some(tok)) = storage.get_item("secnet_jwt_token") {
            if !tok.is_empty() {
                return format!("?token={}", tok);
            }
        }
    }
    String::new()
}

pub fn init_alerts_websocket(
    alerts_signal: WriteSignal<Vec<Alert>>,
    latest_alert: WriteSignal<Option<Alert>>,
    is_connected: WriteSignal<bool>,
) {
    leptos::task::spawn_local(async move {
        let mut backoff_ms = 1000u32;
        loop {
            let window = match web_sys::window() {
                Some(w) => w,
                None => {
                    TimeoutFuture::new(3000).await;
                    continue;
                }
            };
            let host = window.location().host().unwrap_or_else(|_| "localhost:8080".to_string());
            let ws_protocol = if window.location().protocol().unwrap_or_default() == "https:" { "wss:" } else { "ws:" };
            let token_q = get_token_query();
            let ws_url = format!("{}//{}/ws/alerts{}", ws_protocol, host, token_q);

            let (close_tx, mut close_rx) = tokio::sync::mpsc::channel::<()>(2);
            let close_tx_err = close_tx.clone();

            if let Ok(ws) = WebSocket::new(&ws_url) {
                let onopen_callback = Closure::<dyn FnMut()>::new(move || {
                    is_connected.set(true);
                });
                ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
                onopen_callback.forget();

                let onmessage_callback = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                    if let Some(txt) = e.data().as_string() {
                        if let Ok(alert) = serde_json::from_str::<Alert>(&txt) {
                            latest_alert.set(Some(alert.clone()));
                            alerts_signal.update(|list| {
                                list.insert(0, alert);
                                if list.len() > 100 {
                                    list.pop();
                                }
                            });
                        }
                    }
                });
                ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
                onmessage_callback.forget();

                let onclose_callback = Closure::<dyn FnMut(CloseEvent)>::new(move |_| {
                    is_connected.set(false);
                    let _ = close_tx.try_send(());
                });
                ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
                onclose_callback.forget();

                let onerror_callback = Closure::<dyn FnMut(ErrorEvent)>::new(move |_| {
                    is_connected.set(false);
                    let _ = close_tx_err.try_send(());
                });
                ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
                onerror_callback.forget();

                // Wait until the connection is actually closed before attempting to reconnect (Mục 7)
                let _ = close_rx.recv().await;
                backoff_ms = (backoff_ms * 2).min(30000);
            } else {
                is_connected.set(false);
                backoff_ms = (backoff_ms * 2).min(30000);
            }

            TimeoutFuture::new(backoff_ms).await;
        }
    });
}

pub fn init_traffic_websocket(
    traffic_signal: WriteSignal<Vec<TrafficEvent>>,
    throughput_signal: WriteSignal<u64>,
) {
    leptos::task::spawn_local(async move {
        let mut backoff_ms = 1000u32;
        loop {
            let window = match web_sys::window() {
                Some(w) => w,
                None => {
                    TimeoutFuture::new(3000).await;
                    continue;
                }
            };
            let host = window.location().host().unwrap_or_else(|_| "localhost:8080".to_string());
            let ws_protocol = if window.location().protocol().unwrap_or_default() == "https:" { "wss:" } else { "ws:" };
            let token_q = get_token_query();
            let ws_url = format!("{}//{}/ws/traffic{}", ws_protocol, host, token_q);

            let (close_tx, mut close_rx) = tokio::sync::mpsc::channel::<()>(2);
            let close_tx_err = close_tx.clone();

            if let Ok(ws) = WebSocket::new(&ws_url) {
                let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                    if let Some(txt) = e.data().as_string() {
                        if let Ok(event) = serde_json::from_str::<TrafficEvent>(&txt) {
                            throughput_signal.update(|val| *val += event.bytes_transferred as u64);
                            traffic_signal.update(|list| {
                                list.insert(0, event);
                                if list.len() > 50 {
                                    list.pop();
                                }
                            });
                        }
                    }
                });
                ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
                onmessage.forget();

                let onclose_callback = Closure::<dyn FnMut(CloseEvent)>::new(move |_| {
                    let _ = close_tx.try_send(());
                });
                ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
                onclose_callback.forget();

                let onerror_callback = Closure::<dyn FnMut(ErrorEvent)>::new(move |_| {
                    let _ = close_tx_err.try_send(());
                });
                ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
                onerror_callback.forget();

                let _ = close_rx.recv().await;
                backoff_ms = (backoff_ms * 2).min(30000);
            } else {
                backoff_ms = (backoff_ms * 2).min(30000);
            }

            TimeoutFuture::new(backoff_ms).await;
        }
    });
}
