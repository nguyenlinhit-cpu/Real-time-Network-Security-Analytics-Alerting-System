use common::models::{Alert, AlertSeverity, AlertStatus, TrafficEvent, UserPublicDto, UserRole};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;

use crate::api::client::{AlertQuery, ApiClient};
use crate::components::{Navbar, Sidebar, ToastNotification};
use crate::pages::*;
use crate::ws::client::{init_alerts_websocket, init_traffic_websocket};

/// Seconds of throughput history shown in the live chart.
pub const RATE_HISTORY_LEN: usize = 30;

/// Tabs and the minimum role allowed to open them (server-side RBAC still applies).
fn tab_allowed(tab: &str, role: Option<UserRole>) -> bool {
    match (tab, role) {
        ("login", _) => true,
        (_, None) => false,
        ("settings" | "audit_logs", Some(r)) => r == UserRole::Admin,
        ("blocklist", Some(r)) => matches!(r, UserRole::Admin | UserRole::Analyst),
        (_, Some(_)) => true,
    }
}

#[component]
pub fn App() -> impl IntoView {
    let initial_user = ApiClient::get_current_user().filter(|_| ApiClient::is_authenticated());
    let hash_tab = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| h.trim_start_matches('#').to_string())
        .filter(|h| !h.is_empty());

    let initial_role = initial_user.as_ref().map(|u| u.role);
    let initial_tab = match hash_tab {
        Some(tab) if initial_user.is_some() && tab != "login" && tab_allowed(&tab, initial_role) => tab,
        _ if initial_user.is_some() => "dashboard".to_string(),
        _ => "login".to_string(),
    };

    let (current_user, set_current_user) = signal::<Option<UserPublicDto>>(initial_user);
    let (active_tab, set_active_tab) = signal(initial_tab);
    let (alerts, set_alerts) = signal::<Vec<Alert>>(Vec::new());
    let (traffic, set_traffic) = signal::<Vec<TrafficEvent>>(Vec::new());
    let (total_bytes, set_total_bytes) = signal(0u64);
    let (current_rate, set_current_rate) = signal(0u64);
    let (rate_history, set_rate_history) = signal(vec![0u64; RATE_HISTORY_LEN]);
    let (latest_alert, set_latest_alert) = signal::<Option<Alert>>(None);
    let (is_ws_connected, set_is_ws_connected) = signal(false);

    // Route guard: never render a tab the current role may not open.
    Effect::new(move |_| {
        let tab = active_tab.get();
        let role = current_user.get().map(|u| u.role);
        if !tab_allowed(&tab, role) {
            set_active_tab.set(if role.is_some() { "dashboard" } else { "login" }.to_string());
        }
    });

    // Sync active tab to URL hash (Mục 52)
    Effect::new(move |_| {
        let tab = active_tab.get();
        if tab != "login" {
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_hash(&tab);
            }
        }
    });

    // (Re)load data whenever a user logs in; clear it on logout.
    Effect::new(move |_| {
        if current_user.get().is_some() {
            leptos::task::spawn_local(async move {
                let query = AlertQuery {
                    limit: 100,
                    ..Default::default()
                };
                if let Ok(initial_alerts) = ApiClient::get_alerts(&query).await {
                    set_alerts.set(initial_alerts);
                }
                if let Ok(initial_traffic) = ApiClient::get_traffic().await {
                    set_traffic.set(initial_traffic);
                }
            });
        } else {
            set_alerts.set(Vec::new());
            set_traffic.set(Vec::new());
            set_latest_alert.set(None);
        }
    });

    // Real-time streams (they idle until a token exists) and the throughput meter: a single
    // app-wide loop turns the cumulative byte counter into bytes/second.
    init_alerts_websocket(set_alerts, set_latest_alert, set_is_ws_connected);
    init_traffic_websocket(set_traffic, set_total_bytes);
    leptos::task::spawn_local(async move {
        let mut last_total = 0u64;
        loop {
            TimeoutFuture::new(1_000).await;
            let total = total_bytes.get_untracked();
            let rate = total.saturating_sub(last_total);
            last_total = total;
            set_current_rate.set(rate);
            set_rate_history.update(|h| {
                h.push(rate);
                if h.len() > RATE_HISTORY_LEN {
                    h.remove(0);
                }
            });
        }
    });

    view! {
        <div class="min-h-screen text-slate-100 flex flex-col font-sans selection:bg-brand/30 selection:text-brand-light">
            <Navbar
                current_user=current_user
                set_current_user=set_current_user
                set_active_tab=set_active_tab
                is_ws_connected=is_ws_connected
                critical_count=Signal::derive(move || {
                    alerts
                        .get()
                        .iter()
                        .filter(|a| a.severity == AlertSeverity::Critical && a.status != AlertStatus::Resolved)
                        .count()
                })
            />

            <div class="flex-1 flex overflow-hidden">
                {move || {
                    if active_tab.get() != "login" {
                        view! {
                            <Sidebar current_user=current_user active_tab=active_tab set_active_tab=set_active_tab />
                        }.into_any()
                    } else {
                        view! { <span></span> }.into_any()
                    }
                }}

                <main class="flex-1 overflow-y-auto p-4 md:p-8 max-w-7xl mx-auto w-full">
                    {move || {
                        match active_tab.get().as_str() {
                            "login" => view! { <LoginPage set_active_tab=set_active_tab set_current_user=set_current_user /> }.into_any(),
                            "alerts" => view! { <AlertsPage alerts=alerts set_alerts=set_alerts /> }.into_any(),
                            "traffic" => view! { <TrafficPage traffic=traffic current_rate=current_rate /> }.into_any(),
                            "rules" => view! { <RulesPage /> }.into_any(),
                            "devices" => view! { <DevicesPage /> }.into_any(),
                            "blocklist" => view! { <BlocklistPage /> }.into_any(),
                            "settings" => view! { <SettingsPage /> }.into_any(),
                            "audit_logs" => view! { <AuditLogsPage /> }.into_any(),
                            _ => view! {
                                <DashboardPage
                                    alerts=alerts
                                    current_rate=current_rate
                                    rate_history=rate_history
                                    set_active_tab=set_active_tab
                                />
                            }.into_any(),
                        }
                    }}
                </main>
            </div>

            <ToastNotification latest_alert=latest_alert set_latest_alert=set_latest_alert />
        </div>
    }
}
