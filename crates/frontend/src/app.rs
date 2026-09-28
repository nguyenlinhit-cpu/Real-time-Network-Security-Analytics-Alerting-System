use common::models::{Alert, AlertSeverity, TrafficEvent, UserPublicDto};
use leptos::prelude::*;

use crate::api::client::ApiClient;
use crate::components::{Navbar, Sidebar, ToastNotification};
use crate::pages::*;
use crate::ws::client::{init_alerts_websocket, init_traffic_websocket};

#[component]
pub fn App() -> impl IntoView {
    let initial_user = ApiClient::get_current_user();
    let hash_tab = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| h.trim_start_matches('#').to_string())
        .filter(|h| !h.is_empty());

    let initial_tab = if initial_user.is_some() {
        hash_tab.unwrap_or_else(|| "dashboard".to_string())
    } else {
        "login".to_string()
    };

    let (current_user, set_current_user) = signal::<Option<UserPublicDto>>(initial_user);
    let (active_tab, set_active_tab) = signal(initial_tab);
    let (alerts, set_alerts) = signal::<Vec<Alert>>(Vec::new());
    let (traffic, set_traffic) = signal::<Vec<TrafficEvent>>(Vec::new());
    let (throughput, set_throughput) = signal(0u64);
    let (latest_alert, set_latest_alert) = signal::<Option<Alert>>(None);
    let (is_ws_connected, set_is_ws_connected) = signal(false);

    // Sync active tab to URL hash (Mục 52)
    Effect::new(move |_| {
        let tab = active_tab.get();
        if tab != "login" {
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_hash(&tab);
            }
        }
    });

    // Re-fetch data whenever user logs in or on start if already logged in
    Effect::new(move |_| {
        let user = current_user.get();
        if user.is_some() {
            leptos::task::spawn_local(async move {
                if let Ok(initial_alerts) = ApiClient::get_alerts().await {
                    set_alerts.set(initial_alerts);
                }
                if let Ok(initial_traffic) = ApiClient::get_traffic().await {
                    set_traffic.set(initial_traffic);
                }
            });
        }
    });

    Effect::new(move |_| {
        // Initialize WebSockets on startup
        init_alerts_websocket(set_alerts, set_latest_alert, set_is_ws_connected);
        init_traffic_websocket(set_traffic, set_throughput);
    });

    let critical_count = Memo::new(move |_| {
        alerts
            .get()
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count()
    });

    view! {
        <div class="min-h-screen text-slate-100 flex flex-col font-sans selection:bg-brand/30 selection:text-brand-light">
            // Navigation Bar
            <Navbar
                current_user=current_user
                set_current_user=set_current_user
                set_active_tab=set_active_tab
                is_ws_connected=is_ws_connected
                critical_count=Signal::derive(move || critical_count.get())
            />

            // App Body: Sidebar + Main Content
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
                            "dashboard" => view! { <DashboardPage alerts=alerts throughput=throughput set_active_tab=set_active_tab /> }.into_any(),
                            "alerts" => view! { <AlertsPage alerts=alerts set_alerts=set_alerts /> }.into_any(),
                            "traffic" => view! { <TrafficPage traffic=traffic throughput=throughput /> }.into_any(),
                            "rules" => view! { <RulesPage /> }.into_any(),
                            "devices" => view! { <DevicesPage /> }.into_any(),
                            "blocklist" => view! { <BlocklistPage /> }.into_any(),
                            "settings" => view! { <SettingsPage /> }.into_any(),
                            "audit_logs" => view! { <AuditLogsPage /> }.into_any(),
                            _ => view! { <DashboardPage alerts=alerts throughput=throughput set_active_tab=set_active_tab /> }.into_any(),
                        }
                    }}
                </main>
            </div>

            // Real-time Toast Notifications for live threat pushes
            <ToastNotification latest_alert=latest_alert set_latest_alert=set_latest_alert />
        </div>
    }
}
