use common::models::{Alert, AlertSeverity, SensorStatusDto, TrafficSummaryDto};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::api::client::ApiClient;
use crate::components::icons::{IconAlert, IconArrowRight, IconBan, IconDownload, IconPulse};
use crate::components::traffic_chart::format_rate;
use crate::components::{SeverityDonut, TrafficChart};

const SUMMARY_REFRESH_MS: u32 = 15_000;

#[component]
pub fn DashboardPage(
    alerts: ReadSignal<Vec<Alert>>,
    current_rate: ReadSignal<u64>,
    rate_history: ReadSignal<Vec<u64>>,
    set_active_tab: WriteSignal<String>,
) -> impl IntoView {
    let (summary, set_summary) = signal::<Option<TrafficSummaryDto>>(None);
    let (blocked_count, set_blocked_count) = signal::<Option<usize>>(None);
    let (sensors, set_sensors) = signal::<Vec<SensorStatusDto>>(Vec::new());
    let (load_error, set_load_error) = signal::<Option<String>>(None);

    // Poll the aggregates while the page is mounted; the flag stops the loop on unmount.
    let alive = Arc::new(AtomicBool::new(true));
    let alive_loop = alive.clone();
    on_cleanup(move || alive.store(false, Ordering::Relaxed));
    leptos::task::spawn_local(async move {
        while alive_loop.load(Ordering::Relaxed) {
            match ApiClient::get_dashboard_summary().await {
                Ok(data) => {
                    set_summary.set(Some(data));
                    set_load_error.set(None);
                }
                Err(e) => set_load_error.set(Some(e)),
            }
            if let Ok(blocklist) = ApiClient::get_blocklist().await {
                set_blocked_count.set(Some(blocklist.len()));
            }
            if let Ok(list) = ApiClient::get_sensor_status().await {
                set_sensors.set(list);
            }
            TimeoutFuture::new(SUMMARY_REFRESH_MS).await;
        }
    });

    let critical_alerts = Memo::new(move |_| summary.get().map(|s| s.critical_alerts));

    let recent_alerts = Memo::new(move |_| {
        let all = alerts.get();
        all.into_iter().take(5).collect::<Vec<Alert>>()
    });

    let on_export_report = move |_| {
        leptos::task::spawn_local(async move {
            let _ = ApiClient::export_csv_file().await;
        });
    };

    view! {
        <div class="space-y-6">
            // Page Header & Quick Controls
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <div class="flex items-center gap-2 text-[10px] font-mono text-brand uppercase tracking-[0.15em] mb-2">
                        <span class="relative flex w-1.5 h-1.5">
                            <span class="absolute inline-flex h-full w-full rounded-full bg-brand" style="animation: ring-expand 1.6s cubic-bezier(0,0,0.2,1) infinite;"></span>
                            <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-brand"></span>
                        </span>
                        "Live · Security Operations Center"
                    </div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Network overview"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "High-speed packet capture stream & automated intrusion detection metrics"
                    </p>
                </div>
                <div class="flex items-center gap-3">
                    <button
                        on:click=on_export_report
                        class="px-3.5 py-2 rounded-md bg-ink-900 hover:bg-ink-800 text-slate-200 text-xs font-semibold border border-ink-600 transition-colors flex items-center gap-2"
                    >
                        <IconDownload class="w-3.5 h-3.5".to_string() />
                        <span>"Export CSV"</span>
                    </button>
                    <button
                        on:click=move |_| set_active_tab.set("alerts".to_string())
                        class="px-3.5 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors flex items-center gap-2"
                    >
                        <IconAlert class="w-3.5 h-3.5".to_string() />
                        <span>"Investigate incidents"</span>
                    </button>
                </div>
            </div>

            {move || load_error.get().map(|e| view! {
                <div class="px-4 py-2.5 rounded-md border border-sev-high/40 bg-sev-high/10 text-sev-high text-xs font-mono">
                    {format!("Could not load dashboard metrics: {}", e)}
                </div>
            })}

            // Sensor health (heartbeats from capture engines)
            <div class="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                <span class="text-ink-500 uppercase tracking-wide">"Sensors:"</span>
                {move || {
                    let list = sensors.get();
                    if list.is_empty() {
                        view! { <span class="text-sev-high">"no sensor has reported yet"</span> }.into_any()
                    } else {
                        list.into_iter().map(|s| {
                            let color = match s.status.as_str() {
                                "healthy" => "border-brand/40 text-brand",
                                "degraded" => "border-sev-medium/40 text-sev-medium",
                                _ => "border-sev-critical/40 text-sev-critical",
                            };
                            view! {
                                <span class=format!("px-2 py-1 rounded border bg-ink-950 {}", color)
                                    title=format!("{} packets captured, {} dropped, last heartbeat {}", s.packets_captured, s.packets_dropped, s.last_heartbeat.format("%H:%M:%S"))>
                                    {format!("{} [{}] {} · {}", s.sensor_id, s.interface_name, s.status.to_uppercase(), s.packets_captured)}
                                </span>
                            }
                        }).collect::<Vec<_>>().into_any()
                    }
                }}
            </div>

            // Metrics Cards Grid
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                // 1. Throughput
                <div class="bg-ink-900/60 border border-ink-600 border-l-2 border-l-brand rounded-lg p-5">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-mono font-semibold text-ink-500 uppercase tracking-wide">"Current throughput"</span>
                        <span class="w-1.5 h-1.5 rounded-full bg-brand animate-ping"></span>
                    </div>
                    <div class="mt-2 text-2xl font-bold font-mono text-white tabular-nums">
                        {move || format_rate(current_rate.get())}
                    </div>
                    <div class="mt-2 text-[11px] text-brand flex items-center gap-1.5">
                        <IconPulse class="w-3 h-3".to_string() />
                        "live capture stream (1 s window)"
                    </div>
                </div>

                // 2. Total Alerts
                <div class="bg-ink-900/60 border border-ink-600 border-l-2 border-l-ink-500 rounded-lg p-5">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-mono font-semibold text-ink-500 uppercase tracking-wide">"Open alerts"</span>
                        <IconAlert class="w-3.5 h-3.5 text-ink-500".to_string() />
                    </div>
                    <div class="mt-2 text-2xl font-bold font-mono text-white tabular-nums">
                        {move || summary.get().map(|s| s.total_alerts.to_string()).unwrap_or_else(|| "—".to_string())}
                    </div>
                    <div class="mt-2 text-[11px] text-ink-500">
                        {move || summary.get().map(|s| format!("{} packets analyzed (24h)", s.total_packets)).unwrap_or_else(|| "Analyzing stream…".to_string())}
                    </div>
                </div>

                // 3. Critical Incidents
                <div class="bg-ink-900/60 border border-ink-600 border-l-2 border-l-sev-critical rounded-lg p-5">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-mono font-semibold text-sev-critical uppercase tracking-wide">"Critical incidents"</span>
                        <IconAlert class="w-3.5 h-3.5 text-sev-critical".to_string() />
                    </div>
                    <div class="mt-2 text-2xl font-bold font-mono text-sev-critical tabular-nums">
                        {move || critical_alerts.get().map(|c| c.to_string()).unwrap_or_else(|| "—".to_string())}
                    </div>
                    <div class="mt-2 text-[11px] text-sev-critical/80">
                        "Requires immediate analyst triage"
                    </div>
                </div>

                // 4. Blocked IPs
                <div class="bg-ink-900/60 border border-ink-600 border-l-2 border-l-ink-500 rounded-lg p-5">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-mono font-semibold text-ink-500 uppercase tracking-wide">"Active IP blocklist"</span>
                        <IconBan class="w-3.5 h-3.5 text-ink-500".to_string() />
                    </div>
                    <div class="mt-2 text-2xl font-bold font-mono text-white tabular-nums">
                        {move || blocked_count.get().map(|c| c.to_string()).unwrap_or_else(|| "—".to_string())}
                    </div>
                    <div class="mt-2 text-[11px] text-brand">
                        "Currently enforced entries"
                    </div>
                </div>
            </div>

            // Visual Charts Row
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div class="lg:col-span-2">
                    <TrafficChart history=rate_history current_rate=current_rate />
                </div>
                <div>
                    <SeverityDonut alerts=alerts />
                </div>
            </div>

            // Two-column section: Top 5 Sources & Recent Threat Incidents
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
                // Top 5 Source IPs
                <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6">
                    <div class="mb-4">
                        <h3 class="text-sm font-bold text-white tracking-tight">
                            "Top traffic sources"
                        </h3>
                        <p class="text-xs text-ink-500">"Highest packet originators in last 24h"</p>
                    </div>

                    <div class="space-y-3">
                        {move || {
                            if let Some(s) = summary.get() {
                                if s.top_src_ips.is_empty() {
                                    view! { <div class="text-xs text-ink-500 italic">"No traffic captured yet"</div> }.into_any()
                                } else {
                                    view! {
                                        <div class="divide-y divide-ink-700">
                                            {s.top_src_ips.into_iter().take(5).map(|item| {
                                                view! {
                                                    <div class="py-2.5 flex items-center justify-between text-xs">
                                                        <span class="font-mono text-slate-200">{item.key}</span>
                                                        <div class="text-right">
                                                            <div class="font-mono font-bold text-brand">{format!("{} pkts", item.count)}</div>
                                                            <div class="text-[10px] text-ink-500">{format!("{} KB", item.bytes / 1024)}</div>
                                                        </div>
                                                    </div>
                                                }
                                            }).collect::<Vec<_>>()}
                                        </div>
                                    }.into_any()
                                }
                            } else {
                                view! { <div class="text-xs text-ink-500">"Loading traffic summary…"</div> }.into_any()
                            }
                        }}
                    </div>
                </div>

                // Recent Threat Incidents Table Preview (Span 2)
                <div class="lg:col-span-2 bg-ink-900/60 border border-ink-600 rounded-lg p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div>
                            <h3 class="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full bg-sev-critical"></span>
                                "Latest threat incidents"
                            </h3>
                            <p class="text-xs text-ink-500">"Real-time event stream preview"</p>
                        </div>
                        <button
                            on:click=move |_| set_active_tab.set("alerts".to_string())
                            class="text-xs text-brand hover:text-brand-light transition-colors font-medium flex items-center gap-1"
                        >
                            "View all"
                            <IconArrowRight class="w-3 h-3".to_string() />
                        </button>
                    </div>

                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs text-slate-300">

                        <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                            <tr>
                                <th class="pb-3 px-3 font-mono">"Severity"</th>
                                <th class="pb-3 px-3 font-mono">"Title"</th>
                                <th class="pb-3 px-3 font-mono">"Source"</th>
                                <th class="pb-3 px-3 font-mono">"Target"</th>
                                <th class="pb-3 px-3 font-mono">"Detected at"</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-ink-700">
                            <For
                                each=move || recent_alerts.get()
                                key=|a| a.id
                                children=move |alert| {
                                    let sev_badge = match alert.severity {
                                        AlertSeverity::Critical => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                                        AlertSeverity::High => "bg-sev-high/10 text-sev-high border-sev-high/30",
                                        AlertSeverity::Medium => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                                        AlertSeverity::Low => "bg-sev-low/10 text-sev-low border-sev-low/30",
                                    };
                                    view! {
                                        <tr class="hover:bg-ink-800/40 transition-colors">
                                            <td class="py-3 px-3 whitespace-nowrap">
                                                <span class=format!("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border {}", sev_badge)>
                                                    {format!("{:?}", alert.severity).to_uppercase()}
                                                </span>
                                            </td>
                                            <td class="py-3 px-3 font-semibold text-slate-200">
                                                {alert.title}
                                            </td>
                                            <td class="py-3 px-3 font-mono text-ink-500">
                                                {alert.src_ip.ip().to_string()}
                                            </td>
                                            <td class="py-3 px-3 font-mono text-ink-500">
                                                {alert.dst_ip.ip().to_string()}
                                            </td>
                                            <td class="py-3 px-3 text-ink-500 font-mono text-[11px] whitespace-nowrap">
                                                {alert.detected_at.format("%Y-%m-%d %H:%M:%S").to_string()}
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>

                    </table>
                </div>
            </div>
        </div>
    </div>
    }
}
