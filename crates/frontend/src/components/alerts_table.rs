use common::models::{Alert, AlertSeverity, AlertStatus, TrafficEvent};
use leptos::prelude::*;
use uuid::Uuid;

use crate::api::client::{AlertQuery, ApiClient};
use crate::components::icons::{IconClose, IconSearch};

#[component]
pub fn AlertsTable(
    alerts: ReadSignal<Vec<Alert>>,
    set_alerts: WriteSignal<Vec<Alert>>,
) -> impl IntoView {
    let (filter_severity, set_filter_severity) = signal::<Option<AlertSeverity>>(None);
    let (filter_status, set_filter_status) = signal::<Option<AlertStatus>>(None);
    let (search_query, set_search_query) = signal(String::new());

    let (selected_alert, set_selected_alert) = signal::<Option<Alert>>(None);
    let (related_traffic, set_related_traffic) = signal::<Vec<TrafficEvent>>(Vec::new());
    let (is_loading_traffic, set_is_loading_traffic) = signal(false);

    let is_viewer = !ApiClient::is_analyst_or_admin();
    let (action_error, set_action_error) = signal::<Option<String>>(None);
    let (is_loading_more, set_is_loading_more) = signal(false);
    let (no_more, set_no_more) = signal(false);

    let load_related_traffic = move |alert_id: Uuid| {
        set_is_loading_traffic.set(true);
        leptos::task::spawn_local(async move {
            match ApiClient::get_alert_traffic(alert_id).await {
                Ok(traffic) => set_related_traffic.set(traffic),
                Err(e) => {
                    set_related_traffic.set(Vec::new());
                    set_action_error.set(Some(format!("Could not load related traffic: {}", e)));
                }
            }
            set_is_loading_traffic.set(false);
        });
    };

    let filtered_alerts = Memo::new(move |_| {
        let query = search_query.get().to_lowercase();
        alerts
            .get()
            .into_iter()
            .filter(|a| {
                if let Some(sev) = filter_severity.get() {
                    if a.severity != sev {
                        return false;
                    }
                }
                if let Some(st) = filter_status.get() {
                    if a.status != st {
                        return false;
                    }
                }
                if !query.is_empty() {
                    let ip_str = format!("{} {}", a.src_ip, a.dst_ip).to_lowercase();
                    let title_str = a.title.to_lowercase();
                    if !ip_str.contains(&query) && !title_str.contains(&query) {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<Alert>>()
    });

    let on_update_status = move |id: Uuid, new_status: AlertStatus| {
        set_action_error.set(None);
        leptos::task::spawn_local(async move {
            match ApiClient::update_alert_status(id, new_status).await {
                Ok(updated) => set_alerts.update(|list| {
                    if let Some(pos) = list.iter().position(|item| item.id == id) {
                        list[pos] = updated;
                    }
                }),
                Err(e) => set_action_error.set(Some(e)),
            }
        });
    };

    // Server-side pagination with the active filters; results are merged into the shared list.
    let on_load_more = move |_| {
        set_is_loading_more.set(true);
        leptos::task::spawn_local(async move {
            let severity = filter_severity.get_untracked();
            let status = filter_status.get_untracked();
            let search = search_query.get_untracked();
            let offset = filtered_alerts.get_untracked().len() as i64;
            let query = AlertQuery {
                severity,
                status,
                search: Some(search).filter(|s| !s.trim().is_empty()),
                limit: 100,
                offset,
            };
            match ApiClient::get_alerts(&query).await {
                Ok(page) => {
                    set_no_more.set(page.len() < 100);
                    set_alerts.update(|list| {
                        for alert in page {
                            if !list.iter().any(|a| a.id == alert.id) {
                                list.push(alert);
                            }
                        }
                        list.sort_by_key(|a| std::cmp::Reverse(a.detected_at));
                    });
                }
                Err(e) => set_action_error.set(Some(e)),
            }
            set_is_loading_more.set(false);
        });
    };

    view! {
        <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6">
            // Header and controls
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-base font-bold text-white tracking-tight flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-sev-critical"></span>
                        "Security incidents"
                    </h2>
                    <p class="text-xs text-ink-500 mt-0.5">
                        "Real-time event analysis and automated incident response feed"
                    </p>
                </div>

                // Search and filters
                <div class="flex flex-wrap items-center gap-2">
                    <div class="relative">
                        <IconSearch class="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-ink-500".to_string() />
                        <input
                            type="text"
                            placeholder="Search IP, incident..."
                            class="bg-ink-950 border border-ink-600 rounded-md pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-ink-500 focus:outline-none focus:border-brand/60 w-48 transition-colors"
                            on:input=move |e| set_search_query.set(event_target_value(&e))
                        />
                    </div>

                    // Severity filter
                    <select
                        class="bg-ink-950 border border-ink-600 rounded-md px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                        on:change=move |e| {
                            let val = event_target_value(&e);
                            match val.as_str() {
                                "critical" => set_filter_severity.set(Some(AlertSeverity::Critical)),
                                "high" => set_filter_severity.set(Some(AlertSeverity::High)),
                                "medium" => set_filter_severity.set(Some(AlertSeverity::Medium)),
                                "low" => set_filter_severity.set(Some(AlertSeverity::Low)),
                                _ => set_filter_severity.set(None),
                            }
                        }
                    >
                        <option value="all">"All severities"</option>
                        <option value="critical">"Critical only"</option>
                        <option value="high">"High only"</option>
                        <option value="medium">"Medium only"</option>
                        <option value="low">"Low only"</option>
                    </select>

                    // Status filter
                    <select
                        class="bg-ink-950 border border-ink-600 rounded-md px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                        on:change=move |e| {
                            let val = event_target_value(&e);
                            match val.as_str() {
                                "open" => set_filter_status.set(Some(AlertStatus::Open)),
                                "acknowledged" => set_filter_status.set(Some(AlertStatus::Acknowledged)),
                                "resolved" => set_filter_status.set(Some(AlertStatus::Resolved)),
                                _ => set_filter_status.set(None),
                            }
                        }
                    >
                        <option value="all">"All statuses"</option>
                        <option value="open">"Open"</option>
                        <option value="acknowledged">"Acknowledged"</option>
                        <option value="resolved">"Resolved"</option>
                    </select>
                </div>
            </div>

            {move || action_error.get().map(|e| view! {
                <div class="mb-4 px-4 py-2.5 rounded-md border border-sev-high/40 bg-sev-high/10 text-sev-high text-xs font-mono flex items-center justify-between gap-3">
                    <span>{e}</span>
                    <button class="text-ink-500 hover:text-white" on:click=move |_| set_action_error.set(None)>"✕"</button>
                </div>
            })}

            // Table Content
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                        <tr>
                            <th class="pb-3 px-3 font-mono">"Severity"</th>
                            <th class="pb-3 px-3 font-mono">"Title & MITRE ATT&CK"</th>
                            <th class="pb-3 px-3 font-mono">"Source"</th>
                            <th class="pb-3 px-3 font-mono">"Target"</th>
                            <th class="pb-3 px-3 font-mono">"Status"</th>
                            <th class="pb-3 px-3 font-mono text-right">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-700">
                        <For
                            each=move || filtered_alerts.get()
                            // Key includes the status so a row re-renders after Acknowledge/Resolve.
                            key=|alert| format!("{}-{:?}", alert.id, alert.status)
                            children=move |alert| {
                                let alert_id = alert.id;
                                let alert_clone = alert.clone();
                                let sev_class = match alert.severity {
                                    AlertSeverity::Critical => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                                    AlertSeverity::High => "bg-sev-high/10 text-sev-high border-sev-high/30",
                                    AlertSeverity::Medium => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                                    AlertSeverity::Low => "bg-sev-low/10 text-sev-low border-sev-low/30",
                                };

                                let status_badge = match alert.status {
                                    AlertStatus::Open => "bg-sev-critical/10 text-sev-critical border border-sev-critical/20",
                                    AlertStatus::Acknowledged => "bg-sev-high/10 text-sev-high border border-sev-high/20",
                                    AlertStatus::Resolved => "bg-brand/10 text-brand border border-brand/20",
                                };

                                view! {
                                    <tr class="hover:bg-ink-800/40 transition-colors group">
                                        // Severity Pill
                                        <td class="py-3.5 px-3 whitespace-nowrap">
                                            <span class=format!("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border {}", sev_class)>
                                                {format!("{:?}", alert.severity).to_uppercase()}
                                            </span>
                                        </td>

                                        // Title & Description & MITRE ATT&CK
                                        <td class="py-3.5 px-3 max-w-sm">
                                            <div class="font-semibold text-slate-100 group-hover:text-brand transition-colors flex items-center gap-1.5 flex-wrap">
                                                <span>{alert.title.clone()}</span>
                                                {if let Some(ref tech) = alert.mitre_technique {
                                                    view! {
                                                        <span class="inline-flex items-center px-1.5 py-0.2 rounded text-[9px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/30">
                                                            {tech.clone()}
                                                        </span>
                                                    }.into_any()
                                                } else {
                                                    view! { <span></span> }.into_any()
                                                }}
                                            </div>
                                            <div class="text-ink-500 text-[11px] truncate mt-0.5">
                                                {alert.description}
                                            </div>
                                        </td>

                                        // Source IP
                                        <td class="py-3.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                            {alert.src_ip.ip().to_string()}
                                        </td>

                                        // Target IP
                                        <td class="py-3.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                            {alert.dst_ip.ip().to_string()}
                                        </td>

                                        // Status
                                        <td class="py-3.5 px-3 whitespace-nowrap">
                                            <span class=format!("inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium {}", status_badge)>
                                                {format!("{:?}", alert.status).to_uppercase()}
                                            </span>
                                        </td>

                                        // Actions
                                        <td class="py-3.5 px-3 text-right whitespace-nowrap">
                                            <div class="inline-flex items-center gap-1.5">
                                                <button
                                                    class="px-2 py-1 rounded bg-ink-800 hover:bg-ink-700 text-slate-300 border border-ink-600 text-[11px] font-medium transition-colors"
                                                    on:click=move |_| {
                                                        set_selected_alert.set(Some(alert_clone.clone()));
                                                        load_related_traffic(alert_id);
                                                    }
                                                >
                                                    "Inspect"
                                                </button>

                                                {if !is_viewer {
                                                    if alert.status == AlertStatus::Open {
                                                        view! {
                                                            <button
                                                                class="px-2.5 py-1 rounded bg-sev-high/10 hover:bg-sev-high/20 text-sev-high border border-sev-high/30 text-[11px] font-medium transition-colors"
                                                                on:click=move |_| on_update_status(alert_id, AlertStatus::Acknowledged)
                                                            >
                                                                "Acknowledge"
                                                            </button>
                                                        }.into_any()
                                                    } else if alert.status == AlertStatus::Acknowledged {
                                                        view! {
                                                            <button
                                                                class="px-2.5 py-1 rounded bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 text-[11px] font-medium transition-colors"
                                                                on:click=move |_| on_update_status(alert_id, AlertStatus::Resolved)
                                                            >
                                                                "Resolve"
                                                            </button>
                                                        }.into_any()
                                                    } else {
                                                        view! {
                                                            <button
                                                                class="px-2.5 py-1 rounded bg-ink-800 hover:bg-ink-700 text-ink-500 border border-ink-600 text-[11px] font-medium transition-colors"
                                                                title="Re-open this incident"
                                                                on:click=move |_| on_update_status(alert_id, AlertStatus::Open)
                                                            >
                                                                "Re-open"
                                                            </button>
                                                        }.into_any()
                                                    }
                                                } else {
                                                    view! { <span></span> }.into_any()
                                                }}
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
                <div class="pt-4 flex items-center justify-between text-[11px] text-ink-500 font-mono">
                    <span>{move || format!("{} incidents shown", filtered_alerts.get().len())}</span>
                    <button
                        class="px-3 py-1.5 rounded-md bg-ink-800 hover:bg-ink-700 text-slate-300 border border-ink-600 disabled:opacity-40"
                        disabled=move || is_loading_more.get() || no_more.get()
                        on:click=on_load_more
                    >
                        {move || if no_more.get() { "All incidents loaded" } else if is_loading_more.get() { "Loading…" } else { "Load more from server" }}
                    </button>
                </div>
            </div>

            // Inspection Drawer / Modal (Mục 20: Trang chi tiết alert kèm traffic liên quan)
            {move || {
                if let Some(alert) = selected_alert.get() {
                    let sev_style = match alert.severity {
                        AlertSeverity::Critical => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                        AlertSeverity::High => "bg-sev-high/10 text-sev-high border-sev-high/30",
                        AlertSeverity::Medium => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                        AlertSeverity::Low => "bg-sev-low/10 text-sev-low border-sev-low/30",
                    };

                    view! {
                        <div class="fixed inset-0 bg-ink-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div class="bg-ink-900 border border-ink-600 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
                                // Modal Header
                                <div class="p-5 border-b border-ink-700 flex items-start justify-between">
                                    <div>
                                        <div class="flex items-center gap-2">
                                            <span class=format!("px-2 py-0.5 rounded text-[10px] font-mono font-bold border {}", sev_style)>
                                                {format!("{:?}", alert.severity).to_uppercase()}
                                            </span>
                                            <h3 class="text-lg font-bold text-white tracking-tight">{alert.title}</h3>
                                        </div>
                                        <p class="text-xs text-ink-400 mt-1">{alert.description}</p>
                                    </div>
                                    <button
                                        on:click=move |_| set_selected_alert.set(None)
                                        class="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-ink-800 transition-colors"
                                    >
                                        <IconClose class="w-5 h-5".to_string() />
                                    </button>
                                </div>

                                // Modal Metadata
                                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 bg-ink-950/50 border-b border-ink-700 text-xs">
                                    <div>
                                        <div class="text-[10px] font-mono uppercase text-ink-500">"Source IP"</div>
                                        <div class="font-mono text-slate-200 mt-0.5">{alert.src_ip.ip().to_string()}</div>
                                    </div>
                                    <div>
                                        <div class="text-[10px] font-mono uppercase text-ink-500">"Target IP"</div>
                                        <div class="font-mono text-slate-200 mt-0.5">{alert.dst_ip.ip().to_string()}</div>
                                    </div>
                                    <div>
                                        <div class="text-[10px] font-mono uppercase text-ink-500">"MITRE Tactic"</div>
                                        <div class="font-mono text-purple-400 mt-0.5">{alert.mitre_tactic.unwrap_or_else(|| "N/A".to_string())}</div>
                                    </div>
                                    <div>
                                        <div class="text-[10px] font-mono uppercase text-ink-500">"MITRE Technique"</div>
                                        <div class="font-mono text-purple-400 mt-0.5">{alert.mitre_technique.unwrap_or_else(|| "N/A".to_string())}</div>
                                    </div>
                                </div>

                                // Related Traffic Packets
                                <div class="p-5 flex-1 overflow-y-auto">
                                    <div class="flex items-center justify-between mb-3">
                                        <h4 class="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                                            "Correlated Traffic Events (±5 min window)"
                                        </h4>
                                        <span class="text-[11px] text-ink-500 font-mono">
                                            {move || format!("{} packets captured", related_traffic.get().len())}
                                        </span>
                                    </div>

                                    {move || {
                                        if is_loading_traffic.get() {
                                            view! { <div class="text-center py-8 text-xs text-ink-500">"Fetching correlated traffic events..."</div> }.into_any()
                                        } else if related_traffic.get().is_empty() {
                                            view! { <div class="text-center py-8 text-xs text-ink-500">"No correlated traffic packets found in hypertable window."</div> }.into_any()
                                        } else {
                                            view! {
                                                <div class="border border-ink-700 rounded-lg overflow-hidden">
                                                    <table class="w-full text-left text-[11px] font-mono">
                                                        <thead class="bg-ink-950 text-ink-500 border-b border-ink-700 text-[10px]">
                                                            <tr>
                                                                <th class="py-2 px-3">"Time"</th>
                                                                <th class="py-2 px-3">"Src Port"</th>
                                                                <th class="py-2 px-3">"Dst Port"</th>
                                                                <th class="py-2 px-3">"Proto"</th>
                                                                <th class="py-2 px-3">"Bytes"</th>
                                                                <th class="py-2 px-3">"Flags / Metadata"</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody class="divide-y divide-ink-800 text-slate-300">
                                                            <For
                                                                each=move || related_traffic.get()
                                                                key=|t| t.id
                                                                children=|t| {
                                                                    view! {
                                                                        <tr class="hover:bg-ink-800/50">
                                                                            <td class="py-2 px-3 whitespace-nowrap text-ink-400">{t.time.format("%H:%M:%S").to_string()}</td>
                                                                            <td class="py-2 px-3">{t.src_port}</td>
                                                                            <td class="py-2 px-3 text-brand">{t.dst_port}</td>
                                                                            <td class="py-2 px-3 font-semibold">{t.protocol}</td>
                                                                            <td class="py-2 px-3">{t.bytes_transferred}</td>
                                                                            <td class="py-2 px-3 text-ink-400 truncate max-w-xs">{t.flags}</td>
                                                                        </tr>
                                                                    }
                                                                }
                                                            />
                                                        </tbody>
                                                    </table>
                                                </div>
                                            }.into_any()
                                        }
                                    }}
                                </div>
                            </div>
                        </div>
                    }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }
            }}
        </div>
    }
}
