use common::models::{Alert, AlertSeverity, AlertStatus};
use leptos::prelude::*;
use uuid::Uuid;

use crate::api::client::ApiClient;
use crate::components::icons::IconSearch;

#[component]
pub fn AlertsTable(
    alerts: ReadSignal<Vec<Alert>>,
    set_alerts: WriteSignal<Vec<Alert>>,
) -> impl IntoView {
    let (filter_severity, set_filter_severity) = signal::<Option<AlertSeverity>>(None);
    let (filter_status, set_filter_status) = signal::<Option<AlertStatus>>(None);
    let (search_query, set_search_query) = signal(String::new());

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
        leptos::task::spawn_local(async move {
            if let Ok(updated) = ApiClient::update_alert_status(id, new_status).await {
                set_alerts.update(|list| {
                    if let Some(pos) = list.iter().position(|item| item.id == id) {
                        list[pos] = updated;
                    }
                });
            }
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

            // Table Content
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                        <tr>
                            <th class="pb-3 px-3 font-mono">"Severity"</th>
                            <th class="pb-3 px-3 font-mono">"Title & description"</th>
                            <th class="pb-3 px-3 font-mono">"Source"</th>
                            <th class="pb-3 px-3 font-mono">"Target"</th>
                            <th class="pb-3 px-3 font-mono">"Status"</th>
                            <th class="pb-3 px-3 font-mono text-right">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-700">
                        <For
                            each=move || filtered_alerts.get()
                            key=|alert| alert.id
                            children=move |alert| {
                                let alert_id = alert.id;
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

                                        // Title & Description
                                        <td class="py-3.5 px-3 max-w-sm">
                                            <div class="font-semibold text-slate-100 group-hover:text-brand transition-colors">
                                                {alert.title}
                                            </div>
                                            <div class="text-ink-500 text-[11px] truncate mt-0.5">
                                                {alert.description}
                                            </div>
                                        </td>

                                        // Source IP
                                        <td class="py-3.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                            {format!("{}", alert.src_ip)}
                                        </td>

                                        // Target IP
                                        <td class="py-3.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                            {format!("{}", alert.dst_ip)}
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
                                                {if alert.status == AlertStatus::Open {
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
                                                        <span class="text-ink-600 text-[11px] italic">"Closed"</span>
                                                    }.into_any()
                                                }}
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </div>
        </div>
    }
}
