use common::models::AuditLog;
use leptos::prelude::*;

use crate::api::client::ApiClient;
use crate::components::icons::IconSearch;

#[component]
pub fn AuditLogsPage() -> impl IntoView {
    let (logs, set_logs) = signal::<Vec<AuditLog>>(Vec::new());
    let (search_query, set_search_query) = signal(String::new());
    let (is_loading, set_is_loading) = signal(false);

    let load_logs = move || {
        set_is_loading.set(true);
        leptos::task::spawn_local(async move {
            if let Ok(data) = ApiClient::get_audit_logs().await {
                set_logs.set(data);
            }
            set_is_loading.set(false);
        });
    };

    Effect::new(move |_| {
        load_logs();
    });

    let filtered_logs = Memo::new(move |_| {
        let q = search_query.get().to_lowercase();
        logs.get()
            .into_iter()
            .filter(|log| {
                if q.is_empty() {
                    return true;
                }
                log.action.to_lowercase().contains(&q)
                    || log.target.to_lowercase().contains(&q)
                    || log
                        .user_id
                        .map(|u| u.to_string().contains(&q))
                        .unwrap_or(false)
            })
            .collect::<Vec<AuditLog>>()
    });

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Security Audit Trail"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Tamper-evident log of administrative modifications, rule changes, and analyst responses."
                    </p>
                </div>
                <div class="flex items-center gap-2.5">
                    <button
                        on:click=move |_| load_logs()
                        disabled=move || is_loading.get()
                        class="px-3 py-1.5 rounded-md bg-ink-900 hover:bg-ink-800 text-slate-300 text-xs font-medium border border-ink-600 transition-colors"
                    >
                        {move || if is_loading.get() { "Refreshing..." } else { "Refresh" }}
                    </button>
                </div>
            </div>

            // Controls
            <div class="flex items-center gap-3">
                <div class="relative flex-1 max-w-sm">
                    <IconSearch class="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-ink-500".to_string() />
                    <input
                        type="text"
                        placeholder="Search action, target, user ID..."
                        class="bg-ink-950 border border-ink-600 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-ink-500 focus:outline-none focus:border-brand/60 w-full transition-colors"
                        on:input=move |e| set_search_query.set(event_target_value(&e))
                    />
                </div>
            </div>

            // Audit Table
            <div class="bg-ink-900/60 border border-ink-600 rounded-lg overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="text-ink-500 bg-ink-950/80 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                            <tr>
                                <th class="py-3 px-4 font-mono">"Timestamp"</th>
                                <th class="py-3 px-4 font-mono">"Action"</th>
                                <th class="py-3 px-4 font-mono">"Target / Resource"</th>
                                <th class="py-3 px-4 font-mono">"Operator ID"</th>
                                <th class="py-3 px-4 font-mono">"Source IP"</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-ink-700">
                            <For
                                each=move || filtered_logs.get()
                                key=|log| log.id
                                children=move |log| {
                                    let action_style = if log.action.starts_with("CREATE") || log.action.starts_with("BLOCK") {
                                        "bg-sev-critical/10 text-sev-critical border-sev-critical/30"
                                    } else if log.action.starts_with("UPDATE") {
                                        "bg-sev-high/10 text-sev-high border-sev-high/30"
                                    } else if log.action.starts_with("DELETE") || log.action.starts_with("REMOVE") {
                                        "bg-sev-medium/10 text-sev-medium border-sev-medium/30"
                                    } else {
                                        "bg-brand/10 text-brand border-brand/30"
                                    };

                                    let time_formatted = log.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                                    let user_disp = log.user_id.map(|u| u.to_string()).unwrap_or_else(|| "System / Automated".to_string());
                                    let ip_disp = log.ip_address.map(|ip| ip.ip().to_string()).unwrap_or_else(|| "—".to_string());

                                    view! {
                                        <tr class="hover:bg-ink-800/40 transition-colors">
                                            <td class="py-3 px-4 font-mono text-ink-400 whitespace-nowrap">
                                                {time_formatted}
                                            </td>
                                            <td class="py-3 px-4 whitespace-nowrap">
                                                <span class=format!("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold border {}", action_style)>
                                                    {log.action}
                                                </span>
                                            </td>
                                            <td class="py-3 px-4 font-mono text-slate-200">
                                                {log.target}
                                            </td>
                                            <td class="py-3 px-4 font-mono text-ink-400 text-[11px]">
                                                {user_disp}
                                            </td>
                                            <td class="py-3 px-4 font-mono text-ink-500 whitespace-nowrap">
                                                {ip_disp}
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
    }
}
