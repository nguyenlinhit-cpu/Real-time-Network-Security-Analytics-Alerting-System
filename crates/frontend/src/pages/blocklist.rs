use common::models::{BlockedIp, CreateBlockedIpDto};
use leptos::prelude::*;
use uuid::Uuid;

use crate::api::client::ApiClient;
use crate::components::icons::{IconBan, IconClose, IconPlus};

#[component]
pub fn BlocklistPage() -> impl IntoView {
    let (blocklist, set_blocklist) = signal::<Vec<BlockedIp>>(Vec::new());
    let (ip_input, set_ip_input) = signal(String::new());
    let (reason_input, set_reason_input) = signal(String::new());
    let (show_modal, set_show_modal) = signal(false);
    let (status_msg, set_status_msg) = signal::<Option<String>>(None);
    let (duration_secs, set_duration_secs) = signal::<Option<i64>>(Some(86_400));
    let is_admin = ApiClient::is_admin();

    let load_blocklist = move || {
        leptos::task::spawn_local(async move {
            match ApiClient::get_blocklist().await {
                Ok(data) => set_blocklist.set(data),
                Err(e) => set_status_msg.set(Some(format!("Failed to load blocklist: {}", e))),
            }
        });
    };

    Effect::new(move |_| {
        load_blocklist();
    });

    let on_unblock = move |id: Uuid| {
        leptos::task::spawn_local(async move {
            match ApiClient::remove_from_blocklist(id).await {
                Ok(()) => {
                    set_blocklist.update(|list| list.retain(|item| item.id != id));
                    set_status_msg.set(Some("IP successfully removed from blocklist".to_string()));
                }
                Err(e) => set_status_msg.set(Some(format!("Failed to unblock: {}", e))),
            }
        });
    };

    let on_add_blocked = move |e: web_sys::SubmitEvent| {
        e.prevent_default();
        let ip = ip_input.get();
        let reason = reason_input.get();

        leptos::task::spawn_local(async move {
            let dto = CreateBlockedIpDto {
                ip_address: ip,
                reason,
                duration_seconds: duration_secs.get_untracked(),
            };
            match ApiClient::add_to_blocklist(&dto).await {
                Ok(new_block) => {
                    set_blocklist.update(|list| {
                        list.retain(|b| b.id != new_block.id);
                        list.insert(0, new_block);
                    });
                    set_show_modal.set(false);
                    set_ip_input.set(String::new());
                    set_reason_input.set(String::new());
                    set_status_msg.set(Some("IP successfully added to blocklist".to_string()));
                }
                Err(e) => set_status_msg.set(Some(format!("Failed to block IP: {}", e))),
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "IP blocklist"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Active blocks (manual and automatic). Mirrored into the host firewall when FIREWALL_ENFORCEMENT is enabled; expired entries are removed automatically."
                    </p>
                </div>
                {is_admin.then(|| view! {
                <button
                    on:click=move |_| set_show_modal.set(true)
                    class="px-3.5 py-2 rounded-md bg-sev-critical hover:brightness-110 text-white text-xs font-bold transition-all flex items-center gap-2"
                >
                    <IconPlus class="w-3.5 h-3.5".to_string() />
                    <span>"Block host IP"</span>
                </button>
                })}
            </div>

            // Status message
            {move || {
                if let Some(msg) = status_msg.get() {
                    view! {
                        <div class="p-3 rounded-md bg-brand/10 border border-brand/30 text-brand text-xs font-mono flex items-center justify-between">
                            <span>{msg}</span>
                            <button on:click=move |_| set_status_msg.set(None) class="text-ink-500 hover:text-white"><IconClose class="w-3 h-3".to_string() /></button>
                        </div>
                    }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }
            }}

            // Add Block Modal
            {move || {
                if show_modal.get() {
                    view! {
                        <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div class="bg-ink-900 border border-ink-600 rounded-lg p-6 max-w-md w-full shadow-console">
                                <h3 class="text-base font-bold text-white mb-4 flex items-center gap-2">
                                    <IconBan class="w-4 h-4 text-sev-critical".to_string() />
                                    "Add host IP to blocklist"
                                </h3>
                                <form on:submit=on_add_blocked class="space-y-4">
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"IP address (CIDR)"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="192.168.1.50 or 10.0.0.0/24"
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-sev-critical/60 transition-colors"
                                            prop:value=ip_input
                                            on:input=move |e| set_ip_input.set(event_target_value(&e))
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Reason / incident reference"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="Brute-force SSH attack detected"
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-sev-critical/60 transition-colors"
                                            prop:value=reason_input
                                            on:input=move |e| set_reason_input.set(event_target_value(&e))
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Duration"</label>
                                        <select
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sev-critical/60"
                                            on:change=move |e| set_duration_secs.set(event_target_value(&e).parse::<i64>().ok())
                                        >
                                            <option value="3600">"1 hour"</option>
                                            <option value="86400" selected>"24 hours"</option>
                                            <option value="604800">"7 days"</option>
                                            <option value="2592000">"30 days"</option>
                                            <option value="permanent">"Permanent"</option>
                                        </select>
                                    </div>
                                    <div class="flex items-center justify-end gap-3 pt-2">
                                        <button
                                            type="button"
                                            class="px-3.5 py-2 rounded-md bg-ink-800 hover:bg-ink-700 text-slate-300 text-xs font-medium transition-colors"
                                            on:click=move |_| set_show_modal.set(false)
                                        >
                                            "Cancel"
                                        </button>
                                        <button
                                            type="submit"
                                            class="px-4 py-2 rounded-md bg-sev-critical hover:brightness-110 text-white text-xs font-bold transition-all"
                                        >
                                            "Confirm block"
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }
            }}

            // Blocklist Table
            <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6 overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                        <tr>
                            <th class="pb-3 px-3 font-mono">"Blocked IP / CIDR"</th>
                            <th class="pb-3 px-3 font-mono">"Mitigation reason"</th>
                            <th class="pb-3 px-3 font-mono">"Blocked at"</th>
                            <th class="pb-3 px-3 font-mono">"Expires"</th>
                            <th class="pb-3 px-3 font-mono text-right">"Action"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-700">
                        <For
                            each=move || blocklist.get()
                            key=|b| (b.id, b.blocked_at)
                            children=move |item| {
                                let block_id = item.id;
                                view! {
                                    <tr class="hover:bg-ink-800/40 transition-colors">
                                        <td class="py-3.5 px-3 font-mono font-bold text-sev-critical whitespace-nowrap">
                                            {format!("{}", item.ip_address)}
                                        </td>
                                        <td class="py-3.5 px-3 text-slate-200">
                                            {item.reason}
                                        </td>
                                        <td class="py-3.5 px-3 text-ink-500 font-mono text-[11px] whitespace-nowrap">
                                            {item.blocked_at.format("%Y-%m-%d %H:%M:%S").to_string()}
                                        </td>
                                        <td class="py-3.5 px-3 text-ink-500 font-mono text-[11px] whitespace-nowrap">
                                            {item.blocked_until.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "permanent".to_string())}
                                        </td>
                                        <td class="py-3.5 px-3 text-right whitespace-nowrap">
                                            {is_admin.then(|| view! {
                                            <button
                                                class="px-2.5 py-1 rounded bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 text-[11px] font-medium transition-colors"
                                                on:click=move |_| on_unblock(block_id)
                                            >
                                                "Unblock"
                                            </button>
                                            })}
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
