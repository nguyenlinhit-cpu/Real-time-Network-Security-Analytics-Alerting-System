use common::models::{Device, TrafficEvent};
use leptos::prelude::*;

use crate::api::client::ApiClient;
use crate::components::icons::{IconClose, IconHistory, IconSearch};

#[component]
pub fn DevicesPage() -> impl IntoView {
    let (devices, set_devices) = signal::<Vec<Device>>(Vec::new());
    let (search_query, set_search_query) = signal(String::new());
    let (_is_loading, set_is_loading) = signal(true);

    // Selected device history modal state
    let (selected_device, set_selected_device) = signal::<Option<Device>>(None);
    let (device_history, set_device_history) = signal::<Vec<TrafficEvent>>(Vec::new());
    let (history_loading, set_history_loading) = signal(false);

    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            if let Ok(data) = ApiClient::get_devices().await {
                set_devices.set(data);
            }
            set_is_loading.set(false);
        });
    });

    let filtered_devices = Memo::new(move |_| {
        let q = search_query.get().to_lowercase();
        devices
            .get()
            .into_iter()
            .filter(|d| {
                if q.is_empty() {
                    return true;
                }
                let ip = d.ip_address.ip().to_string();
                let mac = d.mac_address.clone().unwrap_or_default().to_lowercase();
                let host = d.hostname.clone().unwrap_or_default().to_lowercase();
                let dev_type = d.device_type.to_lowercase();

                ip.contains(&q) || mac.contains(&q) || host.contains(&q) || dev_type.contains(&q)
            })
            .collect::<Vec<Device>>()
    });

    let on_view_history = move |dev: Device| {
        let dev_id = dev.id;
        set_selected_device.set(Some(dev));
        set_history_loading.set(true);
        set_device_history.set(Vec::new());

        leptos::task::spawn_local(async move {
            if let Ok(hist) = ApiClient::get_device_history(dev_id).await {
                set_device_history.set(hist);
            }
            set_history_loading.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Network node inventory"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Passive ARP and IP mapping of connected endpoints, servers, and IoT devices"
                    </p>
                </div>
                <div class="relative">
                    <IconSearch class="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-ink-500".to_string() />
                    <input
                        type="text"
                        placeholder="Search IP, MAC, hostname..."
                        class="bg-ink-900 border border-ink-600 rounded-md pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 w-64 transition-colors"
                        on:input=move |e| set_search_query.set(event_target_value(&e))
                    />
                </div>
            </div>

            // Device History Modal
            {move || {
                if let Some(dev) = selected_device.get() {
                    view! {
                        <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div class="bg-ink-900 border border-ink-600 rounded-lg p-6 max-w-3xl w-full shadow-console space-y-4 max-h-[85vh] flex flex-col">
                                <div class="flex items-center justify-between border-b border-ink-700 pb-3">
                                    <div>
                                        <h3 class="text-base font-bold text-white flex items-center gap-2">
                                            <IconHistory class="w-4 h-4 text-brand".to_string() />
                                            <span>"Traffic history for"</span>
                                            <span class="font-mono text-brand">{dev.ip_address.ip().to_string()}</span>
                                        </h3>
                                        <p class="text-xs text-ink-500 mt-0.5 font-mono">
                                            {format!("host: {} · mac: {}", dev.hostname.unwrap_or_else(|| "unknown".to_string()), dev.mac_address.unwrap_or_else(|| "-".to_string()))}
                                        </p>
                                    </div>
                                    <button
                                        on:click=move |_| set_selected_device.set(None)
                                        class="text-ink-500 hover:text-white p-1"
                                    >
                                        <IconClose class="w-4 h-4".to_string() />
                                    </button>
                                </div>

                                <div class="overflow-y-auto flex-1">
                                    {move || {
                                        if history_loading.get() {
                                            view! { <div class="text-xs text-ink-500 py-6 text-center font-mono">"Loading event history…"</div> }.into_any()
                                        } else if device_history.get().is_empty() {
                                            view! { <div class="text-xs text-ink-500 py-6 text-center italic">"No recent traffic recorded for this host"</div> }.into_any()
                                        } else {
                                            view! {
                                                <table class="w-full text-left text-xs text-slate-300">
                                                    <thead class="text-ink-500 border-b border-ink-700 font-semibold uppercase text-[10px] font-mono">
                                                        <tr>
                                                            <th class="pb-2">"Time"</th>
                                                            <th class="pb-2">"Protocol"</th>
                                                            <th class="pb-2">"Peer endpoint"</th>
                                                            <th class="pb-2">"Bytes"</th>
                                                            <th class="pb-2">"Flags"</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody class="divide-y divide-ink-700">
                                                        {device_history.get().into_iter().map(|ev| {
                                                            let peer = if ev.src_ip == dev.ip_address {
                                                                format!("-> {}:{}", ev.dst_ip.ip(), ev.dst_port)
                                                            } else {
                                                                format!("<- {}:{}", ev.src_ip.ip(), ev.src_port)
                                                            };
                                                            view! {
                                                                <tr class="hover:bg-ink-800/40 transition-colors">
                                                                    <td class="py-2 font-mono text-[11px] text-ink-500 whitespace-nowrap">
                                                                        {ev.time.format("%H:%M:%S").to_string()}
                                                                    </td>
                                                                    <td class="py-2 uppercase font-mono font-bold text-[10px] text-brand">
                                                                        {ev.protocol}
                                                                    </td>
                                                                    <td class="py-2 font-mono text-slate-200">
                                                                        {peer}
                                                                    </td>
                                                                    <td class="py-2 font-mono text-brand">
                                                                        {format!("{} B", ev.bytes_transferred)}
                                                                    </td>
                                                                    <td class="py-2 font-mono text-ink-500 text-[10px]">
                                                                        {ev.flags}
                                                                    </td>
                                                                </tr>
                                                            }
                                                        }).collect::<Vec<_>>()}
                                                    </tbody>
                                                </table>
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

            <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6 overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                        <tr>
                            <th class="pb-3 px-3 font-mono">"IP address"</th>
                            <th class="pb-3 px-3 font-mono">"MAC address"</th>
                            <th class="pb-3 px-3 font-mono">"Hostname"</th>
                            <th class="pb-3 px-3 font-mono">"Type"</th>
                            <th class="pb-3 px-3 font-mono">"Trust"</th>
                            <th class="pb-3 px-3 font-mono">"Last seen"</th>
                            <th class="pb-3 px-3 font-mono text-right">"History"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-700">
                        <For
                            each=move || filtered_devices.get()
                            key=|d| d.id
                            children=move |device| {
                                let is_trusted = device.is_trusted;
                                let dev_clone = device.clone();
                                view! {
                                    <tr class="hover:bg-ink-800/40 transition-colors">
                                        <td class="py-3.5 px-3 font-mono font-bold text-white whitespace-nowrap">
                                            {device.ip_address.ip().to_string()}
                                        </td>
                                        <td class="py-3.5 px-3 font-mono text-ink-500 whitespace-nowrap">
                                            {device.mac_address.clone().unwrap_or_else(|| "-".to_string())}
                                        </td>
                                        <td class="py-3.5 px-3 text-slate-200">
                                            {device.hostname.clone().unwrap_or_else(|| "Unknown".to_string())}
                                        </td>
                                        <td class="py-3.5 px-3 whitespace-nowrap">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-ink-800 text-slate-300 border border-ink-600">
                                                {device.device_type}
                                            </span>
                                        </td>
                                        <td class="py-3.5 px-3 whitespace-nowrap">
                                            <span class=format!("inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold {}", if is_trusted { "bg-brand/10 text-brand border border-brand/20" } else { "bg-sev-high/10 text-sev-high border border-sev-high/20" })>
                                                {if is_trusted { "TRUSTED" } else { "UNTRUSTED" }}
                                            </span>
                                        </td>
                                        <td class="py-3.5 px-3 text-ink-500 font-mono text-[11px] whitespace-nowrap">
                                            {device.last_seen.format("%Y-%m-%d %H:%M:%S").to_string()}
                                        </td>
                                        <td class="py-3.5 px-3 text-right whitespace-nowrap">
                                            <button
                                                on:click=move |_| on_view_history(dev_clone.clone())
                                                class="px-2.5 py-1 rounded bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 text-[11px] font-medium transition-colors"
                                            >
                                                "View events"
                                            </button>
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
