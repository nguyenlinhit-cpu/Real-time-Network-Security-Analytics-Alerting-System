use common::models::TrafficEvent;
use leptos::prelude::*;

use crate::components::icons::IconSearch;

#[component]
pub fn TrafficPage(
    traffic: ReadSignal<Vec<TrafficEvent>>,
    throughput: ReadSignal<u64>,
) -> impl IntoView {
    let (selected_proto, set_selected_proto) = signal::<Option<String>>(None);
    let (search_text, set_search_text) = signal(String::new());
    let (is_paused, set_is_paused) = signal(false);

    let filtered_traffic = Memo::new(move |_| {
        let query = search_text.get().to_lowercase();
        let proto = selected_proto.get();

        traffic
            .get()
            .into_iter()
            .filter(|t| {
                if let Some(ref p) = proto {
                    if !t.protocol.eq_ignore_ascii_case(p) {
                        return false;
                    }
                }
                if !query.is_empty() {
                    let s_ip = t.src_ip.to_string().to_lowercase();
                    let d_ip = t.dst_ip.to_string().to_lowercase();
                    if !s_ip.contains(&query) && !d_ip.contains(&query) {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<TrafficEvent>>()
    });

    let proto_tab_class = move |val: Option<&str>| {
        if selected_proto.get().as_deref() == val {
            "px-3 py-1.5 rounded text-xs font-mono font-semibold bg-brand text-ink-950 transition-colors"
        } else {
            "px-3 py-1.5 rounded text-xs font-mono font-medium text-ink-500 hover:text-slate-200 transition-colors"
        }
    };

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Live packet stream"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "High-speed TimescaleDB hypertable feed capturing raw packet metadata & flags"
                    </p>
                </div>
                <div class="flex items-center gap-3">
                    <div class="px-3 py-1.5 rounded-md bg-ink-900 border border-ink-600 text-xs font-mono text-brand tabular-nums">
                        {move || format!("{} B/s", throughput.get())}
                    </div>
                    <button
                        class=move || {
                            if is_paused.get() {
                                "px-3.5 py-1.5 rounded-md bg-sev-high/15 text-sev-high border border-sev-high/30 text-xs font-semibold transition-colors"
                            } else {
                                "px-3.5 py-1.5 rounded-md bg-ink-900 hover:bg-ink-800 text-slate-300 border border-ink-600 text-xs font-semibold transition-colors"
                            }
                        }
                        on:click=move |_| set_is_paused.update(|p| *p = !*p)
                    >
                        {move || if is_paused.get() { "Resume stream" } else { "Pause display" }}
                    </button>
                </div>
            </div>

            // Controls & Filters Bar
            <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-4">
                <div class="relative flex-1 max-w-sm">
                    <IconSearch class="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-ink-500".to_string() />
                    <input
                        type="text"
                        placeholder="Filter by source or target IP..."
                        class="w-full bg-ink-950 border border-ink-600 rounded-md pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                        on:input=move |e| set_search_text.set(event_target_value(&e))
                    />
                </div>

                <div class="flex items-center gap-1 bg-ink-950 rounded-md p-1">
                    <button class=move || proto_tab_class(None) on:click=move |_| set_selected_proto.set(None)>"ALL"</button>
                    <button class=move || proto_tab_class(Some("tcp")) on:click=move |_| set_selected_proto.set(Some("tcp".to_string()))>"TCP"</button>
                    <button class=move || proto_tab_class(Some("udp")) on:click=move |_| set_selected_proto.set(Some("udp".to_string()))>"UDP"</button>
                    <button class=move || proto_tab_class(Some("icmp")) on:click=move |_| set_selected_proto.set(Some("icmp".to_string()))>"ICMP"</button>
                    <button class=move || proto_tab_class(Some("dns")) on:click=move |_| set_selected_proto.set(Some("dns".to_string()))>"DNS"</button>
                </div>
            </div>

            // Traffic Table
            <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6 overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-ink-500 border-b border-ink-600 uppercase tracking-wider font-semibold text-[10px]">
                        <tr>
                            <th class="pb-3 px-3 font-mono">"Protocol"</th>
                            <th class="pb-3 px-3 font-mono">"Source"</th>
                            <th class="pb-3 px-3 font-mono">"Target"</th>
                            <th class="pb-3 px-3 font-mono">"Bytes"</th>
                            <th class="pb-3 px-3 font-mono">"Flags"</th>
                            <th class="pb-3 px-3 font-mono">"Timestamp"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-700">
                        <For
                            each=move || filtered_traffic.get()
                            key=|ev| ev.id
                            children=move |event| {
                                let proto_upper = event.protocol.to_uppercase();
                                let proto_badge = match proto_upper.as_str() {
                                    "TCP" => "bg-brand/10 text-brand border-brand/30",
                                    "UDP" => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                                    "ICMP" => "bg-sev-high/10 text-sev-high border-sev-high/30",
                                    "DNS" => "bg-brand-light/10 text-brand-light border-brand-light/30",
                                    "ARP" => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                                    _ => "bg-sev-low/10 text-sev-low border-sev-low/30",
                                };

                                view! {
                                    <tr class="hover:bg-ink-800/40 transition-colors">
                                        <td class="py-3 px-3 whitespace-nowrap">
                                            <span class=format!("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border {}", proto_badge)>
                                                {proto_upper}
                                            </span>
                                        </td>
                                        <td class="py-3 px-3 font-mono text-slate-200">
                                            {format!("{}:{}", event.src_ip, event.src_port)}
                                        </td>
                                        <td class="py-3 px-3 font-mono text-slate-200">
                                            {format!("{}:{}", event.dst_ip, event.dst_port)}
                                        </td>
                                        <td class="py-3 px-3 font-mono text-brand font-semibold">
                                            {format!("{} B", event.bytes_transferred)}
                                        </td>
                                        <td class="py-3 px-3 font-mono text-ink-500">
                                            {event.flags.clone()}
                                        </td>
                                        <td class="py-3 px-3 text-ink-500 whitespace-nowrap font-mono text-[11px]">
                                            {event.time.format("%H:%M:%S.%3f").to_string()}
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
