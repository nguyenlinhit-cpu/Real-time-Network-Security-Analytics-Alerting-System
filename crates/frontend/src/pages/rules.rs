use common::models::{AlertSeverity, CreateRuleDto, DetectionRule, RuleType, UpdateRuleDto};
use leptos::prelude::*;
use uuid::Uuid;

use crate::api::client::ApiClient;
use crate::components::icons::{IconClose, IconPlus, IconSliders};

const BUILTIN_RULES: [&str; 8] = [
    "Port Scan Detection",
    "SYN Flood / DDoS Detection",
    "Brute-force Attack Detection",
    "ARP Spoofing / Poisoning Detection",
    "DNS Tunneling Detection",
    "Traffic Volume Anomaly (Z-Score)",
    "ICMP Flood / Smurf Attack Detection",
    "C2 Beaconing / Periodic Callback Detection",
];

fn empty_update() -> UpdateRuleDto {
    UpdateRuleDto {
        name: None,
        rule_type: None,
        condition_json: None,
        severity: None,
        is_enabled: None,
        threshold_value: None,
        time_window_seconds: None,
        mitre_tactic: None,
        mitre_technique: None,
    }
}

/// What the threshold means for each built-in detector (custom rules count packets).
fn threshold_meaning(rule: &DetectionRule) -> &'static str {
    match rule.name.as_str() {
        "Port Scan Detection" => "distinct ports",
        "SYN Flood / DDoS Detection" => "SYN packets",
        "Brute-force Attack Detection" => "attempts",
        "ARP Spoofing / Poisoning Detection" => "(not used)",
        "DNS Tunneling Detection" => "bits entropy",
        "Traffic Volume Anomaly (Z-Score)" => "std. deviations",
        "ICMP Flood / Smurf Attack Detection" => "ICMP packets",
        "C2 Beaconing / Periodic Callback Detection" => "periodic connections",
        _ => match rule.condition_json.get("metric").and_then(|m| m.as_str()) {
            Some("byte_rate") => "bytes",
            _ => "packets",
        },
    }
}

/// Small thresholds (entropy, z-score) need fine steps; counts use coarse ones.
fn threshold_step(value: f64) -> f64 {
    if value <= 10.0 {
        0.5
    } else {
        10.0
    }
}

#[component]
pub fn RulesPage() -> impl IntoView {
    let is_admin = ApiClient::is_admin();
    let (rules, set_rules) = signal::<Vec<DetectionRule>>(Vec::new());
    let (is_loading, set_is_loading) = signal(true);
    let (status_msg, set_status_msg) = signal::<Option<(bool, String)>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (pending_delete, set_pending_delete) = signal::<Option<Uuid>>(None);

    // Form fields for new rule
    let (new_name, set_new_name) = signal(String::new());
    let (new_severity, set_new_severity) = signal(AlertSeverity::High);
    let (new_metric, set_new_metric) = signal("packet_rate".to_string());
    let (new_group_by, set_new_group_by) = signal("src_ip".to_string());
    let (new_protocol, set_new_protocol) = signal(String::new());
    let (new_port, set_new_port) = signal(String::new());
    let (new_threshold, set_new_threshold) = signal(100.0f64);
    let (new_window, set_new_window) = signal(60i32);

    let ok = move |m: String| set_status_msg.set(Some((true, m)));
    let fail = move |m: String| set_status_msg.set(Some((false, m)));

    let replace_rule = move |updated: DetectionRule| {
        set_rules.update(|list| {
            if let Some(pos) = list.iter().position(|r| r.id == updated.id) {
                list[pos] = updated;
            }
        });
    };

    leptos::task::spawn_local(async move {
        match ApiClient::get_rules().await {
            Ok(data) => set_rules.set(data),
            Err(e) => fail(format!("Failed to load detection rules: {}", e)),
        }
        set_is_loading.set(false);
    });

    let on_toggle_rule = move |id: Uuid, current_state: bool| {
        let new_state = !current_state;
        leptos::task::spawn_local(async move {
            let dto = UpdateRuleDto {
                is_enabled: Some(new_state),
                ..empty_update()
            };
            match ApiClient::update_rule(id, &dto).await {
                Ok(updated) => {
                    replace_rule(updated);
                    ok(format!(
                        "Rule {} — the capture engine reloads it immediately",
                        if new_state { "enabled" } else { "disabled" }
                    ));
                }
                Err(e) => fail(format!("Failed to update rule: {}", e)),
            }
        });
    };

    let on_adjust = move |id: Uuid, new_threshold: f64| {
        leptos::task::spawn_local(async move {
            let dto = UpdateRuleDto {
                threshold_value: Some(new_threshold),
                ..empty_update()
            };
            match ApiClient::update_rule(id, &dto).await {
                Ok(updated) => replace_rule(updated),
                Err(e) => fail(format!("Failed to update threshold: {}", e)),
            }
        });
    };

    let on_delete_rule = move |id: Uuid| {
        set_pending_delete.set(None);
        leptos::task::spawn_local(async move {
            match ApiClient::delete_rule(id).await {
                Ok(_) => {
                    set_rules.update(|list| list.retain(|r| r.id != id));
                    ok("Rule deleted; its detector is now disabled".to_string());
                }
                Err(e) => fail(format!("Failed to delete rule: {}", e)),
            }
        });
    };

    let on_create_rule = move |e: web_sys::SubmitEvent| {
        e.prevent_default();
        let mut condition = serde_json::json!({
            "metric": new_metric.get(),
            "group_by": new_group_by.get(),
        });
        let protocol = new_protocol.get();
        if !protocol.is_empty() {
            condition["protocol"] = serde_json::json!(protocol);
        }
        if let Ok(port) = new_port.get().trim().parse::<u16>() {
            condition["dst_port"] = serde_json::json!(port);
        }
        let dto = CreateRuleDto {
            name: new_name.get(),
            rule_type: RuleType::Threshold,
            condition_json: condition,
            severity: new_severity.get(),
            is_enabled: Some(true),
            threshold_value: new_threshold.get(),
            time_window_seconds: new_window.get(),
            mitre_tactic: None,
            mitre_technique: None,
        };

        leptos::task::spawn_local(async move {
            match ApiClient::create_rule(&dto).await {
                Ok(created) => {
                    set_rules.update(|list| list.push(created));
                    set_show_create_modal.set(false);
                    set_new_name.set(String::new());
                    ok("Custom rule created and active".to_string());
                }
                Err(e) => fail(format!("Failed to create rule: {}", e)),
            }
        });
    };

    let input_class = "w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-brand/60 transition-colors";
    let label_class =
        "block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5";

    view! {
        <div class="space-y-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">"Detection rules"</h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Thresholds, time windows and severities. Changes are pushed to the capture engine in real time."
                    </p>
                </div>
                {is_admin.then(|| view! {
                    <button
                        on:click=move |_| set_show_create_modal.set(true)
                        class="px-3.5 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors flex items-center gap-2"
                    >
                        <IconPlus class="w-3.5 h-3.5".to_string() />
                        <span>"New custom rule"</span>
                    </button>
                })}
            </div>

            {move || status_msg.get().map(|(success, msg)| {
                let style = if success {
                    "bg-brand/10 border-brand/30 text-brand"
                } else {
                    "bg-sev-high/10 border-sev-high/40 text-sev-high"
                };
                view! {
                    <div class=format!("p-3 rounded-md border text-xs flex items-center justify-between font-mono {}", style)>
                        <span>{msg}</span>
                        <button on:click=move |_| set_status_msg.set(None) class="text-ink-500 hover:text-white"><IconClose class="w-3 h-3".to_string() /></button>
                    </div>
                }
            })}

            {move || (!is_admin).then(|| view! {
                <div class="text-[11px] font-mono text-ink-500">"Read-only view: only administrators can change detection rules."</div>
            })}

            // Create Rule Modal
            {move || show_create_modal.get().then(|| view! {
                <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div class="bg-ink-900 border border-ink-600 rounded-lg p-6 max-w-md w-full shadow-console">
                        <h3 class="text-base font-bold text-white mb-1">"New custom threshold rule"</h3>
                        <p class="text-[11px] text-ink-500 mb-4">
                            "Fires when the chosen metric, summed per group over the window, reaches the threshold."
                        </p>
                        <form on:submit=on_create_rule class="space-y-4">
                            <div>
                                <label class=label_class>"Rule name"</label>
                                <input type="text" required minlength="3" maxlength="100"
                                    placeholder="e.g. Telnet connection burst"
                                    class=input_class
                                    prop:value=new_name
                                    on:input=move |e| set_new_name.set(event_target_value(&e)) />
                            </div>
                            <div class="grid grid-cols-2 gap-3">
                                <div>
                                    <label class=label_class>"Metric"</label>
                                    <select class=input_class on:change=move |e| set_new_metric.set(event_target_value(&e))>
                                        <option value="packet_rate">"Packets"</option>
                                        <option value="byte_rate">"Bytes"</option>
                                    </select>
                                </div>
                                <div>
                                    <label class=label_class>"Group by"</label>
                                    <select class=input_class on:change=move |e| set_new_group_by.set(event_target_value(&e))>
                                        <option value="src_ip">"Source IP"</option>
                                        <option value="dst_ip">"Destination IP"</option>
                                    </select>
                                </div>
                                <div>
                                    <label class=label_class>"Protocol"</label>
                                    <select class=input_class on:change=move |e| set_new_protocol.set(event_target_value(&e))>
                                        <option value="">"Any"</option>
                                        <option value="TCP">"TCP"</option>
                                        <option value="UDP">"UDP"</option>
                                        <option value="ICMP">"ICMP"</option>
                                    </select>
                                </div>
                                <div>
                                    <label class=label_class>"Destination port"</label>
                                    <input type="number" min="1" max="65535" placeholder="any" class=input_class
                                        prop:value=new_port
                                        on:input=move |e| set_new_port.set(event_target_value(&e)) />
                                </div>
                                <div>
                                    <label class=label_class>"Threshold"</label>
                                    <input type="number" required min="1" class=input_class
                                        prop:value=new_threshold
                                        on:input=move |e| { if let Ok(v) = event_target_value(&e).parse::<f64>() { set_new_threshold.set(v) } } />
                                </div>
                                <div>
                                    <label class=label_class>"Window (seconds)"</label>
                                    <input type="number" required min="1" max="86400" class=input_class
                                        prop:value=new_window
                                        on:input=move |e| { if let Ok(v) = event_target_value(&e).parse::<i32>() { set_new_window.set(v) } } />
                                </div>
                            </div>
                            <div>
                                <label class=label_class>"Severity"</label>
                                <select class=input_class on:change=move |e| {
                                    set_new_severity.set(match event_target_value(&e).as_str() {
                                        "critical" => AlertSeverity::Critical,
                                        "medium" => AlertSeverity::Medium,
                                        "low" => AlertSeverity::Low,
                                        _ => AlertSeverity::High,
                                    })
                                }>
                                    <option value="high">"High"</option>
                                    <option value="critical">"Critical"</option>
                                    <option value="medium">"Medium"</option>
                                    <option value="low">"Low"</option>
                                </select>
                            </div>
                            <div class="flex items-center justify-end gap-3 pt-2">
                                <button type="button"
                                    class="px-3.5 py-2 rounded-md bg-ink-800 hover:bg-ink-700 text-slate-300 text-xs font-medium transition-colors"
                                    on:click=move |_| set_show_create_modal.set(false)>
                                    "Cancel"
                                </button>
                                <button type="submit"
                                    class="px-4 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors">
                                    "Save rule"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            })}

            {move || (is_loading.get()).then(|| view! {
                <div class="text-xs text-ink-500 font-mono">"Loading rules…"</div>
            })}

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <For
                    each=move || rules.get()
                    // updated_at in the key re-renders a card after every change.
                    key=|r| (r.id, r.updated_at)
                    children=move |rule| {
                        let rule_id = rule.id;
                        let is_enabled = rule.is_enabled;
                        let current_thresh = rule.threshold_value;
                        let step = threshold_step(current_thresh);
                        let meaning = threshold_meaning(&rule);
                        let is_builtin = BUILTIN_RULES.contains(&rule.name.as_str());
                        let mitre = match (&rule.mitre_tactic, &rule.mitre_technique) {
                            (Some(t), Some(id)) => format!("{} · {}", t, id),
                            (Some(t), None) => t.clone(),
                            (None, Some(id)) => id.clone(),
                            _ => "no MITRE mapping".to_string(),
                        };

                        let sev_badge = match rule.severity {
                            AlertSeverity::Critical => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                            AlertSeverity::High => "bg-sev-high/10 text-sev-high border-sev-high/30",
                            AlertSeverity::Medium => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                            AlertSeverity::Low => "bg-sev-low/10 text-sev-low border-sev-low/30",
                        };
                        let toggle_class = if is_enabled {
                            "px-3 py-1 rounded-full text-[11px] font-mono font-semibold bg-brand/15 text-brand border border-brand/30 transition-colors"
                        } else {
                            "px-3 py-1 rounded-full text-[11px] font-mono font-semibold bg-ink-800 text-ink-500 border border-ink-600 transition-colors"
                        };

                        view! {
                            <div class=format!(
                                "bg-ink-900/60 border border-ink-600 border-l-2 {} rounded-lg p-6 flex flex-col justify-between space-y-4",
                                if is_enabled { "border-l-brand" } else { "border-l-ink-600" }
                            )>
                                <div>
                                    <div class="flex items-center justify-between gap-3 mb-2">
                                        <div class="flex items-center gap-2">
                                            <span class=format!("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border {}", sev_badge)>
                                                {format!("{:?}", rule.severity).to_uppercase()}
                                            </span>
                                            <span class="inline-flex items-center gap-1 text-[10px] font-mono text-brand bg-brand/10 px-2 py-0.5 rounded border border-brand/20">
                                                <IconSliders class="w-3 h-3".to_string() />
                                                {if is_builtin { "BUILT-IN".to_string() } else { "CUSTOM".to_string() }}
                                            </span>
                                        </div>

                                        {if is_admin {
                                            view! {
                                                <div class="flex items-center gap-2">
                                                    {move || if pending_delete.get() == Some(rule_id) {
                                                        view! {
                                                            <span class="flex items-center gap-1">
                                                                <button class="px-2 py-1 rounded text-[11px] font-mono font-semibold bg-sev-critical/15 text-sev-critical"
                                                                    on:click=move |_| on_delete_rule(rule_id)>"CONFIRM"</button>
                                                                <button class="px-2 py-1 rounded text-[11px] font-mono text-ink-500"
                                                                    on:click=move |_| set_pending_delete.set(None)>"CANCEL"</button>
                                                            </span>
                                                        }.into_any()
                                                    } else {
                                                        view! {
                                                            <button
                                                                class="px-2 py-1 rounded text-[11px] font-mono font-semibold text-ink-500 hover:text-sev-critical hover:bg-sev-critical/10 transition-colors"
                                                                title=if is_builtin { "Deleting a built-in rule disables its detector" } else { "Delete rule" }
                                                                on:click=move |_| set_pending_delete.set(Some(rule_id))
                                                            >
                                                                "DELETE"
                                                            </button>
                                                        }.into_any()
                                                    }}
                                                    <button class=toggle_class on:click=move |_| on_toggle_rule(rule_id, is_enabled)>
                                                        {if is_enabled { "ACTIVE" } else { "DISABLED" }}
                                                    </button>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <span class=toggle_class>{if is_enabled { "ACTIVE" } else { "DISABLED" }}</span>
                                            }.into_any()
                                        }}
                                    </div>

                                    <h3 class="text-base font-bold text-white tracking-tight">{rule.name.clone()}</h3>
                                    <div class="text-[10px] font-mono text-purple-400 mt-1">{mitre}</div>
                                </div>

                                <div class="grid grid-cols-2 gap-3 p-3 bg-ink-950 rounded-md border border-ink-700 text-xs">
                                    <div>
                                        <div class="text-[10px] text-ink-500 uppercase font-mono font-semibold tracking-wide">"Trigger threshold"</div>
                                        <div class="flex items-center justify-between mt-1.5 gap-2">
                                            <span class="font-mono font-bold text-slate-200">
                                                {format!("{} {}", current_thresh, meaning)}
                                            </span>
                                            {is_admin.then(|| view! {
                                                <div class="flex items-center gap-1">
                                                    <button
                                                        on:click=move |_| on_adjust(rule_id, (current_thresh - step).max(step))
                                                        class="px-1.5 py-0.5 bg-ink-800 hover:bg-ink-700 text-slate-300 rounded text-[10px] font-mono"
                                                    >{format!("-{}", step)}</button>
                                                    <button
                                                        on:click=move |_| on_adjust(rule_id, current_thresh + step)
                                                        class="px-1.5 py-0.5 bg-ink-800 hover:bg-ink-700 text-slate-300 rounded text-[10px] font-mono"
                                                    >{format!("+{}", step)}</button>
                                                </div>
                                            })}
                                        </div>
                                    </div>
                                    <div>
                                        <div class="text-[10px] text-ink-500 uppercase font-mono font-semibold tracking-wide">"Time window"</div>
                                        <div class="font-mono font-bold text-slate-200 mt-1.5">
                                            {format!("{} seconds", rule.time_window_seconds)}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}
