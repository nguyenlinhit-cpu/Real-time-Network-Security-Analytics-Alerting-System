use common::models::{AlertSeverity, CreateRuleDto, DetectionRule, RuleType, UpdateRuleDto};
use leptos::prelude::*;
use uuid::Uuid;

use crate::api::client::ApiClient;
use crate::components::icons::{IconClose, IconPlus, IconSliders};

#[component]
pub fn RulesPage() -> impl IntoView {
    let (rules, set_rules) = signal::<Vec<DetectionRule>>(Vec::new());
    let (_is_loading, set_is_loading) = signal(true);
    let (status_msg, set_status_msg) = signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);

    // Form fields for new rule
    let (new_name, set_new_name) = signal(String::new());
    let (new_rule_type, set_new_rule_type) = signal(RuleType::Threshold);
    let (new_severity, set_new_severity) = signal(AlertSeverity::High);
    let (new_threshold, set_new_threshold) = signal(100.0f64);
    let (new_window, set_new_window) = signal(60i32);

    let load_rules = move || {
        set_is_loading.set(true);
        leptos::task::spawn_local(async move {
            if let Ok(data) = ApiClient::get_rules().await {
                set_rules.set(data);
            }
            set_is_loading.set(false);
        });
    };

    Effect::new(move |_| {
        load_rules();
    });

    let on_toggle_rule = move |id: Uuid, current_state: bool| {
        let new_state = !current_state;
        leptos::task::spawn_local(async move {
            let dto = UpdateRuleDto {
                name: None,
                rule_type: None,
                condition_json: None,
                severity: None,
                is_enabled: Some(new_state),
                threshold_value: None,
                time_window_seconds: None,
            };
            if let Ok(updated) = ApiClient::update_rule(id, &dto).await {
                set_rules.update(|list| {
                    if let Some(pos) = list.iter().position(|r| r.id == id) {
                        list[pos] = updated;
                    }
                });
                set_status_msg.set(Some(format!(
                    "Rule successfully {}",
                    if new_state { "enabled" } else { "disabled" }
                )));
            }
        });
    };

    let on_delete_rule = move |id: Uuid| {
        leptos::task::spawn_local(async move {
            match ApiClient::delete_rule(id).await {
                Ok(_) => {
                    set_rules.update(|list| list.retain(|r| r.id != id));
                    set_status_msg.set(Some("Rule deleted successfully".to_string()));
                }
                Err(e) => {
                    set_status_msg.set(Some(format!("Failed to delete rule: {}", e)));
                }
            }
        });
    };

    let on_create_rule = move |e: web_sys::SubmitEvent| {
        e.prevent_default();
        let name = new_name.get();
        let rtype = new_rule_type.get();
        let sev = new_severity.get();
        let thresh = new_threshold.get();
        let win = new_window.get();

        leptos::task::spawn_local(async move {
            let dto = CreateRuleDto {
                name,
                rule_type: rtype,
                condition_json: serde_json::json!({ "metric": "packet_rate", "operator": ">=" }),
                severity: sev,
                is_enabled: Some(true),
                threshold_value: thresh,
                time_window_seconds: win,
            };

            if let Ok(created) = ApiClient::create_rule(&dto).await {
                set_rules.update(|list| list.push(created));
                set_show_create_modal.set(false);
                set_new_name.set(String::new());
                set_status_msg.set(Some("Rule created successfully".to_string()));
            }
        });
    };

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Detection rules"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Manage multi-pattern detection thresholds, time windows, and real-time triggers."
                    </p>
                </div>
                <button
                    on:click=move |_| set_show_create_modal.set(true)
                    class="px-3.5 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors flex items-center gap-2"
                >
                    <IconPlus class="w-3.5 h-3.5".to_string() />
                    <span>"New rule"</span>
                </button>
            </div>

            // Status message
            {move || {
                if let Some(msg) = status_msg.get() {
                    view! {
                        <div class="p-3 rounded-md bg-brand/10 border border-brand/30 text-brand text-xs flex items-center justify-between font-mono">
                            <span>{msg}</span>
                            <button on:click=move |_| set_status_msg.set(None) class="text-ink-500 hover:text-white"><IconClose class="w-3 h-3".to_string() /></button>
                        </div>
                    }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }
            }}

            // Create Rule Modal
            {move || {
                if show_create_modal.get() {
                    view! {
                        <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div class="bg-ink-900 border border-ink-600 rounded-lg p-6 max-w-md w-full shadow-console">
                                <h3 class="text-base font-bold text-white mb-4">"New detection rule"</h3>
                                <form on:submit=on_create_rule class="space-y-4">
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Rule name"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="e.g. Excessive DNS Query Flood"
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                            prop:value=new_name
                                            on:input=move |e| set_new_name.set(event_target_value(&e))
                                        />
                                    </div>
                                    <div class="grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Rule type"</label>
                                            <select
                                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                                                on:change=move |e| {
                                                    match event_target_value(&e).as_str() {
                                                        "pattern" => set_new_rule_type.set(RuleType::Pattern),
                                                        "anomaly" => set_new_rule_type.set(RuleType::Anomaly),
                                                        _ => set_new_rule_type.set(RuleType::Threshold),
                                                    }
                                                }
                                            >
                                                <option value="threshold">"Threshold"</option>
                                                <option value="pattern">"Pattern"</option>
                                                <option value="anomaly">"Anomaly"</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Severity"</label>
                                            <select
                                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                                                on:change=move |e| {
                                                    match event_target_value(&e).as_str() {
                                                        "critical" => set_new_severity.set(AlertSeverity::Critical),
                                                        "high" => set_new_severity.set(AlertSeverity::High),
                                                        "medium" => set_new_severity.set(AlertSeverity::Medium),
                                                        _ => set_new_severity.set(AlertSeverity::Low),
                                                    }
                                                }
                                            >
                                                <option value="high">"High"</option>
                                                <option value="critical">"Critical"</option>
                                                <option value="medium">"Medium"</option>
                                                <option value="low">"Low"</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Threshold value"</label>
                                            <input
                                                type="number"
                                                required
                                                min="1"
                                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-brand/60 transition-colors"
                                                prop:value=new_threshold
                                                on:input=move |e| {
                                                    if let Ok(val) = event_target_value(&e).parse::<f64>() {
                                                        set_new_threshold.set(val);
                                                    }
                                                }
                                            />
                                        </div>
                                        <div>
                                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Window (seconds)"</label>
                                            <input
                                                type="number"
                                                required
                                                min="1"
                                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-brand/60 transition-colors"
                                                prop:value=new_window
                                                on:input=move |e| {
                                                    if let Ok(val) = event_target_value(&e).parse::<i32>() {
                                                        set_new_window.set(val);
                                                    }
                                                }
                                            />
                                        </div>
                                    </div>
                                    <div class="flex items-center justify-end gap-3 pt-2">
                                        <button
                                            type="button"
                                            class="px-3.5 py-2 rounded-md bg-ink-800 hover:bg-ink-700 text-slate-300 text-xs font-medium transition-colors"
                                            on:click=move |_| set_show_create_modal.set(false)
                                        >
                                            "Cancel"
                                        </button>
                                        <button
                                            type="submit"
                                            class="px-4 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors"
                                        >
                                            "Save rule"
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

            // Rules Cards Grid
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <For
                    each=move || rules.get()
                    key=|r| r.id
                    children=move |rule| {
                        let rule_id = rule.id;
                        let is_enabled = rule.is_enabled;
                        let current_thresh = rule.threshold_value;
                        let current_window = rule.time_window_seconds;

                        let sev_badge = match rule.severity {
                            AlertSeverity::Critical => "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
                            AlertSeverity::High => "bg-sev-high/10 text-sev-high border-sev-high/30",
                            AlertSeverity::Medium => "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
                            AlertSeverity::Low => "bg-sev-low/10 text-sev-low border-sev-low/30",
                        };

                        let on_quick_adjust = move |delta: f64| {
                            leptos::task::spawn_local(async move {
                                let new_t = (current_thresh + delta).max(1.0);
                                let dto = UpdateRuleDto {
                                    name: None,
                                    rule_type: None,
                                    condition_json: None,
                                    severity: None,
                                    is_enabled: None,
                                    threshold_value: Some(new_t),
                                    time_window_seconds: None,
                                };
                                if let Ok(updated) = ApiClient::update_rule(rule_id, &dto).await {
                                    set_rules.update(|list| {
                                        if let Some(pos) = list.iter().position(|r| r.id == rule_id) {
                                            list[pos] = updated;
                                        }
                                    });
                                }
                            });
                        };

                        view! {
                            <div class=move || format!(
                                "bg-ink-900/60 border border-ink-600 border-l-2 {} rounded-lg p-6 flex flex-col justify-between space-y-4 transition-colors",
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
                                                {format!("{:?}", rule.rule_type).to_uppercase()}
                                            </span>
                                        </div>

                                        <div class="flex items-center gap-2">
                                            // Delete Button
                                            <button
                                                class="px-2 py-1 rounded text-[11px] font-mono font-semibold text-ink-500 hover:text-sev-critical hover:bg-sev-critical/10 transition-colors"
                                                title="Delete rule"
                                                on:click=move |_| on_delete_rule(rule_id)
                                            >
                                                "DELETE"
                                            </button>

                                            // Toggle Switch
                                            <button
                                                class=move || {
                                                    if is_enabled {
                                                        "px-3 py-1 rounded-full text-[11px] font-mono font-semibold bg-brand/15 text-brand border border-brand/30 transition-colors"
                                                    } else {
                                                        "px-3 py-1 rounded-full text-[11px] font-mono font-semibold bg-ink-800 text-ink-500 border border-ink-600 transition-colors"
                                                    }
                                                }
                                                on:click=move |_| on_toggle_rule(rule_id, is_enabled)
                                            >
                                                {if is_enabled { "ACTIVE" } else { "DISABLED" }}
                                            </button>
                                        </div>
                                    </div>

                                    <h3 class="text-base font-bold text-white tracking-tight">
                                        {rule.name}
                                    </h3>
                                </div>

                                // Metrics details & quick adjust buttons
                                <div class="grid grid-cols-2 gap-3 p-3 bg-ink-950 rounded-md border border-ink-700 text-xs">
                                    <div>
                                        <div class="text-[10px] text-ink-500 uppercase font-mono font-semibold tracking-wide">"Trigger threshold"</div>
                                        <div class="flex items-center justify-between mt-1.5">
                                            <span class="font-mono font-bold text-slate-200">
                                                {format!("{:.0} events", current_thresh)}
                                            </span>
                                            <div class="flex items-center gap-1">
                                                <button
                                                    on:click=move |_| on_quick_adjust(-10.0)
                                                    class="px-1.5 py-0.5 bg-ink-800 hover:bg-ink-700 text-slate-300 rounded text-[10px] font-mono"
                                                >
                                                    "-10"
                                                </button>
                                                <button
                                                    on:click=move |_| on_quick_adjust(10.0)
                                                    class="px-1.5 py-0.5 bg-ink-800 hover:bg-ink-700 text-slate-300 rounded text-[10px] font-mono"
                                                >
                                                    "+10"
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="text-[10px] text-ink-500 uppercase font-mono font-semibold tracking-wide">"Time window"</div>
                                        <div class="font-mono font-bold text-slate-200 mt-1.5">
                                            {format!("{} seconds", current_window)}
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
