use common::models::{
    AlertSeverity, ChannelType, CreateNotificationChannelDto, NotificationChannel,
    UpdateNotificationChannelDto,
};
use leptos::prelude::*;
use uuid::Uuid;

use crate::{
    api::client::ApiClient,
    components::icons::{IconBell, IconClose, IconPlus},
};

#[component]
pub fn SettingsPage() -> impl IntoView {
    let (channels, set_channels) = signal(Vec::<NotificationChannel>::new());
    let (show_modal, set_show_modal) = signal(false);
    let (status_msg, set_status_msg) = signal(Option::<String>::None);

    let (new_name, set_new_name) = signal(String::new());
    let (new_type, set_new_type) = signal(ChannelType::Webhook);
    let (webhook_url, set_webhook_url) = signal(String::new());
    let (tg_token, set_tg_token) = signal(String::new());
    let (tg_chat_id, set_tg_chat_id) = signal(String::new());
    let (smtp_host, set_smtp_host) = signal(String::from("smtp.gmail.com"));
    let (smtp_port, set_smtp_port) = signal(String::from("587"));
    let (to_email, set_to_email) = signal(String::new());
    let (smtp_user, set_smtp_user) = signal(String::new());
    let (smtp_pass, set_smtp_pass) = signal(String::new());
    let (min_severity, set_min_severity) = signal(AlertSeverity::High);
    let (from_email, set_from_email) = signal(String::new());
    let (smtp_security, set_smtp_security) = signal(String::from("starttls"));
    let (pending_delete, set_pending_delete) = signal::<Option<Uuid>>(None);

    let load_channels = move || {
        leptos::task::spawn_local(async move {
            match ApiClient::get_notification_channels().await {
                Ok(data) => set_channels.set(data),
                Err(e) => set_status_msg.set(Some(format!("Failed to load channels: {}", e))),
            }
        });
    };

    Effect::new(move |_| {
        load_channels();
    });

    let on_test_channel = move |id: Uuid| {
        set_status_msg.set(Some("Sending test alert...".to_string()));
        leptos::task::spawn_local(async move {
            match ApiClient::test_notification_channel(id).await {
                Ok(msg) => set_status_msg.set(Some(msg)),
                Err(err) => set_status_msg.set(Some(err)),
            }
        });
    };

    let on_delete_channel = move |id: Uuid| {
        leptos::task::spawn_local(async move {
            set_pending_delete.set(None);
            match ApiClient::delete_notification_channel(id).await {
                Ok(()) => {
                    set_channels.update(|list| list.retain(|c| c.id != id));
                    set_status_msg.set(Some("Notification channel removed".to_string()));
                }
                Err(e) => set_status_msg.set(Some(format!("Failed to delete channel: {}", e))),
            }
        });
    };

    let on_toggle_channel = move |id: Uuid, enable: bool| {
        leptos::task::spawn_local(async move {
            let dto = UpdateNotificationChannelDto {
                name: None,
                r#type: None,
                config_json: None,
                min_severity: None,
                is_enabled: Some(enable),
            };
            match ApiClient::update_notification_channel(id, &dto).await {
                Ok(updated) => {
                    set_channels.update(|list| {
                        if let Some(pos) = list.iter().position(|c| c.id == id) {
                            list[pos] = updated;
                        }
                    });
                    set_status_msg.set(Some(format!(
                        "Channel {}",
                        if enable { "enabled" } else { "disabled" }
                    )));
                }
                Err(e) => set_status_msg.set(Some(format!("Failed to update channel: {}", e))),
            }
        });
    };

    let on_create_channel = move |e: web_sys::SubmitEvent| {
        e.prevent_default();
        let name = new_name.get();
        let ctype = new_type.get();
        let severity = min_severity.get();

        let config = match ctype {
            ChannelType::Webhook => serde_json::json!({
                "endpoint_url": webhook_url.get(),
            }),
            ChannelType::Slack => serde_json::json!({
                "webhook_url": webhook_url.get(),
            }),
            ChannelType::Telegram => serde_json::json!({
                "bot_token": tg_token.get(),
                "chat_id": tg_chat_id.get(),
            }),
            ChannelType::Email => {
                let mut cfg = serde_json::json!({
                    "smtp_host": smtp_host.get(),
                    "smtp_port": smtp_port.get().parse::<u16>().unwrap_or(587),
                    "to_email": to_email.get(),
                    "smtp_security": smtp_security.get(),
                });
                if !from_email.get().trim().is_empty() {
                    cfg["from_email"] = serde_json::json!(from_email.get().trim());
                }
                // Only send credentials when a username is given (empty ones break auth-less relays).
                if !smtp_user.get().trim().is_empty() {
                    cfg["smtp_username"] = serde_json::json!(smtp_user.get().trim());
                    cfg["smtp_password"] = serde_json::json!(smtp_pass.get());
                }
                cfg
            }
        };

        leptos::task::spawn_local(async move {
            let dto = CreateNotificationChannelDto {
                name,
                r#type: ctype,
                config_json: config,
                min_severity: severity,
                is_enabled: Some(true),
            };
            match ApiClient::create_notification_channel(&dto).await {
                Ok(c) => {
                    set_channels.update(|list| list.push(c));
                    set_show_modal.set(false);
                    set_new_name.set(String::new());
                    set_webhook_url.set(String::new());
                    set_tg_token.set(String::new());
                    set_tg_chat_id.set(String::new());
                    set_to_email.set(String::new());
                    set_status_msg.set(Some("Channel created successfully".to_string()));
                }
                Err(e) => {
                    set_status_msg.set(Some(format!("Failed to create channel: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-ink-700">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">
                        "Alert channels"
                    </h1>
                    <p class="text-xs text-ink-500 mt-1">
                        "Automated push notifications via Email (SMTP), Webhook, Telegram Bot, or Slack"
                    </p>
                </div>
                <button
                    on:click=move |_| set_show_modal.set(true)
                    class="px-3.5 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors flex items-center gap-2"
                >
                    <IconPlus class="w-3.5 h-3.5".to_string() />
                    <span>"Add channel"</span>
                </button>
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

            // Add Channel Modal
            {move || {
                if show_modal.get() {
                    view! {
                        <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div class="bg-ink-900 border border-ink-600 rounded-lg p-6 max-w-lg w-full shadow-console max-h-[90vh] overflow-y-auto">
                                <h3 class="text-base font-bold text-white mb-4">"Add notification channel"</h3>
                                <form on:submit=on_create_channel class="space-y-4">
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Channel name"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="Security Operations SOC Channel"
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                            prop:value=new_name
                                            on:input=move |e| set_new_name.set(event_target_value(&e))
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Channel type"</label>
                                        <select
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                                            on:change=move |e| {
                                                let val = event_target_value(&e);
                                                match val.as_str() {
                                                    "webhook" => set_new_type.set(ChannelType::Webhook),
                                                    "telegram" => set_new_type.set(ChannelType::Telegram),
                                                    "email" => set_new_type.set(ChannelType::Email),
                                                    "slack" => set_new_type.set(ChannelType::Slack),
                                                    _ => set_new_type.set(ChannelType::Webhook),
                                                }
                                            }
                                        >
                                            <option value="webhook">"Webhook (HTTP POST / Generic SIEM)"</option>
                                            <option value="telegram">"Telegram Bot"</option>
                                            <option value="email">"Email (SMTP)"</option>
                                            <option value="slack">"Slack Webhook"</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Minimum Severity"</label>
                                        <select
                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-brand/60 transition-colors"
                                            on:change=move |e| {
                                                match event_target_value(&e).as_str() {
                                                    "low" => set_min_severity.set(AlertSeverity::Low),
                                                    "medium" => set_min_severity.set(AlertSeverity::Medium),
                                                    "critical" => set_min_severity.set(AlertSeverity::Critical),
                                                    _ => set_min_severity.set(AlertSeverity::High),
                                                }
                                            }
                                        >
                                            <option value="high" selected>"High & Critical"</option>
                                            <option value="critical">"Critical Only"</option>
                                            <option value="medium">"Medium, High & Critical"</option>
                                            <option value="low">"All Severities (Low+)"</option>
                                        </select>
                                    </div>

                                    // Dynamic Channel Inputs (Mục 48)
                                    {move || match new_type.get() {
                                        ChannelType::Webhook | ChannelType::Slack => view! {
                                            <div>
                                                <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Target Webhook URL"</label>
                                                <input
                                                    type="url"
                                                    required
                                                    placeholder="https://hooks.example.com/alerts"
                                                    class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                                    prop:value=webhook_url
                                                    on:input=move |e| set_webhook_url.set(event_target_value(&e))
                                                />
                                            </div>
                                        }.into_any(),
                                        ChannelType::Telegram => view! {
                                            <div class="space-y-3">
                                                <div>
                                                    <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Telegram Bot Token"</label>
                                                    <input
                                                        type="text"
                                                        required
                                                        placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
                                                        class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                                        prop:value=tg_token
                                                        on:input=move |e| set_tg_token.set(event_target_value(&e))
                                                    />
                                                </div>
                                                <div>
                                                    <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Telegram Chat ID / Group ID"</label>
                                                    <input
                                                        type="text"
                                                        required
                                                        placeholder="-1001234567890"
                                                        class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                                        prop:value=tg_chat_id
                                                        on:input=move |e| set_tg_chat_id.set(event_target_value(&e))
                                                    />
                                                </div>
                                            </div>
                                        }.into_any(),
                                        ChannelType::Email => view! {
                                            <div class="space-y-3">
                                                <div class="grid grid-cols-3 gap-2">
                                                    <div class="col-span-2">
                                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"SMTP Host"</label>
                                                        <input
                                                            type="text"
                                                            required
                                                            placeholder="smtp.example.com"
                                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                            prop:value=smtp_host
                                                            on:input=move |e| set_smtp_host.set(event_target_value(&e))
                                                        />
                                                    </div>
                                                    <div>
                                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Port"</label>
                                                        <input
                                                            type="number"
                                                            required
                                                            placeholder="587"
                                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                            prop:value=smtp_port
                                                            on:input=move |e| set_smtp_port.set(event_target_value(&e))
                                                        />
                                                    </div>
                                                </div>
                                                <div>
                                                    <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Recipient Email (To)"</label>
                                                    <input
                                                        type="email"
                                                        required
                                                        placeholder="soc-alerts@company.internal"
                                                        class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                        prop:value=to_email
                                                        on:input=move |e| set_to_email.set(event_target_value(&e))
                                                    />
                                                </div>
                                                <div class="grid grid-cols-2 gap-2">
                                                    <div>
                                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Username"</label>
                                                        <input
                                                            type="text"
                                                            placeholder="optional"
                                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                            prop:value=smtp_user
                                                            on:input=move |e| set_smtp_user.set(event_target_value(&e))
                                                        />
                                                    </div>
                                                    <div>
                                                        <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Password"</label>
                                                        <input
                                                            type="password"
                                                            placeholder="optional"
                                                            class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                            prop:value=smtp_pass
                                                            on:input=move |e| set_smtp_pass.set(event_target_value(&e))
                                                        />
                                                    </div>
                                                </div>
                                            </div>
                                        }.into_any(),
                                    }}

                                    {move || (new_type.get() == ChannelType::Email).then(|| view! {
                                        <div class="grid grid-cols-2 gap-3">
                                            <div>
                                                <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"From address"</label>
                                                <input type="email" placeholder="alerts@your-domain"
                                                    class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-brand/60"
                                                    prop:value=from_email
                                                    on:input=move |e| set_from_email.set(event_target_value(&e)) />
                                            </div>
                                            <div>
                                                <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Connection security"</label>
                                                <select class="w-full bg-ink-950 border border-ink-600 rounded-md px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-brand/60"
                                                    on:change=move |e| set_smtp_security.set(event_target_value(&e))>
                                                    <option value="starttls">"STARTTLS (587/2525)"</option>
                                                    <option value="tls">"TLS (465)"</option>
                                                    <option value="none">"None (local relay only)"</option>
                                                </select>
                                            </div>
                                        </div>
                                    })}

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
                                            class="px-4 py-2 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors"
                                        >
                                            "Save channel"
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

            // Channels List Grid
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <For
                    each=move || channels.get()
                    key=|c| (c.id, c.updated_at)
                    children=move |channel| {
                        let chan_id = channel.id;
                        let is_active = channel.is_enabled;
                        let type_label = match channel.r#type {
                            ChannelType::Email => "Email (SMTP)",
                            ChannelType::Webhook => "Webhook",
                            ChannelType::Telegram => "Telegram bot",
                            ChannelType::Slack => "Slack",
                        };

                        view! {
                            <div class="bg-ink-900/60 border border-ink-600 border-l-2 border-l-brand rounded-lg p-6 flex flex-col justify-between space-y-4">
                                <div>
                                    <div class="flex items-center justify-between gap-3 mb-2">
                                        <span class="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold text-brand uppercase bg-brand/10 px-2.5 py-1 rounded border border-brand/20">
                                            <IconBell class="w-3 h-3".to_string() />
                                            {type_label}
                                        </span>
                                        {if is_active {
                                            view! {
                                                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-brand/10 text-brand border border-brand/20">
                                                    "ACTIVE"
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-ink-700 text-ink-400 border border-ink-600">
                                                    "DISABLED"
                                                </span>
                                            }.into_any()
                                        }}
                                    </div>
                                    <h3 class="text-base font-bold text-white tracking-tight">
                                        {channel.name}
                                    </h3>
                                    <div class="text-[11px] font-mono text-ink-500 mt-1 truncate">
                                        {format!("Min Severity: {:?} | Configured", channel.min_severity)}
                                    </div>
                                </div>

                                <div class="flex items-center justify-between pt-2 border-t border-ink-700">
                                    <button
                                        class="px-3 py-1.5 rounded-md bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 text-xs font-medium transition-colors"
                                        on:click=move |_| on_test_channel(chan_id)
                                    >
                                        "Send test alert"
                                    </button>
                                    <div class="flex items-center gap-3">
                                        <button
                                            class="text-xs text-ink-500 hover:text-slate-200 transition-colors"
                                            on:click=move |_| on_toggle_channel(chan_id, !is_active)
                                        >
                                            {if is_active { "Disable" } else { "Enable" }}
                                        </button>
                                        {move || if pending_delete.get() == Some(chan_id) {
                                            view! {
                                                <span class="flex items-center gap-2 text-xs">
                                                    <button class="text-sev-critical font-semibold" on:click=move |_| on_delete_channel(chan_id)>"Confirm delete"</button>
                                                    <button class="text-ink-500" on:click=move |_| set_pending_delete.set(None)>"Cancel"</button>
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <button
                                                    class="text-xs text-sev-critical hover:brightness-125 transition-all"
                                                    on:click=move |_| set_pending_delete.set(Some(chan_id))
                                                >
                                                    "Delete"
                                                </button>
                                            }.into_any()
                                        }}
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
