use common::models::{UserPublicDto, UserRole};
use leptos::prelude::*;

use crate::components::icons::{
    IconAlert, IconBan, IconBell, IconMonitor, IconPulse, IconSliders, IconWaves,
};

#[derive(Clone, Copy)]
enum NavIcon {
    Overview,
    Alerts,
    Traffic,
    Rules,
    Devices,
    Blocklist,
    Settings,
    AuditLogs,
}

fn render_icon(icon: NavIcon) -> impl IntoView {
    let class = "w-4 h-4".to_string();
    match icon {
        NavIcon::Overview => view! { <IconPulse class=class /> }.into_any(),
        NavIcon::Alerts => view! { <IconAlert class=class /> }.into_any(),
        NavIcon::Traffic => view! { <IconWaves class=class /> }.into_any(),
        NavIcon::Rules => view! { <IconSliders class=class /> }.into_any(),
        NavIcon::Devices => view! { <IconMonitor class=class /> }.into_any(),
        NavIcon::Blocklist => view! { <IconBan class=class /> }.into_any(),
        NavIcon::Settings => view! { <IconBell class=class /> }.into_any(),
        NavIcon::AuditLogs => view! { <IconPulse class=class /> }.into_any(),
    }
}

#[component]
pub fn Sidebar(
    current_user: ReadSignal<Option<UserPublicDto>>,
    active_tab: ReadSignal<String>,
    set_active_tab: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <aside class="w-60 bg-ink-900/60 border-r border-ink-600 p-3 flex flex-col justify-between hidden md:flex min-h-[calc(100vh-4rem)]">
            <div>
                <div class="px-3 pt-1 pb-3 flex items-center gap-2 text-[10px] font-mono text-ink-500 uppercase tracking-[0.15em] border-b border-ink-700 mb-2">
                    <span class="w-1 h-1 rounded-full bg-brand"></span>
                    "Operations Deck"
                </div>

                <div class="space-y-0.5">
                {move || {
                    let user_role = current_user.get().map(|u| u.role).unwrap_or(UserRole::Viewer);

                    let mut nav_items = vec![
                        ("dashboard", NavIcon::Overview, "Overview"),
                        ("alerts", NavIcon::Alerts, "Incidents"),
                        ("traffic", NavIcon::Traffic, "Traffic feed"),
                        ("rules", NavIcon::Rules, "Detection rules"),
                        ("devices", NavIcon::Devices, "Devices"),
                    ];

                    if user_role == UserRole::Analyst || user_role == UserRole::Admin {
                        nav_items.push(("blocklist", NavIcon::Blocklist, "Blocklist"));
                    }

                    if user_role == UserRole::Admin {
                        nav_items.push(("settings", NavIcon::Settings, "Alert channels"));
                        nav_items.push(("audit_logs", NavIcon::AuditLogs, "Audit logs"));
                    }

                    nav_items.into_iter().map(|(id, icon, label)| {
                        let item_id = id.to_string();
                        let is_active = move || active_tab.get() == item_id;

                        view! {
                            <button
                                class=move || {
                                    if is_active() {
                                        "w-full flex items-center gap-2.5 pl-2.5 pr-3 py-2.5 rounded-md text-xs font-semibold bg-brand/10 text-brand border-l-2 border-brand transition-colors"
                                    } else {
                                        "w-full flex items-center gap-2.5 pl-3 pr-3 py-2.5 rounded-md text-xs font-medium text-ink-500 hover:text-slate-200 hover:bg-ink-800/60 border-l-2 border-transparent transition-colors"
                                    }
                                }
                                on:click=move |_| set_active_tab.set(id.to_string())
                            >
                                {render_icon(icon)}
                                <span>{label}</span>
                            </button>
                        }
                    }).collect::<Vec<_>>()
                }}
                </div>
            </div>

            // Bottom trust status
            <div class="p-3.5 rounded-md bg-ink-950 border border-ink-600">
                <div class="flex items-center gap-2 text-[11px] font-mono font-medium text-brand">
                    <span class="w-1.5 h-1.5 rounded-full bg-brand shadow-[0_0_6px_1px_rgba(38,217,203,0.6)]"></span>
                    "ZERO TRUST ENFORCED"
                </div>
                <p class="text-[10px] text-ink-500 mt-1.5 leading-relaxed">
                    "OWASP Top 10 controls verified on every request path."
                </p>
            </div>
        </aside>
    }
}
