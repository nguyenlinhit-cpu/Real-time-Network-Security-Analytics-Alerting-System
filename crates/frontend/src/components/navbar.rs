use crate::api::client::ApiClient;
use crate::components::icons::{IconAlert, IconRadar};
use common::models::UserPublicDto;
use leptos::prelude::*;

#[component]
pub fn Navbar(
    current_user: ReadSignal<Option<UserPublicDto>>,
    set_current_user: WriteSignal<Option<UserPublicDto>>,
    set_active_tab: WriteSignal<String>,
    is_ws_connected: ReadSignal<bool>,
    critical_count: Signal<usize>,
) -> impl IntoView {
    let on_logout = move |_| {
        leptos::task::spawn_local(async move {
            // Revoke the tokens server-side before leaving the session.
            ApiClient::api_logout().await;
            set_current_user.set(None);
            set_active_tab.set("login".to_string());
        });
    };

    let on_sign_in = move |_| {
        set_active_tab.set("login".to_string());
    };

    view! {
        <header class="h-16 bg-ink-900/95 border-b border-ink-600 px-4 md:px-6 flex items-center justify-between sticky top-0 z-40">
            // Brand Logo & Status
            <div class="flex items-center gap-4">
                <button
                    on:click=move |_| {
                        if current_user.get().is_some() {
                            set_active_tab.set("dashboard".to_string());
                        } else {
                            set_active_tab.set("login".to_string());
                        }
                    }
                    class="flex items-center gap-3 text-left hover:opacity-90 transition focus:outline-none"
                >
                    <div class="relative w-9 h-9 rounded-md border border-brand/40 bg-ink-950 flex items-center justify-center text-brand">
                        <IconRadar class="w-5 h-5".to_string() />
                        <span class="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-brand shadow-[0_0_6px_2px_rgba(38,217,203,0.6)]"></span>
                    </div>
                    <div>
                        <h1 class="text-sm font-bold text-white tracking-wide leading-none">
                            "SECNET"<span class="text-brand">"//"</span>"ANALYTICS"
                        </h1>
                        <span class="text-[10px] text-ink-500 font-mono tracking-wide">
                            "build v1.0.0-phase5"
                        </span>
                    </div>
                </button>

                // WS Status Badge
                <div class="hidden sm:flex items-center gap-2 pl-3 pr-3 py-1.5 rounded-md text-[11px] font-mono border bg-ink-950/80 border-ink-600">
                    {move || if is_ws_connected.get() {
                        view! {
                            <span class="relative flex w-2 h-2">
                                <span class="absolute inline-flex h-full w-full rounded-full bg-brand" style="animation: ring-expand 1.6s cubic-bezier(0,0,0.2,1) infinite;"></span>
                                <span class="relative inline-flex rounded-full h-2 w-2 bg-brand"></span>
                            </span>
                            <span class="text-brand tracking-wide">"LINK UP"</span>
                        }.into_any()
                    } else {
                        view! {
                            <span class="w-2 h-2 rounded-full bg-sev-high"></span>
                            <span class="text-sev-high tracking-wide">"RECONNECTING"</span>
                        }.into_any()
                    }}
                </div>
            </div>

            // Right side: Critical Alert Counter, User, Logout
            <div class="flex items-center gap-2.5">
                // Critical Alert Badge
                {move || {
                    let count = critical_count.get();
                    if count > 0 {
                        view! {
                            <div class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-sev-critical/10 border border-sev-critical/40 text-sev-critical text-[11px] font-mono font-semibold">
                                <IconAlert class="w-3.5 h-3.5".to_string() />
                                <span>{format!("{:02} CRITICAL", count)}</span>
                            </div>
                        }.into_any()
                    } else {
                        view! { <span></span> }.into_any()
                    }
                }}

                // User Profile
                {move || match current_user.get() {
                    Some(u) => view! {
                        <div class="flex items-center gap-3">
                            <div class="text-right hidden md:block leading-tight">
                                <div class="text-xs font-semibold text-slate-200">{u.username}</div>
                                <div class="text-[10px] font-mono text-brand uppercase tracking-wide">{format!("{:?}", u.role)}</div>
                            </div>
                            <button
                                class="px-3 py-1.5 rounded-md bg-ink-800 hover:bg-ink-700 text-slate-300 text-xs font-medium border border-ink-600 transition-colors"
                                on:click=on_logout
                            >
                                "Sign out"
                            </button>
                        </div>
                    }.into_any(),
                    None => view! {
                        <button
                            on:click=on_sign_in
                            class="px-3.5 py-1.5 rounded-md bg-brand hover:bg-brand-light text-ink-950 text-xs font-bold transition-colors"
                        >
                            "Sign in"
                        </button>
                    }.into_any(),
                }}
            </div>
        </header>
    }
}
