use common::models::{CreateUserDto, LoginDto, UserPublicDto};
use leptos::prelude::*;

use crate::api::client::ApiClient;
use crate::components::icons::{IconLock, IconRadar};

#[component]
pub fn LoginPage(
    set_active_tab: WriteSignal<String>,
    set_current_user: WriteSignal<Option<UserPublicDto>>,
) -> impl IntoView {
    let (is_register, set_is_register) = signal(false);
    let (username, set_username) = signal(String::new());
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error_msg, set_error_msg) = signal::<Option<String>>(None);
    let (is_loading, set_is_loading) = signal(false);

    // If already authenticated, go directly to dashboard
    Effect::new(move |_| {
        if ApiClient::is_authenticated() {
            if let Some(user) = ApiClient::get_current_user() {
                set_current_user.set(Some(user));
            }
            set_active_tab.set("dashboard".to_string());
        }
    });

    let on_submit = move |e: web_sys::SubmitEvent| {
        e.prevent_default();
        set_error_msg.set(None);
        set_is_loading.set(true);

        let u = username.get();
        let p = password.get();
        let em = email.get();
        let reg = is_register.get();

        leptos::task::spawn_local(async move {
            if reg {
                let dto = CreateUserDto {
                    username: u,
                    email: em,
                    password: p,
                    // The server always assigns the Viewer role to self-registered accounts.
                    role: None,
                };
                match ApiClient::register(&dto).await {
                    Ok(auth_data) => {
                        set_is_loading.set(false);
                        set_current_user.set(Some(auth_data.user));
                        set_active_tab.set("dashboard".to_string());
                        if let Some(window) = web_sys::window() {
                            let _ = window.history().and_then(|h| {
                                h.replace_state_with_url(
                                    &wasm_bindgen::JsValue::NULL,
                                    "",
                                    Some("/"),
                                )
                            });
                        }
                    }
                    Err(err) => {
                        set_is_loading.set(false);
                        set_error_msg.set(Some(err));
                    }
                }
            } else {
                let dto = LoginDto {
                    username: u,
                    password: p,
                };
                match ApiClient::login(&dto).await {
                    Ok(auth_data) => {
                        set_is_loading.set(false);
                        set_current_user.set(Some(auth_data.user));
                        set_active_tab.set("dashboard".to_string());
                        if let Some(window) = web_sys::window() {
                            let _ = window.history().and_then(|h| {
                                h.replace_state_with_url(
                                    &wasm_bindgen::JsValue::NULL,
                                    "",
                                    Some("/"),
                                )
                            });
                        }
                    }
                    Err(err) => {
                        set_is_loading.set(false);
                        set_error_msg.set(Some(err));
                    }
                }
            }
        });
    };

    view! {
        <div class="min-h-[calc(100vh-4rem)] flex items-center justify-center p-6">
            <div class="relative w-full max-w-md">
                // Corner brackets
                <div class="absolute -top-2 -left-2 w-5 h-5 border-t-2 border-l-2 border-brand/50"></div>
                <div class="absolute -top-2 -right-2 w-5 h-5 border-t-2 border-r-2 border-brand/50"></div>
                <div class="absolute -bottom-2 -left-2 w-5 h-5 border-b-2 border-l-2 border-brand/50"></div>
                <div class="absolute -bottom-2 -right-2 w-5 h-5 border-b-2 border-r-2 border-brand/50"></div>

                <div class="bg-ink-900/80 border border-ink-600 rounded-lg p-8 shadow-console">
                    // Header
                    <div class="text-center mb-8">
                        <div class="inline-flex items-center justify-center w-12 h-12 rounded-md border border-brand/40 bg-ink-950 text-brand mb-4">
                            <IconRadar class="w-6 h-6".to_string() />
                        </div>
                        <h2 class="text-lg font-bold text-white tracking-tight">
                            {move || if is_register.get() { "Create SecNet account" } else { "SecNet security portal" }}
                        </h2>
                        <p class="text-xs text-ink-500 mt-1.5 font-mono">
                            "real-time packet analytics & intrusion response"
                        </p>
                    </div>

                    // Error alert
                    {move || {
                        if let Some(err) = error_msg.get() {
                            view! {
                                <div class="mb-5 p-3 rounded-md bg-sev-critical/10 border border-sev-critical/30 text-sev-critical text-xs font-mono">
                                    {err}
                                </div>
                            }.into_any()
                        } else {
                            view! { <span></span> }.into_any()
                        }
                    }}

                    // Auth Form
                    <form on:submit=on_submit class="space-y-4">
                        <div>
                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Username"</label>
                            <input
                                type="text"
                                required
                                placeholder="e.g. admin or analyst"
                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                prop:value=username
                                on:input=move |e| set_username.set(event_target_value(&e))
                            />
                        </div>

                        {move || {
                            if is_register.get() {
                                view! {
                                    <div class="space-y-4">
                                        <div>
                                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Email address"</label>
                                            <input
                                                type="email"
                                                required
                                                placeholder="user@secnet.internal"
                                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                                prop:value=email
                                                on:input=move |e| set_email.set(event_target_value(&e))
                                            />
                                        </div>
                                    </div>
                                }.into_any()
                            } else {
                                view! { <span></span> }.into_any()
                            }
                        }}

                        <div>
                            <label class="block text-[11px] font-mono font-semibold text-ink-500 uppercase tracking-wide mb-1.5">"Password"</label>
                            <input
                                type="password"
                                required
                                placeholder="••••••••"
                                class="w-full bg-ink-950 border border-ink-600 rounded-md px-3.5 py-2 text-xs text-slate-200 placeholder-ink-600 focus:outline-none focus:border-brand/60 transition-colors"
                                prop:value=password
                                on:input=move |e| set_password.set(event_target_value(&e))
                            />
                        </div>

                        <button
                            type="submit"
                            disabled=move || is_loading.get()
                            class="w-full mt-2 py-2.5 px-4 rounded-md bg-brand hover:bg-brand-light disabled:opacity-50 text-ink-950 text-xs font-bold transition-colors flex items-center justify-center gap-2"
                        >
                            <IconLock class="w-3.5 h-3.5".to_string() />
                            {move || if is_loading.get() {
                                view! { <span>"Authenticating…"</span> }.into_any()
                            } else if is_register.get() {
                                view! { <span>"Create account"</span> }.into_any()
                            } else {
                                view! { <span>"Sign in to dashboard"</span> }.into_any()
                            }}
                        </button>
                    </form>

                    // Toggle register/login
                    <div class="mt-6 pt-6 border-t border-ink-700 text-center">
                        <button
                            class="text-xs text-brand hover:text-brand-light transition-colors"
                            on:click=move |_| {
                                set_is_register.update(|v| *v = !*v);
                                set_error_msg.set(None);
                            }
                        >
                            {move || if is_register.get() {
                                "Already have an account? Sign in"
                            } else {
                                "Need an account? Register new user"
                            }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}
