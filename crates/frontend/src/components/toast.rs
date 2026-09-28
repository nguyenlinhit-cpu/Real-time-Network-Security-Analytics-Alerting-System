use common::models::{Alert, AlertSeverity};
use leptos::prelude::*;

use crate::components::icons::{IconAlert, IconBell, IconClose};

fn play_critical_sound() {
    let _ = js_sys::eval(
        r#"
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.35);
            gain.gain.setValueAtTime(0.25, ctx.currentTime);
            gain.gain.linearRampToValueAtTime(0.01, ctx.currentTime + 0.35);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.35);
        } catch(e) {}
    "#,
    );
}

#[component]
pub fn ToastNotification(
    latest_alert: ReadSignal<Option<Alert>>,
    set_latest_alert: WriteSignal<Option<Alert>>,
) -> impl IntoView {
    Effect::new(move |_| {
        if let Some(ref alert) = latest_alert.get() {
            if alert.severity == AlertSeverity::Critical {
                play_critical_sound();
            }
        }
    });

    view! {
        {move || {
            if let Some(alert) = latest_alert.get() {
                let is_critical = alert.severity == AlertSeverity::Critical;
                let accent = if is_critical { "border-l-sev-critical" } else { "border-l-brand" };
                let label_color = if is_critical { "text-sev-critical" } else { "text-brand" };

                view! {
                    <div class=format!("anim-slide-in fixed bottom-6 right-6 max-w-sm w-full bg-ink-900 border border-ink-600 border-l-2 {} rounded-md p-4 shadow-console z-50", accent)>
                        <div class="flex items-start justify-between gap-3">
                            <div class="flex items-start gap-2.5">
                                <span class=format!("mt-0.5 {}", label_color)>
                                    {if is_critical {
                                        view! { <IconAlert class="w-4 h-4".to_string() /> }.into_any()
                                    } else {
                                        view! { <IconBell class="w-4 h-4".to_string() /> }.into_any()
                                    }}
                                </span>
                                <div>
                                    <div class=format!("text-[10px] font-mono font-bold uppercase tracking-wide {}", label_color)>
                                        {format!("new {:?} alert", alert.severity)}
                                    </div>
                                    <div class="text-xs font-semibold mt-1 text-white">
                                        {alert.title}
                                    </div>
                                    <div class="text-[11px] text-ink-500 mt-1 truncate">
                                        {alert.description}
                                    </div>
                                </div>
                            </div>
                            <button
                                class="text-ink-500 hover:text-white p-0.5 shrink-0"
                                on:click=move |_| set_latest_alert.set(None)
                            >
                                <IconClose class="w-3.5 h-3.5".to_string() />
                            </button>
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <div></div> }.into_any()
            }
        }}
    }
}
