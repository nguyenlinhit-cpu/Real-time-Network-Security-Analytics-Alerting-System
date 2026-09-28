use common::models::{Alert, AlertSeverity};
use leptos::prelude::*;

use crate::components::icons::{IconAlert, IconBell, IconClose};

fn play_critical_sound() {
    // Safe Web Audio API invocation without js_sys::eval (Mục 53)
    if let Ok(ctx) = web_sys::AudioContext::new() {
        if let (Ok(osc), Ok(gain)) = (ctx.create_oscillator(), ctx.create_gain()) {
            osc.set_type(web_sys::OscillatorType::Sawtooth);
            let now = ctx.current_time();
            let _ = osc.frequency().set_value_at_time(880.0, now);
            let _ = osc
                .frequency()
                .exponential_ramp_to_value_at_time(440.0, now + 0.35);
            let _ = gain.gain().set_value_at_time(0.25, now);
            let _ = gain.gain().linear_ramp_to_value_at_time(0.01, now + 0.35);
            let _ = osc.connect_with_audio_node(&gain);
            let _ = gain.connect_with_audio_node(&ctx.destination());
            let _ = osc.start();
            let _ = osc.stop_with_when(now + 0.35);
        }
    }
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
