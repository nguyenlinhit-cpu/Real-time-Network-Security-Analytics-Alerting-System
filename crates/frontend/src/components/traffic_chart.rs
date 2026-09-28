use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;

const CHART_W: f64 = 500.0;
const CHART_H: f64 = 140.0;

#[component]
pub fn TrafficChart(throughput: ReadSignal<u64>) -> impl IntoView {
    // Real-time throughput history (24 1-second intervals, initially 0) (Mục 47)
    let (history, set_history) = signal(vec![0usize; 24]);
    let (current_rate, set_current_rate) = signal(0u64);

    // Track real B/s rate by computing delta over 1-second interval
    leptos::task::spawn_local(async move {
        let mut last_bytes = throughput.get_untracked();
        loop {
            TimeoutFuture::new(1000).await;
            let current_total = throughput.get_untracked();
            let delta = if current_total >= last_bytes {
                current_total - last_bytes
            } else {
                current_total
            };
            last_bytes = current_total;

            set_current_rate.set(delta);
            set_history.update(|h| {
                h.push(delta as usize);
                if h.len() > 24 {
                    h.remove(0);
                }
            });
        }
    });

    let points = Memo::new(move |_| {
        let data = history.get();
        if data.is_empty() {
            return Vec::new();
        }
        let max_val = *data.iter().max().unwrap_or(&1) as f64;
        let effective_max = if max_val < 100.0 { 100.0 } else { max_val };
        let step = CHART_W / (data.len() - 1).max(1) as f64;
        data.iter()
            .enumerate()
            .map(|(i, &val)| {
                let x = i as f64 * step;
                let y = CHART_H - (val as f64 / effective_max * (CHART_H - 24.0)) - 12.0;
                (x, y)
            })
            .collect::<Vec<_>>()
    });

    let line_path = Memo::new(move |_| {
        let pts = points.get();
        pts.iter()
            .enumerate()
            .fold(String::new(), |mut d, (i, (x, y))| {
                if i == 0 {
                    d.push_str(&format!("M {:.1} {:.1}", x, y));
                } else {
                    d.push_str(&format!(" L {:.1} {:.1}", x, y));
                }
                d
            })
    });

    let fill_path = Memo::new(move |_| {
        let pts = points.get();
        if pts.is_empty() {
            return String::new();
        }
        let mut d = format!("M {:.1} {:.1}", pts[0].0, CHART_H);
        for (x, y) in pts.iter() {
            d.push_str(&format!(" L {:.1} {:.1}", x, y));
        }
        d.push_str(&format!(" L {:.1} {:.1} Z", pts.last().unwrap().0, CHART_H));
        d
    });

    let last_point = Memo::new(move |_| points.get().last().copied().unwrap_or((0.0, CHART_H)));

    let rate_display = Memo::new(move |_| {
        let rate = current_rate.get();
        if rate >= 1_000_000 {
            format!("{:.2} MB/s", rate as f64 / 1_000_000.0)
        } else if rate >= 1_000 {
            format!("{:.1} KB/s", rate as f64 / 1_000.0)
        } else {
            format!("{} B/s", rate)
        }
    });

    view! {
        <div class="bg-ink-900/60 border border-ink-600 rounded-lg p-6 h-full">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h3 class="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                        <span class="w-1.5 h-1.5 rounded-full bg-brand shadow-[0_0_6px_1px_rgba(38,217,203,0.6)]"></span>
                        "Live network throughput"
                    </h3>
                    <p class="text-xs text-ink-500 mt-0.5">"Real-time packet stream from capture-engine"</p>
                </div>
                <div class="text-right">
                    <span class="text-lg font-mono font-bold text-brand tabular-nums">
                        {move || rate_display.get()}
                    </span>
                </div>
            </div>

            // SVG Line Chart
            <div class="w-full h-40">
                <svg viewBox="0 0 500 140" class="w-full h-full overflow-visible">
                    <defs>
                        <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stop-color="#26D9CB" stop-opacity="0.28"/>
                            <stop offset="100%" stop-color="#26D9CB" stop-opacity="0"/>
                        </linearGradient>
                    </defs>

                    // Graticule grid
                    <line x1="0" y1="0.5" x2="500" y2="0.5" stroke="#141B27" stroke-width="1"/>
                    <line x1="0" y1="35" x2="500" y2="35" stroke="#141B27" stroke-dasharray="2 4"/>
                    <line x1="0" y1="70" x2="500" y2="70" stroke="#141B27" stroke-dasharray="2 4"/>
                    <line x1="0" y1="105" x2="500" y2="105" stroke="#141B27" stroke-dasharray="2 4"/>
                    <line x1="0" y1="139.5" x2="500" y2="139.5" stroke="#141B27" stroke-width="1"/>

                    <path d=move || fill_path.get() fill="url(#trafficGradient)" stroke="none"/>

                    <path
                        d=move || line_path.get()
                        fill="none"
                        stroke="#26D9CB"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />

                    // Live cursor head
                    <circle cx=move || last_point.get().0 cy=move || last_point.get().1 r="3.5" fill="#080B11" stroke="#26D9CB" stroke-width="2"/>
                    <circle cx=move || last_point.get().0 cy=move || last_point.get().1 r="7" fill="none" stroke="#26D9CB" stroke-width="1" opacity="0.5">
                        <animate attributeName="r" values="4;10" dur="1.6s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" values="0.6;0" dur="1.6s" repeatCount="indefinite"/>
                    </circle>
                </svg>
            </div>
        </div>
    }
}
