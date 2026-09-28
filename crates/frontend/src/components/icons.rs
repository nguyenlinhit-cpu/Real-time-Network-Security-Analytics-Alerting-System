use leptos::prelude::*;

fn cls(class: Option<String>) -> String {
    class.unwrap_or_else(|| "w-4 h-4".to_string())
}

#[component]
pub fn IconPulse(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M3 12h3.5l2-6 3.5 12 2.5-9 1.5 3H21" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn IconAlert(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M12 4 3 19.5h18L12 4Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
            <path d="M12 10.5v4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <circle cx="12" cy="17" r="0.9" fill="currentColor"/>
        </svg>
    }
}

#[component]
pub fn IconRadar(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.2" opacity="0.35"/>
            <circle cx="12" cy="12" r="5" stroke="currentColor" stroke-width="1.2" opacity="0.5"/>
            <circle cx="12" cy="12" r="1.6" fill="currentColor"/>
            <path d="M12 12 18.5 8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconWaves(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M2.5 9.5c1.5-2 3.5-2 5 0s3.5 2 5 0 3.5-2 5 0 3.5 2 4.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <path d="M2.5 15c1.5-2 3.5-2 5 0s3.5 2 5 0 3.5-2 5 0 3.5 2 4.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.5"/>
        </svg>
    }
}

#[component]
pub fn IconSliders(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h13M20 18h0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <circle cx="13" cy="6" r="2" stroke="currentColor" stroke-width="1.5"/>
            <circle cx="7" cy="12" r="2" stroke="currentColor" stroke-width="1.5"/>
            <circle cx="17" cy="18" r="2" stroke="currentColor" stroke-width="1.5"/>
        </svg>
    }
}

#[component]
pub fn IconMonitor(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <rect x="3.5" y="4.5" width="17" height="11" rx="1.2" stroke="currentColor" stroke-width="1.5"/>
            <path d="M8.5 19.5h7M12 15.5v4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconBan(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="m6.5 6.5 11 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconBell(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M6 10.5a6 6 0 0 1 12 0c0 4 1.5 5.5 1.5 5.5h-15S6 14.5 6 10.5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
            <path d="M10 19a2 2 0 0 0 4 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconDownload(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M12 4v11m0 0-4-4m4 4 4-4M5 18.5h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn IconPlus(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconClose(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="m6 6 12 12M18 6 6 18" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconArrowRight(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M4.5 12h14.5M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn IconSearch(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <circle cx="10.5" cy="10.5" r="6.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="m19.5 19.5-4.3-4.3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn IconLock(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <rect x="5" y="10.5" width="14" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.5"/>
        </svg>
    }
}

#[component]
pub fn IconHistory(#[prop(optional, into)] class: Option<String>) -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" class=cls(class)>
            <path d="M4 12a8 8 0 1 0 2.5-5.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <path d="M4 4v4h4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M12 8v4.5l3 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
