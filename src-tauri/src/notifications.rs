//! System tray icon and scan-complete notifications for background scans.

use crate::checks::Severity;
use crate::scan::ScanCompleteEvent;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

/// Event emitted to the frontend when a background scan completes, so the
/// UI can route straight to that scan's result if the window is open (or is
/// focused via the tray/notification click).
pub const EVENT_BACKGROUND_SCAN_COMPLETE: &str = "netguard://background-scan-complete";

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Ok => "No issues found",
        Severity::Caution => "Caution: some findings need review",
        Severity::AtRisk => "At risk: findings need your attention",
    }
}

pub fn notify_scan_complete(app: &AppHandle, complete: &ScanCompleteEvent) {
    let title = "NetGuard background scan complete";
    let body = format!(
        "{} - based on {} of {} checks.",
        severity_label(complete.overall_severity),
        complete.executed_count,
        complete.total_count
    );

    let _ = app.notification().builder().title(title).body(&body).show();

    // Also emit a frontend event with the same payload, so an already-open
    // window can show its own in-app toast (see Part E) without waiting on
    // the OS notification click.
    let _ = tauri::Emitter::emit(app, EVENT_BACKGROUND_SCAN_COMPLETE, complete);
}

/// Shows and focuses the main window - used by both the tray icon's "Open
/// NetGuard" menu item and a notification click.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let open_item = MenuItem::with_id(app, "open", "Open NetGuard", true, None::<&str>)?;
    let scan_item = MenuItem::with_id(app, "scan_now", "Run scan now", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &scan_item, &quit_item])?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().cloned().expect("default window icon is bundled"))
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("NetGuard")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "scan_now" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    crate::background::run_background_scan(&app).await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}
