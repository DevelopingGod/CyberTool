pub mod background;
pub mod checks;
pub mod commands;
pub mod export;
pub mod history;
pub mod notifications;
pub mod pdf;
pub mod permissions;
pub mod remediation;
pub mod scan;
pub mod sysutil;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_checks_catalog,
            commands::get_permissions,
            commands::set_permission,
            commands::run_scan,
            commands::get_scan_history,
            commands::get_scan_detail,
            commands::clear_scan_history,
            commands::get_background_settings,
            commands::set_background_settings,
            commands::run_background_scan_now,
            commands::export_scan_json,
            commands::export_scan_report,
            commands::export_scan_pdf,
            commands::get_current_username,
            remediation::run_direct_fix,
            remediation::open_settings_deep_link,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            notifications::setup_tray(&handle)?;
            background::spawn_background_scan_task(handle);
            Ok(())
        })
        // Closing the main window (the titlebar 'X') fully exits the app -
        // no hide-to-tray, no background process left running. This is a
        // deliberate product decision: the user must be able to trust that
        // closing the window means NetGuard is completely gone, not quietly
        // scanning in the background. The tray icon (and any "background
        // scan" preference) is only meaningful while the app is actually
        // running - it disappears along with everything else on close.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if window.label() == "main" {
                    tauri::Manager::app_handle(window).exit(0);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
