import { NavDashboardIcon, NavSettingsIcon } from "../lib/icons";
import { ShieldHalf, UserCircle2, FileText, Lock } from "lucide-react";
import styles from "./Sidebar.module.css";

export type View =
  | "dashboard"
  | "settings"
  | "history-detail"
  | "check-detail"
  | "developer"
  | "terms"
  | "privacy";

export type PrimaryView = "dashboard" | "settings" | "developer" | "terms" | "privacy";

interface SidebarProps {
  active: View;
  onNavigate: (view: PrimaryView) => void;
}

export function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <nav className={styles.sidebar} aria-label="Primary">
      <div className={styles.brand}>
        <span className={styles.brandIcon}>
          <ShieldHalf size={22} strokeWidth={2.25} aria-hidden="true" />
        </span>
        <span className={styles.brandName}>NetGuard</span>
      </div>

      <ul className={styles.navList}>
        <li>
          <button
            type="button"
            className={styles.navItem}
            data-active={active === "dashboard" || active === "history-detail" || active === "check-detail"}
            onClick={() => onNavigate("dashboard")}
          >
            <NavDashboardIcon size={18} aria-hidden="true" />
            <span>Dashboard</span>
          </button>
        </li>
        <li>
          <button
            type="button"
            className={styles.navItem}
            data-active={active === "settings"}
            onClick={() => onNavigate("settings")}
          >
            <NavSettingsIcon size={18} aria-hidden="true" />
            <span>Settings</span>
          </button>
        </li>
      </ul>

      <p className={styles.groupLabel}>Legal &amp; About</p>
      <ul className={styles.navList}>
        <li>
          <button type="button" className={styles.navItem} data-active={active === "developer"} onClick={() => onNavigate("developer")}>
            <UserCircle2 size={18} aria-hidden="true" />
            <span>Developer</span>
          </button>
        </li>
        <li>
          <button type="button" className={styles.navItem} data-active={active === "privacy"} onClick={() => onNavigate("privacy")}>
            <Lock size={18} aria-hidden="true" />
            <span>Privacy Policy</span>
          </button>
        </li>
        <li>
          <button type="button" className={styles.navItem} data-active={active === "terms"} onClick={() => onNavigate("terms")}>
            <FileText size={18} aria-hidden="true" />
            <span>Terms &amp; Conditions</span>
          </button>
        </li>
      </ul>

      <p className={styles.footnote}>Diagnostic tool - not an antivirus.</p>
    </nav>
  );
}
