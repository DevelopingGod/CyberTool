import {
  Wifi,
  Cpu,
  History as HistoryIcon,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldQuestion,
  LayoutDashboard,
  Settings as SettingsIcon,
  Loader2,
  type LucideIcon,
} from "lucide-react";
import type { CheckCategory, Severity } from "../types";

/** One consistent icon per check category, used on cards and in nav. */
export const categoryIcon: Record<CheckCategory, LucideIcon> = {
  network: Wifi,
  process: Cpu,
  persistence: HistoryIcon,
  system: ShieldCheck,
};

/** One consistent icon per severity state - always paired with a text
 * label and color, never used as the sole indicator (accessibility). */
export const severityIcon: Record<Severity, LucideIcon> = {
  ok: CheckCircle2,
  caution: AlertTriangle,
  atRisk: ShieldAlert,
};

export const severityLabel: Record<Severity, string> = {
  ok: "Safe",
  caution: "Caution",
  atRisk: "At Risk",
};

export const PermissionNeededIcon = ShieldQuestion;
export const NavDashboardIcon = LayoutDashboard;
export const NavSettingsIcon = SettingsIcon;
export const SpinnerIcon = Loader2;
