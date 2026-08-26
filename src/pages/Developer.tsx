import { Globe, CodeXml, UserCircle2, ShieldHalf } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import styles from "./Developer.module.css";

const LINKS = [
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/in/sankalp-indish/",
    icon: Globe,
    description: "Professional profile and background.",
  },
  {
    label: "GitHub",
    href: "https://github.com/DevelopingGod/",
    icon: CodeXml,
    description: "Source code and other projects.",
  },
];

export function Developer() {
  return (
    <div className={styles.page}>
      <section className={styles.hero}>
        <div className={styles.avatar}>
          <UserCircle2 size={44} aria-hidden="true" />
        </div>
        <div>
          <h1 className={styles.name}>Sankalp Sandeep Indish</h1>
          <p className={styles.role}>Developer of NetGuard</p>
        </div>
      </section>

      <section className={styles.linksGrid}>
        {LINKS.map((link) => (
          <button key={link.label} type="button" className={styles.linkCard} onClick={() => openUrl(link.href)}>
            <span className={styles.linkIcon}>
              <link.icon size={20} aria-hidden="true" />
            </span>
            <div>
              <p className={styles.linkLabel}>{link.label}</p>
              <p className={styles.linkDescription}>{link.description}</p>
            </div>
          </button>
        ))}
      </section>

      <section className={styles.aboutBox}>
        <ShieldHalf size={18} aria-hidden="true" className={styles.aboutIcon} />
        <div>
          <p className={styles.aboutTitle}>About NetGuard</p>
          <p className={styles.aboutCopy}>
            NetGuard is a rule-based network and system security diagnostic tool for Windows. It is not an antivirus:
            it does not scan files for malware signatures, does not remove or clean anything, and every finding is
            meant to be reviewed by you, not acted on blindly. All scan data stays on this device.
          </p>
        </div>
      </section>
    </div>
  );
}
