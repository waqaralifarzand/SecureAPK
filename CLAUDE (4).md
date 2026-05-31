# CLAUDE.md — SecureAPK Project Identity

> **For Claude Code:** This is the first file you read at the start of every session. It defines who the project is, what it is not, and the rules of engagement. Read it before doing anything else.

> **For Nayab:** This file is also your viva study reference. Each section explains both *what* was decided and *why*. When a panel asks "why X?", the answer is here.

---

## 1. Project basics

| Field | Value |
|---|---|
| **Name** | SecureAPK |
| **Full title** | SecureAPK: A Hybrid Static and Dynamic Security Analysis Framework for Android Applications |
| **Repo** | https://github.com/waqaralifarzand/SecureAPK |
| **Student** | Nayab Kazim (FA-22/BS DFCS/081) |
| **Institution** | Lahore Garrison University, Department of Criminology |
| **Programme** | BS Digital Forensics and Cyber Security (BS-DFCS) |
| **Session** | 2022–2026 |
| **Deployment** | Local only — Flask app on the analyst's machine. No cloud, no web hosting. |
| **Demo environment** | Nayab's laptop running Python 3.11 + Android Studio emulator |

---

## 2. What SecureAPK is (one paragraph)

SecureAPK is a web-based, locally-hosted Android security analysis framework that automates the assessment of APK files through a six-phase methodology. The system performs static analysis of the `AndroidManifest.xml` file (Phase 2) and decompiled Java source code (Phase 3), dynamic analysis of runtime behavior in an emulated Android environment (Phase 4), weighted risk scoring with OWASP Mobile Top 10 (2024) and CWE alignment (Phase 5), and structured PDF report generation (Phase 6) — all accessible through a browser-based interface without command-line expertise. SecureAPK additionally provides three differentiating capabilities absent from competing tools like MobSF: **forensic-grade reporting** with SHA-256 hashing and chain-of-custody metadata, a **Pakistan-specific SBP cybersecurity framework compliance ruleset** for banking applications, and an **educational mode** that explains each finding with vulnerable code snippets, fixed alternatives, and plain-English rationale.

---

## 3. What SecureAPK is NOT (hard scope boundaries)

These boundaries are non-negotiable. If a feature lands outside this list during execution, the framework gets violated. Push back in the planning chat before adding anything below.

1. **NOT a cloud service.** Local Flask app only. No multi-tenant deployment, no SaaS architecture, no shared instance.
2. **NOT a multi-user system.** No authentication, no user accounts, no access control. The analyst running the app is the only user.
3. **NOT an iOS or cross-platform tool.** Android APKs only. No IPA, no PWA, no React Native bundle analysis.
4. **NOT a malware classifier.** SecureAPK identifies vulnerabilities in APKs; it does not determine whether an APK is "malicious" using machine learning or signature databases.
5. **NOT a penetration testing platform.** It detects vulnerabilities; it does not exploit them.
6. **NOT a continuous monitoring tool.** It analyzes uploaded APKs on demand; it does not monitor deployed applications in real time.
7. **NOT a replacement for expert human review.** It accelerates security analysis but does not replace forensic judgment.
8. **NOT a competitor to commercial enterprise platforms** (NowSecure, Checkmarx). It is an academic and educational tool that fills the gap between fragmented CLI tools and expensive commercial offerings.
9. **NOT extensible with a plugin architecture.** Adding new detection rules is done by editing `modules/patterns/*.py` directly — no plugin loader, no marketplace.
10. **NOT a tool for analyzing heavily obfuscated APKs.** When ProGuard/R8 obfuscation makes decompiled code unreadable, the system reports what it can and gracefully degrades.

---

## 4. Tech stack (LOCKED — no deviations during execution)

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Proposal-locked. Mature ecosystem for APK analysis (PyAXMLParser, Androguard family). |
| Web framework | Flask 3.x | Proposal-locked. Lightweight, no build step, easy to defend in viva. |
| Templates | Jinja2 (bundled with Flask) | No separate templating engine. |
| Database | SQLite via stdlib `sqlite3` | Proposal-locked. Zero-install, file-based, sufficient for single-user. |
| Manifest parser | PyAXMLParser ≥0.3.27 | Proposal-locked. Handles Android Binary XML format. |
| Decompiler | Jadx 1.5+ (external binary) | Proposal-locked. Industry-standard, produces readable Java output. |
| Dynamic analysis | ADB (external binary) + Android Emulator | Proposal-locked. Standard Android tooling, no third-party agents. |
| PDF generation | ReportLab ≥4.0 | Existing dependency. Good Python integration, no headless browser needed. |
| Hashing | stdlib `hashlib` (SHA-256) | No external dep needed. |
| Frontend | Vanilla HTML + CSS + JavaScript | No React, no Vue, no build tooling. Explainable in viva. |
| Testing | pytest 8.x | Industry-standard. Replaces existing custom `test_runner.py`. |

**Why "locked":** Deviating mid-execution breaks the framework. If a phase needs something not on this list, document the question in `SCRATCHPAD.md` and ask in the planning chat — never improvise.

---

## 5. Design system / brand identity

The visual identity follows security-tool / terminal conventions: dark theme, monospace as an *accent* font for technical labels, a cyan gradient for hero headings, severity color coding aligned with industry norms, and a distinct blue for primary action buttons.

### Color palette

| Element | Spec |
|---|---|
| Theme | Dark mode |
| Background (page) | `#0a0e1a` (deep navy-black) |
| Surface (cards, panels) | `#141826` |
| Surface elevated (modals, hover) | `#1c2333` |
| Border / divider | `#2d3447` |
| **Accent (cyan)** | `#00d4ff` — logo, gradient text, links, monospace IDs, active nav indicator, focus rings |
| Accent gradient | linear gradient `#22d3ee → #3b82f6` used on the hero heading's second line |
| **Primary button (blue)** | `#3b82f6` — Start Analysis, + New Analysis, View. Hover `#2563eb`. Disabled `#2b3a55` with muted text. |
| Action: PDF (green) | `#16a34a` button / hover `#15803d` |
| Action: Delete (red) | `#dc2626` button / hover `#b91c1c` |
| Text primary | `#e6edf3` |
| Text secondary | `#8b949e` |
| Severity HIGH | `#ff4d4f` (red) |
| Severity MEDIUM | `#faad14` (amber) |
| Severity LOW | `#52c41a` (green) |
| Success | `#52c41a` |

### Typography

| Element | Spec |
|---|---|
| Font (UI body, headings) | `system-ui, -apple-system, "Segoe UI", sans-serif` |
| **Font (monospace accent)** | `"JetBrains Mono", "Fira Code", "Cascadia Code", monospace` |
| Hero heading | Large bold sans (≈56px), two lines. Line 1 in `text-primary`, line 2 in the cyan→blue gradient. |
| Section headings | Bold sans, 600 weight |
| Heading weights | 600 (semi-bold) for h1–h3, 500 for h4–h6 |

**Monospace accent usage (important — this is the signature aesthetic):** monospace is NOT just for code. It is used for technical labels and identifiers throughout the UI to give the "security tool / terminal" feel:
- The hero badge text ("Final Year Project — LGU Digital Forensics & Cyber Security")
- Step-card labels in the pipeline ("APK Upload", "Manifest Analysis", "Code Scanning", "Runtime Monitor", "Risk Report")
- Analysis IDs in the dashboard table (e.g. `A7AED466`), rendered in the cyan accent
- Code snippets and file paths (the original code use)

### Components

| Component | Spec |
|---|---|
| Border radius | `12px` cards, `8px` buttons, `4px` inline elements |
| Hero section | Centered. Cyan-bordered monospace badge → two-line gradient title → muted description paragraph. |
| Pipeline strip | Horizontal row of 5 step cards joined by `→` arrows: APK Upload → Manifest Analysis → Code Scanning → Runtime Monitor → Risk Report. Each card: icon + monospace label, dark surface, subtle border. |
| Upload card | Dark surface card titled "Upload APK for Analysis". Dashed-border drag-and-drop zone with box icon, "Drag & drop your APK file here", "or click to browse — max 100 MB". Below the zone: the three analysis toggles, then a full-width primary button "Start Analysis →". |
| Feature cards | 4-column grid below the upload card: Manifest Inspection, Source Code Scanning, Runtime Monitoring, Risk Scoring. Each: icon + bold title + muted description. |
| Dashboard table | Columns: ID (monospace, cyan, links to result) · APK File · Risk Level (colored pill badge) · Score (`NN/100`) · Vulnerabilities · Date (`YYYY-MM-DD`) · Actions (View=blue, PDF=green, Del=red). Row hover highlights to `#1c2333`. |
| Risk pill badge | Pill-shaped, colored by classification: HIGH=red, MEDIUM=amber, LOW=green, using the severity tokens above. |
| Tone | Technical, neutral, factual. No marketing copy. Emojis acceptable only as section/feature-card icons for visual scanning, never in analysis output. |

### Brand footer

Two-line centered footer in muted text: line 1 `SecureAPK © {year} — Nayab Kazim (FA-22/BS DFCS/081) — Lahore Garrison University`, line 2 `Department of Criminology · Digital Forensics & Cyber Security · Final Year Project`. The year is a config/template value, never hardcoded.

---

## 6. Hard rules — Claude Code must never do these

These are absolute. If you find yourself about to violate one, stop and ask in the planning chat.

1. **Never push directly to `main`.** Every phase opens a new branch and a PR. Branch naming: `phase-N-short-description` (e.g., `phase-4-dynamic-analyzer`, `phase-6-reports-forensic`).
2. **Never deviate from the locked tech stack.** No new libraries without explicit approval. Even "obviously useful" additions (`requests`, `pandas`, `numpy`) get vetted first.
3. **Never bypass the orchestrator.** Phases never call each other directly. `modules/analyzer.py` is the only file that knows the phase sequence. This keeps the end-to-end flow traceable for viva walkthroughs.
4. **Never hardcode secrets** in the source. No API keys, no passwords, no tokens. SecureAPK detects these in OTHER apps — finding one in our own code would be embarrassing.
5. **Never run actual malware** in the dynamic analysis emulator. Test ONLY with intentionally-vulnerable APKs from documented sources (DIVA, InsecureShop, AndroGoat). This restriction is documented in code comments inside `dynamic_analyzer.py`.
6. **Never break the fallback chains.** PyAXMLParser failures fall back to `aapt`, then to raw DEX string extraction. Jadx failures fall back to DEX string extraction. ADB unavailable means dynamic analysis returns a meaningful "skipped" status, never a crash. These chains are the difference between "works on all APKs" and "works on some APKs."
7. **Never modify the quantitative claims** the proposal and Chapters 1–3 already make. The code must hit or exceed: **37 dangerous permissions**, **30+ regex patterns across 9 categories**, **10 runtime event categories**, **34 automated tests**. If a phase produces fewer, flag it in the planning chat before merging.
8. **Never skip the `SCRATCHPAD.md` update** at the end of a phase. The next Claude Code session cannot pick up cleanly without it.
9. **Never make architectural decisions inside a Claude Code session.** If a spec is ambiguous, document the question in `SCRATCHPAD.md` under a `## Open questions` heading and surface it in the planning chat. Don't guess.
10. **Never use Frida, Xposed, or any dynamic-instrumentation tool not in the proposal.** ADB + logcat + monkey is the proposal-locked dynamic toolchain. Going deeper changes the project's scope and invalidates the literature review.
11. **Never auto-delete uploaded APKs.** Forensic chain-of-custody requires preserving the analyzed APK as evidence. Files in `uploads/` are kept until manually removed via the dashboard.
12. **Never store sensitive findings in plaintext logs.** When dynamic analysis captures credentials or tokens leaked in logcat, store them in the SQLite database with a redaction flag — never write them to stdout or to log files.

---

## 7. Audience and academic context

### Primary user
Security analysts, Android developers, and digital forensic investigators who need automated APK security assessment without orchestrating multiple CLI tools.

### Secondary user
University students in digital forensics and cyber security programmes who use SecureAPK as a hands-on teaching tool — this is what Educational Mode (Phase 8) is for.

### Tertiary user (regional differentiator)
Pakistani banking sector compliance analysts who need to verify Android applications against State Bank of Pakistan cybersecurity framework requirements — this is what SBP Compliance Mode (Phase 7) is for.

### Not a target user
Enterprise security teams with NowSecure/Checkmarx budgets. Pen-testers who need exploitation tooling. ML researchers building malware classifiers.

### Academic context
This is a Final Year Project for the BS-DFCS programme at LGU's Department of Criminology. The viva panel evaluates:

1. Technical correctness of each phase
2. Methodological soundness (alignment with proposal + literature review)
3. Originality of the three differentiating features (forensic, SBP, educational)
4. Nayab's ability to defend every architectural choice in plain language

Code is written to be **explainable**, not clever. Readability beats brevity. Comments explain *why*, not *what*.

---

## 8. The three differentiators (Mobile Security Framework comparison)

These features are why SecureAPK exists as a distinct contribution rather than a MobSF clone.

| Feature | What it does | Why MobSF doesn't have it | Phase |
|---|---|---|---|
| **Forensic-grade reporting** | SHA-256 hashes the uploaded APK, embeds the hash + analysis timestamp + tool version into the PDF report, maintains an immutable audit log per analysis. Supports forensic chain-of-custody requirements. | MobSF is engineered for developers and DevSecOps pipelines, not forensic investigators. It does not embed cryptographic integrity proofs or audit metadata in its reports. | Phase 6 |
| **SBP banking compliance ruleset** | A dedicated rules pack that runs additionally when the APK is detected (heuristically) as a financial/banking app. Maps findings to State Bank of Pakistan cybersecurity framework requirements. | MobSF is built for global enterprise audiences. It has no concept of regional banking compliance frameworks, certainly not SBP-specific ones. | Phase 7 |
| **Educational mode** | UI toggle. When enabled, each finding expands to show: (1) the vulnerable code snippet from decompiled output, (2) a hand-written fixed/safe version, (3) plain-English explanation of why this matters. | MobSF reports are factual and terse — they list findings but don't teach. Their target user is presumed to already understand the vulnerability. | Phase 8 |

---

## 9. Glossary (for clarity across the planning chat)

| Term | Meaning |
|---|---|
| **Phase** | One of nine sequential execution units in `PHASES.md`. Each phase = one focused Claude Code session. |
| **Proposal phase** | One of the six phases defined in Nayab's original project proposal (Phases 2–6 here correspond to proposal Phases 2–6; proposal Phase 1 is folded into our Phase 1 Foundation). |
| **Differentiator** | One of the three new features (forensic, SBP, educational) that distinguish SecureAPK from MobSF. |
| **Pattern data** | The catalog of detection rules — dangerous permissions, regex patterns, runtime events, SBP rules, OWASP/CWE mappings. Lives in `modules/patterns/`. |
| **Fallback chain** | The sequence of degraded parsers used when a primary tool fails. Critical for robustness. |
| **Risk score** | The 0–100 normalized score computed by `risk_engine.py` from weighted findings. |
| **Classification** | Low (0–30) / Medium (31–70) / High (71–100) — derived from risk score. |

---

*This file is the single source of truth for project identity. Any change requires explicit approval in the planning chat. Last updated: when this file was first written.*
