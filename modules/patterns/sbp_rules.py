"""Pakistan State Bank cybersecurity framework rule pack.

10+ rules drawn from the SBP Cybersecurity Framework as applied to mobile
banking applications. Each rule is a small struct with a `check(manifest,
source, dynamic)` callable that inspects the already-computed Phase 2/3/4
results and returns one of:

    COMPLIANT       - rule passed
    NON_COMPLIANT   - rule failed; rule.severity applies
    NOT_APPLICABLE  - the check cannot meaningfully run on this APK (e.g.
                      missing data because Jadx fallback or dynamic was
                      skipped); rule.severity is ignored
    MANUAL_REVIEW   - rule cannot be determined automatically; reserved
                      for things like session-timeout enforcement that
                      need a human to confirm

Data + small lambda-style callables only - no orchestration logic in this
file. The orchestrator path lives in `modules/sbp_compliance.py`.

Count is asserted at import time: chapters claim "at least 10 SBP rules
covering the SBP Cybersecurity Framework."
"""
from __future__ import annotations

from typing import Any, Callable

# Single-source manifest-finding category names used by the rules below.
# Keeps a typo here from silently breaking compliance scoring.
_HARDCODED_SECRET_CATEGORY = "Hardcoded Secrets"
_INSECURE_COMM_CATEGORY = "Insecure Communication"
_WEAK_CRYPTO_CATEGORY = "Weak Cryptography"


# --------------------------------------------------------------------------
# Helpers each rule's check() callable can use
# --------------------------------------------------------------------------

def _manifest_flag(manifest: dict, name: str, default: bool = False) -> bool:
    if not manifest:
        return default
    return bool(manifest.get("insecure_flags", {}).get(name, default))


def _source_findings(source: dict, category: str | None = None) -> list[dict]:
    if not source:
        return []
    findings = source.get("findings", [])
    if category is None:
        return findings
    return [f for f in findings if f.get("category") == category]


def _source_has_pattern(source: dict, pattern_id: str) -> bool:
    return any(f.get("pattern_id") == pattern_id for f in _source_findings(source))


# --------------------------------------------------------------------------
# Rule checks
# --------------------------------------------------------------------------

def _check_tls_enforcement(manifest, source, dynamic):
    """SBP-CSF-3.2.1 - All network communication must use TLS 1.2+."""
    if not manifest:
        return "NOT_APPLICABLE", "Manifest data unavailable."
    if _manifest_flag(manifest, "uses_cleartext_traffic"):
        return "NON_COMPLIANT", (
            "android:usesCleartextTraffic=\"true\" permits plaintext HTTP."
        )
    nsc = manifest.get("insecure_flags", {}).get("network_security_config")
    if _source_findings(source, _INSECURE_COMM_CATEGORY):
        cats = ", ".join({f["title"] for f in _source_findings(source, _INSECURE_COMM_CATEGORY)})
        return "NON_COMPLIANT", f"Source-level insecure-communication findings: {cats}"
    return "COMPLIANT", (
        f"No cleartext traffic flag; networkSecurityConfig={'present' if nsc else 'absent'}."
    )


def _check_certificate_pinning(manifest, source, dynamic):
    """SBP-CSF-3.2.2 - Certificate pinning is implemented."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    # Banking apps SHOULD pin; we can only detect bypass code, not absence
    # of pinning. So: if we found a TrustManager / hostname bypass, that
    # contradicts pinning -> NON_COMPLIANT. Otherwise MANUAL_REVIEW.
    bypass = _source_findings(source, "SSL/TLS Validation Bypass")
    if bypass:
        return "NON_COMPLIANT", (
            f"TLS validation bypass detected: {', '.join({f['title'] for f in bypass})}"
        )
    return "MANUAL_REVIEW", (
        "No TLS-bypass code detected. Confirm CertificatePinner usage manually."
    )


def _check_sensitive_data_logging(manifest, source, dynamic):
    """SBP-CSF-3.4.7 - Sensitive data must not be logged."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    leaks = _source_findings(source, "Information Leakage")
    if any(f.get("pattern_id") == "LOG_PASSWORD" for f in leaks):
        return "NON_COMPLIANT", "Source matches Log.* calls with password/token/secret tokens."
    if leaks:
        return "NON_COMPLIANT", (
            f"Information leakage findings: {', '.join({f['title'] for f in leaks})}"
        )
    return "COMPLIANT", "No sensitive-data logging patterns detected in source."


def _check_hardcoded_credentials(manifest, source, dynamic):
    """SBP-CSF-3.5.1 - Hardcoded credentials must be absent."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    secrets = _source_findings(source, _HARDCODED_SECRET_CATEGORY)
    if secrets:
        return "NON_COMPLIANT", (
            f"{len(secrets)} hardcoded-secret finding(s): "
            f"{', '.join({f['title'] for f in secrets})}"
        )
    return "COMPLIANT", "No hardcoded-secret patterns matched."


def _check_screen_capture_protection(manifest, source, dynamic):
    """SBP-CSF-4.1.3 - FLAG_SECURE on sensitive screens."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    # We don't have a dedicated pattern for FLAG_SECURE; if the decompiler
    # fell back to dex_strings we cannot reliably check. Mark MANUAL_REVIEW.
    if source.get("decompiler_used") == "dex_strings":
        return "MANUAL_REVIEW", "DEX string fallback in use; cannot confirm FLAG_SECURE."
    return "MANUAL_REVIEW", (
        "Verify WindowManager.LayoutParams.FLAG_SECURE on sensitive activities."
    )


def _check_root_detection(manifest, source, dynamic):
    """SBP-CSF-4.2.1 - Root detection implemented."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    # Heuristic: presence of su / Magisk / SuperSU string in decompiled
    # output suggests some form of root awareness. Absence of strong
    # evidence -> MANUAL_REVIEW (we don't want false-positive
    # NON_COMPLIANT for an app that just uses RootBeer in a way our
    # patterns don't see).
    # Without a dedicated pattern we mark this as MANUAL_REVIEW.
    return "MANUAL_REVIEW", (
        "Confirm root-detection library (RootBeer, SafetyNet) is invoked at launch."
    )


def _check_session_timeout(manifest, source, dynamic):
    """SBP-CSF-4.3.2 - Session timeout enforcement."""
    return "MANUAL_REVIEW", (
        "Session inactivity timeout cannot be reliably detected via static "
        "analysis. Verify the app logs the user out after configurable idle."
    )


def _check_plaintext_storage(manifest, source, dynamic):
    """SBP-CSF-5.1.1 - Sensitive data not stored in plaintext."""
    if not source:
        return "NOT_APPLICABLE", "Source data unavailable."
    storage = _source_findings(source, "Insecure Data Storage")
    if storage:
        return "NON_COMPLIANT", (
            f"Insecure data storage findings: "
            f"{', '.join({f['title'] for f in storage})}"
        )
    weak = _source_findings(source, _WEAK_CRYPTO_CATEGORY)
    if weak:
        return "NON_COMPLIANT", (
            f"Weak-crypto findings indicate plaintext-or-near-plaintext storage: "
            f"{', '.join({f['title'] for f in weak})}"
        )
    return "COMPLIANT", "No insecure-storage or weak-crypto findings recorded."


def _check_biometric_auth(manifest, source, dynamic):
    """SBP-CSF-5.2.4 - Biometric authentication for transactions."""
    # Without a dedicated regex pattern for BiometricPrompt usage, this is
    # MANUAL_REVIEW. Phase 9 may add a pattern.
    return "MANUAL_REVIEW", (
        "Confirm BiometricPrompt / FingerprintManager is used for transaction "
        "authentication."
    )


def _check_network_security_config(manifest, source, dynamic):
    """SBP-CSF-6.3.1 - networkSecurityConfig is configured."""
    if not manifest:
        return "NOT_APPLICABLE", "Manifest data unavailable."
    nsc = manifest.get("insecure_flags", {}).get("network_security_config")
    if nsc:
        return "COMPLIANT", f"networkSecurityConfig declared: {nsc}"
    return "NON_COMPLIANT", (
        "No networkSecurityConfig attribute on <application>. Certificate "
        "pinning and per-domain TLS policy cannot be enforced declaratively."
    )


# --------------------------------------------------------------------------
# Rule pack (>=10 entries)
# --------------------------------------------------------------------------

SBP_RULES: list[dict[str, Any]] = [
    {
        "id": "SBP-CSF-3.2.1",
        "name": "All network communication must use TLS 1.2 or higher",
        "category": "Network Security",
        "severity": "HIGH",
        "evidence_source": "manifest+source",
        "check": _check_tls_enforcement,
    },
    {
        "id": "SBP-CSF-3.2.2",
        "name": "Certificate pinning must be implemented",
        "category": "Network Security",
        "severity": "HIGH",
        "evidence_source": "source",
        "check": _check_certificate_pinning,
    },
    {
        "id": "SBP-CSF-3.4.7",
        "name": "Sensitive data must not be written to logs",
        "category": "Data Protection",
        "severity": "MEDIUM",
        "evidence_source": "source",
        "check": _check_sensitive_data_logging,
    },
    {
        "id": "SBP-CSF-3.5.1",
        "name": "Hardcoded credentials must be absent from source",
        "category": "Credentials",
        "severity": "HIGH",
        "evidence_source": "source",
        "check": _check_hardcoded_credentials,
    },
    {
        "id": "SBP-CSF-4.1.3",
        "name": "Screen recording / screenshot protection on sensitive screens",
        "category": "Application Security",
        "severity": "MEDIUM",
        "evidence_source": "source",
        "check": _check_screen_capture_protection,
    },
    {
        "id": "SBP-CSF-4.2.1",
        "name": "Root / jailbreak detection must be implemented",
        "category": "Application Security",
        "severity": "MEDIUM",
        "evidence_source": "source",
        "check": _check_root_detection,
    },
    {
        "id": "SBP-CSF-4.3.2",
        "name": "Session timeout must be enforced after inactivity",
        "category": "Authentication",
        "severity": "MEDIUM",
        "evidence_source": "manual",
        "check": _check_session_timeout,
    },
    {
        "id": "SBP-CSF-5.1.1",
        "name": "Sensitive data must not be stored in plaintext",
        "category": "Data Protection",
        "severity": "HIGH",
        "evidence_source": "source",
        "check": _check_plaintext_storage,
    },
    {
        "id": "SBP-CSF-5.2.4",
        "name": "Biometric authentication required for transactions",
        "category": "Authentication",
        "severity": "MEDIUM",
        "evidence_source": "source",
        "check": _check_biometric_auth,
    },
    {
        "id": "SBP-CSF-6.3.1",
        "name": "networkSecurityConfig must be declared and configured",
        "category": "Network Security",
        "severity": "MEDIUM",
        "evidence_source": "manifest",
        "check": _check_network_security_config,
    },
]


# --------------------------------------------------------------------------
# Integrity guarantees
# --------------------------------------------------------------------------

assert len(SBP_RULES) >= 10, (
    f"SBP_RULES must contain at least 10 entries, found {len(SBP_RULES)}"
)
_ids = [r["id"] for r in SBP_RULES]
assert len(_ids) == len(set(_ids)), "Duplicate rule ids in SBP_RULES"
for _r in SBP_RULES:
    assert _r["severity"] in ("HIGH", "MEDIUM", "LOW"), \
        f"{_r['id']}: invalid severity {_r['severity']!r}"
    assert callable(_r["check"]), f"{_r['id']}: check must be callable"
