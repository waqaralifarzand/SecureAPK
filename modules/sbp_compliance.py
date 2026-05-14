"""Phase 7 - Pakistan State Bank cybersecurity framework compliance.

The second MobSF differentiator: a thin compliance layer that runs against
the already-computed Phase 2 / 3 / 4 results and reports per-rule pass /
fail / not-applicable status against the SBP Cybersecurity Framework.

Per ARCHITECTURE.md sec 11.2, SBP does NOT re-parse the APK - it consumes
the manifest and source results directly. Banking-app heuristic also
lives here (package + app-name + permission-combo signals).
"""
from __future__ import annotations

import logging
from typing import Any

from modules.patterns.sbp_rules import SBP_RULES

log = logging.getLogger(__name__)


# --- Banking app heuristic -------------------------------------------------

_PACKAGE_SUBSTRINGS = ("bank", "pay", "wallet", "finance", "cash")
_APP_NAME_SUBSTRINGS = (
    "bank", "pay", "wallet",
    "jazzcash", "easypaisa",
    "hbl", "mcb", "ubl", "allied", "faysal", "bankislami",
    "meezan", "habib", "standard chartered", "soneri", "askari",
)
_BANKING_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.INTERNET",
}


def is_banking_app(manifest: dict | None) -> tuple[bool, str]:
    """Return (flag, reason). reason is human-readable for the UI tab."""
    if not manifest:
        return False, "Manifest data unavailable."
    pkg = (manifest.get("package_name") or "").lower()
    name = (manifest.get("app_name") or "").lower()

    for token in _PACKAGE_SUBSTRINGS:
        if token in pkg:
            return True, f"Package name contains '{token}'."
    for token in _APP_NAME_SUBSTRINGS:
        if token in name:
            return True, f"App name contains '{token}'."

    perms = {(p.get("name") or "") for p in manifest.get("permissions", [])}
    if _BANKING_PERMS.issubset(perms):
        return True, ("Permission combo READ_SMS + READ_CONTACTS + INTERNET "
                      "is typical of OTP-based banking apps.")

    return False, "No banking-app signals matched in package/app name or permissions."


# --- Public entry point ----------------------------------------------------

def analyze(
    apk_path: str,
    manifest: dict | None,
    source: dict | None,
    dynamic: dict | None = None,
) -> dict[str, Any]:
    """Run every SBP rule and return the structured result.

    `apk_path` is accepted for symmetry with the other phase analyzers,
    but SBP intentionally does NOT re-parse the APK - per ARCH §11.2 it
    is a thin layer over the already-computed Phase 2/3/4 results.
    """
    banking, banking_reason = is_banking_app(manifest)

    rule_results: list[dict[str, Any]] = []
    counts = {"COMPLIANT": 0, "NON_COMPLIANT": 0,
              "NOT_APPLICABLE": 0, "MANUAL_REVIEW": 0}
    findings: list[dict[str, Any]] = []

    for rule in SBP_RULES:
        try:
            status, evidence = rule["check"](manifest, source, dynamic)
        except Exception as e:  # noqa: BLE001 - rule bugs must not fail the analysis
            log.exception("SBP rule %s threw; treating as NOT_APPLICABLE", rule["id"])
            status, evidence = "NOT_APPLICABLE", f"Rule check error: {e}"

        if status not in counts:
            log.warning("rule %s returned unknown status %r; coercing to NOT_APPLICABLE",
                        rule["id"], status)
            status = "NOT_APPLICABLE"

        counts[status] += 1

        rule_results.append({
            "rule_id": rule["id"],
            "name": rule["name"],
            "category": rule["category"],
            "severity": rule["severity"] if status == "NON_COMPLIANT" else None,
            "compliance_status": status,
            "evidence": evidence,
        })

        # Promote NON_COMPLIANT rules into Phase-7 Finding-shaped rows so
        # the risk engine can score them under the `sbp` bucket.
        if status == "NON_COMPLIANT":
            findings.append({
                "id": None,
                "phase": 7,
                "category": "SBP Compliance",
                "severity": rule["severity"],
                "title": f"{rule['id']}: {rule['name']}",
                "description": evidence,
                "file_location": "SBP rule",
                "line_number": None,
                "code_snippet": None,
                "owasp_id": None,
                "cwe_id": None,
                "pattern_id": rule["id"],
            })

    return {
        "is_banking_app": banking,
        "banking_reason": banking_reason,
        "counts": counts,
        "rules": rule_results,
        "findings": findings,
        "non_compliant_count": counts["NON_COMPLIANT"],
    }
