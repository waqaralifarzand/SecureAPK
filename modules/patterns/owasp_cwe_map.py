"""OWASP Mobile Top 10 (2024) categories and finding-category mappings.

Phase 2 seeds the manifest-related entries. Phase 3 (source analyzer) and
later phases extend `CATEGORY_TO_OWASP` with their own categories — do NOT
rename keys here without checking callers in those phases.
"""
from __future__ import annotations


OWASP_MTW10_2024: dict[str, str] = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


# Finding categories surfaced by the manifest analyzer (Phase 2).
# Source-code categories (Phase 3) and dynamic categories (Phase 4) extend
# this dict in their own files.
CATEGORY_TO_OWASP: dict[str, str] = {
    # Phase 2 — manifest-level findings
    "Dangerous Permission": "M6",
    "Exported Component": "M8",
    "Insecure Configuration": "M8",
    "Cleartext Traffic": "M5",
    "Debuggable Build": "M7",
    "Backup Allowed": "M9",
    "Missing Network Security Config": "M5",
}


CATEGORY_TO_CWE: dict[str, str] = {
    "Dangerous Permission": "CWE-250",
    "Exported Component": "CWE-926",
    "Insecure Configuration": "CWE-16",
    "Cleartext Traffic": "CWE-319",
    "Debuggable Build": "CWE-489",
    "Backup Allowed": "CWE-530",
    "Missing Network Security Config": "CWE-319",
}
