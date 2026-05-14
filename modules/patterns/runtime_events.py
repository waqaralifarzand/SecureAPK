"""Catalog of runtime event categories detected in logcat output.

Exactly 10 entries — count asserted at import time. Order/IDs come from
ARCHITECTURE.md sec 11. Each entry is regex-driven; the dynamic analyzer
walks each captured logcat line against every category's `logcat_patterns`
and emits the first match.

Severity values map to CLAUDE.md sec 5 colour conventions
(HIGH=red, MEDIUM=amber, LOW=green) — Phase 5 will weight on them.

Data only — no logic.
"""
from __future__ import annotations


RUNTIME_EVENT_CATEGORIES: list[dict] = [
    {
        "id": "CLEARTEXT_HTTP",
        "name": "Cleartext HTTP Communication",
        "severity": "HIGH",
        "logcat_patterns": [
            r"CleartextTraffic",
            r"http://[^\s\"']+",
            r"NetworkSecurityConfig: .*cleartext",
        ],
        "description": "Application transmitted data over unencrypted HTTP.",
    },
    {
        "id": "CREDENTIAL_LOG_EXPOSURE",
        "name": "Credential Exposure in Logs",
        "severity": "HIGH",
        "logcat_patterns": [
            r"(?i)password\s*[=:]\s*\S+",
            r"(?i)token\s*[=:]\s*[A-Za-z0-9._\-]+",
            r"(?i)api[_\-]?key\s*[=:]\s*\S+",
            r"(?i)secret\s*[=:]\s*\S+",
        ],
        "description": "A sensitive credential, token, or secret was written to logcat.",
    },
    {
        "id": "SSL_VALIDATION_EXCEPTION",
        "name": "SSL Certificate Validation Exception",
        "severity": "HIGH",
        "logcat_patterns": [
            r"javax\.net\.ssl\.SSLHandshakeException",
            r"java\.security\.cert\.CertPathValidatorException",
            r"Trust anchor for certification path not found",
            r"X509TrustManager",
        ],
        "description": "TLS handshake failed or certificate validation was bypassed.",
    },
    {
        "id": "INSECURE_NETWORK_OP",
        "name": "Insecure Network Operation",
        "severity": "MEDIUM",
        "logcat_patterns": [
            r"NetworkOnMainThreadException",
            r"StrictMode policy violation.*network",
            r"http\.HttpURLConnection: cleartext",
        ],
        "description": "Network operation flagged by StrictMode or other platform checks.",
    },
    {
        "id": "IMPLICIT_INTENT_IPC",
        "name": "IPC via Implicit Intent",
        "severity": "MEDIUM",
        "logcat_patterns": [
            r"ActivityManager: START u\d+ \{act=[^/]+ ",
            r"sendBroadcast.*action=",
            r"Intent\.createChooser",
        ],
        "description": "Application sent an implicit intent — receivable by any app with a matching filter.",
    },
    {
        "id": "RUNTIME_PERMISSION_DENIAL",
        "name": "Runtime Permission Denial",
        "severity": "LOW",
        "logcat_patterns": [
            r"java\.lang\.SecurityException: .*permission\.",
            r"Permission Denial:",
            r"requires android\.permission\.",
        ],
        "description": "App attempted a privileged operation without the required runtime permission.",
    },
    {
        "id": "WORLD_READABLE_FILE_ACCESS",
        "name": "Suspicious File System Access",
        "severity": "MEDIUM",
        "logcat_patterns": [
            r"MODE_WORLD_READABLE",
            r"MODE_WORLD_WRITEABLE",
            r"/sdcard/[^\s]+\.(db|json|xml|key|pem)\b",
            r"/storage/emulated/0/[^\s]+\.(db|json|xml|key|pem)\b",
        ],
        "description": "App accessed world-readable storage or wrote sensitive files to shared storage.",
    },
    {
        "id": "COMMAND_EXECUTION",
        "name": "Command Execution",
        "severity": "HIGH",
        "logcat_patterns": [
            r"Runtime\.exec",
            r"ProcessBuilder.*start",
            r"/system/bin/sh",
            r"su\b.*-c\b",
        ],
        "description": "Application spawned a shell or external process at runtime.",
    },
    {
        "id": "REFLECTIVE_INVOCATION",
        "name": "Reflective Method Invocation",
        "severity": "LOW",
        "logcat_patterns": [
            r"java\.lang\.reflect\.Method\.invoke",
            r"Class\.forName\(",
            r"DexClassLoader",
            r"PathClassLoader.*loadClass",
        ],
        "description": "Application used Java reflection or dynamic class loading at runtime.",
    },
    {
        "id": "SECURITY_EXCEPTION_CRASH",
        "name": "Security-Sensitive Crash",
        "severity": "HIGH",
        "logcat_patterns": [
            r"FATAL EXCEPTION:.*",
            r"java\.lang\.SecurityException(?!:\s*.*permission)",
            r"AndroidRuntime: .*SecurityException",
            r"E/AndroidRuntime: .*FATAL",
        ],
        "description": "App crashed in a security-relevant code path (excluding plain permission denials).",
    },
]


# --------------------------------------------------------------------------
# Integrity guarantees enforced at import time.
# --------------------------------------------------------------------------

# The chapter claim is "10 runtime event categories." Drift fails loud.
assert len(RUNTIME_EVENT_CATEGORIES) == 10, (
    f"RUNTIME_EVENT_CATEGORIES must contain exactly 10 entries, "
    f"found {len(RUNTIME_EVENT_CATEGORIES)}"
)

_ids = [c["id"] for c in RUNTIME_EVENT_CATEGORIES]
assert len(_ids) == len(set(_ids)), "Duplicate category ids in RUNTIME_EVENT_CATEGORIES"

for _c in RUNTIME_EVENT_CATEGORIES:
    assert _c["severity"] in ("HIGH", "MEDIUM", "LOW"), \
        f"{_c['id']}: invalid severity {_c['severity']!r}"
    assert _c["logcat_patterns"], f"{_c['id']}: empty logcat_patterns"
