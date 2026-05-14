"""Phase 2 — static analysis of AndroidManifest.xml.

Returns a `ManifestAnalysisResult` dict matching the contract in
ARCHITECTURE.md §6. The fallback chain (ARCHITECTURE.md §10) is:

    1. PyAXMLParser (primary)
    2. `aapt dump xmltree`              (Fallback 1)
    3. raw DEX / ZIP string extraction  (Fallback 2 — never raises)

No source-code analysis here (that's Phase 3). No risk scoring (Phase 5).
Findings produced here carry severity values per CLAUDE.md §5 colour
conventions; aggregation happens later.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import uuid
import zipfile
from typing import Any

import config
from modules.patterns.permissions import DANGEROUS_PERMISSIONS

log = logging.getLogger(__name__)


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def analyze(apk_path: str) -> dict[str, Any]:
    """Run the manifest analysis pipeline with fallbacks. Never raises."""
    try:
        result = _analyze_with_pyaxmlparser(apk_path)
        result["parser_used"] = "pyaxmlparser"
        return _finalize(result)
    except Exception as e:  # noqa: BLE001 — fallback path is by design
        log.warning("PyAXMLParser failed for %s: %s", apk_path, e)

    try:
        result = _analyze_with_aapt(apk_path)
        result["parser_used"] = "aapt"
        return _finalize(result)
    except Exception as e:  # noqa: BLE001
        log.warning("aapt fallback failed for %s: %s", apk_path, e)

    result = _analyze_with_dex_strings(apk_path)
    result["parser_used"] = "dex_strings"
    return _finalize(result)


# --------------------------------------------------------------------------
# Primary: PyAXMLParser
# --------------------------------------------------------------------------

def _analyze_with_pyaxmlparser(apk_path: str) -> dict[str, Any]:
    from pyaxmlparser import APK  # local import — keeps fallback path importable when missing

    apk = APK(apk_path)
    xml = apk.get_android_manifest_xml()
    if xml is None:
        raise RuntimeError("AndroidManifest.xml not present in APK")

    package_name = apk.get_package() or None
    app_name = apk.get_app_name() or None
    version_name = apk.get_androidversion_name() or None
    try:
        version_code = int(apk.get_androidversion_code() or 0) or None
    except (TypeError, ValueError):
        version_code = None
    target_sdk = _int_or_none(apk.get_target_sdk_version())
    min_sdk = _int_or_none(apk.get_min_sdk_version())

    # Insecure flags from <application> attributes
    app_el = xml.find("application")
    if app_el is None:
        insecure_flags = {
            "uses_cleartext_traffic": False,
            "debuggable": False,
            "allow_backup": True,  # default on Android is True
            "network_security_config": None,
        }
    else:
        insecure_flags = {
            "uses_cleartext_traffic": _bool_attr(app_el, "usesCleartextTraffic", default=False),
            "debuggable": _bool_attr(app_el, "debuggable", default=False),
            "allow_backup": _bool_attr(app_el, "allowBackup", default=True),
            "network_security_config": app_el.get(f"{ANDROID_NS}networkSecurityConfig"),
        }

    requested = apk.get_permissions() or []
    permissions = _build_permissions(requested)

    components = []
    for tag, ctype in (("activity", "activity"), ("service", "service"),
                       ("receiver", "receiver"), ("provider", "provider")):
        for el in xml.iter(tag):
            components.append(_component_from_element(el, ctype))

    return {
        "package_name": package_name,
        "app_name": app_name,
        "version_name": version_name,
        "version_code": version_code,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "insecure_flags": insecure_flags,
        "permissions": permissions,
        "exported_components": components,
        "findings": [],  # filled by _finalize
    }


def _component_from_element(el, ctype: str) -> dict[str, Any]:
    name = el.get(f"{ANDROID_NS}name") or "<unnamed>"
    permission_attr = el.get(f"{ANDROID_NS}permission")
    exported_raw = el.get(f"{ANDROID_NS}exported")
    has_intent_filter = el.find("intent-filter") is not None

    if exported_raw is not None:
        exported = exported_raw.strip().lower() == "true"
    else:
        # Android default: exported=true if an intent-filter is declared,
        # exported=false otherwise. From API 31+ the attribute is required when
        # an intent-filter is present; we approximate the legacy default.
        exported = has_intent_filter

    is_protected = bool(permission_attr)
    is_dangerous = exported and not is_protected
    return {
        "type": ctype,
        "name": name,
        "exported": exported,
        "is_protected": is_protected,
        "permission_attr": permission_attr,
        "is_dangerous": is_dangerous,
    }


def _bool_attr(el, local: str, default: bool) -> bool:
    raw = el.get(f"{ANDROID_NS}{local}")
    if raw is None:
        return default
    return str(raw).strip().lower() == "true"


def _int_or_none(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Fallback 1: aapt dump xmltree
# --------------------------------------------------------------------------

_AAPT_PERM_RE = re.compile(r"uses-permission[^\n]*?android:name[^=]*=['\"]([^'\"]+)['\"]")
_AAPT_PKG_RE = re.compile(r"package(?:\s*:\s*)?name=['\"]([^'\"]+)['\"]|package=['\"]([^'\"]+)['\"]")
_AAPT_VNAME_RE = re.compile(r"versionName=['\"]([^'\"]+)['\"]")
_AAPT_VCODE_RE = re.compile(r"versionCode=['\"]?(\d+)")
_AAPT_TARGET_RE = re.compile(r"targetSdkVersion[^0-9]+(\d+)")
_AAPT_MIN_RE = re.compile(r"(?<!target)sdkVersion[^0-9]+(\d+)")


def _analyze_with_aapt(apk_path: str) -> dict[str, Any]:
    aapt = config.AAPT_PATH or "aapt"
    if shutil.which(aapt) is None:
        raise RuntimeError("aapt binary not on PATH")
    proc = subprocess.run(
        [aapt, "dump", "badging", apk_path],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"aapt failed: {proc.stderr.strip()[:200]}")
    text = proc.stdout

    pkg_match = _AAPT_PKG_RE.search(text)
    package_name = (pkg_match.group(1) or pkg_match.group(2)) if pkg_match else None
    version_name = _first(_AAPT_VNAME_RE, text)
    version_code = _int_or_none(_first(_AAPT_VCODE_RE, text))
    target_sdk = _int_or_none(_first(_AAPT_TARGET_RE, text))
    min_sdk = _int_or_none(_first(_AAPT_MIN_RE, text))
    app_name = None
    # application-label-default or application-label
    label_match = re.search(r"application-label(?:-\w+)?:'([^']+)'", text)
    if label_match:
        app_name = label_match.group(1)

    requested = _AAPT_PERM_RE.findall(text)
    permissions = _build_permissions(requested)

    # aapt badging does not enumerate components reliably. Mark as empty —
    # the insecure-flags / components sections will be sparse but truthful.
    return {
        "package_name": package_name,
        "app_name": app_name,
        "version_name": version_name,
        "version_code": version_code,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "insecure_flags": {
            "uses_cleartext_traffic": False,
            "debuggable": False,
            "allow_backup": True,
            "network_security_config": None,
        },
        "permissions": permissions,
        "exported_components": [],
        "findings": [],
    }


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Fallback 2: raw string extraction from the APK ZIP (last-resort, never raises)
# --------------------------------------------------------------------------

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
_PERM_NAME_RE = re.compile(r"android\.permission\.[A-Z_0-9]+")
_PACKAGE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,5}$")


def _analyze_with_dex_strings(apk_path: str) -> dict[str, Any]:
    strings: list[str] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            # Read manifest binary + DEX files; collect printable strings.
            targets = [n for n in zf.namelist()
                       if n == "AndroidManifest.xml" or n.startswith("classes")]
            for name in targets:
                try:
                    blob = zf.read(name)
                except (KeyError, zipfile.BadZipFile):
                    continue
                for chunk in _PRINTABLE_RE.findall(blob):
                    try:
                        strings.append(chunk.decode("ascii"))
                    except UnicodeDecodeError:
                        continue
    except (zipfile.BadZipFile, OSError) as e:
        log.error("dex_strings fallback could not open APK %s: %s", apk_path, e)

    perm_set: set[str] = set()
    pkg_candidates: list[str] = []
    for s in strings:
        for p in _PERM_NAME_RE.findall(s):
            perm_set.add(p)
        if "." in s and _PACKAGE_NAME_RE.match(s):
            pkg_candidates.append(s)

    # Pick the shortest plausible package name (heuristic — fewer dots usually
    # = the real app package, not a class FQCN).
    package_name = min(pkg_candidates, key=len) if pkg_candidates else None
    permissions = _build_permissions(sorted(perm_set))

    return {
        "package_name": package_name,
        "app_name": None,
        "version_name": None,
        "version_code": None,
        "target_sdk": None,
        "min_sdk": None,
        "insecure_flags": {
            "uses_cleartext_traffic": False,
            "debuggable": False,
            "allow_backup": True,
            "network_security_config": None,
        },
        "permissions": permissions,
        "exported_components": [],
        "findings": [],
    }


# --------------------------------------------------------------------------
# Shared post-processing: permissions + findings
# --------------------------------------------------------------------------

def _build_permissions(requested: list[str]) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for raw in requested:
        name = (raw or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        meta = DANGEROUS_PERMISSIONS.get(name)
        if meta:
            out.append({
                "name": name,
                "is_dangerous": True,
                "severity": meta["severity"],
                "description": meta["description"],
                "owasp_id": meta.get("owasp_id"),
                "cwe_id": meta.get("cwe_id"),
            })
        else:
            out.append({
                "name": name,
                "is_dangerous": False,
                "severity": None,
                "description": None,
                "owasp_id": None,
                "cwe_id": None,
            })
    return out


def _finalize(result: dict[str, Any]) -> dict[str, Any]:
    """Derive findings from the parsed structure."""
    findings: list[dict[str, Any]] = []

    # Dangerous permissions
    for perm in result["permissions"]:
        if not perm["is_dangerous"]:
            continue
        findings.append(_finding(
            category="Dangerous Permission",
            severity=perm["severity"],
            title=f"Dangerous permission declared: {perm['name'].split('.')[-1]}",
            description=perm["description"] or "Dangerous permission requested.",
            owasp_id=perm["owasp_id"],
            cwe_id=perm["cwe_id"],
            pattern_id=f"PERM_{perm['name'].split('.')[-1]}",
        ))

    # Insecure flags
    flags = result["insecure_flags"]
    if flags.get("debuggable"):
        findings.append(_finding(
            category="Debuggable Build",
            severity="HIGH",
            title="Application is debuggable",
            description=("android:debuggable=\"true\" was found on the <application> tag. "
                         "Debuggable builds expose internal state via JDWP and must never "
                         "ship to production."),
            owasp_id="M7",
            cwe_id="CWE-489",
            pattern_id="MANIFEST_DEBUGGABLE_TRUE",
        ))
    if flags.get("uses_cleartext_traffic"):
        findings.append(_finding(
            category="Cleartext Traffic",
            severity="HIGH",
            title="Cleartext (HTTP) traffic allowed",
            description=("android:usesCleartextTraffic=\"true\" permits unencrypted HTTP "
                         "communication. All network traffic should be TLS."),
            owasp_id="M5",
            cwe_id="CWE-319",
            pattern_id="MANIFEST_CLEARTEXT_TRAFFIC",
        ))
    if flags.get("allow_backup"):
        findings.append(_finding(
            category="Backup Allowed",
            severity="MEDIUM",
            title="Application data is backup-enabled",
            description=("android:allowBackup is true (or defaulted to true). adb backup "
                         "can extract app data, including sensitive files, off the device."),
            owasp_id="M9",
            cwe_id="CWE-530",
            pattern_id="MANIFEST_ALLOW_BACKUP",
        ))
    if not flags.get("network_security_config"):
        findings.append(_finding(
            category="Missing Network Security Config",
            severity="LOW",
            title="No networkSecurityConfig declared",
            description=("The application does not declare a networkSecurityConfig. "
                         "Without one, certificate pinning and per-domain cleartext rules "
                         "cannot be enforced."),
            owasp_id="M5",
            cwe_id="CWE-319",
            pattern_id="MANIFEST_NO_NSC",
        ))

    # Exported components without permission protection
    for comp in result["exported_components"]:
        if not comp.get("is_dangerous"):
            continue
        findings.append(_finding(
            category="Exported Component",
            severity="MEDIUM",
            title=f"Exported {comp['type']} is not permission-protected",
            description=(f"{comp['type'].capitalize()} '{comp['name']}' is exported "
                         "(or has an implicit intent-filter) without an android:permission "
                         "attribute. Any other app on the device can invoke it."),
            owasp_id="M8",
            cwe_id="CWE-926",
            pattern_id=f"MANIFEST_EXPORTED_{comp['type'].upper()}",
        ))

    result["findings"] = findings
    return result


def _finding(*, category: str, severity: str, title: str, description: str,
             owasp_id: str | None, cwe_id: str | None, pattern_id: str) -> dict[str, Any]:
    return {
        "id": uuid.uuid4().hex,
        "phase": 2,
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "file_location": "AndroidManifest.xml",
        "line_number": None,
        "code_snippet": None,
        "owasp_id": owasp_id,
        "cwe_id": cwe_id,
        "pattern_id": pattern_id,
    }
