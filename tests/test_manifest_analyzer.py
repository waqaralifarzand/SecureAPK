"""Phase 2 - Manifest Analyzer tests.

The fixtures here favour mocked PyAXMLParser / aapt / ZIP inputs over real APKs,
because committing binary APKs to the repo is forbidden (see
``tests/fixtures/sample_apks/README.md``). Tests that *can* exercise the
primary parser will use a real APK if one is dropped into that fixtures dir.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from modules import manifest_analyzer
from modules.patterns.permissions import DANGEROUS_PERMISSIONS


SAMPLE_APK_DIR = Path(__file__).parent / "fixtures" / "sample_apks"
ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS_URI)


def _real_apk() -> Path | None:
    """Return a path to a real APK fixture if present, else None."""
    if not SAMPLE_APK_DIR.is_dir():
        return None
    for path in SAMPLE_APK_DIR.iterdir():
        if path.suffix.lower() == ".apk" and path.is_file():
            return path
    return None


# --------------------------------------------------------------------------
# Helpers - build a synthetic in-memory manifest XML that the analyzer's
# PyAXMLParser code path can walk via lxml-like Element access.
# --------------------------------------------------------------------------

def _build_manifest_xml(**overrides):
    """Build a textual AndroidManifest.xml ET tree mirroring what
    pyaxmlparser.get_android_manifest_xml() returns (lxml-compatible Element)."""
    ns = ANDROID_NS_URI
    root = ET.Element("manifest", {"package": overrides.get("package", "com.example.demo")})

    app_attrs = {}
    if overrides.get("debuggable"):
        app_attrs[f"{{{ns}}}debuggable"] = "true"
    if overrides.get("cleartext"):
        app_attrs[f"{{{ns}}}usesCleartextTraffic"] = "true"
    if overrides.get("allow_backup") is False:
        app_attrs[f"{{{ns}}}allowBackup"] = "false"
    if overrides.get("nsc"):
        app_attrs[f"{{{ns}}}networkSecurityConfig"] = "@xml/network_security_config"

    application = ET.SubElement(root, "application", app_attrs)

    for comp in overrides.get("components", []):
        c_attrs = {f"{{{ns}}}name": comp["name"]}
        if "exported" in comp:
            c_attrs[f"{{{ns}}}exported"] = "true" if comp["exported"] else "false"
        if comp.get("permission"):
            c_attrs[f"{{{ns}}}permission"] = comp["permission"]
        element = ET.SubElement(application, comp["type"], c_attrs)
        if comp.get("intent_filter"):
            ET.SubElement(element, "intent-filter")
    return root


class _FakeAPK:
    """A drop-in stand-in for pyaxmlparser.APK for tests."""
    def __init__(self, *, package="com.example.demo", app_name="Demo App",
                 version_name="1.0", version_code=1, target_sdk=33, min_sdk=21,
                 permissions=None, xml=None):
        self._package = package
        self._app_name = app_name
        self._version_name = version_name
        self._version_code = version_code
        self._target = target_sdk
        self._min = min_sdk
        self._perms = list(permissions or [])
        self._xml = xml if xml is not None else _build_manifest_xml()

    # PyAXMLParser API surface used by manifest_analyzer
    def get_android_manifest_xml(self): return self._xml
    def get_package(self): return self._package
    def get_app_name(self): return self._app_name
    def get_androidversion_name(self): return self._version_name
    def get_androidversion_code(self): return self._version_code
    def get_target_sdk_version(self): return self._target
    def get_min_sdk_version(self): return self._min
    def get_permissions(self): return list(self._perms)


@pytest.fixture
def patch_apk(monkeypatch):
    """Return a callable that installs a _FakeAPK as pyaxmlparser.APK."""
    def _install(**kwargs):
        fake = _FakeAPK(**kwargs)
        import pyaxmlparser
        monkeypatch.setattr(pyaxmlparser, "APK", lambda *_a, **_kw: fake)
        return fake
    return _install


# --------------------------------------------------------------------------
# Test 1 - Successful PyAXMLParser parse on a valid APK fixture
# --------------------------------------------------------------------------

def test_pyaxmlparser_parses_valid_apk(patch_apk, tmp_path):
    real = _real_apk()
    if real is not None:
        # Bonus: when a real APK fixture is present, exercise the genuine code path.
        result = manifest_analyzer.analyze(str(real))
        assert result["parser_used"] == "pyaxmlparser", \
            f"Expected primary parser to succeed on real APK, got {result['parser_used']}"
        assert result["package_name"], "Real APK should yield a package_name"
        return

    # Otherwise use the FakeAPK to verify the analyzer's PyAXMLParser code path.
    patch_apk(
        permissions=["android.permission.READ_SMS", "android.permission.INTERNET"],
        xml=_build_manifest_xml(
            components=[{"type": "activity", "name": ".Main", "exported": False}],
            nsc=True,
            allow_backup=False,
        ),
    )
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"not a real apk - APK class is mocked")

    result = manifest_analyzer.analyze(str(apk))

    assert result["parser_used"] == "pyaxmlparser"
    assert result["package_name"] == "com.example.demo"
    assert result["app_name"] == "Demo App"
    assert result["version_name"] == "1.0"
    assert result["target_sdk"] == 33
    assert result["min_sdk"] == 21
    # READ_SMS is dangerous; INTERNET is not in our 37-perm catalog
    dangerous = [p for p in result["permissions"] if p["is_dangerous"]]
    assert len(dangerous) == 1
    assert dangerous[0]["name"] == "android.permission.READ_SMS"
    assert dangerous[0]["severity"] == "HIGH"


# --------------------------------------------------------------------------
# Test 2 - Fallback to aapt when PyAXMLParser fails
# --------------------------------------------------------------------------

def test_falls_back_to_aapt_when_pyaxmlparser_fails(monkeypatch, tmp_path):
    apk = tmp_path / "broken.apk"
    apk.write_bytes(b"definitely not an APK")

    # 1) Force the primary parser to raise.
    def boom(_path):
        raise RuntimeError("simulated PyAXMLParser failure")
    monkeypatch.setattr(manifest_analyzer, "_analyze_with_pyaxmlparser", boom)

    # 2) Pretend `aapt` is on PATH and returns a known badging output.
    monkeypatch.setattr(manifest_analyzer.shutil, "which", lambda _name: "/usr/bin/aapt")
    fake_badging = (
        "package: name='com.test.app' versionCode='42' versionName='2.1'\n"
        "sdkVersion:'21'\n"
        "targetSdkVersion:'33'\n"
        "application-label:'Test App'\n"
        "uses-permission: android:name=\"android.permission.READ_SMS\"\n"
        "uses-permission: android:name=\"android.permission.CAMERA\"\n"
    )
    monkeypatch.setattr(
        manifest_analyzer.subprocess, "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=fake_badging, stderr=""),
    )

    result = manifest_analyzer.analyze(str(apk))

    assert result["parser_used"] == "aapt"
    assert result["package_name"] == "com.test.app"
    assert result["version_name"] == "2.1"
    assert result["target_sdk"] == 33
    perm_names = {p["name"] for p in result["permissions"]}
    assert "android.permission.READ_SMS" in perm_names
    assert "android.permission.CAMERA" in perm_names


# --------------------------------------------------------------------------
# Test 3 - Final fallback to DEX string extraction
# --------------------------------------------------------------------------

def test_falls_back_to_dex_strings_when_aapt_unavailable(monkeypatch, tmp_path):
    # Build a tiny ZIP that looks enough like an APK for string scanning.
    apk = tmp_path / "stringy.apk"
    payload = (
        b"\x00\x00classes.dex synthetic payload\x00"
        b"com.fallback.app\x00\x00"
        b"android.permission.READ_SMS\x00"
        b"android.permission.RECEIVE_SMS\x00"
        b"android.permission.INTERNET\x00"
        b"some other padding string to keep things stable\x00"
    )
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-manifest-stub")
        zf.writestr("classes.dex", payload)

    # Force the first two stages to fail/be absent.
    def boom(_path):
        raise RuntimeError("simulated primary failure")
    monkeypatch.setattr(manifest_analyzer, "_analyze_with_pyaxmlparser", boom)
    monkeypatch.setattr(manifest_analyzer.shutil, "which", lambda _name: None)

    result = manifest_analyzer.analyze(str(apk))

    assert result["parser_used"] == "dex_strings"
    assert result["package_name"] == "com.fallback.app"
    perm_names = {p["name"] for p in result["permissions"]}
    assert "android.permission.READ_SMS" in perm_names
    assert "android.permission.RECEIVE_SMS" in perm_names
    # Dangerous permissions are still flagged in the fallback path
    assert any(p["is_dangerous"] for p in result["permissions"])


# --------------------------------------------------------------------------
# Test 4 - Detection of android:debuggable="true"
# --------------------------------------------------------------------------

def test_detects_debuggable_application(patch_apk, tmp_path):
    patch_apk(
        permissions=[],
        xml=_build_manifest_xml(debuggable=True, nsc=True),
    )
    apk = tmp_path / "debuggable.apk"
    apk.write_bytes(b"unused - APK class is mocked")

    result = manifest_analyzer.analyze(str(apk))

    assert result["insecure_flags"]["debuggable"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "Debuggable Build" in categories
    debug = next(f for f in result["findings"] if f["category"] == "Debuggable Build")
    assert debug["severity"] == "HIGH"
    assert debug["phase"] == 2
    assert debug["owasp_id"] == "M7"


# --------------------------------------------------------------------------
# Test 5 - Detection of an unprotected exported component
# --------------------------------------------------------------------------

def test_detects_unprotected_exported_component(patch_apk, tmp_path):
    patch_apk(
        permissions=[],
        xml=_build_manifest_xml(
            components=[
                {"type": "activity", "name": ".SecretActivity", "exported": True},  # bad
                {"type": "service", "name": ".OkService", "exported": True,
                 "permission": "com.example.SAFE_PERM"},  # good
                {"type": "receiver", "name": ".ImplicitReceiver",
                 "intent_filter": True},  # bad (implicit-export)
            ],
            nsc=True,
        ),
    )
    apk = tmp_path / "exported.apk"
    apk.write_bytes(b"unused")

    result = manifest_analyzer.analyze(str(apk))

    dangerous = [c for c in result["exported_components"] if c["is_dangerous"]]
    dangerous_names = {c["name"] for c in dangerous}
    assert ".SecretActivity" in dangerous_names
    assert ".ImplicitReceiver" in dangerous_names
    assert ".OkService" not in dangerous_names

    exported_findings = [f for f in result["findings"] if f["category"] == "Exported Component"]
    assert len(exported_findings) == 2
    assert all(f["severity"] == "MEDIUM" for f in exported_findings)
    assert all(f["owasp_id"] == "M8" for f in exported_findings)


# --------------------------------------------------------------------------
# Sanity check: the 37-permission claim is preserved.
# Not one of the five required tests, but cheap to assert and catches
# accidental drift of the chapter-cited number.
# --------------------------------------------------------------------------

def test_dangerous_permission_catalog_count():
    assert len(DANGEROUS_PERMISSIONS) >= 37
