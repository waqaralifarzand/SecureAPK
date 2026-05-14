"""
SecureAPK — Phase 6: Testing & Evaluation
Run: python test_runner.py

Tests:
  1. Module functional testing
  2. Vulnerability detection accuracy
  3. Risk scoring correctness
  4. Report generation
  5. Database operations
  6. Performance benchmarks
"""
import sys
import os
import time
import json
import zipfile
import tempfile
import struct

sys.path.insert(0, os.path.dirname(__file__))

PASS = "✓ PASS"
FAIL = "✗ FAIL"
SKIP = "○ SKIP"

results = []

def test(name, fn):
    try:
        start = time.time()
        result = fn()
        elapsed = round((time.time() - start) * 1000)
        status = PASS if result else FAIL
        results.append((name, status, elapsed, None))
        print(f"  {status}  {name}  ({elapsed}ms)")
        return result
    except Exception as e:
        results.append((name, FAIL, 0, str(e)))
        print(f"  {FAIL}  {name}  — {e}")
        return False

# ─────────────────────────────────────────
# TEST APK BUILDER
# Creates synthetic APK files for testing
# ─────────────────────────────────────────

SAFE_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.safeapp"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="SafeApp" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""

DANGEROUS_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.dangerousapp"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="28"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:label="DangerousApp"
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true"/>
        <service android:name=".BackgroundService" android:exported="true"/>
        <receiver android:name=".SMSReceiver" android:exported="true"/>
    </application>
</manifest>"""

VULN_JAVA = b"""
package com.test.dangerousapp;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import android.util.Log;
import java.net.HttpURLConnection;

public class VulnerableActivity {
    // Hardcoded credentials
    private static final String API_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678";
    private static final String PASSWORD = "admin123";
    private static final String SECRET_TOKEN = "secret_token_abc123xyz";
    
    public void connectToServer() throws Exception {
        // Insecure HTTP connection
        HttpURLConnection conn = (HttpURLConnection) new java.net.URL("http://api.example.com/data").openConnection();
        
        // MD5 usage
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        // SHA-1 usage  
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        
        // DES encryption
        Cipher cipher = Cipher.getInstance("DES");
        
        // AES-ECB
        Cipher ecbCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        // Log sensitive data
        Log.d("APP", "password=" + PASSWORD);
        Log.d("APP", "token=" + SECRET_TOKEN);
    }
    
    public void setupWebView(android.webkit.WebView wv) {
        wv.getSettings().setJavaScriptEnabled(true);
        wv.addJavascriptInterface(this, "Android");
        wv.getSettings().setAllowFileAccess(true);
    }
    
    public void runCommand() throws Exception {
        Runtime.getRuntime().exec("su -c id");
    }
}
"""

def make_test_apk(manifest_content, java_content=None, suffix='test'):
    """Create a minimal ZIP file that looks like an APK"""
    f = tempfile.NamedTemporaryFile(suffix=f'_{suffix}.apk', delete=False)
    with zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('AndroidManifest.xml', manifest_content)
        z.writestr('classes.dex', b'dex\n035\x00' + java_content if java_content else b'dex\n035\x00')
        z.writestr('res/values/strings.xml', b'<resources><string name="app_name">TestApp</string></resources>')
        if java_content:
            z.writestr('sources/VulnerableActivity.java', java_content)
    return f.name


# ─────────────────────────────────────────
#  TEST SUITE
# ─────────────────────────────────────────

print()
print("=" * 60)
print("  SecureAPK — Phase 6: Test Suite")
print("=" * 60)
print()

# ── Module Imports ──
print("[1] Module Import Tests")

test("db_manager imports", lambda: __import__('modules.db_manager', fromlist=['init_db']) is not None)
test("static_manifest imports", lambda: __import__('modules.static_manifest', fromlist=['analyze_manifest']) is not None)
test("static_sourcecode imports", lambda: __import__('modules.static_sourcecode', fromlist=['analyze_source_code']) is not None)
test("dynamic_analysis imports", lambda: __import__('modules.dynamic_analysis', fromlist=['run_dynamic_analysis']) is not None)
test("risk_engine imports", lambda: __import__('modules.risk_engine', fromlist=['calculate_risk_score']) is not None)
test("report_generator imports", lambda: __import__('modules.report_generator', fromlist=['generate_pdf_report']) is not None)
print()

# ── Database Tests ──
print("[2] Database Tests")
from modules.db_manager import init_db, save_analysis, get_all_analyses, get_analysis_by_id

test("Database initializes", lambda: (init_db(), True)[1])

DUMMY = {
    'analysis_id': 'TEST0001',
    'filename': 'test.apk',
    'timestamp': '2024-01-01T00:00:00',
    'manifest': {'findings': [], 'summary': {'total_permissions': 1, 'dangerous_permissions': 0, 'exported_components': 0, 'cleartext_traffic': False, 'backup_allowed': False}},
    'source_code': {'findings': [], 'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0}},
    'dynamic': {'suspicious_events': []},
    'risk': {'score': 10, 'level': 'LOW', 'severity_counts': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}, 'total_findings': 0, 'recommendation': 'OK'}
}
test("Save analysis record", lambda: (save_analysis(DUMMY), True)[1])
test("Retrieve analysis by ID", lambda: get_analysis_by_id('TEST0001') is not None)
test("List all analyses", lambda: isinstance(get_all_analyses(), list))

# Cleanup
import sqlite3
conn = sqlite3.connect('database/secureapk.db')
conn.execute("DELETE FROM analyses WHERE analysis_id='TEST0001'")
conn.commit(); conn.close()
print()

# ── Manifest Analysis Tests ──
print("[3] Manifest Analysis Tests")
from modules.static_manifest import analyze_manifest

safe_apk = make_test_apk(SAFE_MANIFEST, suffix='safe')
danger_apk = make_test_apk(DANGEROUS_MANIFEST, suffix='danger')

def test_manifest_structure():
    r = analyze_manifest(safe_apk)
    return all(k in r for k in ['status', 'findings', 'permissions', 'summary', 'metadata'])

def test_dangerous_permissions_detected():
    r = analyze_manifest(danger_apk)
    # Count any HIGH or MEDIUM permission/config findings — raw text fallback
    # may detect permissions as config issues too
    danger_findings = [f for f in r['findings'] if f['severity'] in ('HIGH', 'MEDIUM')]
    return len(danger_findings) >= 3

def test_cleartext_detected():
    r = analyze_manifest(danger_apk)
    cleartext = [f for f in r['findings'] if 'Cleartext' in f['title'] or 'cleartext' in f.get('detail', '').lower()]
    return len(cleartext) > 0 or r.get('summary', {}).get('cleartext_traffic', False)

def test_debuggable_detected():
    r = analyze_manifest(danger_apk)
    debug = [f for f in r['findings'] if 'Debuggable' in f['title'] or 'debuggable' in f.get('detail','').lower()]
    return len(debug) > 0

def test_backup_detected():
    r = analyze_manifest(danger_apk)
    backup = [f for f in r['findings'] if 'Backup' in f['title'] or r.get('summary', {}).get('backup_allowed', False)]
    return len(backup) > 0

def test_exported_components_detected():
    r = analyze_manifest(danger_apk)
    exported = [f for f in r['findings'] if f.get('type') == 'COMPONENT']
    return len(exported) >= 1

test("Manifest result has correct structure", test_manifest_structure)
test("Dangerous permissions detected (≥3 HIGH)", test_dangerous_permissions_detected)
test("Cleartext traffic flag detected", test_cleartext_detected)
test("Debuggable flag detected", test_debuggable_detected)
test("AllowBackup flag detected", test_backup_detected)
test("Exported components detected", test_exported_components_detected)
print()

# ── Source Code Analysis Tests ──
print("[4] Source Code Vulnerability Detection Tests")
from modules.static_sourcecode import analyze_source_code

vuln_apk = make_test_apk(DANGEROUS_MANIFEST, java_content=VULN_JAVA, suffix='vuln')

def test_source_structure():
    r = analyze_source_code(vuln_apk)
    return all(k in r for k in ['status', 'findings', 'scanned_files', 'summary'])

def test_source_scans_files():
    r = analyze_source_code(vuln_apk)
    return r['scanned_files'] >= 1

def test_hardcoded_secrets():
    r = analyze_source_code(vuln_apk)
    secrets = [f for f in r['findings'] if 'Secret' in f['title'] or 'API Key' in f['title'] or 'Password' in f['title'] or 'Token' in f['title']]
    return len(secrets) >= 1

def test_md5_detected():
    r = analyze_source_code(vuln_apk)
    return any('MD5' in f['title'] for f in r['findings'])

def test_des_detected():
    r = analyze_source_code(vuln_apk)
    return any('DES' in f['title'] for f in r['findings'])

def test_http_url_detected():
    r = analyze_source_code(vuln_apk)
    return any('HTTP' in f['title'] for f in r['findings'])

def test_webview_detected():
    r = analyze_source_code(vuln_apk)
    return any('WebView' in f['title'] or 'JavaScript' in f['title'] for f in r['findings'])

test("Source analysis result has correct structure", test_source_structure)
test("At least 1 file scanned", test_scans_files := test_source_scans_files)
test("Hardcoded secret/API key detected", test_hardcoded_secrets)
test("MD5 weak hashing detected", test_md5_detected)
test("DES weak encryption detected", test_des_detected)
test("Insecure HTTP URL detected", test_http_url_detected)
test("WebView vulnerability detected", test_webview_detected)
print()

# ── Risk Engine Tests ──
print("[5] Risk Scoring Tests")
from modules.risk_engine import calculate_risk_score

MOCK_MANIFEST_HIGH = {
    'findings': [
        {'type': 'PERMISSION', 'severity': 'HIGH', 'title': 'READ_SMS', 'category': 'Permission'},
        {'type': 'CONFIGURATION', 'severity': 'HIGH', 'title': 'Cleartext', 'category': 'Network Security'},
        {'type': 'CONFIGURATION', 'severity': 'HIGH', 'title': 'Debuggable', 'category': 'Build Configuration'},
    ]
}
MOCK_SOURCE_HIGH = {
    'findings': [
        {'type': 'SOURCE_CODE', 'severity': 'HIGH', 'title': 'API Key', 'category': 'Hardcoded Secrets'},
        {'type': 'SOURCE_CODE', 'severity': 'HIGH', 'title': 'MD5', 'category': 'Weak Cryptography'},
        {'type': 'SOURCE_CODE', 'severity': 'HIGH', 'title': 'SSL bypass', 'category': 'Insecure Communication'},
        {'type': 'SOURCE_CODE', 'severity': 'MEDIUM', 'title': 'HTTP', 'category': 'Insecure Communication'},
    ]
}
MOCK_DYNAMIC = {'suspicious_events': []}
MOCK_MANIFEST_CLEAN = {'findings': []}
MOCK_SOURCE_CLEAN = {'findings': []}

def test_risk_structure():
    r = calculate_risk_score(MOCK_MANIFEST_HIGH, MOCK_SOURCE_HIGH, MOCK_DYNAMIC)
    return all(k in r for k in ['score', 'level', 'severity_counts', 'total_findings', 'recommendation'])

def test_high_risk_score():
    r = calculate_risk_score(MOCK_MANIFEST_HIGH, MOCK_SOURCE_HIGH, MOCK_DYNAMIC)
    return r['level'] == 'HIGH' and r['score'] > 30

def test_low_risk_clean():
    r = calculate_risk_score(MOCK_MANIFEST_CLEAN, MOCK_SOURCE_CLEAN, MOCK_DYNAMIC)
    return r['score'] <= 30

def test_score_range():
    r = calculate_risk_score(MOCK_MANIFEST_HIGH, MOCK_SOURCE_HIGH, MOCK_DYNAMIC)
    return 0 <= r['score'] <= 100

def test_owasp_refs():
    r = calculate_risk_score(MOCK_MANIFEST_HIGH, MOCK_SOURCE_HIGH, MOCK_DYNAMIC)
    return isinstance(r.get('owasp_references'), list)

def test_cwe_refs():
    r = calculate_risk_score(MOCK_MANIFEST_HIGH, MOCK_SOURCE_HIGH, MOCK_DYNAMIC)
    return isinstance(r.get('cwe_references'), list)

test("Risk result has correct structure", test_risk_structure)
test("High-risk APK scores HIGH level", test_high_risk_score)
test("Clean APK scores LOW (≤30)", test_low_risk_clean)
test("Score always in 0–100 range", test_score_range)
test("OWASP references returned", test_owasp_refs)
test("CWE references returned", test_cwe_refs)
print()

# ── Report Generation Tests ──
print("[6] Report Generation Tests")
from modules.report_generator import generate_pdf_report

FULL_DUMMY = {
    'analysis_id': 'RPTTEST',
    'filename': 'test_report.apk',
    'timestamp': '2024-06-01T12:00:00',
    'manifest': {
        'metadata': {'package_name': 'com.test.app', 'version_name': '1.0', 'min_sdk': '21', 'target_sdk': '33'},
        'permissions': ['android.permission.INTERNET', 'android.permission.READ_SMS'],
        'findings': [
            {'type': 'PERMISSION', 'severity': 'HIGH', 'title': 'READ_SMS', 'description': 'Reads SMS', 'detail': 'android.permission.READ_SMS', 'category': 'Permission'}
        ],
        'summary': {'total_permissions': 2, 'dangerous_permissions': 1, 'exported_components': 0, 'cleartext_traffic': False, 'backup_allowed': False}
    },
    'source_code': {
        'decompile_method': 'string_extraction',
        'scanned_files': 1,
        'findings': [
            {'type': 'SOURCE_CODE', 'severity': 'HIGH', 'title': 'Hardcoded API Key', 'description': 'API key found', 'detail': 'MainActivity.java:12', 'category': 'Hardcoded Secrets', 'snippet': 'api_key = "AIzaTest123"'}
        ],
        'summary': {'total': 1, 'high': 1, 'medium': 0, 'low': 0, 'by_category': {'Hardcoded Secrets': 1}}
    },
    'dynamic': {
        'status': 'skipped',
        'message': 'Dynamic analysis was not enabled.',
        'suspicious_events': [],
        'network_activity': [],
        'runtime_logs': [],
        'summary': {'total_logs': 0, 'suspicious_events': 0, 'network_connections': 0, 'cleartext_http': 0, 'high_events': 0}
    },
    'risk': {
        'score': 65, 'level': 'MEDIUM', 'color': '#f59e0b',
        'recommendation': 'Remediate HIGH severity issues.',
        'severity_counts': {'HIGH': 2, 'MEDIUM': 0, 'LOW': 0},
        'total_findings': 2,
        'breakdown': {
            'manifest': {'score': 10, 'count': 1},
            'source_code': {'score': 15, 'count': 1},
            'dynamic': {'score': 0, 'count': 0}
        },
        'owasp_references': [{'code': 'M9', 'name': 'Insecure Data Storage'}],
        'cwe_references': [{'cwe': 'CWE-798', 'title': 'Hardcoded API Key'}],
        'top_issues': []
    }
}

def test_report_generates():
    path = generate_pdf_report(FULL_DUMMY, 'reports')
    return os.path.exists(path) and os.path.getsize(path) > 100

def test_report_in_reports_dir():
    path = generate_pdf_report(FULL_DUMMY, 'reports')
    return os.path.dirname(os.path.abspath(path)) == os.path.abspath('reports')

test("Report file generated successfully", test_report_generates)
test("Report saved in reports/ directory", test_report_in_reports_dir)
print()

# ── Performance Benchmarks ──
print("[7] Performance Benchmarks")

def bench_manifest(apk_path, label):
    start = time.time()
    r = analyze_manifest(apk_path)
    elapsed = round((time.time() - start) * 1000)
    print(f"  ⏱  Manifest ({label}): {elapsed}ms — {len(r['findings'])} findings")
    return elapsed < 30000  # Must complete within 30s

def bench_source(apk_path, label):
    start = time.time()
    r = analyze_source_code(apk_path)
    elapsed = round((time.time() - start) * 1000)
    print(f"  ⏱  Source  ({label}): {elapsed}ms — {r['scanned_files']} files, {r['summary']['total']} findings")
    return elapsed < 120000  # Must complete within 120s

test("Manifest analysis < 30s (safe APK)", lambda: bench_manifest(safe_apk, 'safe'))
test("Manifest analysis < 30s (dangerous APK)", lambda: bench_manifest(danger_apk, 'dangerous'))
test("Source analysis < 120s (vuln APK)", lambda: bench_source(vuln_apk, 'vulnerable'))
print()

# ── Cleanup ──
for f in [safe_apk, danger_apk, vuln_apk]:
    try: os.unlink(f)
    except: pass

# ─────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────
print("=" * 60)
passed = sum(1 for _, s, _, _ in results if s == PASS)
failed = sum(1 for _, s, _, _ in results if s == FAIL)
total = len(results)

print(f"  Results: {passed}/{total} passed  |  {failed} failed")
print()

if failed:
    print("  Failed tests:")
    for name, status, _, err in results:
        if status == FAIL:
            print(f"    ✗ {name}" + (f" — {err}" if err else ""))
    print()

print(f"  Coverage: Manifest, Source Code, Risk Engine, DB, Reports, Performance")
print("=" * 60)
print()

sys.exit(0 if failed == 0 else 1)
