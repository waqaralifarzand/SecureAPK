"""
Phase 3: Static Analysis - Source Code Vulnerability Detection
Uses Jadx to decompile APK and scans for vulnerability patterns
"""
import os
import re
import subprocess
import tempfile
import zipfile
import shutil

# ──────────────────────────────────────────────────────────────────
#  VULNERABILITY PATTERNS
#  Each entry: (pattern, severity, title, description, category)
# ──────────────────────────────────────────────────────────────────
VULN_PATTERNS = [
    # ── Hardcoded Secrets ──
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
     'HIGH', 'Hardcoded Password',
     'Hardcoded credential found in source code. Attackers can extract this via decompilation.',
     'Hardcoded Secrets'),

    (r'(?i)(api_key|apikey|api_secret|secret_key|secretkey)\s*=\s*["\'][^"\']{6,}["\']',
     'HIGH', 'Hardcoded API Key / Secret',
     'Hardcoded API key or secret detected. This exposes backend services to unauthorized access.',
     'Hardcoded Secrets'),

    (r'(?i)(token|auth_token|access_token|bearer)\s*=\s*["\'][^"\']{6,}["\']',
     'HIGH', 'Hardcoded Token',
     'Hardcoded authentication token found. Should be stored securely using Android Keystore.',
     'Hardcoded Secrets'),

    (r'(?i)(private_key|rsa_key|ssh_key)\s*=\s*["\'][^"\']{10,}["\']',
     'HIGH', 'Hardcoded Private Key',
     'Private cryptographic key hardcoded in source. Critical security violation.',
     'Hardcoded Secrets'),

    (r'AIza[0-9A-Za-z\-_]{35}',
     'HIGH', 'Google API Key Exposed',
     'Google API key pattern detected. This key may grant access to paid Google services.',
     'Hardcoded Secrets'),

    (r'AAAA[a-zA-Z0-9_-]{140,}',
     'MEDIUM', 'Firebase Server Key Pattern',
     'Possible Firebase Cloud Messaging server key detected.',
     'Hardcoded Secrets'),

    # ── Insecure Network ──
    (r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.)[a-zA-Z0-9]',
     'HIGH', 'Insecure HTTP URL (Non-local)',
     'Unencrypted HTTP connection to a remote server. Vulnerable to Man-in-the-Middle attacks.',
     'Insecure Communication'),

    (r'HttpURLConnection|HttpClient|OkHttpClient',
     'LOW', 'HTTP Client Usage',
     'HTTP client detected. Verify that all connections use HTTPS and certificate validation is not bypassed.',
     'Insecure Communication'),

    (r'(?i)setHostnameVerifier\s*\([^)]*ALLOW_ALL|ALLOW_ALL_HOSTNAME_VERIFIER',
     'HIGH', 'Hostname Verification Disabled',
     'ALLOW_ALL_HOSTNAME_VERIFIER disables hostname verification, making SSL/TLS ineffective.',
     'Insecure Communication'),

    (r'(?i)trustAllCerts|X509TrustManager|checkServerTrusted\s*\(\s*\)',
     'HIGH', 'SSL Certificate Validation Bypassed',
     'Custom TrustManager may accept all certificates including self-signed/invalid ones.',
     'Insecure Communication'),

    (r'SSLContext\.getInstance\s*\(\s*["\']SSL["\']',
     'MEDIUM', 'Deprecated SSL Protocol Used',
     'SSLv3 is deprecated and vulnerable to POODLE attack. Use TLS 1.2 or higher.',
     'Insecure Communication'),

    # ── Weak Cryptography ──
    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
     'HIGH', 'MD5 Hashing Used',
     'MD5 is cryptographically broken. Use SHA-256 or SHA-3 for integrity checks.',
     'Weak Cryptography'),

    (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
     'MEDIUM', 'SHA-1 Hashing Used',
     'SHA-1 is deprecated and collision-vulnerable. Migrate to SHA-256 or higher.',
     'Weak Cryptography'),

    (r'Cipher\.getInstance\s*\(\s*["\']DES',
     'HIGH', 'DES Encryption Used',
     'DES is a 56-bit cipher, easily brute-forced. Replace with AES-256.',
     'Weak Cryptography'),

    (r'Cipher\.getInstance\s*\(\s*["\']AES/ECB',
     'HIGH', 'AES-ECB Mode Used',
     'ECB mode produces identical ciphertext for identical plaintext blocks, leaking patterns.',
     'Weak Cryptography'),

    (r'Cipher\.getInstance\s*\(\s*["\']AES["\'](?!\s*/\s*(CBC|GCM|CTR))',
     'MEDIUM', 'AES Without Explicit Mode/Padding',
     'AES without specifying mode defaults to ECB in some JVM implementations.',
     'Weak Cryptography'),

    (r'SecureRandom\s*\(\s*\)\.setSeed|new\s+Random\s*\(',
     'MEDIUM', 'Insecure Pseudo-Random Number Generator',
     'java.util.Random is not cryptographically secure. Use SecureRandom for security-sensitive values.',
     'Weak Cryptography'),

    (r'(?i)rc4|arcfour|blowfish',
     'HIGH', 'Deprecated Cipher Algorithm',
     'RC4/Blowfish are deprecated ciphers with known vulnerabilities. Use AES-256-GCM.',
     'Weak Cryptography'),

    # ── Data Storage ──
    (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
     'HIGH', 'World-Readable/Writable File Mode',
     'Files created with WORLD_READABLE/WRITEABLE can be accessed by any app on the device.',
     'Insecure Data Storage'),

    (r'getSharedPreferences|SharedPreferences',
     'LOW', 'SharedPreferences Usage',
     'SharedPreferences stores data in plaintext XML. Verify no sensitive data (passwords/tokens) is stored here.',
     'Insecure Data Storage'),

    (r'(?i)openFileOutput\s*\([^,]+,\s*0\)',
     'MEDIUM', 'File Created in Private Mode — Verify Content',
     'Private file creation detected. Ensure no sensitive unencrypted data is written.',
     'Insecure Data Storage'),

    (r'SQLiteDatabase|openOrCreateDatabase',
     'LOW', 'SQLite Database Usage',
     'SQLite database detected. Verify sensitive data is encrypted (e.g., via SQLCipher).',
     'Insecure Data Storage'),

    (r'(?i)Log\.(d|v|i|e|w)\s*\([^,]*,\s*[^)]*(?:password|token|key|secret|pin|card)',
     'HIGH', 'Sensitive Data Logged',
     'Sensitive information (password/token/key) may be written to Android logs readable by other apps.',
     'Information Leakage'),

    # ── Intent / IPC ──
    (r'sendBroadcast\s*\(|sendOrderedBroadcast',
     'LOW', 'Implicit Broadcast Usage',
     'Unprotected broadcasts can be intercepted by any app. Use explicit intents or permissions.',
     'IPC Security'),

    (r'startActivity\s*\(|startActivityForResult',
     'LOW', 'Activity Launch Detected',
     'Verify that Activity launches do not expose sensitive data through extras.',
     'IPC Security'),

    (r'PendingIntent\.getActivity|PendingIntent\.getService',
     'MEDIUM', 'Mutable PendingIntent',
     'PendingIntent without FLAG_IMMUTABLE can be hijacked by malicious apps on Android <12.',
     'IPC Security'),

    # ── Root / Emulator Detection bypass ──
    (r'(?i)isRooted|checkRoot|detectRoot|RootBeer',
     'LOW', 'Root Detection Code Found',
     'Root detection implemented. Ensure it is not trivially bypassable.',
     'Tampering & Reverse Engineering'),

    (r'(?i)Runtime\.getRuntime\(\)\.exec',
     'HIGH', 'Runtime Command Execution',
     'Dynamic command execution via Runtime.exec(). Can be abused for command injection.',
     'Code Execution'),

    # ── JavaScript / WebView ──
    (r'setJavaScriptEnabled\s*\(\s*true\s*\)',
     'MEDIUM', 'JavaScript Enabled in WebView',
     'JavaScript execution in WebView. If loading untrusted URLs, this enables XSS attacks.',
     'WebView Security'),

    (r'addJavascriptInterface',
     'HIGH', 'JavaScript Interface Added to WebView',
     'addJavascriptInterface bridges Java and JS. Exploitable via XSS on Android < 4.2 (API 17).',
     'WebView Security'),

    (r'setAllowFileAccess\s*\(\s*true\s*\)',
     'MEDIUM', 'WebView File Access Enabled',
     'WebView can read local files. Cross-origin file access can leak sensitive data.',
     'WebView Security'),
]

MAX_FINDINGS_PER_PATTERN = 3  # Avoid flooding with same issue

def analyze_source_code(apk_path):
    """Main entry point for source code analysis"""
    findings = []
    scanned_files = 0
    decompile_method = 'none'

    with tempfile.TemporaryDirectory() as tmpdir:
        # Try Jadx first
        java_sources = _decompile_with_jadx(apk_path, tmpdir)
        if java_sources:
            decompile_method = 'jadx'
        else:
            # Fallback: extract .dex / .smali / .class strings
            java_sources = _extract_strings_fallback(apk_path, tmpdir)
            if java_sources:
                decompile_method = 'string_extraction'
            else:
                return _error_result('Could not decompile APK. Install jadx for full analysis.')

        # Scan all extracted files
        pattern_hit_count = {}
        for src_file in java_sources:
            try:
                with open(src_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                scanned_files += 1
                rel_path = os.path.relpath(src_file, tmpdir)

                for (pattern, severity, title, description, category) in VULN_PATTERNS:
                    key = title
                    if pattern_hit_count.get(key, 0) >= MAX_FINDINGS_PER_PATTERN:
                        continue

                    matches = list(re.finditer(pattern, content, re.MULTILINE))
                    for match in matches:
                        if pattern_hit_count.get(key, 0) >= MAX_FINDINGS_PER_PATTERN:
                            break
                        lineno = content[:match.start()].count('\n') + 1
                        snippet = content[max(0, match.start()-40):match.end()+40].strip()
                        snippet = snippet[:120] + '...' if len(snippet) > 120 else snippet

                        findings.append({
                            'type': 'SOURCE_CODE',
                            'severity': severity,
                            'title': title,
                            'description': description,
                            'detail': f'{rel_path}:{lineno}',
                            'snippet': snippet,
                            'category': category
                        })
                        pattern_hit_count[key] = pattern_hit_count.get(key, 0) + 1

            except Exception:
                continue

    # Deduplicate by title+file
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['title'], f['detail'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    category_counts = {}
    for f in unique_findings:
        cat = f['category']
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        'status': 'success',
        'decompile_method': decompile_method,
        'scanned_files': scanned_files,
        'findings': unique_findings,
        'summary': {
            'total': len(unique_findings),
            'high': len([f for f in unique_findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in unique_findings if f['severity'] == 'MEDIUM']),
            'low': len([f for f in unique_findings if f['severity'] == 'LOW']),
            'by_category': category_counts
        }
    }


def _decompile_with_jadx(apk_path, output_dir):
    """Decompile APK using jadx"""
    try:
        jadx_out = os.path.join(output_dir, 'jadx_out')
        result = subprocess.run(
            ['jadx', '-d', jadx_out, '--no-res', apk_path],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists(jadx_out):
            java_files = []
            for root, dirs, files in os.walk(jadx_out):
                for fname in files:
                    if fname.endswith(('.java', '.kt')):
                        java_files.append(os.path.join(root, fname))
            return java_files if java_files else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return None


def _extract_strings_fallback(apk_path, output_dir):
    """Fallback: extract readable strings from DEX/classes"""
    try:
        text_files = []
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            for name in apk_zip.namelist():
                if name.endswith('.dex') or name.endswith('.smali'):
                    raw = apk_zip.read(name)
                    # Extract printable ASCII strings (length > 5)
                    strings = re.findall(rb'[ -~]{6,}', raw)
                    if strings:
                        out_path = os.path.join(output_dir, name.replace('/', '_') + '.txt')
                        with open(out_path, 'w', encoding='utf-8', errors='replace') as f:
                            f.write('\n'.join(s.decode('utf-8', errors='replace') for s in strings))
                        text_files.append(out_path)
                elif name.endswith(('.xml', '.properties', '.json')):
                    try:
                        content = apk_zip.read(name)
                        out_path = os.path.join(output_dir, name.replace('/', '_'))
                        with open(out_path, 'wb') as f:
                            f.write(content)
                        text_files.append(out_path)
                    except Exception:
                        pass
        return text_files if text_files else None
    except Exception:
        return None


def _error_result(message):
    return {
        'status': 'error',
        'error': message,
        'decompile_method': 'none',
        'scanned_files': 0,
        'findings': [],
        'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_category': {}}
    }
