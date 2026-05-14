"""
Phase 2: Static Analysis - APK Parsing and Manifest Inspection
Uses PyAXMLParser to extract AndroidManifest.xml metadata
"""
import os
import zipfile
import subprocess
import re
import tempfile

# High-risk permissions defined per OWASP Mobile Top 10 and Android security guidelines
HIGH_RISK_PERMISSIONS = {
    'android.permission.READ_SMS': ('HIGH', 'Reads SMS messages — can intercept OTPs and private messages'),
    'android.permission.SEND_SMS': ('HIGH', 'Sends SMS — potential for SMS fraud or premium-rate abuse'),
    'android.permission.RECEIVE_SMS': ('HIGH', 'Intercepts incoming SMS messages'),
    'android.permission.READ_CONTACTS': ('MEDIUM', 'Accesses all device contacts'),
    'android.permission.WRITE_CONTACTS': ('MEDIUM', 'Can modify or delete contacts'),
    'android.permission.ACCESS_FINE_LOCATION': ('HIGH', 'Precise GPS location tracking'),
    'android.permission.ACCESS_COARSE_LOCATION': ('LOW', 'Approximate network-based location'),
    'android.permission.ACCESS_BACKGROUND_LOCATION': ('HIGH', 'Location access even when app is closed'),
    'android.permission.RECORD_AUDIO': ('HIGH', 'Microphone access — can eavesdrop conversations'),
    'android.permission.CAMERA': ('MEDIUM', 'Camera access — potential privacy violation'),
    'android.permission.READ_CALL_LOG': ('HIGH', 'Access to call history'),
    'android.permission.WRITE_CALL_LOG': ('HIGH', 'Can modify call logs'),
    'android.permission.PROCESS_OUTGOING_CALLS': ('HIGH', 'Can intercept outgoing calls'),
    'android.permission.READ_PHONE_STATE': ('MEDIUM', 'Reads IMEI, network info, phone number'),
    'android.permission.CALL_PHONE': ('HIGH', 'Can make phone calls without user interaction'),
    'android.permission.GET_ACCOUNTS': ('MEDIUM', 'Accesses all signed-in accounts on device'),
    'android.permission.USE_CREDENTIALS': ('MEDIUM', 'Uses account credentials'),
    'android.permission.MANAGE_ACCOUNTS': ('HIGH', 'Full control over user accounts'),
    'android.permission.READ_EXTERNAL_STORAGE': ('MEDIUM', 'Reads all files on external storage'),
    'android.permission.WRITE_EXTERNAL_STORAGE': ('MEDIUM', 'Writes/deletes files on external storage'),
    'android.permission.INSTALL_PACKAGES': ('HIGH', 'Installs additional APKs — dropper behavior'),
    'android.permission.DELETE_PACKAGES': ('HIGH', 'Deletes applications'),
    'android.permission.RECEIVE_BOOT_COMPLETED': ('MEDIUM', 'Auto-starts on device boot'),
    'android.permission.FOREGROUND_SERVICE': ('LOW', 'Runs persistent foreground services'),
    'android.permission.REQUEST_INSTALL_PACKAGES': ('HIGH', 'Can request installation of packages'),
    'android.permission.SYSTEM_ALERT_WINDOW': ('HIGH', 'Overlays on top of other apps — phishing risk'),
    'android.permission.BIND_ACCESSIBILITY_SERVICE': ('HIGH', 'Full UI control — used in banking trojans'),
    'android.permission.CHANGE_NETWORK_STATE': ('LOW', 'Can toggle network connectivity'),
    'android.permission.INTERNET': ('LOW', 'Network access — expected but notable'),
    'android.permission.VIBRATE': ('LOW', 'Vibration access'),
    'android.permission.WAKE_LOCK': ('LOW', 'Prevents device from sleeping'),
    'android.permission.USE_BIOMETRIC': ('MEDIUM', 'Biometric authentication access'),
    'android.permission.USE_FINGERPRINT': ('MEDIUM', 'Fingerprint sensor access'),
    'android.permission.NFC': ('MEDIUM', 'NFC chip access — payment data risk'),
    'android.permission.BLUETOOTH': ('LOW', 'Bluetooth device access'),
    'android.permission.BLUETOOTH_ADMIN': ('MEDIUM', 'Full Bluetooth control'),
    'android.permission.ACCESS_WIFI_STATE': ('LOW', 'Reads WiFi state'),
    'android.permission.CHANGE_WIFI_STATE': ('LOW', 'Can modify WiFi settings'),
    'android.permission.DISABLE_KEYGUARD': ('HIGH', 'Can disable screen lock'),
    'android.permission.MASTER_CLEAR': ('HIGH', 'Factory reset capability'),
    'android.permission.REBOOT': ('HIGH', 'Can reboot the device'),
}

def analyze_manifest(apk_path):
    """Main entry point for manifest analysis"""
    findings = []
    metadata = {}
    permissions_found = []
    exported_components = []
    cleartext_traffic = False
    backup_allowed = False

    try:
        # Extract APK (it's a ZIP file)
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            namelist = apk_zip.namelist()

            # Check for AndroidManifest.xml
            if 'AndroidManifest.xml' not in namelist:
                return _error_result('AndroidManifest.xml not found in APK')

            # Try PyAXMLParser first, fallback to aapt
            manifest_content = _parse_with_pyaxmlparser(apk_zip, apk_path)
            if not manifest_content:
                manifest_content = _parse_with_aapt(apk_path)
            if not manifest_content:
                manifest_content = _parse_raw_binary(apk_zip)

    except zipfile.BadZipFile:
        return _error_result('Invalid APK file — not a valid ZIP archive')
    except Exception as e:
        return _error_result(f'APK extraction failed: {str(e)}')

    if not manifest_content:
        return _error_result('Could not parse AndroidManifest.xml')

    # ---- Parse metadata ----
    pkg_match = re.search(r'package[=\s]+["\']?([a-zA-Z0-9_.]+)["\']?', manifest_content)
    if pkg_match:
        metadata['package_name'] = pkg_match.group(1)

    ver_match = re.search(r'versionName[=\s]+["\']?([^\s"\'<>]+)["\']?', manifest_content)
    if ver_match:
        metadata['version_name'] = ver_match.group(1)

    vercode_match = re.search(r'versionCode[=\s]+["\']?(\d+)["\']?', manifest_content)
    if vercode_match:
        metadata['version_code'] = vercode_match.group(1)

    sdk_match = re.search(r'minSdkVersion[=\s]+["\']?(\d+)["\']?', manifest_content)
    if sdk_match:
        metadata['min_sdk'] = sdk_match.group(1)

    target_match = re.search(r'targetSdkVersion[=\s]+["\']?(\d+)["\']?', manifest_content)
    if target_match:
        metadata['target_sdk'] = target_match.group(1)

    # ---- Parse permissions ----
    perm_patterns = [
        r'uses-permission[^>]*android:name=["\']([^"\']+)["\']',
        r'uses-permission[^>]*name=["\']([^"\']+)["\']',
        r'<permission[^>]*android:name=["\']([^"\']+)["\']',
    ]
    for pattern in perm_patterns:
        perms = re.findall(pattern, manifest_content, re.IGNORECASE)
        for p in perms:
            if p not in permissions_found:
                permissions_found.append(p)

    # Evaluate permissions
    for perm in permissions_found:
        perm_normalized = perm if perm.startswith('android.permission.') else perm
        if perm_normalized in HIGH_RISK_PERMISSIONS:
            severity, desc = HIGH_RISK_PERMISSIONS[perm_normalized]
            findings.append({
                'type': 'PERMISSION',
                'severity': severity,
                'title': f'Dangerous Permission: {perm_normalized.split(".")[-1]}',
                'description': desc,
                'detail': perm_normalized,
                'category': 'Permission'
            })

    # ---- Check cleartext traffic ----
    if re.search(r'usesCleartextTraffic\s*=\s*["\']?true["\']?', manifest_content, re.IGNORECASE):
        cleartext_traffic = True
        findings.append({
            'type': 'CONFIGURATION',
            'severity': 'HIGH',
            'title': 'Cleartext Traffic Allowed',
            'description': 'android:usesCleartextTraffic="true" allows unencrypted HTTP communication. Vulnerable to MITM attacks.',
            'detail': 'android:usesCleartextTraffic="true"',
            'category': 'Network Security'
        })
    metadata['cleartext_traffic'] = cleartext_traffic

    # ---- Check allowBackup ----
    backup_match = re.search(r'allowBackup\s*=\s*["\']?(true)["\']?', manifest_content, re.IGNORECASE)
    if backup_match:
        backup_allowed = True
        findings.append({
            'type': 'CONFIGURATION',
            'severity': 'MEDIUM',
            'title': 'Backup Allowed (android:allowBackup=true)',
            'description': 'App data can be extracted via ADB backup without root. May expose sensitive user data.',
            'detail': 'android:allowBackup="true"',
            'category': 'Data Security'
        })
    metadata['backup_allowed'] = backup_allowed

    # ---- Check debuggable ----
    if re.search(r'debuggable\s*=\s*["\']?true["\']?', manifest_content, re.IGNORECASE):
        findings.append({
            'type': 'CONFIGURATION',
            'severity': 'HIGH',
            'title': 'App is Debuggable',
            'description': 'android:debuggable="true" enables runtime debugging. Should never be true in production builds.',
            'detail': 'android:debuggable="true"',
            'category': 'Build Configuration'
        })

    # ---- Check exported components ----
    activity_patterns = [
        (r'<activity[^>]*android:name=["\']([^"\']+)["\'][^>]*android:exported=["\']true["\']', 'Activity'),
        (r'<service[^>]*android:name=["\']([^"\']+)["\'][^>]*android:exported=["\']true["\']', 'Service'),
        (r'<receiver[^>]*android:name=["\']([^"\']+)["\'][^>]*android:exported=["\']true["\']', 'Receiver'),
        (r'<provider[^>]*android:name=["\']([^"\']+)["\'][^>]*android:exported=["\']true["\']', 'Provider'),
    ]

    for pattern, comp_type in activity_patterns:
        matches = re.findall(pattern, manifest_content, re.IGNORECASE | re.DOTALL)
        for m in matches:
            exported_components.append({'name': m, 'type': comp_type})
            # Only flag if no permission protection
            if not re.search(rf'{re.escape(m)}[^<]*android:permission', manifest_content):
                findings.append({
                    'type': 'COMPONENT',
                    'severity': 'MEDIUM',
                    'title': f'Unprotected Exported {comp_type}',
                    'description': f'{comp_type} "{m}" is exported without android:permission, allowing any app to invoke it.',
                    'detail': m,
                    'category': 'Component Security'
                })

    # ---- Check Network Security Config ----
    if not re.search(r'networkSecurityConfig', manifest_content):
        findings.append({
            'type': 'CONFIGURATION',
            'severity': 'LOW',
            'title': 'No Network Security Config Defined',
            'description': 'App does not define a Network Security Configuration. No certificate pinning or custom trust anchors.',
            'detail': 'Missing android:networkSecurityConfig attribute',
            'category': 'Network Security'
        })

    return {
        'status': 'success',
        'metadata': metadata,
        'permissions': permissions_found,
        'exported_components': exported_components,
        'findings': findings,
        'summary': {
            'total_permissions': len(permissions_found),
            'dangerous_permissions': len([f for f in findings if f['type'] == 'PERMISSION' and f['severity'] in ('HIGH', 'MEDIUM')]),
            'exported_components': len(exported_components),
            'cleartext_traffic': cleartext_traffic,
            'backup_allowed': backup_allowed
        }
    }


def _parse_with_pyaxmlparser(apk_zip, apk_path):
    """Try PyAXMLParser library"""
    try:
        from pyaxmlparser import APK
        apk = APK(apk_path)
        # Build a pseudo-XML string from parsed data
        lines = []
        lines.append(f'package="{apk.get_package()}"')
        lines.append(f'versionName="{apk.get_androidversion_name()}"')
        lines.append(f'versionCode="{apk.get_androidversion_code()}"')
        lines.append(f'minSdkVersion="{apk.get_min_sdk_version()}"')
        lines.append(f'targetSdkVersion="{apk.get_target_sdk_version()}"')

        for perm in apk.get_permissions():
            lines.append(f'<uses-permission android:name="{perm}"/>')

        # Get manifest XML if available
        try:
            manifest_xml = apk.get_android_manifest_xml().decode('utf-8', errors='replace')
            return manifest_xml
        except:
            return '\n'.join(lines)
    except Exception:
        return None


def _parse_with_aapt(apk_path):
    """Try Android Asset Packaging Tool"""
    try:
        result = subprocess.run(
            ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return result.stdout
        # Also try badging
        result2 = subprocess.run(
            ['aapt', 'dump', 'badging', apk_path],
            capture_output=True, text=True, timeout=30
        )
        return result2.stdout if result2.returncode == 0 else None
    except Exception:
        return None


def _parse_raw_binary(apk_zip):
    """Attempt to extract readable strings from binary AndroidManifest.xml"""
    try:
        raw = apk_zip.read('AndroidManifest.xml')
        # Decode readable strings
        text = raw.decode('utf-8', errors='replace')
        # Also try latin-1
        readable = re.findall(r'[a-zA-Z0-9._:/"=\s<>]+', text)
        return ' '.join(readable)
    except Exception:
        return None


def _error_result(message):
    return {
        'status': 'error',
        'error': message,
        'metadata': {},
        'permissions': [],
        'exported_components': [],
        'findings': [],
        'summary': {
            'total_permissions': 0,
            'dangerous_permissions': 0,
            'exported_components': 0,
            'cleartext_traffic': False,
            'backup_allowed': False
        }
    }
