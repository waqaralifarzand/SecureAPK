"""
Phase 4: Dynamic Analysis - Runtime Behavior Monitoring
Executes APK in Android emulator via ADB and captures runtime behavior
"""
import subprocess
import time
import re
import os
import threading

ADB_TIMEOUT = 60  # seconds for ADB operations
RUNTIME_DURATION = 30  # seconds of runtime monitoring


def run_dynamic_analysis(apk_path, analysis_id):
    """Main entry point for dynamic analysis"""
    result = {
        'status': 'running',
        'network_activity': [],
        'runtime_logs': [],
        'suspicious_events': [],
        'installed': False,
        'launched': False,
        'package_name': None,
        'summary': {}
    }

    # Check if ADB is available
    if not _adb_available():
        return _no_emulator_result()

    # Check if emulator is running
    devices = _get_connected_devices()
    if not devices:
        return _no_emulator_result()

    device_id = devices[0]

    try:
        # Extract package name for ADB operations
        package_name = _extract_package_name(apk_path)
        result['package_name'] = package_name

        # Install APK
        install_success = _install_apk(apk_path, device_id)
        result['installed'] = install_success

        if not install_success:
            result['status'] = 'partial'
            result['error'] = 'APK installation failed'
            return result

        # Clear logcat
        _run_adb(['logcat', '-c'], device_id)

        # Launch application
        launch_success = _launch_app(package_name, device_id)
        result['launched'] = launch_success

        # Monitor runtime
        time.sleep(3)  # Wait for app to stabilize

        # Collect logcat
        logs = _collect_logcat(package_name, device_id, duration=RUNTIME_DURATION)
        result['runtime_logs'] = logs

        # Analyze logs for suspicious behavior
        suspicious = _analyze_logs(logs)
        result['suspicious_events'] = suspicious

        # Network traffic observation
        network = _observe_network(device_id)
        result['network_activity'] = network

        # Cleanup
        _uninstall_apk(package_name, device_id)

        result['status'] = 'success'
        result['summary'] = {
            'total_logs': len(logs),
            'suspicious_events': len(suspicious),
            'network_connections': len(network),
            'cleartext_http': len([n for n in network if n.get('protocol') == 'HTTP']),
            'high_events': len([e for e in suspicious if e.get('severity') == 'HIGH'])
        }

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)

    return result


def _adb_available():
    try:
        result = subprocess.run(['adb', 'version'], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _get_connected_devices():
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\n')[1:]
        devices = [l.split('\t')[0] for l in lines if 'device' in l and not l.startswith('*')]
        return devices
    except Exception:
        return []


def _run_adb(args, device_id=None):
    cmd = ['adb']
    if device_id:
        cmd += ['-s', device_id]
    cmd += args
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=ADB_TIMEOUT)
    except Exception:
        return None


def _install_apk(apk_path, device_id):
    result = _run_adb(['install', '-r', '-t', apk_path], device_id)
    if result and 'Success' in result.stdout:
        return True
    return False


def _extract_package_name(apk_path):
    """Extract package name from APK"""
    try:
        result = subprocess.run(
            ['aapt', 'dump', 'badging', apk_path],
            capture_output=True, text=True, timeout=30
        )
        match = re.search(r"package: name='([^']+)'", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    try:
        from pyaxmlparser import APK
        apk = APK(apk_path)
        return apk.get_package()
    except Exception:
        pass

    return None


def _launch_app(package_name, device_id):
    if not package_name:
        return False
    result = _run_adb(
        ['shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'],
        device_id
    )
    return result and result.returncode == 0


def _collect_logcat(package_name, device_id, duration=30):
    """Collect logcat for a specified duration"""
    logs = []
    try:
        proc = subprocess.Popen(
            ['adb', '-s', device_id, 'logcat', '-v', 'time'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(duration)
        proc.terminate()
        stdout, _ = proc.communicate(timeout=5)

        for line in stdout.split('\n')[:500]:  # Cap at 500 lines
            if line.strip():
                logs.append(line.strip())
    except Exception:
        pass
    return logs


def _analyze_logs(logs):
    """Detect suspicious patterns in runtime logs"""
    suspicious = []
    SUSPICIOUS_PATTERNS = [
        (r'(?i)(http://[a-zA-Z0-9./_?=&-]+)', 'HIGH', 'Cleartext HTTP Request in Logs',
         'App making unencrypted HTTP request detected in runtime logs'),
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', 'HIGH', 'Password in Logs',
         'Possible password value logged to Android logcat'),
        (r'(?i)(token|api_key|secret)\s*[:=]\s*\S+', 'HIGH', 'Secret/Token in Logs',
         'Authentication token or API key logged at runtime'),
        (r'(?i)root|superuser|su\s+granted', 'MEDIUM', 'Root Access Attempt Logged',
         'Evidence of root access or superuser interaction'),
        (r'ClassNotFoundException|NoSuchMethodException', 'LOW', 'Reflection Exception',
         'Reflection-related exception may indicate dynamic class loading'),
        (r'java\.lang\.SecurityException', 'MEDIUM', 'Security Exception',
         'Security exception thrown — permission denied or security violation'),
        (r'javax\.net\.ssl\.SSLException|javax\.net\.ssl\.SSLHandshakeException', 'HIGH', 'SSL/TLS Error',
         'SSL/TLS handshake failure — possible certificate issue or pinning bypass attempt'),
        (r'(?i)exec\s*\(|Runtime\.exec', 'HIGH', 'Shell Command Execution',
         'Dynamic command execution detected at runtime'),
        (r'W/System\.err', 'LOW', 'System Error Logged',
         'System error written to logcat'),
        (r'(?i)doInBackground|AsyncTask', 'LOW', 'Background Task',
         'Async background task observed during execution'),
    ]

    seen = set()
    for log_line in logs:
        for (pattern, severity, title, description) in SUSPICIOUS_PATTERNS:
            match = re.search(pattern, log_line)
            if match:
                key = (title, match.group(0)[:50])
                if key not in seen:
                    seen.add(key)
                    suspicious.append({
                        'severity': severity,
                        'title': title,
                        'description': description,
                        'evidence': log_line[:200],
                        'matched': match.group(0)[:100]
                    })
    return suspicious


def _observe_network(device_id):
    """Basic network traffic observation via netstat"""
    connections = []
    try:
        result = _run_adb(['shell', 'netstat', '-n'], device_id)
        if result and result.stdout:
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'TIME_WAIT' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote = parts[4] if len(parts) > 4 else 'unknown'
                        port = remote.split(':')[-1] if ':' in remote else '?'
                        protocol = 'HTTP' if port == '80' else 'HTTPS' if port == '443' else 'OTHER'
                        connections.append({
                            'remote': remote,
                            'port': port,
                            'protocol': protocol,
                            'state': parts[-1] if parts else 'UNKNOWN'
                        })
    except Exception:
        pass
    return connections[:20]  # Cap at 20 connections


def _uninstall_apk(package_name, device_id):
    if package_name:
        _run_adb(['uninstall', package_name], device_id)


def _no_emulator_result():
    return {
        'status': 'unavailable',
        'message': 'No Android emulator detected. Dynamic analysis requires ADB and a running Android emulator.',
        'setup_instructions': [
            'Install Android Studio and create an AVD (Android Virtual Device)',
            'Start the emulator: emulator -avd <avd_name>',
            'Ensure ADB is in your PATH: adb devices',
            'Re-run analysis with dynamic module enabled'
        ],
        'network_activity': [],
        'runtime_logs': [],
        'suspicious_events': [],
        'installed': False,
        'launched': False,
        'package_name': None,
        'summary': {
            'total_logs': 0,
            'suspicious_events': 0,
            'network_connections': 0,
            'cleartext_http': 0,
            'high_events': 0
        }
    }
