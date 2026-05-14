"""Catalog of dangerous Android permissions monitored by SecureAPK.

37 entries — this count is asserted in tests/test_manifest_analyzer.py and is
mandated by CLAUDE.md §6 rule 7 and the FYP chapter claims.

Each entry maps `android.permission.<NAME>` to:
    severity: 'HIGH' | 'MEDIUM' | 'LOW'
    description: why this permission is sensitive
    owasp_id: OWASP Mobile Top 10 (2024) category id (M1..M10)
    cwe_id: relevant CWE identifier

Data only — no logic in this file.
"""
from __future__ import annotations


DANGEROUS_PERMISSIONS: dict[str, dict[str, str]] = {
    # ----- SMS / MMS (HIGH — banking OTP exfiltration vector) -----
    "android.permission.READ_SMS": {
        "severity": "HIGH",
        "description": "Allows reading SMS messages. Enables OTP interception and banking fraud.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },
    "android.permission.SEND_SMS": {
        "severity": "HIGH",
        "description": "Allows sending SMS messages. Can incur charges or enable premium-SMS fraud.",
        "owasp_id": "M3",
        "cwe_id": "CWE-269",
    },
    "android.permission.RECEIVE_SMS": {
        "severity": "HIGH",
        "description": "Allows receiving SMS messages. Used to intercept OTPs silently.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },
    "android.permission.RECEIVE_MMS": {
        "severity": "MEDIUM",
        "description": "Allows the app to receive MMS messages.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },
    "android.permission.RECEIVE_WAP_PUSH": {
        "severity": "MEDIUM",
        "description": "Allows receiving WAP push messages.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },

    # ----- Contacts / Calendar / User data -----
    "android.permission.READ_CONTACTS": {
        "severity": "HIGH",
        "description": "Allows reading the user's contact list. High privacy risk.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.WRITE_CONTACTS": {
        "severity": "HIGH",
        "description": "Allows modifying the user's contact list.",
        "owasp_id": "M6",
        "cwe_id": "CWE-284",
    },
    "android.permission.GET_ACCOUNTS": {
        "severity": "MEDIUM",
        "description": "Allows access to the list of accounts on the device.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.READ_CALENDAR": {
        "severity": "MEDIUM",
        "description": "Allows reading the user's calendar data.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.WRITE_CALENDAR": {
        "severity": "MEDIUM",
        "description": "Allows writing to the user's calendar.",
        "owasp_id": "M6",
        "cwe_id": "CWE-284",
    },
    "android.permission.READ_CALL_LOG": {
        "severity": "HIGH",
        "description": "Allows reading the user's call log.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.WRITE_CALL_LOG": {
        "severity": "HIGH",
        "description": "Allows writing the user's call log.",
        "owasp_id": "M6",
        "cwe_id": "CWE-284",
    },

    # ----- Location -----
    "android.permission.ACCESS_FINE_LOCATION": {
        "severity": "HIGH",
        "description": "Allows precise GPS location access. High privacy risk.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "severity": "MEDIUM",
        "description": "Allows approximate (network-based) location access.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "severity": "HIGH",
        "description": "Allows location access while the app is in the background.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },

    # ----- Phone / Telephony -----
    "android.permission.CALL_PHONE": {
        "severity": "HIGH",
        "description": "Allows the app to initiate phone calls without user confirmation.",
        "owasp_id": "M3",
        "cwe_id": "CWE-269",
    },
    "android.permission.READ_PHONE_STATE": {
        "severity": "MEDIUM",
        "description": "Allows reading phone state including IMEI/IMSI and active calls.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "severity": "MEDIUM",
        "description": "Allows reading the device's phone number.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "severity": "HIGH",
        "description": "Allows monitoring and modifying outgoing call data.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },
    "android.permission.ANSWER_PHONE_CALLS": {
        "severity": "HIGH",
        "description": "Allows the app to answer incoming phone calls.",
        "owasp_id": "M3",
        "cwe_id": "CWE-269",
    },
    "android.permission.ADD_VOICEMAIL": {
        "severity": "MEDIUM",
        "description": "Allows the app to add voicemails to the system.",
        "owasp_id": "M3",
        "cwe_id": "CWE-284",
    },
    "android.permission.USE_SIP": {
        "severity": "MEDIUM",
        "description": "Allows the app to make/receive SIP (VoIP) calls.",
        "owasp_id": "M3",
        "cwe_id": "CWE-284",
    },

    # ----- Camera / Microphone / Sensors -----
    "android.permission.CAMERA": {
        "severity": "HIGH",
        "description": "Allows capturing photos and video. Privacy and surveillance risk.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.RECORD_AUDIO": {
        "severity": "HIGH",
        "description": "Allows recording audio from the microphone. Surveillance risk.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.BODY_SENSORS": {
        "severity": "MEDIUM",
        "description": "Allows access to body sensor data such as heart rate.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "severity": "MEDIUM",
        "description": "Allows the app to detect physical activity (walking, driving).",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },

    # ----- Storage -----
    "android.permission.READ_EXTERNAL_STORAGE": {
        "severity": "MEDIUM",
        "description": "Allows reading files on shared/external storage.",
        "owasp_id": "M9",
        "cwe_id": "CWE-200",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "severity": "MEDIUM",
        "description": "Allows writing files to shared/external storage.",
        "owasp_id": "M9",
        "cwe_id": "CWE-276",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "severity": "HIGH",
        "description": "Grants broad access to all files on external storage.",
        "owasp_id": "M9",
        "cwe_id": "CWE-732",
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "severity": "MEDIUM",
        "description": "Allows reading image files on the device (Android 13+).",
        "owasp_id": "M9",
        "cwe_id": "CWE-200",
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "severity": "MEDIUM",
        "description": "Allows reading video files on the device (Android 13+).",
        "owasp_id": "M9",
        "cwe_id": "CWE-200",
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "severity": "MEDIUM",
        "description": "Allows reading audio files on the device (Android 13+).",
        "owasp_id": "M9",
        "cwe_id": "CWE-200",
    },

    # ----- System / Device control -----
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "HIGH",
        "description": "Allows drawing over other apps. Common in overlay/tapjacking attacks.",
        "owasp_id": "M8",
        "cwe_id": "CWE-1021",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "HIGH",
        "description": "Allows requesting installation of arbitrary APK packages.",
        "owasp_id": "M8",
        "cwe_id": "CWE-829",
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "severity": "HIGH",
        "description": "Allows reading per-app usage statistics. Behavioural tracking risk.",
        "owasp_id": "M6",
        "cwe_id": "CWE-359",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "severity": "HIGH",
        "description": "Allows binding as an accessibility service — can observe and act on any UI.",
        "owasp_id": "M8",
        "cwe_id": "CWE-269",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "severity": "HIGH",
        "description": "Allows the app to act as a device administrator.",
        "owasp_id": "M8",
        "cwe_id": "CWE-269",
    },
}


# Sanity check at import time — a missed entry should fail loudly, not silently
# slip past the FYP claim of "37 dangerous permissions monitored".
assert len(DANGEROUS_PERMISSIONS) == 37, (
    f"DANGEROUS_PERMISSIONS must contain exactly 37 entries, found {len(DANGEROUS_PERMISSIONS)}"
)
