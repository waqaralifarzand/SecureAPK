"""
Phase 5: Risk Scoring and Automated Reporting
Combines static and dynamic findings into a weighted risk score
"""

# Severity weights
SEVERITY_WEIGHTS = {
    'HIGH':   10,
    'MEDIUM':  5,
    'LOW':     2,
}

# Category multipliers (some categories are more critical)
CATEGORY_MULTIPLIERS = {
    'Hardcoded Secrets':          1.5,
    'Insecure Communication':     1.4,
    'Weak Cryptography':          1.3,
    'WebView Security':           1.3,
    'Code Execution':             1.5,
    'Permission':                 1.0,
    'Network Security':           1.2,
    'Data Security':              1.1,
    'Build Configuration':        1.2,
    'Component Security':         1.0,
    'Insecure Data Storage':      1.1,
    'Information Leakage':        1.3,
    'IPC Security':               1.0,
    'Tampering & Reverse Engineering': 0.8,
    'SOURCE_CODE':                1.0,
    'PERMISSION':                 1.0,
    'CONFIGURATION':              1.1,
    'COMPONENT':                  1.0,
}

# Thresholds
THRESHOLDS = {
    'LOW':    (0, 30),
    'MEDIUM': (31, 70),
    'HIGH':   (71, float('inf'))
}

MAX_SCORE = 100  # Normalize — 100 raw pts = 100% score

def calculate_risk_score(manifest_findings, source_findings, dynamic_findings):
    """Calculate unified risk score from all findings"""
    breakdown = {
        'manifest': {'score': 0, 'findings': 0},
        'source_code': {'score': 0, 'findings': 0},
        'dynamic': {'score': 0, 'findings': 0},
    }

    all_findings = []

    # ── Manifest Findings ──
    for f in manifest_findings.get('findings', []):
        weight = SEVERITY_WEIGHTS.get(f.get('severity', 'LOW'), 2)
        category = f.get('category', f.get('type', 'UNKNOWN'))
        multiplier = CATEGORY_MULTIPLIERS.get(category, 1.0)
        score = weight * multiplier
        breakdown['manifest']['score'] += score
        breakdown['manifest']['findings'] += 1
        all_findings.append({**f, 'source': 'manifest', 'weighted_score': round(score, 1)})

    # ── Source Code Findings ──
    for f in source_findings.get('findings', []):
        weight = SEVERITY_WEIGHTS.get(f.get('severity', 'LOW'), 2)
        category = f.get('category', 'SOURCE_CODE')
        multiplier = CATEGORY_MULTIPLIERS.get(category, 1.0)
        score = weight * multiplier
        breakdown['source_code']['score'] += score
        breakdown['source_code']['findings'] += 1
        all_findings.append({**f, 'source': 'source_code', 'weighted_score': round(score, 1)})

    # ── Dynamic Findings ──
    for f in dynamic_findings.get('suspicious_events', []):
        weight = SEVERITY_WEIGHTS.get(f.get('severity', 'LOW'), 2)
        score = weight * 1.2  # Dynamic findings weighted higher (runtime confirmed)
        breakdown['dynamic']['score'] += score
        breakdown['dynamic']['findings'] += 1
        all_findings.append({**f, 'source': 'dynamic', 'weighted_score': round(score, 1), 'type': 'DYNAMIC'})

    # ── Raw Score ──
    raw_score = (
        breakdown['manifest']['score'] +
        breakdown['source_code']['score'] +
        breakdown['dynamic']['score']
    )

    # Normalize to 0-100
    normalized = min(100, (raw_score / MAX_SCORE) * 100)
    score_int = round(normalized)

    # ── Risk Level ──
    if score_int <= THRESHOLDS['LOW'][1]:
        level = 'LOW'
        color = '#22c55e'
        icon = '🟢'
        recommendation = 'Application appears relatively secure. Address any flagged issues before production release.'
    elif score_int <= THRESHOLDS['MEDIUM'][1]:
        level = 'MEDIUM'
        color = '#f59e0b'
        icon = '🟡'
        recommendation = 'Significant security issues detected. Remediate HIGH and MEDIUM severity findings before deployment.'
    else:
        level = 'HIGH'
        color = '#ef4444'
        icon = '🔴'
        recommendation = 'Critical security vulnerabilities found. Application should NOT be published until all HIGH severity issues are resolved.'

    # ── Severity breakdown across all findings ──
    sev_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in all_findings:
        sev = f.get('severity', 'LOW')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # ── Top issues ──
    top_issues = sorted(
        [f for f in all_findings if f.get('severity') == 'HIGH'],
        key=lambda x: x.get('weighted_score', 0),
        reverse=True
    )[:5]

    return {
        'score': score_int,
        'raw_score': round(raw_score, 1),
        'level': level,
        'color': color,
        'icon': icon,
        'recommendation': recommendation,
        'breakdown': {
            'manifest': {'score': round(breakdown['manifest']['score'], 1), 'count': breakdown['manifest']['findings']},
            'source_code': {'score': round(breakdown['source_code']['score'], 1), 'count': breakdown['source_code']['findings']},
            'dynamic': {'score': round(breakdown['dynamic']['score'], 1), 'count': breakdown['dynamic']['findings']},
        },
        'severity_counts': sev_counts,
        'total_findings': len(all_findings),
        'top_issues': top_issues,
        'cwe_references': _get_cwe_references(all_findings),
        'owasp_references': _get_owasp_references(all_findings),
    }


def _get_cwe_references(findings):
    """Map common finding types to CWE IDs"""
    cwe_map = {
        'Hardcoded Password': 'CWE-259',
        'Hardcoded API Key / Secret': 'CWE-798',
        'Hardcoded Token': 'CWE-798',
        'MD5 Hashing Used': 'CWE-327',
        'SHA-1 Hashing Used': 'CWE-327',
        'DES Encryption Used': 'CWE-326',
        'AES-ECB Mode Used': 'CWE-327',
        'SSL Certificate Validation Bypassed': 'CWE-295',
        'Hostname Verification Disabled': 'CWE-297',
        'Insecure HTTP URL (Non-local)': 'CWE-319',
        'Cleartext Traffic Allowed': 'CWE-319',
        'Runtime Command Execution': 'CWE-78',
        'JavaScript Interface Added to WebView': 'CWE-749',
        'Sensitive Data Logged': 'CWE-532',
        'World-Readable/Writable File Mode': 'CWE-732',
    }
    refs = []
    seen = set()
    for f in findings:
        title = f.get('title', '')
        if title in cwe_map and cwe_map[title] not in seen:
            seen.add(cwe_map[title])
            refs.append({'cwe': cwe_map[title], 'title': title})
    return refs[:8]


def _get_owasp_references(findings):
    """Map finding categories to OWASP Mobile Top 10 2024"""
    owasp_map = {
        'Hardcoded Secrets': ('M9', 'Insecure Data Storage'),
        'Insecure Communication': ('M5', 'Insecure Communication'),
        'Weak Cryptography': ('M10', 'Insufficient Cryptography'),
        'WebView Security': ('M1', 'Improper Credential Usage'),
        'Permission': ('M6', 'Inadequate Privacy Controls'),
        'Insecure Data Storage': ('M9', 'Insecure Data Storage'),
        'Information Leakage': ('M9', 'Insecure Data Storage'),
        'Code Execution': ('M7', 'Insufficient Binary Protection'),
        'IPC Security': ('M4', 'Insufficient Input/Output Validation'),
        'Network Security': ('M5', 'Insecure Communication'),
    }
    refs = []
    seen = set()
    for f in findings:
        cat = f.get('category', '')
        if cat in owasp_map and owasp_map[cat][0] not in seen:
            seen.add(owasp_map[cat][0])
            code, name = owasp_map[cat]
            refs.append({'code': code, 'name': name})
    return sorted(refs, key=lambda x: x['code'])[:6]
