import sqlite3
import json
import os

DB_PATH = 'database/secureapk.db'

def init_db():
    os.makedirs('database', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT UNIQUE NOT NULL,
            filename TEXT,
            timestamp TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            total_vulnerabilities INTEGER,
            data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_analysis(result):
    conn = sqlite3.connect(DB_PATH)
    risk = result.get('risk', {})
    total_vulns = (
        len(result.get('manifest', {}).get('findings', [])) +
        len(result.get('source_code', {}).get('findings', [])) +
        len(result.get('dynamic', {}).get('suspicious_events', []))
    )
    conn.execute('''
        INSERT OR REPLACE INTO analyses
        (analysis_id, filename, timestamp, risk_level, risk_score, total_vulnerabilities, data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        result['analysis_id'],
        result['filename'],
        result['timestamp'],
        risk.get('level', 'Unknown'),
        risk.get('score', 0),
        total_vulns,
        json.dumps(result)
    ))
    conn.commit()
    conn.close()

def get_all_analyses():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        'SELECT analysis_id, filename, timestamp, risk_level, risk_score, total_vulnerabilities FROM analyses ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_analysis_by_id(analysis_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        'SELECT data FROM analyses WHERE analysis_id=?', (analysis_id,)
    ).fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None
