import os
import uuid
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from modules.static_manifest import analyze_manifest
from modules.static_sourcecode import analyze_source_code
from modules.dynamic_analysis import run_dynamic_analysis
from modules.risk_engine import calculate_risk_score
from modules.report_generator import generate_pdf_report
from modules.db_manager import init_db, save_analysis, get_all_analyses, get_analysis_by_id

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secureapk-fyp-lgu-2024'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['REPORTS_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

ALLOWED_EXTENSIONS = {'apk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    analyses = get_all_analyses()
    return render_template('dashboard.html', analyses=analyses)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'apk_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['apk_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Only .apk files are allowed'}), 400

    analysis_id = str(uuid.uuid4())[:8].upper()
    filename = secure_filename(file.filename)
    apk_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis_id}_{filename}")
    file.save(apk_path)

    try:
        # Phase 2: Static - Manifest Analysis
        manifest_findings = analyze_manifest(apk_path)

        # Phase 3: Static - Source Code Analysis
        source_findings = analyze_source_code(apk_path)

        # Phase 4: Dynamic Analysis
        enable_dynamic = request.form.get('enable_dynamic', 'false').lower() == 'true'
        dynamic_findings = run_dynamic_analysis(apk_path, analysis_id) if enable_dynamic else {
            'status': 'skipped',
            'message': 'Dynamic analysis was not enabled for this scan.',
            'network_activity': [],
            'runtime_logs': [],
            'suspicious_events': []
        }

        # Phase 5: Risk Scoring
        risk_result = calculate_risk_score(manifest_findings, source_findings, dynamic_findings)

        result = {
            'analysis_id': analysis_id,
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'manifest': manifest_findings,
            'source_code': source_findings,
            'dynamic': dynamic_findings,
            'risk': risk_result
        }

        save_analysis(result)

        return jsonify({'success': True, 'analysis_id': analysis_id})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/result/<analysis_id>')
def result(analysis_id):
    data = get_analysis_by_id(analysis_id)
    if not data:
        return redirect(url_for('index'))
    return render_template('result.html', data=data)

@app.route('/api/result/<analysis_id>')
def api_result(analysis_id):
    data = get_analysis_by_id(analysis_id)
    if not data:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(data)

@app.route('/download-report/<analysis_id>')
def download_report(analysis_id):
    data = get_analysis_by_id(analysis_id)
    if not data:
        return jsonify({'error': 'Analysis not found'}), 404

    pdf_path = generate_pdf_report(data, app.config['REPORTS_FOLDER'])
    return send_file(pdf_path, as_attachment=True,
                     download_name=f"SecureAPK_Report_{analysis_id}.pdf")

@app.route('/api/analyses')
def api_analyses():
    return jsonify(get_all_analyses())

@app.route('/delete/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    conn = sqlite3.connect('database/secureapk.db')
    conn.execute("DELETE FROM analyses WHERE analysis_id=?", (analysis_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
