import io
from flask import Flask, render_template, request, send_file
from modules.ip_analyzer import analyze_ip
from modules.email_analyzer import analyze_email_header
from modules.url_scanner import scan_url
from modules.cdr_parser import parse_cdr
from modules.report_generator import generate_report
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ip', methods=['GET', 'POST'])
def ip_page():
    result = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if ip:
            result = analyze_ip(ip)
    return render_template('result_ip.html', result=result)

@app.route('/ip/report', methods=['POST'])
def ip_report():
    data = {
        'ip': request.form.get('ip'),
        'country': request.form.get('country'),
        'region': request.form.get('region'),
        'city': request.form.get('city'),
        'isp': request.form.get('isp'),
        'org': request.form.get('org'),
        'timezone': request.form.get('timezone'),
    }
    pdf_bytes = generate_report('IP Analyzer', data)
    if pdf_bytes:
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='CyberTrace_IP_Report.pdf'
        )
    return "Report generation failed", 500

@app.route('/email', methods=['GET', 'POST'])
def email_page():
    result = None
    if request.method == 'POST':
        header = request.form.get('header', '').strip()
        if header:
            result = analyze_email_header(header)
    return render_template('result_email.html', result=result)

@app.route('/email/report', methods=['POST'])
def email_report():
    data = {
        'from': request.form.get('from_addr'),
        'to': request.form.get('to_addr'),
        'subject': request.form.get('subject'),
        'date': request.form.get('date'),
        'spf': request.form.get('spf'),
        'dkim': request.form.get('dkim'),
        'spoof_alert': request.form.get('spoof_alert'),
    }
    pdf_bytes = generate_report('Email Header Analyzer', data)
    if pdf_bytes:
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='CyberTrace_Email_Report.pdf'
        )
    return "Report generation failed", 500

@app.route('/url', methods=['GET', 'POST'])
def url_page():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            result = scan_url(url)
    return render_template('result_url.html', result=result)

@app.route('/url/report', methods=['POST'])
def url_report():
    data = {
        'url': request.form.get('url'),
        'verdict': request.form.get('verdict'),
        'malicious': request.form.get('malicious'),
        'suspicious': request.form.get('suspicious'),
        'harmless': request.form.get('harmless'),
        'total_engines': request.form.get('total_engines'),
    }
    pdf_bytes = generate_report('URL Scanner', data)
    if pdf_bytes:
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='CyberTrace_URL_Report.pdf'
        )
    return "Report generation failed", 500

@app.route('/cdr', methods=['GET', 'POST'])
def cdr_page():
    result = None
    if request.method == 'POST':
        if 'cdr_file' not in request.files:
            return render_template('result_cdr.html', result={'status': 'error', 'message': 'No file uploaded'})
        file = request.files['cdr_file']
        if file.filename == '':
            return render_template('result_cdr.html', result={'status': 'error', 'message': 'No file selected'})
        if file and file.filename.endswith('.csv'):
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            result = parse_cdr(filepath)
    return render_template('result_cdr.html', result=result)

@app.route('/cdr/report', methods=['POST'])
def cdr_report():
    data = {
        'total_records': request.form.get('total_records'),
        'top_callers': request.form.get('top_callers'),
    }
    chart_b64 = request.form.get('chart_callers')
    pdf_bytes = generate_report('CDR Parser', data, chart_b64)
    if pdf_bytes:
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='CyberTrace_CDR_Report.pdf'
        )
    return "Report generation failed", 500

if __name__ == '__main__':
    app.run(debug=True)