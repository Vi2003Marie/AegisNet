from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
import datetime
import csv
import io
from flask_mail import Mail, Message
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_socketio import SocketIO
import pymysql
import pymysql.cursors
from config import DB_CONFIG
import threading

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
socketio = SocketIO(app)

app.secret_key = 'aegisnet_secret_2026'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'buwembovianney551@gmail.com'
app.config['MAIL_PASSWORD'] = 'xhqc zvjn ukry jipt'
app.config['MAIL_PASSWORD'] = 'xhqc zvjn ukry jipt'
app.config['MAIL_DEFAULT_SENDER'] = 'buwembovianney551@gmail.com'

mail = Mail(app)
ALERT_EMAIL_RECIPIENT = 'buwembovianney551@gmail.com'

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'aegisnet123'

def get_connection():
    return pymysql.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        database=DB_CONFIG['database'],
        charset='utf8',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/api/packets')
def get_packets():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_logs ORDER BY timestamp DESC LIMIT 50")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/api/devices')
def get_devices():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM connected_devices ORDER BY first_seen DESC")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/api/alerts')
def get_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/api/stats')
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total_packets FROM network_logs")
    packets = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) as total_devices FROM connected_devices")
    devices = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) as total_alerts FROM alerts")
    alerts = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify({
        'total_packets': packets['total_packets'],
        'total_devices': devices['total_devices'],
        'total_alerts': alerts['total_alerts']
    })

def start_capture():
    import packet_capture
    packet_capture.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        from database import verify_user
        user = verify_user(username, password)
        if user:
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def send_alert_email(alert_type, src_ip, description, severity):
    try:
        msg = Message(
            subject=f"[AegisNet Alert] {severity} - {alert_type}",
            recipients=[ALERT_EMAIL_RECIPIENT],
            body=f"""
AegisNet Security Alert
=======================
Alert Type : {alert_type}
Severity   : {severity}
Source IP  : {src_ip}
Description: {description}

This is an automated alert from AegisNet Network Security Monitor.
            """
        )
        mail.send(msg)
        print(f"[EMAIL] Alert sent for {alert_type} from {src_ip}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

@app.route('/export/packets')
def export_packets():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_logs ORDER BY timestamp DESC")
    data = cursor.fetchall()
    cursor.close()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Source IP', 'Destination IP', 'Protocol', 'Packet Size', 'Timestamp'])
    for row in data:
        writer.writerow([row['id'], row['src_ip'], row['dst_ip'], row['protocol'], row['packet_size'], row['timestamp']])

    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=aegisnet_packets.csv'}
    )

@app.route('/export/devices')
def export_devices():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM connected_devices ORDER BY first_seen DESC")
    data = cursor.fetchall()
    cursor.close()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'IP Address', 'MAC Address', 'Device Name', 'First Seen', 'Last Seen', 'Status'])
    for row in data:
        writer.writerow([row['id'], row['ip_address'], row['mac_address'], row['device_name'], row['first_seen'], row['last_seen'], row['status']])

    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=aegisnet_devices.csv'}
    )

@app.route('/export/alerts')
def export_alerts():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    data = cursor.fetchall()
    cursor.close()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Alert Type', 'Source IP', 'Description', 'Severity', 'Timestamp'])
    for row in data:
        writer.writerow([row['id'], row['alert_type'], row['src_ip'], row['description'], row['severity'], row['timestamp']])

    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=aegisnet_alerts.csv'}
    )

@app.route('/api/blocked')
def get_blocked():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    from database import get_blocked_ips
    data = get_blocked_ips()
    for row in data:
        if row.get('blocked_at'):
            row['blocked_at'] = str(row['blocked_at'])
    return jsonify(data)

@app.route('/block_ip', methods=['POST'])
def block_ip_route():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    from database import block_ip
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manually blocked by admin')
    block_ip(ip, reason)
    return jsonify({'status': 'blocked', 'ip': ip})

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip_route():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    from database import unblock_ip
    data = request.get_json()
    ip = data.get('ip')
    unblock_ip(ip)
    return jsonify({'status': 'unblocked', 'ip': ip})

@app.route('/export/blocked')
def export_blocked():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    from database import get_blocked_ips
    data = get_blocked_ips()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'IP Address', 'Reason', 'Blocked At'])
    for row in data:
        writer.writerow([row['id'], row['ip_address'], row['reason'], row['blocked_at']])
    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=aegisnet_blocked_ips.csv'}
    )

@app.route('/users')
def users_page():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('role') != 'superadmin':
        return redirect(url_for('index'))
    from database import get_all_users
    users = get_all_users()
    for u in users:
        if u.get('created_at'):
            u['created_at'] = str(u['created_at'])
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['POST'])
def add_user_route():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('role') != 'superadmin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    from database import add_user
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'admin')
    success = add_user(username, password, role)
    if success:
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Username already exists'})

@app.route('/delete_user', methods=['POST'])
def delete_user_route():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('role') != 'superadmin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    from database import delete_user
    data = request.get_json()
    user_id = data.get('id')
    success = delete_user(user_id)
    if success:
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'})
@app.route('/topology')
def topology():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('topology.html')

@app.route('/api/topology')
def get_topology():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, mac_address, status, first_seen FROM connected_devices")
    devices = cursor.fetchall()
    cursor.execute("SELECT ip_address FROM blocked_ips")
    blocked = [row['ip_address'] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    for d in devices:
        if d.get('first_seen'):
            d['first_seen'] = str(d['first_seen'])
        d['blocked'] = d['ip_address'] in blocked
    return jsonify(devices)

@app.route('/rename_device', methods=['POST'])
def rename_device():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = request.get_json()
    ip = data.get('ip')
    name = data.get('name')
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE connected_devices SET device_name = %s WHERE ip_address = %s",
            (name, ip)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/settings')
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = request.get_json()
    current = data.get('current_password')
    new_pass = data.get('new_password')
    username = session.get('username')
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = %s AND password = %s",
            (username, current)
        )
        user = cursor.fetchone()
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'})
        cursor.execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (new_pass, username)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/save_thresholds', methods=['POST'])
def save_thresholds():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    data = request.get_json()
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM settings")
        for key, value in data.items():
            cursor.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)",
                (key, value)
            )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/api/health')
def get_health():
    if not session.get('logged_in'):
        return jsonify({})
    import psutil
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    return jsonify({
        'cpu_percent': cpu,
        'memory_percent': memory.percent,
        'memory_used': round(memory.used / (1024 * 1024 * 1024), 2),
        'memory_total': round(memory.total / (1024 * 1024 * 1024), 2),
        'disk_percent': disk.percent,
        'disk_used': round(disk.used / (1024 * 1024 * 1024), 2),
        'disk_total': round(disk.total / (1024 * 1024 * 1024), 2),
        'bytes_sent': round(net.bytes_sent / (1024 * 1024), 2),
        'bytes_recv': round(net.bytes_recv / (1024 * 1024), 2)
    })

@app.route('/export/report')
def export_report():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM network_logs")
    total_packets = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as total FROM connected_devices")
    total_devices = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as total FROM alerts")
    total_alerts = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as total FROM blocked_ips")
    total_blocked = cursor.fetchone()['total']
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20")
    alerts = cursor.fetchall()
    cursor.execute("SELECT * FROM connected_devices ORDER BY first_seen DESC")
    devices = cursor.fetchall()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
    blocked = cursor.fetchall()
    cursor.close()
    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=50,
        bottomMargin=40
    )

    story = []
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#00d4ff'),
        spaceAfter=5
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#00d4ff'),
        spaceBefore=20,
        spaceAfter=10
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=5
    )
    sub_style = ParagraphStyle(
        'SubStyle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#666666'),
        spaceAfter=3
    )

    # Title
    story.append(Paragraph("AEGISNET", title_style))
    story.append(Paragraph("Network Security Monitoring Report", styles['Heading2']))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
        sub_style
    ))
    story.append(Spacer(1, 20))

    # Summary stats table
    story.append(Paragraph("Executive Summary", heading_style))
    summary_data = [
        ['Metric', 'Value'],
        ['Total Packets Captured', str(total_packets)],
        ['Devices Detected', str(total_devices)],
        ['Security Alerts', str(total_alerts)],
        ['Blocked IP Addresses', str(total_blocked)],
        ['Report Generated By', session.get('username', 'Admin')],
    ]
    summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 11),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTSIZE', (0,1), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f9ff'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Security Alerts
    story.append(Paragraph("Security Alerts", heading_style))
    if alerts:
        alert_data = [['Alert Type', 'Source IP', 'Severity', 'Description', 'Time']]
        for a in alerts:
            alert_data.append([
                str(a.get('alert_type', '')),
                str(a.get('src_ip', '')),
                str(a.get('severity', '')),
                str(a.get('description', ''))[:40],
                str(a.get('timestamp', ''))[:16]
            ])
        alert_table = Table(alert_data, colWidths=[1.3*inch, 1.2*inch, 0.9*inch, 2.2*inch, 1.4*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ff4d4d')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#fff5f5'), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(alert_table)
    else:
        story.append(Paragraph("No security alerts recorded.", normal_style))

    story.append(Spacer(1, 20))

    # Connected Devices
    story.append(Paragraph("Connected Devices", heading_style))
    if devices:
        device_data = [['IP Address', 'MAC Address', 'Device Name', 'First Seen', 'Status']]
        for d in devices:
            device_data.append([
                str(d.get('ip_address', '')),
                str(d.get('mac_address', '')),
                str(d.get('device_name', 'Unknown')),
                str(d.get('first_seen', ''))[:16],
                str(d.get('status', ''))
            ])
        device_table = Table(device_data, colWidths=[1.2*inch, 1.6*inch, 1.4*inch, 1.4*inch, 0.9*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00aa55')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5fff9'), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(device_table)
    else:
        story.append(Paragraph("No devices recorded.", normal_style))

    story.append(Spacer(1, 20))

    # Blocked IPs
    story.append(Paragraph("Blocked IP Addresses", heading_style))
    if blocked:
        blocked_data = [['IP Address', 'Reason', 'Blocked At']]
        for b in blocked:
            blocked_data.append([
                str(b.get('ip_address', '')),
                str(b.get('reason', '')),
                str(b.get('blocked_at', ''))[:16]
            ])
        blocked_table = Table(blocked_data, colWidths=[1.5*inch, 3.5*inch, 1.5*inch])
        blocked_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#cc4400')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#fff8f5'), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(blocked_table)
    else:
        story.append(Paragraph("No blocked IPs recorded.", normal_style))

    # Footer note
    story.append(Spacer(1, 30))
    story.append(Paragraph(
        "This report was automatically generated by AegisNet — Intelligent Network Security Monitoring Platform.",
        sub_style
    ))

    doc.build(story)
    buffer.seek(0)

    from flask import Response
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename=AegisNet_Security_Report_{datetime.datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
        }
    )

if __name__ == '__main__':
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()
    print("AegisNet Dashboard running at http://localhost:5000")
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)