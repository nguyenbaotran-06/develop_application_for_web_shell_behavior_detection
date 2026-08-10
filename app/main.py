# app/main.py
from flask import Blueprint, jsonify, render_template, current_app, request, Response
from flask_socketio import emit
from app import socketio
import logging
import json
import os
import glob
from datetime import datetime

main_bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

# Đường dẫn thư mục logs
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'data', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

def get_api():
    return current_app.wazuh_api

@main_bp.route('/')
def index():
    """Dashboard"""
    return render_template('dashboard.html')

# ===== 🔥 API HISTORY TỪ FILE JSON =====

@main_bp.route('/api/alerts/history')
def get_alerts_history():
    """Lấy lịch sử alerts từ file JSON"""
    try:
        # Tìm tất cả file JSON trong thư mục logs
        json_files = glob.glob(os.path.join(LOG_DIR, 'alert_*.json'))
        
        if not json_files:
            return jsonify({'alerts': [], 'total': 0})
        
        alerts = []
        for filepath in sorted(json_files, reverse=True):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    alerts.append(data)
            except Exception as e:
                print(f"⚠️ Error reading {filepath}: {e}")
                continue
        
        # Giới hạn 100 alerts
        alerts = alerts[:100]
        
        # Format cho frontend
        formatted = []
        for alert in alerts:
            formatted.append({
                'id': alert.get('alert_id'),
                'timestamp': alert.get('timestamp'),
                'message': alert.get('message'),
                'level': alert.get('level'),
                'agent_name': alert.get('agent_name'),
                'confidence': alert.get('confidence'),
                'is_malicious': alert.get('is_malicious', False),
                'created_at': alert.get('saved_at'),
                'events': alert.get('events', []),
                'processing_time': alert.get('processing_time')
            })
        
        return jsonify({
            'alerts': formatted,
            'total': len(formatted)
        })
        
    except Exception as e:
        print(f"❌ History error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'alerts': [], 'total': 0, 'error': str(e)}), 500

# ===== 🔥 API CHI TIẾT ALERT =====

@main_bp.route('/api/alerts/<int:alert_id>')
def get_alert_detail(alert_id):
    """Lấy chi tiết một alert từ file JSON"""
    try:
        # Tìm file JSON theo alert_id
        pattern = os.path.join(LOG_DIR, f'*_{alert_id}.json')
        files = glob.glob(pattern)
        
        if not files:
            return jsonify({'error': 'Alert not found'}), 404
        
        with open(files[0], 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return jsonify(data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== 🔥 EXPORT ALERTS =====

@main_bp.route('/api/alerts/export')
def export_alerts():
    """Export alerts ra file CSV từ JSON"""
    try:
        import csv
        import io
        
        json_files = glob.glob(os.path.join(LOG_DIR, 'alert_*.json'))
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Timestamp', 'Message', 'Level', 'Agent', 'Confidence', 'Malicious'])
        
        for filepath in sorted(json_files, reverse=True)[:1000]:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    alert = json.load(f)
                    writer.writerow([
                        alert.get('alert_id'),
                        alert.get('timestamp'),
                        alert.get('message'),
                        alert.get('level'),
                        alert.get('agent_name'),
                        alert.get('confidence'),
                        'Yes' if alert.get('is_malicious') else 'No'
                    ])
            except:
                continue
        
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                       headers={'Content-Disposition': 'attachment; filename=alerts_export.csv'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== 🔥 ARCHIVES =====

@main_bp.route('/api/archives')
def list_archives():
    """Liệt kê các file archive"""
    try:
        archive_dir = os.path.join(BASE_DIR, 'data', 'archives')
        os.makedirs(archive_dir, exist_ok=True)
        
        files = []
        for f in glob.glob(os.path.join(archive_dir, '*.gz')):
            stat = os.stat(f)
            files.append({
                'name': os.path.basename(f),
                'size': stat.st_size,
                'modified': stat.st_mtime
            })
        
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'files': [], 'error': str(e)}), 500

@main_bp.route('/api/archives/download/<filename>')
def download_archive(filename):
    """Download file archive"""
    try:
        from flask import send_file
        archive_dir = os.path.join(BASE_DIR, 'data', 'archives')
        filepath = os.path.join(archive_dir, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== CÁC ROUTE KHÁC =====

@main_bp.route('/api/alerts')
def get_alerts():
    """Get alerts via HTTP (fallback)"""
    api = get_api()
    alerts = api.get_alerts(100)
    return jsonify({
        'alerts': alerts,
        'total': len(alerts),
        'source': 'cache'
    })

@main_bp.route('/api/stats')
def get_stats():
    """Get statistics"""
    api = get_api()
    agents = api.get_agents()
    
    return jsonify({
        'active_agents': len(agents),
        'mode': 'webhook + polling',
        'status': 'running'
    })

@main_bp.route('/api/agents')
def get_agents():
    """Get agents list"""
    api = get_api()
    agents = api.get_agents()
    return jsonify({
        'agents': agents,
        'total': len(agents)
    })

# ===== SOCKET.IO EVENTS =====

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    logger.info(f"Client connected: {request.sid}")
    emit('history', {
        'alerts': [],
        'total': 0,
        'mode': 'webhook'
    })

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")