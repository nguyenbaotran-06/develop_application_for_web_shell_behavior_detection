# app/__init__.py
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
import logging
import sys

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-here'
    
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # ✅ Tắt WebSocket debug
    socketio.init_app(
        app,
        cors_allowed_origins="*",
        async_mode='threading',
        ping_timeout=60,
        ping_interval=25,
        logger=False,
        engineio_logger=False
    )
    
    from app.main import main_bp
    from app.routes.webhook import webhook_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(webhook_bp)
    
    # ✅ Tắt WebSocket client trong Wazuh API
    with app.app_context():
        from app.services.wazuh_api import WazuhAPI
        
        print("\n" + "="*60)
        print("🛡️ EDR SYSTEM - WEBHOOK MODE")
        print("="*60)
        
        api = WazuhAPI()
        api.use_websocket = False  # ✅ Tắt WebSocket
        app.wazuh_api = api
        
        initial_alerts = api.get_alerts_initial(50)
        #print(f"📊 Initial alerts loaded: {len(initial_alerts)}")
        
        # ✅ Lấy IP thực tế
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        print("\n📡 WEBHOOK ENDPOINTS:")
        print(f"   POST http://0.0.0.0:5000/webhook ")
        #print(f"   GET  http://0.0.0.0:5000/webhook/test <- Test webhook")
        print(f"\n🔗 DASHBOARD IP: {local_ip}")
        print(f"\n💡 CONFIG WAZUH (use this IP):")
        print(f"   <integration>")
        print(f"     <name>custom-webhook</name>")
        print(f"     <hook_url>http://{local_ip}:5000/webhook</hook_url>")
        print(f"     <level>3</level>")
        print(f"     <alert_format>json</alert_format>")
        print(f"   </integration>")
        print("="*60 + "\n")
    
    return app