# run.py
import sys
import os
import logging

# Fix Unicode for Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    # 🔥 TẮT LOG CỦA WERKZEUG (Flask)
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # 🔥 TẮT LOG CỦA ENGINEIO VÀ SOCKETIO
    logging.getLogger('engineio').setLevel(logging.ERROR)
    logging.getLogger('socketio').setLevel(logging.ERROR)
    
    print("\n" + "="*60)
    print("🛡️ EDR DASHBOARD - REAL-TIME MODE")
    print("="*60)
    print("📡 WebSocket: ENABLED")
    print("🔄 Polling: DISABLED (fallback only)")
    print("🚀 Server: http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,           # 🔥 TẮT DEBUG
        use_reloader=False,    # 🔥 TẮT RELOADER
        log_output=False,      # 🔥 TẮT LOG OUTPUT
        allow_unsafe_werkzeug=True
    )