# app/services/wazuh_websocket.py
import websocket  # ✅ Đúng - websocket-client được import là websocket
import json
import threading
import logging
import time
import ssl
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)

class WazuhWebSocket:
    """
    WebSocket client for Wazuh Indexer
    Receive REAL-TIME alerts instead of polling
    """
    
    def __init__(self, host="172.26.94.81", port=9200, user="admin", password="Admin123*"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ws = None
        self.callbacks = []
        self.running = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.recent_alerts = deque(maxlen=1000)
        
        # WebSocket URL for Wazuh Indexer
        self.ws_url = f"wss://{host}:{port}/_wazuh/_ws"
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def on_message(self, ws, message):
        """Handle message from WebSocket - ONLY WHEN NEW ALERT ARRIVES"""
        try:
            data = json.loads(message)
            timestamp = datetime.now().isoformat()
            
            # Log real-time
            print(f"\n🔔 [REAL-TIME] Alert received at {timestamp}")
            
            # Store in recent
            alert_data = {
                'timestamp': timestamp,
                'data': data
            }
            self.recent_alerts.append(alert_data)
            
            # Call all registered callbacks
            for callback in self.callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
        except Exception as e:
            logger.error(f"Message handler error: {e}")
    
    def on_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")
    
    def on_close(self, ws, close_status_code, close_msg):
        logger.warning(f"WebSocket closed: {close_status_code} - {close_msg}")
        self.running = False
        
        # Auto reconnect
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            wait_time = min(30, self.reconnect_attempts * 5)
            logger.info(f"Reconnecting in {wait_time}s (attempt {self.reconnect_attempts})")
            time.sleep(wait_time)
            self.start()
    
    def on_open(self, ws):
        logger.info("✅ Connected to Wazuh Indexer WebSocket")
        self.running = True
        self.reconnect_attempts = 0
        
        # Send authentication
        auth_msg = {
            "type": "auth",
            "username": self.user,
            "password": self.password
        }
        ws.send(json.dumps(auth_msg))
        
        # Subscribe to alerts
        subscribe_msg = {
            "type": "subscribe",
            "channel": "alerts"
        }
        ws.send(json.dumps(subscribe_msg))
        logger.info("📡 Subscribed to alerts channel")
    
    def start(self):
        """Start WebSocket connection"""
        try:
            logger.info(f"Connecting to WebSocket: {self.ws_url}")
            
            # ✅ Sửa: Tạo WebSocketApp từ module websocket
            self.ws = websocket.WebSocketApp(
                self.ws_url,
                on_open=self.on_open,
                on_message=self.on_message,
                on_error=self.on_error,
                on_close=self.on_close
            )
            
            # Run in separate thread
            wst = threading.Thread(
                target=self.ws.run_forever,
                kwargs={
                    'sslopt': {
                        'cert_reqs': ssl.CERT_NONE,
                        'check_hostname': False
                    }
                }
            )
            wst.daemon = True
            wst.start()
            
            logger.info("✅ WebSocket thread started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop(self):
        """Stop WebSocket"""
        self.running = False
        if self.ws:
            self.ws.close()
            self.ws = None
        logger.info("WebSocket stopped")
    
    def register_callback(self, callback):
        """Register callback for new alerts"""
        self.callbacks.append(callback)
        logger.info(f"Registered callback: {callback.__name__}")
    
    def get_recent_alerts(self, limit=100):
        """Get recent alerts"""
        return list(self.recent_alerts)[-limit:]