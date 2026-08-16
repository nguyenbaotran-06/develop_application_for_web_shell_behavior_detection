# app/services/wazuh_api.py
import requests
import json
import logging
from app.config import Config
from app.services.wazuh_websocket import WazuhWebSocket

logger = logging.getLogger(__name__)

class WazuhAPI:
    def __init__(self, host=None, port=None, user=None, password=None):
        # Indexer API (for alerts)
        self.indexer_host = "172.26.94.81"
        self.indexer_port = 9200
        self.indexer_user = "admin"
        self.indexer_password = "Admin123*"
        
        # Wazuh API (for agents)
        self.wazuh_host = "172.26.94.81"
        self.wazuh_port = 55000
        self.wazuh_user = "wazuh-wui"
        self.wazuh_password = "wazuh-wui"
        
        self.token = None
        self.connected = False
        
        # WebSocket for real-time
        self.ws = None
        self.use_websocket = False
        self.alert_callbacks = []
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Auto init WebSocket
        self.init_websocket()
    
    def init_websocket(self):
        """Initialize WebSocket connection for real-time alerts"""
        if not self.use_websocket:
            return False
        
        try:
            self.ws = WazuhWebSocket(
                host=self.indexer_host,
                port=self.indexer_port,
                user=self.indexer_user,
                password=self.indexer_password
            )
            
            # Register callback for new alerts
            self.ws.register_callback(self._on_new_alert)
            
            # Start WebSocket
            if self.ws.start():
                logger.info("✅ WebSocket real-time alerts ENABLED")
                logger.info("   - Polling disabled for alerts")
                logger.info("   - Only use polling for initial load")
                return True
            else:
                logger.warning("⚠️ WebSocket failed, falling back to polling")
                self.use_websocket = False
                return False
                
        except Exception as e:
            logger.error(f"WebSocket init error: {e}")
            self.use_websocket = False
            return False
    
    def _on_new_alert(self, alert_data):
        """
        Callback when new alert arrives via WebSocket
        This is where REAL-TIME processing happens
        """
        try:
            alert = alert_data.get('data', {})
            timestamp = alert_data.get('timestamp')
            
            # 🔥 THÊM: Chạy ML detection trên alert mới
            confidence = 0.0
            is_malicious = False
            
            try:
                from app.models.detector import WebShellDetector
                detector = WebShellDetector()
                result = detector.predict_log(alert)
                if result and isinstance(result, dict):
                    confidence = result.get('confidence', 0.0)
                    is_malicious = result.get('is_malicious', False)
                    
                    # Thêm confidence vào alert
                    alert['ml_confidence'] = confidence
                    alert['is_malicious'] = is_malicious
                    
                    if is_malicious:
                        logger.info(f"🔴 MALICIOUS DETECTED: {alert.get('rule', {}).get('description')} (conf: {confidence:.2f})")
                        
            except Exception as e:
                logger.error(f"ML detection error: {e}")
            
            # Print to console
            print(f"\n{'='*60}")
            print(f"🔔 NEW ALERT REAL-TIME")
            print(f"{'='*60}")
            print(f"⏰ Time: {timestamp}")
            print(f"📋 Rule: {alert.get('rule', {}).get('description', 'Unknown')}")
            print(f"📊 Level: {alert.get('rule', {}).get('level', 0)}")
            print(f"🖥️  Agent: {alert.get('agent', {}).get('name', 'Unknown')}")
            
            # 🔥 SHOW ML RESULT
            if confidence > 0:
                print(f"🧠 ML Confidence: {confidence:.2%}")
                if is_malicious:
                    print("🔴 STATUS: MALICIOUS DETECTED!")
                else:
                    print("🟢 STATUS: Normal")
            print(f"{'='*60}\n")
            
            # Call registered callbacks (for dashboard)
            for callback in self.alert_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing real-time alert: {e}")
    
    def register_alert_callback(self, callback):
        """Register callback for real-time alerts"""
        self.alert_callbacks.append(callback)
        logger.info(f"Registered alert callback: {callback.__name__}")
    
    # ===== WAZUH API (for agents) =====
    def authenticate_wazuh(self):
        try:
            url = f"https://{self.wazuh_host}:{self.wazuh_port}/security/user/authenticate?raw=true"

            response = requests.get(
                url,
                auth=(self.wazuh_user, self.wazuh_password),
                verify=False,
                timeout=10
            )

            if response.status_code == 200:
                self.token = response.text.strip().strip('"')
                self.connected = True
                logger.info("✅ Connected to Wazuh API")
                return True

            logger.error(f"Auth failed: {response.status_code} - {response.text}")
            return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def _ensure_wazuh_auth(self):
        if not self.connected or not self.token:
            return self.authenticate_wazuh()
        return True
    
    def get_agents(self):
        """Get agents from Wazuh API (port 55000)"""
        if not self._ensure_wazuh_auth():
            return []
        
        try:
            url = f"https://{self.wazuh_host}:{self.wazuh_port}/agents"
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                agents = data.get('data', {}).get('affected_items', [])
                logger.info(f"Found {len(agents)} agents")
                return agents
            else:
                logger.error(f"Failed: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error: {e}")
            return []
    
    # ===== INDEXER API (for alerts - INITIAL LOAD ONLY) =====
    def get_alerts_initial(self, limit=100):
        """
        Get alerts ONCE on initialization
        After that, use WebSocket for real-time
        """
        if self.use_websocket and self.ws:
            logger.info("📡 Using WebSocket for real-time alerts")
            recent = self.ws.get_recent_alerts(limit)
            logger.info(f"📊 Loaded {len(recent)} recent alerts from WebSocket")
            return [a['data'] for a in recent]
        
        # Fallback to polling (only when WebSocket not available)
        logger.warning("⚠️ WebSocket not available, using polling (fallback)")
        return self._poll_alerts(limit)
    
    def _poll_alerts(self, limit=100):
        """Polling alerts (fallback when WebSocket is down)"""
        try:
            url = f"https://{self.indexer_host}:{self.indexer_port}/wazuh-alerts/_search?size={limit}"
            auth = (self.indexer_user, self.indexer_password)
            
            query = {
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            response = requests.get(
                url,
                auth=auth,
                json=query,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                alerts = [hit.get('_source', {}) for hit in hits]
                logger.info(f"📊 Fetched {len(alerts)} alerts from Indexer (polling)")
                return alerts
            else:
                logger.error(f"Failed: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error: {e}")
            return []
    
    def get_stats(self):
        """Get statistics"""
        try:
            url = f"https://{self.indexer_host}:{self.indexer_port}/_cat/indices?v"
            auth = (self.indexer_user, self.indexer_password)
            response = requests.get(url, auth=auth, verify=False, timeout=10)
            if response.status_code == 200:
                return {"indices": response.text}
            return {}
        except Exception as e:
            return {}