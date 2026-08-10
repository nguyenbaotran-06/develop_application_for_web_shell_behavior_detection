# app/models/database.py
import sqlite3
import pandas as pd
import os
import gzip
import shutil
import json
from datetime import datetime, timedelta
import threading
import time

class DatabaseManager:
    def __init__(self, db_path=None):
        # 🔥 Tạo thư mục data/
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.data_dir = os.path.join(base_dir, 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # 🔥 Các thư mục con
        self.log_dir = os.path.join(self.data_dir, 'logs')
        self.archive_dir = os.path.join(self.data_dir, 'archives')
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        
        # 🔥 Đường dẫn DB
        if db_path is None:
            db_path = os.path.join(self.data_dir, 'edr.db')
        self.db_path = db_path
        
        self._init_db()
        self._start_cleanup_thread()
        print(f"📁 Data directory: {self.data_dir}")
    
    def _init_db(self):
        """Khởi tạo database và bảng"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Bảng alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                group_key TEXT,
                agent_name TEXT,
                confidence REAL,
                is_malicious INTEGER,
                message TEXT,
                level INTEGER,
                events_count INTEGER,
                features TEXT,
                processing_time REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Bảng events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                event_id INTEGER,
                command_line TEXT,
                image TEXT,
                process_guid TEXT,
                target_filename TEXT,
                user TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"✅ Database initialized at: {self.db_path}")
    
    def save_alert(self, alert_data, events, features, processing_time=0):
        """Lưu alert vào DB và file JSON"""
        
        # === LƯU VÀO DB ===
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (
                timestamp, group_key, agent_name, confidence, 
                is_malicious, message, level, events_count, features, processing_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data.get('timestamp'),
            alert_data.get('group_key', ''),
            alert_data.get('agent_name', 'Unknown'),
            alert_data.get('confidence', 0.0),
            1 if alert_data.get('is_malicious') else 0,
            alert_data.get('message', ''),
            alert_data.get('level', 0),
            len(events),
            json.dumps(features) if features else '',
            processing_time
        ))
        
        alert_id = cursor.lastrowid
        
        # Lưu events
        for event in events:
            cursor.execute('''
                INSERT INTO events (
                    alert_id, event_id, command_line, image,
                    process_guid, target_filename, user
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_id,
                event.get('EventID', 0),
                event.get('CommandLine', '')[:500],
                event.get('Image', ''),
                event.get('ProcessGuid', ''),
                event.get('TargetFilename', '')[:500],
                event.get('User', '')
            ))
        
        conn.commit()
        conn.close()
        
        # === LƯU VÀO FILE JSON ===
        self._save_to_json(alert_data, events, features, processing_time, alert_id)
        
        # === LƯU VÀO LOG FILE ===
        self._save_to_json(alert_data, events, features, processing_time, alert_id)
        self._save_to_log(alert_data, events)
        print(f"💾 Saved alert {alert_id} to data/")
    
    def _save_to_json(self, alert_data, events, features, processing_time, alert_id):
        """Lưu alert ra file JSON"""
        filename = os.path.join(self.log_dir, f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{alert_id}.json")
        
        data = {
            'alert_id': alert_id,
            'timestamp': alert_data.get('timestamp'),
            'group_key': alert_data.get('group_key'),
            'agent_name': alert_data.get('agent_name'),
            'confidence': alert_data.get('confidence'),
            'is_malicious': alert_data.get('is_malicious'),
            'message': alert_data.get('message'),
            'level': alert_data.get('level'),
            'processing_time': processing_time,
            'events': [
                {
                    'event_id': e.get('EventID'),
                    'command': e.get('CommandLine', '')[:200],
                    'image': e.get('Image', ''),
                    'target': e.get('TargetFilename', ''),
                    'user': e.get('User', '')
                }
                for e in events
            ],
            'features': features if features else {},
            'saved_at': datetime.now().isoformat()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _save_to_log(self, alert_data, events):
        """Lưu alert vào log file dạng text"""
        log_file = os.path.join(self.log_dir, 'alerts.log')
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"🔴 ALERT at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Message: {alert_data.get('message')}\n")
            f.write(f"Level: {alert_data.get('level')}\n")
            f.write(f"Agent: {alert_data.get('agent_name')}\n")
            f.write(f"Confidence: {alert_data.get('confidence')}\n")
            f.write(f"Events: {len(events)}\n")
            for i, e in enumerate(events, 1):
                f.write(f"  {i}. EventID: {e.get('EventID')} | {e.get('CommandLine', '')[:50]}\n")
            f.write(f"{'='*60}\n")
    
    def get_recent_alerts(self, limit=100):
        """Lấy alert gần đây - trả về list of dict"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    id, timestamp, group_key, agent_name, confidence, 
                    is_malicious, message, level, events_count, features, 
                    processing_time, created_at
                FROM alerts 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            results = cursor.fetchall()
            conn.close()
            
            # Kiểm tra kết quả
            if not results:
                return []
            
            # Chuyển thành list of dict
            return [dict(row) for row in results]
        except Exception as e:
            print(f"❌ DB error: {e}")
            return []
    
    def _start_cleanup_thread(self):
        """Thread dọn dẹp dữ liệu cũ"""
        def cleanup_worker():
            while True:
                time.sleep(3600)
                self._cleanup_old_data()
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def _cleanup_old_data(self):
        """Xóa dữ liệu cũ theo quy tắc quay vòng"""
        now = datetime.now()
        three_months_ago = now - timedelta(days=90)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM alerts WHERE created_at < ?', 
                      (three_months_ago.isoformat(),))
        cursor.execute('DELETE FROM events WHERE created_at < ?', 
                      (three_months_ago.isoformat(),))
        
        conn.commit()
        conn.close()