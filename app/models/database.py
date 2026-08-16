# app/models/database.py
import sqlite3
import os
import gzip
import shutil
import json
from datetime import datetime, timedelta
import threading
import time
import zipfile

class DatabaseManager:
    def __init__(self, db_path=None):
        # 🔥 Tạo thư mục data/
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.data_dir = os.path.join(base_dir, 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # 🔥 Các thư mục con - CHỈ GIỮ NHỮNG CẦN THIẾT
        self.log_dir = os.path.join(self.data_dir, 'logs')
        self.current_dir = os.path.join(self.log_dir, 'current')          # JSON trực tiếp trong logs/
        self.weekly_zip_dir = os.path.join(self.log_dir, 'weekly_zip')    # ZIP theo tuần
        self.archive_log_dir = os.path.join(self.log_dir, 'archive_log')  # Text log cũ
        
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.current_dir, exist_ok=True)
        os.makedirs(self.weekly_zip_dir, exist_ok=True)
        os.makedirs(self.archive_log_dir, exist_ok=True)
        
        # 🔥 Đường dẫn DB
        if db_path is None:
            db_path = os.path.join(self.data_dir, 'edr.db')
        self.db_path = db_path
        
        # 🔥 Cấu hình
        self.retention_days = 90      # Giữ log bao nhiêu ngày
        self.max_log_size_mb = 10     # Max size của alerts.log (MB)
        self.max_all_events_size_mb = 10  # 🔥 Max size của all_events.log (MB)
        
        # 🔥 File log cho tất cả sự kiện
        self.all_events_log = os.path.join(self.log_dir, 'all_events.log')
        self.all_events_archive_dir = os.path.join(self.archive_log_dir, 'all_events')
        os.makedirs(self.all_events_archive_dir, exist_ok=True)
        
        # 🔥 File để lưu trạng thái weekly zip (persistent)
        self.state_file = os.path.join(self.log_dir, 'weekly_zip_state.json')
        
        self._load_weekly_zip_state()
        
        self._init_db()
        self._start_cleanup_thread()
        print(f"📁 Data directory: {self.data_dir}")
        print(f"📅 Log retention: {self.retention_days} days")
        print(f"📋 All events log: {self.all_events_log}")
    
    def _load_weekly_zip_state(self):
        """Load trạng thái weekly zip từ file"""
        self.weekly_zip_state = {
            'last_week_zipped': None,
            'files_zipped': []
        }
        
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    saved_state = json.load(f)
                    self.weekly_zip_state.update(saved_state)
                print(f"📂 Loaded weekly zip state: {self.weekly_zip_state['last_week_zipped']}")
            except Exception as e:
                print(f"⚠️ Failed to load state: {e}")
    
    def _save_weekly_zip_state(self):
        """Lưu trạng thái weekly zip vào file"""
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.weekly_zip_state, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save state: {e}")
    
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
    
    # 🔥 HÀM LƯU 1 SỰ KIỆN RIÊNG LẺ (GỌI NGAY KHI NHẬN)
    def save_single_event_to_log(self, event):
        """
        🔥 Lưu 1 sự kiện riêng lẻ vào all_events.log (KHÔNG CẦN ĐỢI)
        event: dict - 1 event đơn lẻ
        """
        log_file = self.all_events_log
        
        # 🔥 Kiểm tra kích thước file - ROTATION THEO DUNG LƯỢNG
        if os.path.exists(log_file):
            size_mb = os.path.getsize(log_file) / (1024 * 1024)
            if size_mb > self.max_all_events_size_mb:
                self._rotate_all_events_log(log_file)
        
        # 🔥 Ghi 1 event vào log (1 dòng)
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(
                    f"[{event.get('TimeCreated', datetime.now().isoformat())}] | "
                    f"EventID: {event.get('EventID', 0)} | "
                    f"User: {event.get('User', '')} | "
                    f"Command: {event.get('CommandLine', '')[:200]} | "
                    f"Image: {event.get('Image', '')} | "
                    f"Target: {event.get('TargetFilename', '')} | "
                    f"SourceIP: {event.get('SourceIp', '')} | "
                    f"DestIP: {event.get('DestinationIp', '')} | "
                    f"IsMalicious: Unknown\n"
                )
            print(f"📝 Saved single event: EventID={event.get('EventID')}")
            return True
        except Exception as e:
            print(f"❌ Error saving single event: {e}")
            return False
    
    # 🔥 HÀM LƯU NHIỀU SỰ KIỆN (GỌI SAU KHI PHÂN TÍCH)
    def save_all_events_to_log(self, events, is_malicious=False):
        """
        🔥 Lưu tất cả sự kiện vào all_events.log (mỗi event 1 dòng)
        events: list of dict
        is_malicious: bool - label cho cả batch
        """
        log_file = self.all_events_log
        
        # 🔥 Kiểm tra kích thước file - ROTATION THEO DUNG LƯỢNG
        if os.path.exists(log_file):
            size_mb = os.path.getsize(log_file) / (1024 * 1024)
            if size_mb > self.max_all_events_size_mb:
                self._rotate_all_events_log(log_file)
        
        # 🔥 Ghi tất cả events vào log (mỗi event 1 dòng)
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                for event in events:
                    f.write(
                        f"[{event.get('TimeCreated', datetime.now().isoformat())}] | "
                        f"EventID: {event.get('EventID', 0)} | "
                        f"User: {event.get('User', '')} | "
                        f"Command: {event.get('CommandLine', '')[:200]} | "
                        f"Image: {event.get('Image', '')} | "
                        f"Target: {event.get('TargetFilename', '')} | "
                        f"SourceIP: {event.get('SourceIp', '')} | "
                        f"DestIP: {event.get('DestinationIp', '')} | "
                        f"IsMalicious: {is_malicious}\n"
                    )
            print(f"📝 Saved {len(events)} events to all_events.log")
        except Exception as e:
            print(f"❌ Error saving all_events.log: {e}")
    
    def _rotate_all_events_log(self, log_file):
        """Xoay vòng all_events.log (nén thành .gz)"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.all_events_archive_dir, f'all_events_{timestamp}.log')
        
        shutil.move(log_file, backup_file)
        print(f"🔄 All events log rotated: {os.path.basename(backup_file)}")
        
        try:
            with open(backup_file, 'rb') as f_in:
                with gzip.open(f"{backup_file}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(backup_file)
            print(f"🗜️ Compressed: {os.path.basename(backup_file)}.gz")
        except Exception as e:
            print(f"❌ Compress error: {e}")
    
    def save_alert(self, alert_data, events, features, processing_time=0):
        """Lưu alert vào DB và file JSON (CHỈ MALICIOUS)"""
        
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
        self._save_to_log(alert_data, events)
        print(f"💾 Saved alert {alert_id} to data/")
        
        # 🔥 Kiểm tra weekly zip sau mỗi alert
        self._check_weekly_zip()
    
    def _save_to_json(self, alert_data, events, features, processing_time, alert_id):
        """Lưu alert ra file JSON (CHỈ MALICIOUS)"""
        filename = os.path.join(self.current_dir, f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{alert_id}.json")
        
        source_ips = alert_data.get('source_ips', [])
        dest_ips = alert_data.get('dest_ips', [])
        
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
            'source_ips': source_ips,
            'dest_ips': dest_ips,
            'events': [
                {
                    'event_id': e.get('EventID'),
                    'command': e.get('CommandLine', '')[:200],
                    'image': e.get('Image', ''),
                    'target': e.get('TargetFilename', ''),
                    'user': e.get('User', ''),
                    'source_ip': e.get('SourceIp', ''),
                    'dest_ip': e.get('DestinationIp', '')
                }
                for e in events
            ],
            'features': features if features else {},
            'saved_at': datetime.now().isoformat()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _save_to_log(self, alert_data, events):
        """Lưu alert vào log file dạng text với rotation"""
        log_file = os.path.join(self.log_dir, 'alerts.log')
        
        if os.path.exists(log_file):
            size_mb = os.path.getsize(log_file) / (1024 * 1024)
            if size_mb > self.max_log_size_mb:
                self._rotate_log_file(log_file)
        
        source_ips = alert_data.get('source_ips', [])
        dest_ips = alert_data.get('dest_ips', [])
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"🔴 ALERT at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Message: {alert_data.get('message')}\n")
            f.write(f"Level: {alert_data.get('level')}\n")
            f.write(f"Agent: {alert_data.get('agent_name')}\n")
            f.write(f"Confidence: {alert_data.get('confidence')}\n")
            f.write(f"Events: {len(events)}\n")
            
            if source_ips:
                f.write(f"Source IPs: {', '.join(source_ips)}\n")
            if dest_ips:
                f.write(f"Dest IPs: {', '.join(dest_ips)}\n")
            
            for i, e in enumerate(events, 1):
                source_ip = e.get('SourceIp', '')
                dest_ip = e.get('DestinationIp', '')
                ip_info = f" [src:{source_ip}->dst:{dest_ip}]" if source_ip or dest_ip else ""
                f.write(f"  {i}. EventID: {e.get('EventID')} | {e.get('CommandLine', '')[:50]}{ip_info}\n")
            f.write(f"{'='*60}\n")
    
    def _rotate_log_file(self, log_file):
        """Xoay vòng log file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.archive_log_dir, f'alerts_{timestamp}.log')
        
        shutil.move(log_file, backup_file)
        print(f"🔄 Log rotated: {os.path.basename(backup_file)}")
        self._compress_file(backup_file)
    
    def _compress_file(self, file_path):
        """Nén file thành .gz"""
        try:
            with open(file_path, 'rb') as f_in:
                with gzip.open(f"{file_path}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(file_path)
            print(f"🗜️ Compressed: {os.path.basename(file_path)}.gz")
        except Exception as e:
            print(f"❌ Compress error: {e}")
    
    def _get_previous_week(self, year, week):
        if week > 1:
            return year, week - 1
        else:
            prev_year = year - 1
            last_week = datetime(prev_year, 12, 28).isocalendar()[1]
            return prev_year, last_week
    
    def _check_weekly_zip(self):
        """Gom JSON alert thành 1 file ZIP theo tuần"""
        now = datetime.now()
        current_year = now.year
        current_week = now.isocalendar()[1]
        
        prev_year, prev_week = self._get_previous_week(current_year, current_week)
        prev_week_key = f"{prev_year}_W{prev_week:02d}"
        
        if self.weekly_zip_state.get('last_week_zipped') == prev_week_key:
            return
        
        json_files = []
        for filename in os.listdir(self.current_dir):
            if filename.startswith('alert_') and filename.endswith('.json'):
                file_path = os.path.join(self.current_dir, filename)
                try:
                    parts = filename.split('_')
                    if len(parts) >= 3:
                        date_str = parts[1]
                        file_date = datetime.strptime(date_str, '%Y%m%d')
                        file_year = file_date.year
                        file_week = file_date.isocalendar()[1]
                        
                        if file_year == prev_year and file_week == prev_week:
                            json_files.append(file_path)
                except Exception as e:
                    print(f"⚠️ Weekly zip error for {filename}: {e}")
        
        if json_files:
            zip_filename = f"week_{prev_week:02d}_{prev_year}.zip"
            zip_path = os.path.join(self.weekly_zip_dir, zip_filename)
            
            try:
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in json_files:
                        arcname = os.path.basename(file_path)
                        zipf.write(file_path, arcname)
                        os.remove(file_path)
                        print(f"📦 Added to zip: {arcname}")
                
                print(f"✅ Created weekly zip: {zip_filename} ({len(json_files)} files)")
                self.weekly_zip_state['last_week_zipped'] = prev_week_key
                self.weekly_zip_state['files_zipped'] = [os.path.basename(f) for f in json_files]
                self._save_weekly_zip_state()
            except Exception as e:
                print(f"❌ Weekly zip error: {e}")
    
    def _cleanup_old_data(self):
        """Xóa dữ liệu cũ theo quy tắc quay vòng"""
        now = datetime.now()
        cutoff_date = now - timedelta(days=self.retention_days)
        
        print(f"🧹 Cleaning up data older than {self.retention_days} days...")
        
        # 1. Xóa trong SQLite
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM alerts WHERE created_at < ?', (cutoff_date.isoformat(),))
            cursor.execute('DELETE FROM events WHERE created_at < ?', (cutoff_date.isoformat(),))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ DB cleanup error: {e}")
        
        # 2. Xóa current JSON files cũ
        try:
            for filename in os.listdir(self.current_dir):
                if filename.startswith('alert_') and filename.endswith('.json'):
                    file_path = os.path.join(self.current_dir, filename)
                    try:
                        parts = filename.split('_')
                        if len(parts) >= 3:
                            date_str = parts[1]
                            file_date = datetime.strptime(date_str, '%Y%m%d')
                            if (now - file_date).days > self.retention_days:
                                os.remove(file_path)
                                print(f"🗑️ Deleted old JSON: {filename}")
                    except Exception as e:
                        print(f"⚠️ Cleanup error for {filename}: {e}")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
        
        # 3. Xóa weekly zip files cũ
        try:
            if os.path.exists(self.weekly_zip_dir):
                for filename in os.listdir(self.weekly_zip_dir):
                    if filename.endswith('.zip'):
                        file_path = os.path.join(self.weekly_zip_dir, filename)
                        try:
                            parts = filename.replace('.zip', '').split('_')
                            if len(parts) >= 3:
                                week_num = int(parts[-2])
                                year = int(parts[-1])
                                first_day = datetime.strptime(f"{year}-W{week_num:02d}-1", "%Y-W%W-%w")
                                if (now - first_day).days > self.retention_days:
                                    os.remove(file_path)
                                    print(f"🗑️ Deleted old zip: {filename}")
                        except Exception as e:
                            print(f"⚠️ Zip cleanup error for {filename}: {e}")
        except Exception as e:
            print(f"❌ Zip cleanup error: {e}")
        
        # 4. Xóa log files cũ (.log.gz)
        try:
            if os.path.exists(self.archive_log_dir):
                for filename in os.listdir(self.archive_log_dir):
                    if filename.endswith('.log.gz'):
                        file_path = os.path.join(self.archive_log_dir, filename)
                        file_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if (now - file_modified).days > self.retention_days:
                            os.remove(file_path)
                            print(f"🗑️ Deleted old log archive: {filename}")
        except Exception as e:
            print(f"❌ Log cleanup error: {e}")
        
        # 5. Xóa all_events archive cũ
        try:
            if os.path.exists(self.all_events_archive_dir):
                for filename in os.listdir(self.all_events_archive_dir):
                    file_path = os.path.join(self.all_events_archive_dir, filename)
                    if os.path.isfile(file_path):
                        file_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if (now - file_modified).days > self.retention_days:
                            os.remove(file_path)
                            print(f"🗑️ Deleted old all_events archive: {filename}")
        except Exception as e:
            print(f"❌ All_events archive cleanup error: {e}")
        
        print(f"🧹 Cleanup completed. Kept logs from last {self.retention_days} days")
    
    def _start_cleanup_thread(self):
        def cleanup_worker():
            while True:
                time.sleep(3600)
                self._cleanup_old_data()
                self._check_weekly_zip()
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def get_recent_alerts(self, limit=100):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, group_key, agent_name, confidence, 
                       is_malicious, message, level, events_count, features, 
                       processing_time, created_at
                FROM alerts ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            results = cursor.fetchall()
            conn.close()
            if not results:
                return []
            return [dict(row) for row in results]
        except Exception as e:
            print(f"❌ DB error: {e}")
            return []
    
    def get_alerts_by_date(self, start_date, end_date):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, group_key, agent_name, confidence, 
                       is_malicious, message, level, events_count, features, 
                       processing_time, created_at
                FROM alerts WHERE created_at BETWEEN ? AND ? ORDER BY created_at DESC
            ''', (start_date.isoformat(), end_date.isoformat()))
            results = cursor.fetchall()
            conn.close()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"❌ DB error: {e}")
            return []