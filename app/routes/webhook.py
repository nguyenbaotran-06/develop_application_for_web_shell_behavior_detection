# app/routes/webhook.py
import os
from flask import Blueprint, request, jsonify
from flask_socketio import emit
from app import socketio
from app.models.feature_extractor import (
    extract_target_from_command,
    LogSegmenter,
    aggregate_labels_to_segment
)
import pandas as pd
import numpy as np
import time
import logging
from datetime import datetime
from collections import defaultdict
import threading
import signal
import sys
import time
from app.models.database import DatabaseManager
db = DatabaseManager()
webhook_bp = Blueprint('webhook', __name__)
logger = logging.getLogger(__name__)

detector = None
event_cache = defaultdict(list)
cache_timestamps = defaultdict(float)
event_receive_times = defaultdict(float)
CACHE_TIMEOUT = 30
MIN_EVENTS_FOR_DETECTION = 3


detected_alerts = set()
DETECT_COOLDOWN = 60

# 🔥 Cache để theo dõi events đã xử lý
processed_events = set()
PROCESSED_EVENTS_LIMIT = 50000

# 🔥 Giới hạn số lượng alert broadcast
MAX_ALERTS_PER_MINUTE = 10
alert_counter = 0
alert_counter_lock = threading.Lock()
last_alert_time = 0
alert_cooldown = 10

# 🔥 Biến để dừng thread
running = True

def reset_alert_counter():
    global alert_counter
    while running:
        time.sleep(60)
        with alert_counter_lock:
            alert_counter = 0

# 🔥 Chạy reset counter trong background
reset_thread = threading.Thread(target=reset_alert_counter, daemon=True)
reset_thread.start()

def get_detector():
    global detector
    if detector is None:
        try:
            import joblib
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_path = os.path.join(base_dir, 'models_data', 'decision_tree.pkl')
            scaler_path = os.path.join(base_dir, 'models_data', 'scaler.pkl')
            from app.models.detector import WebShellDetector
            detector = WebShellDetector(model_path=model_path, scaler_path=scaler_path)
        except Exception as e:
            print(f"❌ Load detector error: {e}")
            detector = None
    return detector

# ===== HÀM XỬ LÝ CACHED EVENTS =====
def process_cached_events(group_key):
    total_start = time.time()
    events = event_cache.get(group_key, [])
    print(f"⏱️ [START] Processing {len(events)} events for {group_key}")
    if len(events) < MIN_EVENTS_FOR_DETECTION:
        return None
    
    try:
        # BƯỚC 1: Tạo DataFrame
        step_start = time.time()
        df = pd.DataFrame(events)
        df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])
        df = df.sort_values('TimeCreated')
        df['label'] = 'unknown'
        print(f"⏱️ Step 1 (Create DataFrame): {(time.time() - step_start)*1000:.2f}ms")
        
        # 🔥 CHỈ GỌI 1 LẦN DUY NHẤT - KHÔNG CẦN THÊM GÌ KHÁC
        step_start = time.time()
        from app.models.feature_extractor import extract_features_with_segment
        segment_data = extract_features_with_segment(df)
        print(f"⏱️ Step 2 (Feature Extraction): {(time.time() - step_start)*1000:.2f}ms")
        # BƯỚC 5: Xóa cột không cần (đã được xử lý trong extract_features_with_segment)
        # Không cần làm gì thêm vì extract_features_with_segment đã xử lý
        
        # BƯỚC 6: Xóa cột chuỗi
        string_cols = segment_data.select_dtypes(include=['object']).columns.tolist()
        string_cols = [col for col in string_cols if col != 'label']
        if string_cols:
            segment_data = segment_data.drop(columns=string_cols)
        
        # BƯỚC 7: Fill NaN
        numeric_cols = segment_data.select_dtypes(include=[np.number]).columns.tolist()
        for col in numeric_cols:
            if segment_data[col].isna().sum() > 0:
                median_val = segment_data[col].median()
                if pd.isna(median_val):
                    median_val = 0
                segment_data[col] = segment_data[col].fillna(median_val)
        
        segment_data = segment_data.fillna(0)
        print(f"🔍 Segment columns: {segment_data.columns.tolist()[:20]}")
        print(f"✅ Segment features: {segment_data.shape[1]}")
        # Sau khi có segment_data
        
        # ===== IN RA FILE ĐỂ DỄ XEM =====
        # Tạo thư mục debug nếu chưa có
        debug_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'debug_output')
        os.makedirs(debug_dir, exist_ok=True)
        
        # Lưu segment_data ra file CSV
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        segment_file = os.path.join(debug_dir, f'segment_features_{timestamp}.csv')
        segment_data.to_csv(segment_file, index=False)
        print(f"💾 Segment features saved to: {segment_file}")
        
        # Lưu raw events ra file CSV
        events_file = os.path.join(debug_dir, f'raw_events_{timestamp}.csv')
        df.to_csv(events_file, index=False)
        print(f"💾 Raw events saved to: {events_file}")
        
        # In thông tin tóm tắt
        print(f"\n📊 Segment data shape: {segment_data.shape}")
        print(f"📊 Non-zero features: {(segment_data != 0).sum().sum()}")
        
        # In các features khác 0
        print("\n🔍 NON-ZERO FEATURES:")
        non_zero_cols = []
        for col in segment_data.columns:
            val = segment_data[col].values[0] if len(segment_data) > 0 else 0
            if val != 0:
                non_zero_cols.append((col, val))
                print(f"   {col}: {val}")
        
        if not non_zero_cols:
            print("   ⚠️ No non-zero features!")
        # ===== KẾT THÚC IN FILE =====
        
        # BƯỚC 8: ALIGN VỚI 185 FEATURES
        det = get_detector()
        if det is None:
            print("❌ Detector is None!")
            return False
            
        if not hasattr(det, 'expected_features') or det.expected_features is None:
            print("❌ No expected_features!")
            return False
        
        aligned_df = pd.DataFrame(0, index=segment_data.index, columns=det.expected_features)
        for col in segment_data.columns:
            if col in aligned_df.columns:
                aligned_df[col] = segment_data[col].values
        
        # 🔥 Lưu aligned features ra file
        aligned_file = os.path.join(debug_dir, f'aligned_features_{timestamp}.csv')
        aligned_df.to_csv(aligned_file, index=False)
        print(f"💾 Aligned features (185) saved to: {aligned_file}")
        
        print(f"✅ Aligned features: {aligned_df.shape[1]}")
        print(f"🔍 Non-zero features after align: {(aligned_df != 0).sum().sum()}")
        
        # BƯỚC 9: SCALE VÀ PREDICT
        if det.scaler is None:
            print("❌ Scaler is None!")
            return False
        
        print("🔄 Scaling and predicting...")
        try:
            features_scaled = det.scaler.transform(aligned_df)
            prediction = det.model.predict(features_scaled)[0]
            
            # 🔥 LOG PREDICTION
            print(f"🔍 PREDICTION: {prediction}")
            
            if hasattr(det.model, 'predict_proba'):
                proba = det.model.predict_proba(features_scaled)[0]
                confidence = float(max(proba))
                print(f"🔍 Confidence: {confidence:.4f}")
                print(f"🔍 Probabilities: {proba}")
            else:
                confidence = 0.85 if prediction == 1 else 0.15
                print(f"🔍 Confidence (estimated): {confidence:.4f}")
            
            is_malicious = bool(prediction == 1)
            print(f"🔍 Perdict: {'🚨 MALICIOUS' if is_malicious else '✅ BENIGN'}")
            
            events_summary = []
            for e in events:
                events_summary.append({
                    'event_id': e.get('EventID'),
                    'command': e.get('CommandLine', '')[:200],
                    'image': e.get('Image', ''),
                    'target': e.get('TargetFilename', ''),
                    'user': e.get('User', ''),
                    'time': e.get('TimeCreated', '')
                })

            # 🔥 TẠO MESSAGE CHI TIẾT
            if is_malicious:
                reasons = []
                if any(e.get('EventID') == 11 for e in events):
                    reasons.append("Phát hiện file WebShell (.aspx/.php) được tạo trên server")
                if any('whoami' in e.get('CommandLine', '').lower() for e in events):
                    reasons.append("Thực thi lệnh whoami (kiểm tra người dùng hiện tại)")
                if any('net user' in e.get('CommandLine', '').lower() for e in events):
                    reasons.append("Thực thi lệnh net user (khám phá tài khoản người dùng)")
                if any('ipconfig' in e.get('CommandLine', '').lower() for e in events):
                    reasons.append("Thực thi lệnh ipconfig (kiểm tra cấu hình mạng)")
                if any('systeminfo' in e.get('CommandLine', '').lower() for e in events):
                    reasons.append("Thực thi lệnh systeminfo (kiểm tra thông tin hệ thống)")
                if any(e.get('EventID') == 3 for e in events):
                    reasons.append("Kết nối mạng từ web server ra ngoài (nguy cơ C2)")
                if any('w3wp.exe' in e.get('Image', '').lower() for e in events):
                    reasons.append("Lệnh được thực thi thông qua IIS Web Server")
                
                # Ghép thành câu dễ hiểu
                if reasons:
                    reason_text = ". ".join(reasons)
                    message = f"PHÁT HIỆN WEBSHELL: {reason_text} ({len(events)} sự kiện)"
                else:
                    message = f"PHÁT HIỆN WEBSHELL: Hành vi bất thường trên web server ({len(events)} sự kiện)"
            else:
                message = f"✅ BENIGN: {len(events)} events"

            # 🔥 LƯU VÀO DB
            last_event = events[-1] if events else {}
            agent_name = last_event.get('agent_name', 'Unknown')
            total_time = (time.time() - total_start) * 1000
            if is_malicious:
                try:
                    features_dict = segment_data.iloc[0].to_dict() if len(segment_data) > 0 else {}
                    alert_data = {
                        'timestamp': last_event.get('TimeCreated', datetime.now().isoformat()),
                        'group_key': group_key,
                        'agent_name': agent_name,
                        'confidence': confidence,
                        'is_malicious': is_malicious,
                        'message': message,
                        'level': 8,
                        'events_summary': events_summary,
                        'reasons': reasons if is_malicious else []
                    }
                    db.save_alert(alert_data, events, features_dict, total_time)
                    print(f"💾 Saved MALICIOUS alert to database")
                except Exception as e:
                    print(f"❌ DB save error: {e}")
            else:
                print(f"BENIGN - Not saved to database")
            
            # 🔥 CHỈ BROADCAST KHI MALICIOUS VÀ CHƯA DETECTED
            if is_malicious and group_key not in detected_alerts:
                # 🔥 KIỂM TRA COOLDOWN VÀ GIỚI HẠN
                global last_alert_time, alert_counter
                current_time = time.time()
                
                if current_time - last_alert_time < alert_cooldown:
                    print(f"⏭️ Alert cooldown: {current_time - last_alert_time:.1f}s")
                    return True
                
                with alert_counter_lock:
                    if alert_counter >= MAX_ALERTS_PER_MINUTE:
                        print(f"⏭️ Alert limit reached ({MAX_ALERTS_PER_MINUTE}/min)")
                        return True
                    alert_counter += 1
                
                last_alert_time = current_time
                
                detected_alerts.add(group_key)
                alert_data = {
                    'timestamp': last_event.get('TimeCreated', datetime.now().isoformat()),
                    'message': f"WebShell detected ({len(events)} events)",
                    'level': 8,
                    'agent_name': agent_name,
                    'confidence': confidence,
                    'is_malicious': is_malicious,
                }
                socketio.emit('new_alert', alert_data)
                print(f"🚨 ALERT EMITTED: {is_malicious}, conf: {confidence:.2%}")
                
                threading.Timer(DETECT_COOLDOWN, lambda: detected_alerts.discard(group_key)).start()
            else:
                if not is_malicious:
                    print("✅ No alert (BENIGN)")
                elif group_key in detected_alerts:
                    print("⏭️ Already detected, skipping")
            
            print(f"⏱️ [END] Total processing time: {total_time:.2f}ms")

            return True
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return False
        
    except Exception as e:
        print(f"❌ Process error: {e}")
        import traceback
        traceback.print_exc()
        return None

@webhook_bp.route('/webhook', methods=['POST'])
def webhook_receiver():
    try:
        receive_start = time.time()
        receive_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        # 🔥 GIỚI HẠN KÍCH THƯỚC PROCESSED_EVENTS
        if len(processed_events) > PROCESSED_EVENTS_LIMIT:
            processed_events.clear()
            print("🗑️ Processed events cache cleared (size limit)")
        
        alert = request.json
        #print("🔔 Webhook received")
        
        data = alert.get('data', {})
        win = data.get('win', {})
        system = win.get('system', {})
        provider = system.get('providerName', '')
        agent = alert.get('agent', {})
        event_id = system.get('eventID', '')
        
        # 🔥 CHỈ LỌC SYSMON
        if 'Sysmon' not in provider:
            return jsonify({'status': 'skipped'}), 200
        
        eventdata = win.get('eventdata', {})
        
        # 🔥 LẤY USER TRƯỚC KHI FILTER
        user = eventdata.get('user', '')
        command_line = eventdata.get('commandLine', '').lower()
        image = eventdata.get('image', '').lower()
        #🔥 FILTER EVENT 3 - CHỈ NHẬN TỪ IIS USER
        if event_id == '3':
            if'IIS APPPOOL' not in user:
                return jsonify({'status': 'skipped'}), 200
        if event_id == '1':            
            # Kiểm tra curl/ping
            if 'curl' in command_line.lower():
                #print(f"⏭️ SKIPPED: {command_line[:50]}")
                return jsonify({'status': 'skipped'}), 200
        # 🔥 TẠO UNIQUE ID CHO EVENT
        event_unique_id = f"{event_id}_{eventdata.get('processGuid', '')}_{alert.get('timestamp', '')}"
        
        # 🔥 KIỂM TRA EVENT ĐÃ XỬ LÝ CHƯA
        if event_unique_id in processed_events:
            return jsonify({'status': 'duplicate'}), 200
        
        processed_events.add(event_unique_id)
        
        # 🔥 KIỂM TRA THỜI GIAN (bỏ qua event cũ > 5 phút)
        alert_time = alert.get('timestamp', datetime.now().isoformat())
        try:
            alert_dt = pd.to_datetime(alert_time)
            now = pd.to_datetime(datetime.now().isoformat())
            if (now - alert_dt).total_seconds() > 300:
                return jsonify({'status': 'skipped', 'reason': 'old_event'}), 200
        except:
            pass
        
        # 🔥 LẤY THÔNG TIN CƠ BẢN
        parent_guid = eventdata.get('parentProcessGuid', '')
        parent_image = eventdata.get('parentImage', '')
        process_guid = eventdata.get('processGuid', '')
        logon_guid = eventdata.get('logonGuid', '')
        #command_line = eventdata.get('commandLine', '').lower()
        #image = eventdata.get('image', '').lower()
        user = eventdata.get('user', '')
        
        # 🔥 TẠO GROUP KEY - ƯU TIÊN THEO USER (để group cả EventID 11 và EventID 1)
        if user:
            # Group theo user (IIS APPPOOL\VulnerableSite)
            group_key = f"user_{user.replace(' ', '_').replace('\\\\', '_').replace('\\', '_')}"
        elif logon_guid:
            group_key = f"session_{logon_guid}"
        elif event_id == '11' and 'w3wp.exe' in image:
            # EventID 11 từ IIS, dùng processGuid của w3wp
            group_key = f"iis_{process_guid}"
        elif 'w3wp.exe' in parent_image and parent_guid:
            group_key = f"iis_{parent_guid}"
        elif parent_guid:
            group_key = f"chain_{parent_guid}"
        else:
            group_key = process_guid
        
        print(f"📝 EventID: {event_id}, Group: {group_key}")
        print(f"📝 User: {user[:50] if user else 'None'}")
        print(f"📝 Command: {command_line[:80]}...")
        
        if group_key in detected_alerts:
            return jsonify({'status': 'duplicate'}), 200
        
        # 🔥 TRÍCH XUẤT TARGET FILENAME NẾU CÓ
        target = eventdata.get('targetFilename', '')
        if not target and command_line:
            target = extract_target_from_command(command_line)
        
        # 🔥 TẠO EVENT OBJECT
        event = {
            'EventID': int(event_id) if event_id else 0,
            'CommandLine': command_line,
            'Image': eventdata.get('image', ''),
            'ProcessGuid': process_guid,
            'ParentImage': parent_image,
            'TargetFilename': target,
            'DestinationIp': eventdata.get('destinationIp', ''),
            'DestinationPort': eventdata.get('destinationPort', ''),
            'Protocol': eventdata.get('protocol', ''),
            'Initiated': eventdata.get('initiated', 'false'),
            'TimeCreated': alert.get('timestamp', datetime.now().isoformat()),
            'agent_name': agent.get('name', 'Unknown'),
            'User': eventdata.get('user', ''),
            'LogonGuid': logon_guid,
            'ParentProcessGuid': parent_guid,
            'Hashes': eventdata.get('hashes', ''),
            'IntegrityLevel': eventdata.get('integrityLevel', ''),
            'SourceIp': eventdata.get('sourceIp', ''),
            'TargetObject': eventdata.get('targetObject', ''),
            'EventType': event_id,
        }
        try:
            db.save_all_events_to_log([event])
            print(f"📝 Saved single event: EventID={event_id}, User={user[:20]}")
        except Exception as e:
            print(f"❌ Save single event error: {e}")
        # 🔥 CACHE EVENT
        event_cache[group_key].append(event)
        cache_timestamps[group_key] = time.time()
        print(f"📥 Cached: {group_key} ({len(event_cache[group_key])} events)")
        
        # 🔥 XỬ LÝ KHI ĐỦ EVENTS
        if len(event_cache[group_key]) >= MIN_EVENTS_FOR_DETECTION:
            print(f"✅ Processing {len(event_cache[group_key])} events...")
            process_cached_events(group_key)
            # 🔥 XÓA CACHE SAU KHI XỬ LÝ
            if group_key in event_cache:
                del event_cache[group_key]
            if group_key in cache_timestamps:
                del cache_timestamps[group_key]
            print(f"🗑️ Cache cleared for {group_key}")
        
        # 🔥 CLEANUP TIMEOUT
        now = time.time()
        for pid in list(cache_timestamps.keys()):
            if now - cache_timestamps[pid] > CACHE_TIMEOUT:
                if pid in event_cache:
                    del event_cache[pid]
                if pid in cache_timestamps:
                    del cache_timestamps[pid]
                print(f"🗑️ Cache timeout cleared for {pid}")
        
        if len(detected_alerts) > 1000:
            detected_alerts.clear()
        if group_key:
            event_receive_times[group_key] = time.time()
            print(f"⏱️ Received at: {receive_time_str}")
            print(f"⏱️ Processing time: {(time.time() - receive_start)*1000:.2f}ms")
        return jsonify({'status': 'cached'}), 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error'}), 500

# 🔥 SIGNAL HANDLER CHO CTRL+C
def signal_handler(sig, frame):
    global running
    print("\n🛑 Shutting down gracefully...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)