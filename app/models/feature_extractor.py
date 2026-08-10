# app/models/feature_extractor.py
import pandas as pd
import numpy as np
import re
import math
import hashlib
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# ===== LOG SEGMENTER =====
class LogSegmenter:
    def __init__(self, time_window='auto', soft_reset_threshold=0.7):
        self.time_window = time_window
        self.soft_reset_threshold = soft_reset_threshold
    def segment_combined(self, df, time_col='TimeCreated'):
        """Gom tất cả vào 1 segment"""
        df = df.copy()
        df['segment_id'] = 'all_events'
        df['segment_type'] = 'combined'
        return df

    def segment_by_time_window(self, df, time_col='TimeCreated', window_size='auto'):
        if len(df) == 0:
            return df
        
        if time_col in df.columns:
            df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
            df = df.dropna(subset=[time_col]).copy()
        
        if len(df) == 0:
            return df
        
        if window_size == 'auto':
            if len(df) > 1:
                time_diffs = df[time_col].diff().dt.total_seconds().dropna()
                if len(time_diffs) > 0:
                    window_size = np.percentile(time_diffs, 75) * 2
                    window_size = max(window_size, 60)
                else:
                    window_size = 3600
            else:
                window_size = 3600
        
        df = df.sort_values(time_col).reset_index(drop=True)
        segments = []
        current_window = []
        window_start = df[time_col].iloc[0]
        
        for idx, row in df.iterrows():
            current_time = row[time_col]
            time_diff = (current_time - window_start).total_seconds()
            
            if time_diff > window_size and current_window:
                segment = pd.DataFrame(current_window)
                segment['segment_type'] = 'time_window'
                segment['segment_id'] = f'window_{len(segments)}'
                segments.append(segment)
                current_window = []
                window_start = current_time
            
            current_window.append(row.to_dict())
        
        if current_window:
            segment = pd.DataFrame(current_window)
            segment['segment_type'] = 'time_window'
            segment['segment_id'] = f'window_{len(segments)}'
            segments.append(segment)
        
        return pd.concat(segments, ignore_index=True) if segments else df
    
    def soft_reset_segmentation(self, df, time_col='TimeCreated', feature_cols=None):
        if len(df) < 2:
            return df
        
        if time_col in df.columns:
            df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
            df = df.dropna(subset=[time_col]).copy()
        
        if len(df) < 2:
            return df
        
        if feature_cols is None:
            feature_cols = [col for col in df.columns if col not in [time_col, 'label'] 
                           and df[col].dtype in ['int64', 'float64']]
            feature_cols = feature_cols[:50]
        
        df = df.sort_values(time_col).reset_index(drop=True)
        time_diffs = df[time_col].diff().dt.total_seconds().fillna(0).values
        
        semantic_diffs = np.zeros(len(df))
        if len(feature_cols) > 0 and len(df) > 1:
            features = df[feature_cols].values
            for i in range(1, len(features)):
                if np.all(features[i-1] == features[i]):
                    semantic_diffs[i] = 0
                else:
                    semantic_diffs[i] = np.linalg.norm(features[i] - features[i-1])
        
        if semantic_diffs.max() > 0:
            semantic_diffs = semantic_diffs / semantic_diffs.max()
        
        if time_diffs.max() > 0:
            time_diffs_norm = time_diffs / time_diffs.max()
        else:
            time_diffs_norm = time_diffs
        
        combined_scores = time_diffs_norm + semantic_diffs * self.soft_reset_threshold
        if combined_scores.max() > 0:
            combined_scores = combined_scores / combined_scores.max()
        
        threshold = np.percentile(combined_scores, 95)
        boundaries = np.where(combined_scores > threshold)[0]
        
        segments = []
        start_idx = 0
        for boundary in boundaries:
            if boundary > start_idx:
                segment = df.iloc[start_idx:boundary].copy()
                segment['segment_type'] = 'soft_reset'
                segment['segment_id'] = f'session_{len(segments)}'
                segments.append(segment)
                start_idx = boundary
        
        if start_idx < len(df):
            segment = df.iloc[start_idx:].copy()
            segment['segment_type'] = 'soft_reset'
            segment['segment_id'] = f'session_{len(segments)}'
            segments.append(segment)
        
        return pd.concat(segments, ignore_index=True) if segments else df
    
    def segment_logs(self, df, time_col='TimeCreated', methods='combined'):
        if methods == 'combined':
            return self.segment_combined(df, time_col)
        if len(df) == 0:
            return df
        
        results = []
        
        if methods in ['all', 'time_window']:
            seg_tw = self.segment_by_time_window(df, time_col)
            results.append(seg_tw)
        
        if methods in ['all', 'soft_reset']:
            seg_sr = self.soft_reset_segmentation(df, time_col)
            results.append(seg_sr)
        
        if results:
            combined = pd.concat(results, ignore_index=True)
            combined = combined.sort_values(time_col).reset_index(drop=True)
            return combined
        
        return df


# ===== AGGREGATE LABELS TO SEGMENT =====
def aggregate_labels_to_segment(df, time_col='TimeCreated'):
    """Chuyển nhãn từ cấp độ sự kiện → cấp độ segment"""
    
    if 'segment_id' not in df.columns:
        df = df.copy()
        df['segment_id'] = 'default'
        df['segment_type'] = 'none'
    
    df = df.copy()
    
    # 🔥 THÊM FEATURES TỪ TARGET FILENAME
    if 'TargetFilename' in df.columns:
        target = df['TargetFilename'].astype(str).fillna('')
        # Đếm số file .aspx/.php/.jsp trong segment
        df['is_webshell_file'] = target.str.contains(r'\.(php|aspx|ashx|jsp|war|cgi|asmx)', case=False, na=False).astype(int)
        df['has_target_file'] = (target != '').astype(int)
        df['target_len'] = target.str.len()
        
        # Log để debug
        if df['is_webshell_file'].sum() > 0:
            print(f"🔥🔥🔥 WEBSHELL FILE FOUND IN SEGMENT: {target.iloc[0]}")
    
    # Thêm các features cơ bản
    df['event_count'] = 1
    df['cmd_len'] = df['CommandLine'].astype(str).str.len()
    df['cmd_has_suspicious'] = df['CommandLine'].astype(str).str.contains('whoami|net user|ipconfig|systeminfo', case=False).astype(int)
    df['is_cmd'] = df['Image'].astype(str).str.contains('cmd|powershell', case=False).astype(int)
    df['is_whoami'] = df['CommandLine'].astype(str).str.contains('whoami', case=False).astype(int)
    df['is_iis_parent'] = df['ParentImage'].astype(str).str.contains('w3wp', case=False).astype(int)
    df['cmd_has_pipe'] = df['CommandLine'].astype(str).str.contains('\\|', case=False).astype(int)
    df['cmd_has_redirect'] = df['CommandLine'].astype(str).str.contains('>|>>', case=False).astype(int)
    # cmd = df['CommandLine'].astype(str).fillna('')
    # df['cmd_entropy'] = cmd.apply(calculate_entropy)
    # df['cmd_complexity'] = cmd.apply(calculate_complexity)
    # df['cmd_length'] = np.clip(cmd.str.len(), 0, 500)
    # df['cmd_has_encoded'] = cmd.str.contains('-enc|-e|base64', case=False, na=False).astype(int)
    # df['cmd_has_download'] = cmd.str.contains('wget|curl|downloadstring', case=False, na=False).astype(int)
    # df['cmd_has_whoami'] = cmd.str.contains('whoami', case=False, na=False).astype(int)
    # df['cmd_has_pipe'] = cmd.str.contains('\\|', case=False, na=False).astype(int)
    # df['cmd_num_args'] = cmd.str.split().str.len().fillna(0)
    # Lấy tất cả numeric columns (bao gồm cả is_webshell_file vừa thêm)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Loại bỏ các cột không cần
    exclude_cols = ['TimeCreated', 'segment_id', 'is_time_window', 'is_soft_reset']
    numeric_cols = [col for col in numeric_cols if col not in exclude_cols]
    
    if not numeric_cols:
        numeric_cols = ['event_count']
    
    # Tạo agg_dict
    agg_dict = {}
    for col in numeric_cols:
        if col == 'EventID':
            agg_dict[col] = ['count', 'nunique', 'mean', 'std']
        elif col == 'event_count':
            agg_dict[col] = ['sum', 'mean']
        elif col in ['is_webshell_file', 'has_target_file']:
            agg_dict[col] = ['sum', 'mean']
        else:
            agg_dict[col] = ['mean', 'std', 'min', 'max']
    
    print(f"📊 Aggregating {len(agg_dict)} columns")
    print(f"📊 Columns: {list(agg_dict.keys())}")
    
    # Aggregate
    segment_features = df.groupby('segment_id').agg(agg_dict).reset_index()
    
    # Flatten column names
    new_cols = ['segment_id']
    for col in agg_dict.keys():
        for agg_func in agg_dict[col]:
            new_cols.append(f'{col}_{agg_func}')
    
    if len(segment_features.columns) == len(new_cols):
        segment_features.columns = new_cols
    
    # Thêm label
    segment_labels = df.groupby('segment_id').agg({
        'label': lambda x: 'attack' if 'attack' in x.values else 'normal' if 'normal' in x.values else 'unknown',
        'segment_type': 'first'
    }).reset_index()
    
    segment_data = segment_labels.merge(segment_features, on='segment_id')
    
    print(f"📊 Segment features after aggregate: {len(segment_data.columns)}")
    
    return segment_data

# ===== EXTRACT FEATURES WITH SEGMENT =====
def extract_features_with_segment(events_df):
    df = events_df.copy()
    df['label'] = 'unknown'
    
    # 1. Segment logs
    segmenter = LogSegmenter(time_window='auto', soft_reset_threshold=0.7)
    segmented_df = segmenter.segment_logs(df, time_col='TimeCreated', methods='combined')
    
    if 'segment_id' not in segmented_df.columns:
        segmented_df['segment_id'] = 'all_events'
        segmented_df['segment_type'] = 'combined'
    
    # 🔥 THÊM TẤT CẢ FEATURES VÀO DF
    # Temporal features
    temporal_features = build_temporal_sequences(df, window_size=10)
    for col in temporal_features.columns:
        df[col] = temporal_features[col]
    
    # Process classification
    df['is_web_server'] = df['Image'].astype(str).str.contains('w3wp|exchange|nginx|apache|httpd|iis', case=False, na=False).astype(int)
    df['is_shell'] = df['Image'].astype(str).str.contains('cmd|powershell|bash|sh|pwsh', case=False, na=False).astype(int)
    df['is_system_process'] = df['Image'].astype(str).str.contains('system|lsass|services|svchost|wininit|csrss', case=False, na=False).astype(int)
    
    # Behavior patterns
    process_events = defaultdict(list)
    for idx, row in df.iterrows():
        pid = row.get('ProcessGuid', '')
        if pid:
            process_events[pid].append(row.get('EventID', 0))
    df['behavior_diversity'] = df['ProcessGuid'].apply(
        lambda x: len(set(process_events.get(x, []))) if x else 0
    ).fillna(0).astype(int)
    
    # Event type features
    df['event_id'] = df['EventID'].astype(float).fillna(0)
    df['is_network_event'] = (df['event_id'] == 3).astype(int)
    df['is_file_event'] = (df['event_id'] == 11).astype(int)
    df['is_process_event'] = (df['event_id'] == 1).astype(int)
    
    # Network features
    df['is_outbound'] = (df['Initiated'].astype(str).str.lower() == 'true').astype(int)
    df['is_tcp'] = (df['Protocol'].astype(str).str.lower() == 'tcp').astype(int)
    df['dst_port_high'] = (pd.to_numeric(df['DestinationPort'], errors='coerce') > 10000).astype(int)
    df['dst_port_suspicious'] = pd.to_numeric(df['DestinationPort'], errors='coerce').isin([4444, 5555, 6666, 7777, 8888, 1337, 31337]).astype(int)
    
    # 2. Aggregate
    segment_data = aggregate_labels_to_segment(df, time_col='TimeCreated')
    
    # 3. Merge command features
    cmd = df['CommandLine'].astype(str).fillna('')
    temp_df = segmented_df[['segment_id']].copy()
    temp_df['cmd_entropy'] = cmd.apply(calculate_entropy)
    temp_df['cmd_complexity'] = cmd.apply(calculate_complexity)
    temp_df['cmd_length'] = np.clip(cmd.str.len(), 0, 500)
    temp_df['cmd_has_encoded'] = cmd.str.contains('-enc|-e|base64', case=False, na=False).astype(int)
    temp_df['cmd_has_download'] = cmd.str.contains('wget|curl|downloadstring', case=False, na=False).astype(int)
    temp_df['cmd_has_whoami'] = cmd.str.contains('whoami', case=False, na=False).astype(int)
    temp_df['cmd_has_pipe'] = cmd.str.contains('\\|', case=False, na=False).astype(int)
    temp_df['cmd_num_args'] = cmd.str.split().str.len().fillna(0)
    
    cmd_agg = temp_df.groupby('segment_id').agg({
        'cmd_entropy': ['mean', 'std'],
        'cmd_complexity': ['mean', 'std'],
        'cmd_length': ['mean', 'std'],
        'cmd_has_encoded': ['mean', 'std'],
        'cmd_has_download': ['mean', 'std'],
        'cmd_has_whoami': ['mean', 'std'],
        'cmd_has_pipe': ['mean', 'std'],
        'cmd_num_args': ['mean', 'std'],
    }).reset_index()
    
    cmd_cols = ['segment_id']
    for col in ['cmd_entropy', 'cmd_complexity', 'cmd_length', 'cmd_has_encoded', 
                'cmd_has_download', 'cmd_has_whoami', 'cmd_has_pipe', 'cmd_num_args']:
        for agg in ['mean', 'std']:
            cmd_cols.append(f'{col}_{agg}')
    
    if len(cmd_agg.columns) == len(cmd_cols):
        cmd_agg.columns = cmd_cols
    
    segment_data = segment_data.merge(cmd_agg, on='segment_id', how='left')
    
    # 4. Xóa segment_id
    cols_to_remove = ['segment_id', 'segment_type', 'TimeCreated']
    for col in cols_to_remove:
        if col in segment_data.columns:
            segment_data = segment_data.drop(col, axis=1)
    
    # 5. Giữ numeric
    numeric_cols = segment_data.select_dtypes(include=[np.number]).columns.tolist()
    segment_data = segment_data[numeric_cols]
    
    # 6. Fill NaN
    segment_data = segment_data.fillna(0)
    
    print(f"✅ Segment features: {segment_data.shape[1]}")
    print(f"🔍 Non-zero features: {(segment_data != 0).sum().sum()}")
    
    return segment_data


# ===== HÀM TÍNH TOÁN =====
def calculate_entropy(text: str) -> float:
    if len(text) < 3:
        return 0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def calculate_complexity(text: str) -> float:
    if len(text) < 3:
        return 0
    def char_type(c):
        if c.isupper(): return 0
        elif c.islower(): return 1
        elif c.isdigit(): return 2
        else: return 3
    changes = 0
    prev_type = char_type(text[0])
    for c in text[1:]:
        curr_type = char_type(c)
        if curr_type != prev_type:
            changes += 1
        prev_type = curr_type
    entropy = calculate_entropy(text)
    return min(entropy * math.exp(changes / max(len(text), 1)), 100)

def has_double_extension(filename: str) -> int:
    parts = filename.lower().split('.')
    return 1 if len(parts) >= 3 else 0

def contains_hex_or_base64(text: str) -> int:
    if re.search(r'[0-9a-f]{32,}', text) or re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        return 1
    return 0

def tokenize_and_hash(text: str, num_features: int = 20) -> list:
    if not text:
        return [0] * num_features
    tokens = re.split(r'[\\/:\.]', text)
    tokens = [t for t in tokens if t and len(t) > 1]
    result = [0] * num_features
    for token in tokens[:20]:
        hash_val = int(hashlib.md5(token.encode()).hexdigest(), 16) % num_features
        result[hash_val] = 1
    return result

def extract_target_from_command(command_line):
    if not command_line:
        return ''
    patterns = [
        r'[>\]]\s*([A-Za-z]:\\[^\s>]+\.\w+)',
        r'[>\]]\s*([A-Za-z]:\\[^\s>]+)',
        r'-o\s+([A-Za-z]:\\[^\s]+)',
        r'-outfile\s+([A-Za-z]:\\[^\s]+)',
        r'-FilePath\s+([A-Za-z]:\\[^\s]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, command_line, re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r'echo\s+.*>\s*([A-Za-z]:\\[^\s]+)', command_line, re.IGNORECASE)
    if match:
        return match.group(1)
    return ''


# ===== BUILD TEMPORAL SEQUENCES =====
def build_temporal_sequences(df: pd.DataFrame, window_size: int = 10):
    temporal_sequences = defaultdict(lambda: deque(maxlen=window_size))
    temporal_features = pd.DataFrame(index=df.index)
    
    for idx, row in df.iterrows():
        pid = row.get('ProcessGuid', '')
        if not pid:
            continue
        event_id = row.get('EventID', 0)
        temporal_sequences[pid].append(event_id)
        seq_list = list(temporal_sequences[pid])
        
        temporal_features.loc[idx, 'temporal_length'] = len(seq_list)
        for i, ev in enumerate(seq_list, 1):
            temporal_features.loc[idx, f'temporal_pos_{i}'] = ev
        for i in range(len(seq_list) + 1, window_size + 1):
            temporal_features.loc[idx, f'temporal_pos_{i}'] = 0
        
        event_counts = defaultdict(int)
        for ev in seq_list:
            event_counts[ev] += 1
        for ev_type in [1, 3, 7, 11, 12, 17, 18, 23]:
            temporal_features.loc[idx, f'temporal_count_{ev_type}'] = event_counts.get(ev_type, 0)
            temporal_features.loc[idx, f'temporal_ratio_{ev_type}'] = event_counts.get(ev_type, 0) / max(len(seq_list), 1)
        temporal_features.loc[idx, 'temporal_diversity'] = len(set(seq_list))
    
    return temporal_features


# ===== ADD FEATURES =====
def add_command_features(features, df):
    cmd = df['CommandLine'].astype(str).fillna('')
    has_cmd = (cmd != '') & (cmd != 'nan')
    features['cmd_entropy'] = cmd.apply(calculate_entropy)
    features['cmd_complexity'] = cmd.apply(calculate_complexity)
    features['cmd_length'] = 0
    features['cmd_length'].where(~has_cmd, np.clip(cmd.str.len(), 0, 500), inplace=True)
    features['cmd_has_encoded'] = cmd.str.contains('-enc|-e|base64', case=False, na=False).astype(int)
    features['cmd_has_download'] = cmd.str.contains('wget|curl|downloadstring', case=False, na=False).astype(int)
    features['cmd_has_whoami'] = cmd.str.contains('whoami', case=False, na=False).astype(int)
    features['cmd_has_pipe'] = cmd.str.contains('\\|', case=False, na=False).astype(int)
    features['cmd_num_args'] = 0
    features['cmd_num_args'].where(~has_cmd, np.clip(cmd.str.split().str.len().fillna(0), 0, 20), inplace=True)
    return features

def add_behavior_patterns(features, df):
    process_events = defaultdict(list)
    for idx, row in df.iterrows():
        pid = row.get('ProcessGuid', '')
        if pid:
            process_events[pid].append(row.get('EventID', 0))
    features['behavior_diversity'] = df['ProcessGuid'].apply(
        lambda x: len(set(process_events.get(x, []))) if x else 0
    ).fillna(0).astype(int)
    return features

def add_network_features(features, df):
    features['is_outbound'] = (df['Initiated'].astype(str).str.lower() == 'true').astype(int)
    features['is_tcp'] = (df['Protocol'].astype(str).str.lower() == 'tcp').astype(int)
    
    dst_port = pd.to_numeric(df['DestinationPort'], errors='coerce').fillna(0)
    features['dst_port_high'] = (dst_port > 10000).astype(int)
    features['dst_port_suspicious'] = dst_port.isin([4444, 5555, 6666, 7777, 8888, 1337, 31337]).astype(int)
    
    dst_ip = df['DestinationIp'].astype(str).fillna('')
    ip_parts = dst_ip.str.split('.', expand=True)
    for i in range(4):
        if i < len(ip_parts.columns):
            features[f'dst_ip_octet_{i+1}'] = pd.to_numeric(ip_parts[i], errors='coerce').fillna(0).astype(int)
    features['no_url_indicator'] = (
        (~dst_ip.str.contains('[a-zA-Z]', na=False)) & 
        (dst_ip.str.match(r'^\d+\.\d+\.\d+\.\d+$', na=False))
    ).astype(int)
    return features


# ===== EXTRACT FEATURES (HÀM CHÍNH) - ĐÃ SỬA =====
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Trích xuất features từ DataFrame - CÓ TRÍCH XUẤT TARGET TỪ COMMAND LINE"""
    features = pd.DataFrame(index=df.index)
    
    # Thông tin gốc
    features['EventID'] = df['EventID'].astype(str)
    features['Image'] = df['Image'].astype(str).str.split('\\').str[-1].str.split('/').str[-1].fillna('unknown')
    
    # NHÓM 1: Process Features
    temporal_features = build_temporal_sequences(df, window_size=10)
    features = pd.concat([features, temporal_features], axis=1)
    
    features['is_web_server'] = df['Image'].astype(str).str.contains('w3wp|exchange|nginx|apache|httpd|iis', case=False, na=False).astype(int)
    features['is_shell'] = df['Image'].astype(str).str.contains('cmd|powershell|bash|sh|pwsh', case=False, na=False).astype(int)
    features['is_system_process'] = df['Image'].astype(str).str.contains('system|lsass|services|svchost|wininit|csrss', case=False, na=False).astype(int)
    
    features = add_command_features(features, df)
    features = add_behavior_patterns(features, df)
    features['event_id'] = pd.to_numeric(features['EventID'], errors='coerce').fillna(0)
    features['is_network_event'] = (features['event_id'] == 3).astype(int)
    features['is_file_event'] = (features['event_id'] == 11).astype(int)
    features['is_process_event'] = (features['event_id'] == 1).astype(int)
    
    # ===== NHÓM 2: File Features - ĐÃ SỬA =====
    # Lấy TargetFilename từ df
    target = df['TargetFilename'].astype(str).fillna('')
    
    # 🔥 NẾU KHÔNG CÓ TARGET, TRÍCH XUẤT TỪ COMMAND LINE
    if target.str.len().sum() == 0:
        cmd = df['CommandLine'].astype(str).fillna('')
        print(f"📂 No TargetFilename found, extracting from CommandLine...")
        
        for idx, cmd_line in cmd.items():
            if not cmd_line or cmd_line == 'nan':
                continue
            # Tìm đường dẫn file .aspx/.php/.jsp/.ashx/.cgi
            match = re.search(r'([A-Za-z]:\\[^\s]*\.(aspx|php|jsp|ashx|cgi|asmx))', cmd_line, re.IGNORECASE)
            if match:
                target.iloc[idx] = match.group(1)
                print(f"📂 Extracted from command: {match.group(1)}")
    
    # Xử lý file features
    if target.str.len().sum() > 0:
        features['path_depth'] = target.str.count('\\\\') + target.str.count('/')
        features['path_entropy'] = target.apply(calculate_entropy)
        features['path_complexity'] = target.apply(calculate_complexity)
        features['has_double_extension'] = target.apply(has_double_extension)
        features['has_hex_or_base64'] = target.apply(contains_hex_or_base64)
        features['is_webshell_file'] = target.str.contains(r'\.(php|aspx|ashx|jsp|war|cgi|asmx)', case=False, na=False).astype(int)
        features['file_in_web_dir'] = target.str.contains('wwwroot|inetpub|htdocs|owa|ecp|exchange', case=False, na=False).astype(int)
        
        # 🔥 LOG NẾU PHÁT HIỆN WEBSHELL
        if features['is_webshell_file'].sum() > 0:
            print(f"🔥🔥🔥 WEBSHELL FILE DETECTED: {target.iloc[0]}")
        
        path_hash = target.apply(lambda x: tokenize_and_hash(x, 20))
        path_hash_df = pd.DataFrame(path_hash.tolist(), index=features.index, 
                                     columns=[f'path_hash_{i}' for i in range(20)])
        features = pd.concat([features, path_hash_df], axis=1)
    else:
        features['path_depth'] = 0
        features['path_entropy'] = 0
        features['path_complexity'] = 0
        features['has_double_extension'] = 0
        features['has_hex_or_base64'] = 0
        features['is_webshell_file'] = 0
        features['file_in_web_dir'] = 0
        for i in range(20):
            features[f'path_hash_{i}'] = 0
    
    # NHÓM 3: Network Features
    features = add_network_features(features, df)
    
    features = features.fillna(0)
    info_cols = ['EventID', 'Image']
    other_cols = [c for c in features.columns if c not in info_cols]
    features = features[info_cols + other_cols]
    
    return features


# ===== HÀM ĐỌC JSON (cho detector) =====
def load_json_file(filepath: str):
    """Đọc file JSON (hỗ trợ nhiều định dạng)"""
    import json
    events = []
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    if content.startswith('['):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
        except:
            pass
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except:
            pass
    
    return events


__all__ = [
    'extract_features',
    'extract_features_with_segment',
    'LogSegmenter',
    'aggregate_labels_to_segment',
    'extract_target_from_command',
    'calculate_entropy',
    'calculate_complexity',
    'has_double_extension',
    'contains_hex_or_base64',
    'tokenize_and_hash',
    'build_temporal_sequences',
    'add_command_features',
    'add_behavior_patterns',
    'add_network_features',
    'load_json_file'
]