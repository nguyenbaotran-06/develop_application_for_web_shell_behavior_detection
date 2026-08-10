# app/models/detector.py
import os
import sys
import joblib
import pandas as pd
import numpy as np
import json
import logging
from datetime import datetime

# Import feature_extractor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features  # ✅ Chỉ import extract_features

logger = logging.getLogger(__name__)

class WebShellDetector:
    
    def __init__(self, model_path=None, scaler_path=None):
        self.model_path = model_path or 'models_data/decision_tree.pkl'
        self.scaler_path = scaler_path or 'models_data/scaler.pkl'
        self.model = None
        self.scaler = None
        self.expected_features = None
        self._load_model()
    
    def _load_model(self):
        try:
            if os.path.exists(self.model_path):
                try:
                    self.model = joblib.load(self.model_path)
                    logger.info(f"[OK] Model loaded: {self.model_path}")
                except Exception as e:
                    logger.warning(f"Joblib failed, trying pickle: {e}")
                    import pickle
                    with open(self.model_path, 'rb') as f:
                        self.model = pickle.load(f)
                    logger.info(f"[OK] Model loaded with pickle: {self.model_path}")
            else:
                logger.error(f"[ERROR] Model file not found: {self.model_path}")
                return False
            
            if os.path.exists(self.scaler_path):
                try:
                    self.scaler = joblib.load(self.scaler_path)
                    logger.info(f"✅ Scaler loaded: {self.scaler_path}")
                except:
                    import pickle
                    with open(self.scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                    logger.info(f"✅ Scaler loaded with pickle: {self.scaler_path}")
                
                if hasattr(self.scaler, 'feature_names_in_'):
                    self.expected_features = self.scaler.feature_names_in_.tolist()
                    logger.info(f"   📊 Expected features: {len(self.expected_features)}")
            else:
                logger.warning(f"⚠️ Scaler file not found: {self.scaler_path}")
                self.scaler = None
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _align_features(self, features_df):
        if self.expected_features is None:
            return features_df
        
        aligned_df = pd.DataFrame(index=features_df.index)
        
        missing_cols = []
        for col in self.expected_features:
            if col in features_df.columns:
                aligned_df[col] = features_df[col].values
            else:
                aligned_df[col] = 0
                missing_cols.append(col)
        
        if missing_cols:
            print(f"   ⚠️ Missing {len(missing_cols)} columns (filled with 0)")
        
        return aligned_df
    
    def _parse_wazuh_alert(self, alert):
        log_data = {}
        data = alert.get('data', {})
        win = data.get('win', {})
        event_data = win.get('eventdata', {})
        system = win.get('system', {})
        
        log_data['EventID'] = int(system.get('eventID', 0))
        log_data['CommandLine'] = event_data.get('commandLine', '')
        log_data['Image'] = event_data.get('image', '')
        log_data['ParentImage'] = event_data.get('parentImage', '')
        log_data['TargetFilename'] = event_data.get('targetFilename', '')
        log_data['DestinationIp'] = event_data.get('destinationIp', '')
        log_data['DestinationPort'] = event_data.get('destinationPort', '')
        log_data['SourceIp'] = event_data.get('sourceIp', '')
        log_data['Protocol'] = event_data.get('protocol', '')
        log_data['TargetObject'] = event_data.get('targetObject', '')
        log_data['User'] = event_data.get('user', '')
        log_data['ProcessGuid'] = event_data.get('processGuid', '')
        log_data['ParentProcessGuid'] = event_data.get('parentProcessGuid', '')
        log_data['UtcTime'] = event_data.get('utcTime', '')
        log_data['Timestamp'] = system.get('systemTime', '')
        log_data['IntegrityLevel'] = event_data.get('integrityLevel', '')
        log_data['Hashes'] = event_data.get('hashes', '')
        log_data['Initiated'] = event_data.get('initiated', 'false')
        
        return log_data
    
    def _get_expected_features(self):
        if self.scaler and hasattr(self.scaler, 'feature_names_in_'):
            return self.scaler.feature_names_in_.tolist()
        return None
    
    def predict_log(self, log_data):
        try:
            # Parse log data
            if isinstance(log_data, dict):
                if 'win' in log_data:
                    parsed = self._parse_wazuh_alert(log_data)
                else:
                    parsed = log_data
            else:
                return {
                    'prediction': 0,
                    'confidence': 0.0,
                    'is_malicious': False,
                    'error': 'Invalid input type'
                }
            
            # Bước 1: Chuyển thành DataFrame
            df = pd.DataFrame([parsed])
            
            # Bước 2: Trích xuất đặc trưng
            features_df = extract_features(df)
            
            if features_df is None or features_df.empty:
                logger.warning("⚠️ No features extracted")
                return {
                    'prediction': 0,
                    'confidence': 0.0,
                    'is_malicious': False,
                    'error': 'No features extracted'
                }
            
            # Bước 3: Đồng bộ features
            aligned_df = self._align_features(features_df)
            
            # Bước 4: Chuẩn hóa
            if self.scaler is not None:
                try:
                    features_scaled = self.scaler.transform(aligned_df)
                except Exception as e:
                    logger.error(f"❌ Scaling error: {e}")
                    features_scaled = aligned_df.values
            else:
                features_scaled = aligned_df.values
            
            # Bước 5: Dự đoán
            if self.model is None:
                return {
                    'prediction': 0,
                    'confidence': 0.0,
                    'is_malicious': False,
                    'error': 'Model not loaded'
                }
            
            try:
                prediction = self.model.predict(features_scaled)[0]
                
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba(features_scaled)[0]
                    confidence = float(max(proba))
                    prediction_prob = float(proba[1]) if len(proba) > 1 else 0.0
                elif hasattr(self.model, 'decision_function'):
                    score = self.model.decision_function(features_scaled)[0]
                    confidence = 1.0 / (1.0 + np.exp(-abs(score)))
                    prediction_prob = confidence if prediction == 1 else 1 - confidence
                else:
                    confidence = 1.0
                    prediction_prob = 1.0 if prediction == 1 else 0.0
                
                logger.info(f"🔍 Prediction: {prediction}, Confidence: {confidence:.2f}")
                return {
                    'prediction': int(prediction),
                    'confidence': float(confidence),
                    'prediction_prob': float(prediction_prob),
                    'is_malicious': bool(prediction == 1),
                    'features': aligned_df.iloc[0].to_dict() if not aligned_df.empty else {}
                }
                
            except Exception as e:
                logger.error(f"❌ Prediction error: {e}")
                return {
                    'prediction': 0,
                    'confidence': 0.0,
                    'is_malicious': False,
                    'error': str(e)
                }
                
        except Exception as e:
            logger.error(f"❌ Predict log error: {e}")
            return {
                'prediction': 0,
                'confidence': 0.0,
                'is_malicious': False,
                'error': str(e)
            }
    
    def predict_batch(self, logs):
        results = []
        for log in logs:
            result = self.predict_log(log)
            results.append(result)
        return results
    
    def predict_from_json(self, json_data):
        if isinstance(json_data, list):
            return self.predict_batch(json_data)
        elif isinstance(json_data, dict):
            return self.predict_log(json_data)
        else:
            return {
                'prediction': 0,
                'confidence': 0.0,
                'is_malicious': False,
                'error': 'Invalid input format'
            }
    
    def get_model_info(self):
        info = {
            'model_path': self.model_path,
            'scaler_path': self.scaler_path,
            'model_loaded': self.model is not None,
            'scaler_loaded': self.scaler is not None,
        }
        if self.expected_features:
            info['expected_features_count'] = len(self.expected_features)
        return info