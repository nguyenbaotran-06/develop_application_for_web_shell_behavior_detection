# app/config.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    # ===== Wazuh API (port 55000) =====
    WAZUH_HOST = os.getenv('WAZUH_HOST', 'localhost')
    WAZUH_PORT = int(os.getenv('WAZUH_PORT', 55000))  # ← SỬA THÀNH 55000
    WAZUH_USER = os.getenv('WAZUH_USER', 'wazuh-wui')  # ← SỬA THÀNH wazuh-wui
    WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', 'wazuh-wui')  # ← SỬA THÀNH wazuh-wui
    
    # ===== Model paths =====
    MODELS_DIR = os.path.join(BASE_DIR, 'models_data')
    MODEL_PATH = os.path.join(MODELS_DIR, 'decision_tree.pkl')
    SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
    
    # ===== Database =====
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///edr.db')
    
    # ===== Alert =====
    ALERT_THRESHOLD = float(os.getenv('ALERT_THRESHOLD', 0.7))
    
    # ===== Logging =====
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(BASE_DIR, 'logs', 'app.log')
    
    # ===== Flask =====
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))