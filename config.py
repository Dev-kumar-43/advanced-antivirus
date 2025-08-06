# config.py
import os
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class Config:
    # Application settings
    APP_NAME = "Advanced Antivirus Solution"
    VERSION = "1.0.0"
    
    # Directories
    BASE_DIR = Path(__file__).parent
    DATA_DIR = BASE_DIR / "data"
    RULES_DIR = DATA_DIR / "rules"
    LOGS_DIR = DATA_DIR / "logs"
    QUARANTINE_DIR = DATA_DIR / "quarantine"
    
    # Database
    DATABASE_PATH = DATA_DIR / "antivirus.db"
    
    # VirusTotal API
    VT_API_URL = "https://www.virustotal.com/vtapi/v2/file/report"
    VT_UPLOAD_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
    
    # Settings file
    SETTINGS_FILE = DATA_DIR / "settings.json"
    
    # Encryption key for API key storage
    KEY_FILE = DATA_DIR / ".key"
    
    @classmethod
    def ensure_directories(cls):
        """Ensure all required directories exist"""
        for directory in [cls.DATA_DIR, cls.RULES_DIR, cls.LOGS_DIR, cls.QUARANTINE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_encryption_key(cls):
        """Get or create encryption key for sensitive data"""
        if cls.KEY_FILE.exists():
            with open(cls.KEY_FILE, 'rb') as f:
                return f.read()
        else:
            key = get_random_bytes(32)
            with open(cls.KEY_FILE, 'wb') as f:
                f.write(key)
            return key
    
    @classmethod
    def encrypt_data(cls, data: str) -> str:
        """Encrypt sensitive data"""
        key = cls.get_encryption_key()
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    
    @classmethod
    def decrypt_data(cls, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        key = cls.get_encryption_key()
        data = base64.b64decode(encrypted_data.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    
    @classmethod
    def load_settings(cls):
        """Load application settings"""
        if cls.SETTINGS_FILE.exists():
            with open(cls.SETTINGS_FILE, 'r') as f:
                return json.load(f)
        return {
            'vt_api_key': '',
            'heuristics_enabled': True,
            'auto_quarantine': False,
            'scan_archives': True,
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'excluded_extensions': ['.txt', '.md', '.log']
        }
    
    @classmethod
    def save_settings(cls, settings):
        """Save application settings"""
        with open(cls.SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
