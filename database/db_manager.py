import sqlite3
import json
from datetime import datetime
from pathlib import Path
from config import Config

class DatabaseManager:
    def __init__(self):
        self.db_path = Config.DATABASE_PATH
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    threat_level TEXT,
                    vt_result TEXT,
                    heuristic_result TEXT,
                    yara_matches TEXT,
                    quarantined BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Quarantine table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    quarantine_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    threat_reason TEXT,
                    file_hash TEXT
                )
            ''')
            
            conn.commit()
    
    def add_scan_result(self, file_path, file_hash, threat_level, vt_result, 
                       heuristic_result, yara_matches, quarantined=False):
        """Add scan result to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history 
                (file_path, file_hash, threat_level, vt_result, heuristic_result, 
                 yara_matches, quarantined)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_path, file_hash, threat_level, json.dumps(vt_result),
                  json.dumps(heuristic_result), json.dumps(yara_matches), quarantined))
            conn.commit()
    
    def add_quarantine_entry(self, original_path, quarantine_path, threat_reason, file_hash):
        """Add quarantine entry to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quarantine 
                (original_path, quarantine_path, threat_reason, file_hash)
                VALUES (?, ?, ?, ?)
            ''', (original_path, quarantine_path, threat_reason, file_hash))
            conn.commit()
    
    def get_scan_history(self, limit=100):
        """Get recent scan history"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY scan_date DESC 
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
    
    def get_quarantine_list(self):
        """Get list of quarantined files"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quarantine ORDER BY quarantine_date DESC')
            return cursor.fetchall()
    
    def remove_quarantine_entry(self, quarantine_id):
        """Remove quarantine entry from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM quarantine WHERE id = ?', (quarantine_id,))
            conn.commit()
