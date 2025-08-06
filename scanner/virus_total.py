# virus_total.pyimport requests
import hashlib
import time
from pathlib import Path
from config import Config

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
    
    def calculate_file_hash(self, file_path, hash_type='sha256'):
        """Calculate file hash"""
        hash_obj = hashlib.new(hash_type)
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return None
    
    def scan_file_hash(self, file_hash):
        """Scan file hash using VirusTotal API"""
        if not self.api_key:
            return {'error': 'No API key configured'}
        
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        try:
            response = self.session.get(Config.VT_API_URL, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': f'API request failed: {str(e)}'}
    
    def upload_file(self, file_path):
        """Upload file to VirusTotal for scanning"""
        if not self.api_key:
            return {'error': 'No API key configured'}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (Path(file_path).name, f)}
                params = {'apikey': self.api_key}
                
                response = self.session.post(
                    Config.VT_UPLOAD_URL, 
                    files=files, 
                    params=params, 
                    timeout=60
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            return {'error': f'Upload failed: {str(e)}'}
    
    def analyze_vt_result(self, vt_response):
        """Analyze VirusTotal response and return threat assessment"""
        if 'error' in vt_response:
            return {
                'threat_level': 'unknown',
                'detection_count': 0,
                'total_engines': 0,
                'details': vt_response['error']
            }
        
        if vt_response.get('response_code') != 1:
            return {
                'threat_level': 'unknown',
                'detection_count': 0,
                'total_engines': 0,
                'details': 'File not found in VirusTotal database'
            }
        
        positives = vt_response.get('positives', 0)
        total = vt_response.get('total', 0)
        
        # Determine threat level based on detection ratio
        if positives == 0:
            threat_level = 'safe'
        elif positives <= 3:
            threat_level = 'suspicious'
        else:
            threat_level = 'malicious'
        
        return {
            'threat_level': threat_level,
            'detection_count': positives,
            'total_engines': total,
            'scan_date': vt_response.get('scan_date'),
            'permalink': vt_response.get('permalink'),
            'details': vt_response.get('scans', {})
        }
