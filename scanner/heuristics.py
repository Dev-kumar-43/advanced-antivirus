# heuristics.pyimport os
import re
import mimetypes
from pathlib import Path

class HeuristicAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            # Suspicious file patterns
            r'(?i)(download|temp|tmp).*\.(exe|scr|bat|cmd|pif)',
            r'(?i).*\.(exe|scr)\..*',  # Double extensions
            r'(?i)(virus|trojan|malware|keylog|backdoor)',
            
            # Suspicious script patterns
            r'(?i)(powershell|cmd|wscript|cscript).*-enc',
            r'(?i)(eval|exec|system|shell_exec)',
            r'(?i)(base64|gzip|compress)',
        ]
        
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.vbs', '.js',
            '.jar', '.app', '.deb', '.pkg', '.dmg'
        }
        
        self.risky_paths = [
            'temp', 'tmp', 'download', 'appdata', 'programdata'
        ]
    
    def analyze_file(self, file_path):
        """Perform heuristic analysis on file"""
        results = {
            'threat_level': 'safe',
            'suspicious_indicators': [],
            'risk_score': 0,
            'details': {}
        }
        
        try:
            file_path = Path(file_path)
            
            # Check file extension
            self._check_extension(file_path, results)
            
            # Check file location
            self._check_location(file_path, results)
            
            # Check file size
            self._check_size(file_path, results)
            
            # Check file content (for small files)
            if file_path.stat().st_size < 1024 * 1024:  # 1MB limit
                self._check_content(file_path, results)
            
            # Calculate final threat level
            self._calculate_threat_level(results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_extension(self, file_path, results):
        """Check for suspicious file extensions"""
        ext = file_path.suffix.lower()
        
        if ext in self.suspicious_extensions:
            results['suspicious_indicators'].append(f'Suspicious extension: {ext}')
            results['risk_score'] += 30
        
        # Check for double extensions
        if len(file_path.suffixes) > 1:
            results['suspicious_indicators'].append('Double file extension detected')
            results['risk_score'] += 25
    
    def _check_location(self, file_path, results):
        """Check file location for suspicious paths"""
        path_str = str(file_path).lower()
        
        for risky_path in self.risky_paths:
            if risky_path in path_str:
                results['suspicious_indicators'].append(f'Located in risky directory: {risky_path}')
                results['risk_score'] += 15
                break
    
    def _check_size(self, file_path, results):
        """Check file size for anomalies"""
        try:
            size = file_path.stat().st_size
            
            # Very small executables might be suspicious
            if file_path.suffix.lower() in ['.exe', '.scr'] and size < 1024:
                results['suspicious_indicators'].append('Unusually small executable')
                results['risk_score'] += 20
            
            # Very large files might be suspicious
            if size > 100 * 1024 * 1024:  # 100MB
                results['suspicious_indicators'].append('Unusually large file')
                results['risk_score'] += 10
                
        except OSError:
            pass
    
    def _check_content(self, file_path, results):
        """Check file content for suspicious patterns"""
        try:
            # Try to read as text
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10000)  # Read first 10KB
            except:
                with open(file_path, 'rb') as f:
                    content = f.read(10000).decode('utf-8', errors='ignore')
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    results['suspicious_indicators'].append(f'Suspicious pattern found: {pattern}')
                    results['risk_score'] += 20
            
            # Check for obfuscated content
            if self._is_obfuscated(content):
                results['suspicious_indicators'].append('Potentially obfuscated content')
                results['risk_score'] += 25
                
        except Exception:
            pass  # Unable to read content
    
    def _is_obfuscated(self, content):
        """Check if content appears to be obfuscated"""
        if len(content) < 100:
            return False
        
        # High ratio of non-printable characters
        non_printable = sum(1 for c in content if ord(c) < 32 or ord(c) > 126)
        if non_printable / len(content) > 0.3:
            return True
        
        # High entropy (lots of random-looking characters)
        import string
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        for count in char_counts.values():
            p = count / len(content)
            entropy -= p * (p.bit_length() - 1) if p > 0 else 0
        
        return entropy > 4.5  # Threshold for high entropy
    
    def _calculate_threat_level(self, results):
        """Calculate final threat level based on risk score"""
        score = results['risk_score']
        
        if score >= 60:
            results['threat_level'] = 'malicious'
        elif score >= 30:
            results['threat_level'] = 'suspicious'
        else:
            results['threat_level'] = 'safe'
