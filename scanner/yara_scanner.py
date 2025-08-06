# yara_scanner.py
import yara
import os
from pathlib import Path
from config import Config

class YaraScanner:
    def __init__(self):
        self.rules = None
        self.load_rules()
    
    def load_rules(self):
        """Load YARA rules from rules directory"""
        rules_dir = Config.RULES_DIR
        rule_files = {}
        
        try:
            for rule_file in rules_dir.glob('*.yar'):
                try:
                    rule_files[rule_file.stem] = str(rule_file)
                except Exception as e:
                    print(f"Error loading rule {rule_file}: {e}")
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
            else:
                # Create default rules if none exist
                self._create_default_rules()
                
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            self.rules = None
    
    def _create_default_rules(self):
        """Create default YARA rules"""
        default_rules = '''
rule Suspicious_Executable {
    meta:
        description = "Detects suspicious executable patterns"
        severity = "medium"
    
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "SetWindowsHookEx" ascii
    
    condition:
        2 of ($s*)
}

rule Potential_Keylogger {
    meta:
        description = "Detects potential keylogger behavior"
        severity = "high"
    
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $k3 = "WH_KEYBOARD" ascii
        $k4 = "keylog" ascii nocase
    
    condition:
        2 of ($k*)
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "medium"
    
    strings:
        $p1 = "powershell" nocase
        $p2 = "-enc" nocase
        $p3 = "-nop" nocase
        $p4 = "-w hidden" nocase
        $p5 = "IEX" nocase
        $p6 = "DownloadString" nocase
    
    condition:
        $p1 and 2 of ($p2, $p3, $p4, $p5, $p6)
}
'''
        
        default_rule_file = Config.RULES_DIR / "default.yar"
        with open(default_rule_file, 'w') as f:
            f.write(default_rules)
        
        try:
            self.rules = yara.compile(source=default_rules)
        except Exception as e:
            print(f"Error compiling default rules: {e}")
    
   # In the YaraScanner class, update the scan_file method:
def scan_file(self, file_path):
    """Scan file with YARA rules"""
    if not self.rules:
        return {
            'matches': [],
            'threat_level': 'unknown',
            'error': 'No YARA rules loaded'
        }
    
    try:
        # Convert Path object to string if needed
        file_path_str = str(file_path)
        matches = self.rules.match(file_path_str, timeout=30)
        
        results = {
            'matches': [],
            'threat_level': 'safe',
            'rule_count': len(matches)
        }
        
        max_severity = 0
        for match in matches:
            severity = self._get_severity_level(match.meta.get('severity', 'low'))
            max_severity = max(max_severity, severity)
            
            match_info = {
                'rule_name': match.rule,
                'description': match.meta.get('description', 'No description'),
                'severity': match.meta.get('severity', 'low'),
                'tags': list(match.tags),  # Convert to list for JSON serialization
                'strings': [(s.identifier, [inst.offset for inst in s.instances]) for s in match.strings]
            }
            results['matches'].append(match_info)
        
        # Determine threat level based on highest severity
        if max_severity >= 3:
            results['threat_level'] = 'malicious'
        elif max_severity >= 2:
            results['threat_level'] = 'suspicious'
        
        return results
        
    except Exception as e:
        return {
            'matches': [],
            'threat_level': 'unknown',
            'error': f'YARA scan failed: {str(e)}'
        }

    
    def _get_severity_level(self, severity):
        """Convert severity string to numeric level"""
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(severity.lower(), 1)
    
    def add_custom_rule(self, rule_name, rule_content):
        """Add custom YARA rule"""
        rule_file = Config.RULES_DIR / f"{rule_name}.yar"
        
        try:
            # Validate rule syntax
            yara.compile(source=rule_content)
            
            # Save rule to file
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Reload all rules
            self.load_rules()
            return True
            
        except Exception as e:
            return False, str(e)
    
    def remove_rule(self, rule_name):
        """Remove YARA rule"""
        rule_file = Config.RULES_DIR / f"{rule_name}.yar"
        
        try:
            if rule_file.exists():
                rule_file.unlink()
                self.load_rules()
                return True
        except Exception:
            pass
        
        return False
