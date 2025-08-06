# manager.py
import shutil
import os
from pathlib import Path
from datetime import datetime
from config import Config
from database.db_manager import DatabaseManager

class QuarantineManager:
    def __init__(self):
        self.quarantine_dir = Config.QUARANTINE_DIR
        self.db = DatabaseManager()
        Config.ensure_directories()
    
    def quarantine_file(self, file_path, threat_reason, file_hash):
        """Move file to quarantine"""
        try:
            original_path = Path(file_path)
            
            if not original_path.exists():
                return False, "File does not exist"
            
            # Generate unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{original_path.stem}_{timestamp}.quarantined"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file to quarantine
            shutil.move(str(original_path), str(quarantine_path))
            
            # Make file read-only and hidden
            os.chmod(quarantine_path, 0o400)  # Read-only for owner
            
            # Add to database
            self.db.add_quarantine_entry(
                str(original_path),
                str(quarantine_path),
                threat_reason,
                file_hash
            )
            
            return True, str(quarantine_path)
            
        except Exception as e:
            return False, f"Quarantine failed: {str(e)}"
    
    def restore_file(self, quarantine_id):
        """Restore file from quarantine"""
        try:
            quarantine_entries = self.db.get_quarantine_list()
            entry = next((e for e in quarantine_entries if e[0] == quarantine_id), None)
            
            if not entry:
                return False, "Quarantine entry not found"
            
            original_path = Path(entry[1])
            quarantine_path = Path(entry[2])
            
            if not quarantine_path.exists():
                return False, "Quarantined file not found"
            
            # Ensure original directory exists
            original_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Restore file permissions
            os.chmod(quarantine_path, 0o644)
            
            # Move file back to original location
            shutil.move(str(quarantine_path), str(original_path))
            
            # Remove from database
            self.db.remove_quarantine_entry(quarantine_id)
            
            return True, f"File restored to {original_path}"
            
        except Exception as e:
            return False, f"Restore failed: {str(e)}"
    
    def delete_quarantined_file(self, quarantine_id):
        """Permanently delete quarantined file"""
        try:
            quarantine_entries = self.db.get_quarantine_list()
            entry = next((e for e in quarantine_entries if e[0] == quarantine_id), None)
            
            if not entry:
                return False, "Quarantine entry not found"
            
            quarantine_path = Path(entry[2])
            
            if quarantine_path.exists():
                # Securely delete file
                self._secure_delete(quarantine_path)
            
            # Remove from database
            self.db.remove_quarantine_entry(quarantine_id)
            
            return True, "File permanently deleted"
            
        except Exception as e:
            return False, f"Delete failed: {str(e)}"
    
    def _secure_delete(self, file_path):
        """Securely delete file by overwriting with random data"""
        try:
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r+b') as f:
                # Overwrite with zeros
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Overwrite with random data
                import secrets
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            # Remove file
            file_path.unlink()
            
        except Exception:
            # Fallback to simple deletion
            file_path.unlink()
    
    def get_quarantine_list(self):
        """Get list of quarantined files"""
        return self.db.get_quarantine_list()
    
    def get_quarantine_stats(self):
        """Get quarantine statistics"""
        entries = self.get_quarantine_list()
        total_files = len(entries)
        total_size = 0
        
        for entry in entries:
            quarantine_path = Path(entry[2])
            if quarantine_path.exists():
                total_size += quarantine_path.stat().st_size
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2)
        }
