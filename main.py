# main.py
#!/usr/bin/env python3
"""
Advanced Antivirus Solution
A comprehensive antivirus tool with VirusTotal integration, heuristic analysis,
YARA rule support, and modern GUI interface.
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main application entry point"""
    try:
        from config import Config
        from gui.main_window import main as gui_main
        
        # Ensure required directories exist
        Config.ensure_directories()
        
        # Launch GUI application
        gui_main()
        
    except ImportError as e:
        print(f"Error importing required modules: {e}")
        print("Please ensure all dependencies are installed:")
        print("pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
