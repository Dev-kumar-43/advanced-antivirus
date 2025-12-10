🛡️ Advanced Malware Detection & Analysis System

A hybrid antivirus-style security tool designed to detect malicious files using static analysis, heuristic detection, YARA rules, and VirusTotal threat intelligence.
Built for practical cybersecurity workflows such as threat hunting, malware analysis, and automated incident response.

🚀 Features
🔍 Static Analysis Engine

Extracts file metadata, magic numbers, imports, headers, and structure

Computes SHA-256 / MD5 hashes

Detects known malicious patterns from signatures and anomalies

🤖 Heuristic Detection System

Identifies suspicious behaviors such as:

High entropy (packed/obfuscated malware)

Dangerous API imports

Suspicious file permissions

Assigns a risk score → Safe / Suspicious / Malicious

🧿 YARA Rule Integration

Supports custom & community YARA rule sets

Detects malware families, trojans, ransomware traits, keyloggers, etc.

Extensible rule system for threat research

🌐 VirusTotal API Integration

Performs hash-based lookups

Enhances internal detection with external threat intelligence

Doesn’t upload full files — privacy-safe

🔐 Quarantine System

Moves detected malicious files to a protected directory

Enforces restricted permissions

Supports restore/delete actions

📊 Threat Report & Logging

Generates detailed scan reports

Logs all detections to a SQLite database

Useful for security operations & analysis

🖥️ Simple GUI (Tkinter)

📁 Project Structure (Example)
/core
  ├── static_analysis.py
  ├── heuristic_engine.py
  ├── yara_engine.py
  ├── vt_lookup.py

/gui
  ├── main_ui.py

/database
  ├── scan_history.sqlite

/quarantine
  ├── (isolated malicious files)

README.md
requirements.txt

Clean and easy-to-use interface

Scan files, view results, manage quarantine

Ideal for non-technical users
