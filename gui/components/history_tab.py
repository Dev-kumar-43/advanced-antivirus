# history_tab.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QTableWidget, QTableWidgetItem, QHeaderView, 
                           QGroupBox, QMessageBox, QLabel, QDateEdit)
from PyQt5.QtCore import Qt, QDate
from PyQt5.QtGui import QColor
from database.db_manager import DatabaseManager
from pathlib import Path
import json
from datetime import datetime

class HistoryTab(QWidget):
    """Scan history tab widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.db = DatabaseManager()
        self.init_ui()
        self.load_history()
    
    def init_ui(self):
        """Initialize the history tab UI"""
        layout = QVBoxLayout(self)
        
        # Controls section
        controls_group = QGroupBox("History Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Refresh button
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.load_history)
        
        # Clear history button
        self.clear_btn = QPushButton("🗑️ Clear History")
        self.clear_btn.clicked.connect(self.clear_history)
        
        # Export button
        self.export_btn = QPushButton("📤 Export History")
        self.export_btn.clicked.connect(self.export_history)
        
        controls_layout.addWidget(self.refresh_btn)
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.export_btn)
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        # Statistics section
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.total_scans_label = QLabel("Total Scans: 0")
        self.threats_found_label = QLabel("Threats Found: 0")
        self.quarantined_label = QLabel("Quarantined: 0")
        
        stats_layout.addWidget(self.total_scans_label)
        stats_layout.addWidget(self.threats_found_label)
        stats_layout.addWidget(self.quarantined_label)
        stats_layout.addStretch()
        
        layout.addWidget(stats_group)
        
        # History table
        history_group = QGroupBox("Scan History")
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "Date", "File", "Hash", "Threat Level", "VirusTotal", "Heuristic", "Quarantined"
        ])
        
        # Configure table
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setSortingEnabled(True)
        
        history_layout.addWidget(self.history_table)
        layout.addWidget(history_group)
    
    def load_history(self):
        """Load scan history from database"""
        try:
            history_data = self.db.get_scan_history()
            self.populate_table(history_data)
            self.update_statistics(history_data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load history: {str(e)}")
    
    def populate_table(self, history_data):
        """Populate history table with data"""
        self.history_table.setRowCount(len(history_data))
        
        for row, record in enumerate(history_data):
            # Extract data from record
            scan_id, file_path, file_hash, scan_date, threat_level, vt_result, heuristic_result, yara_matches, quarantined = record
            
            # Date
            date_item = QTableWidgetItem(scan_date)
            self.history_table.setItem(row, 0, date_item)
            
            # File name
            file_name = Path(file_path).name if file_path else "Unknown"
            file_item = QTableWidgetItem(file_name)
            file_item.setToolTip(file_path)  # Show full path in tooltip
            self.history_table.setItem(row, 1, file_item)
            
            # Hash (truncated)
            hash_display = file_hash[:16] + "..." if file_hash and len(file_hash) > 16 else (file_hash or "N/A")
            hash_item = QTableWidgetItem(hash_display)
            hash_item.setToolTip(file_hash)  # Show full hash in tooltip
            self.history_table.setItem(row, 2, hash_item)
            
            # Threat level with color coding
            threat_item = QTableWidgetItem(threat_level.upper() if threat_level else "UNKNOWN")
            if threat_level == 'malicious':
                threat_item.setBackground(QColor(255, 0, 0, 50))  # Light red
            elif threat_level == 'suspicious':
                threat_item.setBackground(QColor(255, 165, 0, 50))  # Light orange
            else:
                threat_item.setBackground(QColor(0, 255, 0, 50))  # Light green
            
            self.history_table.setItem(row, 3, threat_item)
            
            # VirusTotal results
            vt_data = json.loads(vt_result) if vt_result else {}
            vt_display = f"{vt_data.get('detection_count', 0)}/{vt_data.get('total_engines', 0)}"
            self.history_table.setItem(row, 4, QTableWidgetItem(vt_display))
            
            # Heuristic results
            heuristic_data = json.loads(heuristic_result) if heuristic_result else {}
            heuristic_display = f"Score: {heuristic_data.get('risk_score', 0)}"
            self.history_table.setItem(row, 5, QTableWidgetItem(heuristic_display))
            
            # Quarantined status
            quarantine_status = "Yes" if quarantined else "No"
            quarantine_item = QTableWidgetItem(quarantine_status)
            if quarantined:
                quarantine_item.setBackground(QColor(255, 255, 0, 50))  # Light yellow
            self.history_table.setItem(row, 6, quarantine_item)
    
    def update_statistics(self, history_data):
        """Update statistics labels"""
        total_scans = len(history_data)
        threats_found = sum(1 for record in history_data if record[4] in ['malicious', 'suspicious'])
        quarantined = sum(1 for record in history_data if record[8])  # quarantined column
        
        self.total_scans_label.setText(f"Total Scans: {total_scans}")
        self.threats_found_label.setText(f"Threats Found: {threats_found}")
        self.quarantined_label.setText(f"Quarantined: {quarantined}")
    
    def clear_history(self):
        """Clear scan history"""
        reply = QMessageBox.question(
            self, 
            "Clear History", 
            "Are you sure you want to clear all scan history? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Clear history from database
                with self.db.db_path.open() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_history")
                    conn.commit()
                
                # Refresh display
                self.load_history()
                QMessageBox.information(self, "Success", "Scan history cleared successfully!")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear history: {str(e)}")
    
    def export_history(self):
        """Export scan history to CSV"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            import csv
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export History", "scan_history.csv", "CSV Files (*.csv)"
            )
            
            if filename:
                history_data = self.db.get_scan_history()
                
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Write header
                    writer.writerow([
                        "Scan Date", "File Path", "File Hash", "Threat Level",
                        "VirusTotal Detections", "Heuristic Score", "YARA Matches", "Quarantined"
                    ])
                    
                    # Write data
                    for record in history_data:
                        scan_id, file_path, file_hash, scan_date, threat_level, vt_result, heuristic_result, yara_matches, quarantined = record
                        
                        # Parse JSON results
                        vt_data = json.loads(vt_result) if vt_result else {}
                        heuristic_data = json.loads(heuristic_result) if heuristic_result else {}
                        yara_data = json.loads(yara_matches) if yara_matches else {}
                        
                        writer.writerow([
                            scan_date,
                            file_path,
                            file_hash,
                            threat_level,
                            f"{vt_data.get('detection_count', 0)}/{vt_data.get('total_engines', 0)}",
                            heuristic_data.get('risk_score', 0),
                            yara_data.get('rule_count', 0),
                            "Yes" if quarantined else "No"
                        ])
                
                QMessageBox.information(self, "Success", f"History exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export history: {str(e)}")
