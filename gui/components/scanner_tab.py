# scanner_tab.py
import os
import threading
from pathlib import Path
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                           QFileDialog, QTextEdit, QProgressBar, QLabel, 
                           QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                           QHeaderView, QMessageBox, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor

from scanner.virus_total import VirusTotalScanner
from scanner.heuristics import HeuristicAnalyzer
from scanner.yara_scanner import YaraScanner
from quarantine.manager import QuarantineManager
from reports.report_generator import ReportGenerator
from database.db_manager import DatabaseManager
from config import Config

class ScanEngine(QThread):
    """Background thread for file scanning"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    file_scanned = pyqtSignal(dict)
    
    def __init__(self, files_to_scan, settings):
        super().__init__()
        self.files_to_scan = files_to_scan
        self.settings = settings
        self.scan_results = []
        self.is_cancelled = False
        
        # Initialize scanners
        api_key = settings.get('vt_api_key', '')
        self.vt_scanner = VirusTotalScanner(api_key) if api_key else None
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.yara_scanner = YaraScanner()
        self.quarantine_manager = QuarantineManager()
        self.db = DatabaseManager()
    
    def run(self):
        """Run the scan process"""
        total_files = len(self.files_to_scan)
        
        for i, file_path in enumerate(self.files_to_scan):
            if self.is_cancelled:
                break
                
            # Update progress
            progress = int((i + 1) * 100 / total_files)
            self.progress_updated.emit(progress)
            self.status_updated.emit(f"Scanning: {Path(file_path).name}")
            
            # Perform scan
            result = self.scan_single_file(file_path)
            self.scan_results.append(result)
            self.file_scanned.emit(result)
        
        self.scan_completed.emit(self.scan_results)
    
    def scan_single_file(self, file_path):
        """Scan a single file with all available methods"""
        result = {
            'file_path': str(file_path),
            'file_hash': None,
            'threat_level': 'safe',
            'vt_result': {},
            'heuristic_result': {},
            'yara_result': {},
            'quarantined': False
        }
        
        try:
            # Calculate file hash
            if self.vt_scanner:
                file_hash = self.vt_scanner.calculate_file_hash(file_path)
                result['file_hash'] = file_hash
                
                # VirusTotal scan
                if file_hash:
                    vt_response = self.vt_scanner.scan_file_hash(file_hash)
                    result['vt_result'] = self.vt_scanner.analyze_vt_result(vt_response)
            
            # Heuristic analysis
            if self.settings.get('heuristics_enabled', True):
                result['heuristic_result'] = self.heuristic_analyzer.analyze_file(file_path)
            
            # YARA scan
            result['yara_result'] = self.yara_scanner.scan_file(file_path)
            
            # Determine overall threat level
            threat_levels = []
            if result['vt_result'].get('threat_level'):
                threat_levels.append(result['vt_result']['threat_level'])
            if result['heuristic_result'].get('threat_level'):
                threat_levels.append(result['heuristic_result']['threat_level'])
            if result['yara_result'].get('threat_level'):
                threat_levels.append(result['yara_result']['threat_level'])
            
            # Use highest threat level
            if 'malicious' in threat_levels:
                result['threat_level'] = 'malicious'
            elif 'suspicious' in threat_levels:
                result['threat_level'] = 'suspicious'
            else:
                result['threat_level'] = 'safe'
            
            # Auto-quarantine if enabled
            if (self.settings.get('auto_quarantine', False) and 
                result['threat_level'] == 'malicious'):
                success, quarantine_path = self.quarantine_manager.quarantine_file(
                    file_path, 
                    f"Detected as {result['threat_level']}", 
                    result['file_hash']
                )
                result['quarantined'] = success
            
            # Save to database
            self.db.add_scan_result(
                result['file_path'],
                result['file_hash'],
                result['threat_level'],
                result['vt_result'],
                result['heuristic_result'],
                result['yara_result'],
                result['quarantined']
            )
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def cancel(self):
        """Cancel the scan process"""
        self.is_cancelled = True

class ScannerTab(QWidget):
    """Main scanner tab widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.scan_engine = None
        self.scan_results = []
        self.settings = Config.load_settings()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the scanner tab UI"""
        layout = QVBoxLayout(self)
        
        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        # File selection buttons
        button_layout = QHBoxLayout()
        self.select_files_btn = QPushButton("📄 Select Files")
        self.select_folder_btn = QPushButton("📁 Select Folder")
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.cancel_btn = QPushButton("❌ Cancel")
        
        self.select_files_btn.clicked.connect(self.select_files)
        self.select_folder_btn.clicked.connect(self.select_folder)
        self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        
        self.cancel_btn.setEnabled(False)
        
        button_layout.addWidget(self.select_files_btn)
        button_layout.addWidget(self.select_folder_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.scan_btn)
        button_layout.addWidget(self.cancel_btn)
        
        file_layout.addLayout(button_layout)
        
        # Selected files display
        self.selected_files_text = QTextEdit()
        self.selected_files_text.setMaximumHeight(100)
        self.selected_files_text.setPlaceholderText("No files selected")
        file_layout.addWidget(self.selected_files_text)
        
        layout.addWidget(file_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.heuristics_cb = QCheckBox("Enable Heuristic Analysis")
        self.yara_cb = QCheckBox("Enable YARA Rules")
        self.auto_quarantine_cb = QCheckBox("Auto-quarantine threats")
        
        self.heuristics_cb.setChecked(self.settings.get('heuristics_enabled', True))
        self.yara_cb.setChecked(True)
        self.auto_quarantine_cb.setChecked(self.settings.get('auto_quarantine', False))
        
        options_layout.addWidget(self.heuristics_cb)
        options_layout.addWidget(self.yara_cb)
        options_layout.addWidget(self.auto_quarantine_cb)
        
        layout.addWidget(options_group)
        
        # Progress section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.status_label = QLabel("Ready to scan")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "File", "Threat Level", "VirusTotal", "Heuristic", "YARA"
        ])
        
        # Make table responsive
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        results_layout.addWidget(self.results_table)
        
        # Results actions
        results_actions = QHBoxLayout()
        self.export_pdf_btn = QPushButton("📄 Export PDF")
        self.export_text_btn = QPushButton("📝 Export Text")
        self.clear_results_btn = QPushButton("🗑️ Clear Results")
        
        self.export_pdf_btn.clicked.connect(self.export_pdf_report)
        self.export_text_btn.clicked.connect(self.export_text_report)
        self.clear_results_btn.clicked.connect(self.clear_results)
        
        self.export_pdf_btn.setEnabled(False)
        self.export_text_btn.setEnabled(False)
        self.clear_results_btn.setEnabled(False)
        
        results_actions.addWidget(self.export_pdf_btn)
        results_actions.addWidget(self.export_text_btn)
        results_actions.addStretch()
        results_actions.addWidget(self.clear_results_btn)
        
        results_layout.addLayout(results_actions)
        
        layout.addWidget(results_group)
        
        # Store selected files
        self.selected_files = []
    
    def select_files(self):
        """Select individual files for scanning"""
        files, _ = QFileDialog.getOpenFileNames(
            self, 
            "Select Files to Scan",
            "",
            "All Files (*.*)"
        )
        
        if files:
            self.selected_files = files
            self.update_selected_files_display()
    
    def select_folder(self):
        """Select folder for scanning"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        
        if folder:
            # Get all files in folder and subfolders
            files = []
            for root, _, filenames in os.walk(folder):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
            
            self.selected_files = files
            self.update_selected_files_display()
    
    def update_selected_files_display(self):
        """Update the selected files display"""
        if not self.selected_files:
            self.selected_files_text.setPlainText("No files selected")
            return
        
        display_text = f"Selected {len(self.selected_files)} files:\n"
        for file_path in self.selected_files[:10]:  # Show first 10 files
            display_text += f"• {Path(file_path).name}\n"
        
        if len(self.selected_files) > 10:
            display_text += f"... and {len(self.selected_files) - 10} more files"
        
        self.selected_files_text.setPlainText(display_text)
    
    def start_scan(self):
        """Start the scanning process"""
        if not self.selected_files:
            QMessageBox.warning(self, "Warning", "Please select files to scan first.")
            return
        
        # Update settings from checkboxes
        self.settings['heuristics_enabled'] = self.heuristics_cb.isChecked()
        self.settings['auto_quarantine'] = self.auto_quarantine_cb.isChecked()
        
        # Clear previous results
        self.scan_results = []
        self.results_table.setRowCount(0)
        
        # Setup UI for scanning
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Start scan engine
        self.scan_engine = ScanEngine(self.selected_files, self.settings)
        self.scan_engine.progress_updated.connect(self.update_progress)
        self.scan_engine.status_updated.connect(self.update_status)
        self.scan_engine.file_scanned.connect(self.add_scan_result)
        self.scan_engine.scan_completed.connect(self.scan_finished)
        self.scan_engine.start()
    
    def cancel_scan(self):
        """Cancel the current scan"""
        if self.scan_engine:
            self.scan_engine.cancel()
            self.scan_finished([])
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        if self.parent:
            self.parent.update_progress(value)
    
    def update_status(self, message):
        """Update status label"""
        self.status_label.setText(message)
        if self.parent:
            self.parent.update_status(message)
    
    def add_scan_result(self, result):
        """Add a scan result to the table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # File name
        file_name = Path(result['file_path']).name
        self.results_table.setItem(row, 0, QTableWidgetItem(file_name))
        
        # Threat level with color coding
        threat_level = result['threat_level'].upper()
        threat_item = QTableWidgetItem(threat_level)
        
        if threat_level == 'MALICIOUS':
            threat_item.setBackground(QColor(255, 0, 0, 50))  # Light red
        elif threat_level == 'SUSPICIOUS':
            threat_item.setBackground(QColor(255, 165, 0, 50))  # Light orange
        else:
            threat_item.setBackground(QColor(0, 255, 0, 50))  # Light green
        
        self.results_table.setItem(row, 1, threat_item)
        
        # VirusTotal results
        vt_result = result.get('vt_result', {})
        vt_text = f"{vt_result.get('detection_count', 0)}/{vt_result.get('total_engines', 0)}"
        self.results_table.setItem(row, 2, QTableWidgetItem(vt_text))
        
        # Heuristic results
        heuristic_result = result.get('heuristic_result', {})
        heuristic_text = f"Score: {heuristic_result.get('risk_score', 0)}"
        self.results_table.setItem(row, 3, QTableWidgetItem(heuristic_text))
        
        # YARA results
        yara_result = result.get('yara_result', {})
        yara_text = f"Matches: {yara_result.get('rule_count', 0)}"
        self.results_table.setItem(row, 4, QTableWidgetItem(yara_text))
    
    def scan_finished(self, results):
        """Handle scan completion"""
        self.scan_results = results
        
        # Reset UI
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # Enable export buttons
        if results:
            self.export_pdf_btn.setEnabled(True)
            self.export_text_btn.setEnabled(True)
            self.clear_results_btn.setEnabled(True)
        
        # Update status
        total_files = len(results)
        threats_found = sum(1 for r in results if r['threat_level'] in ['malicious', 'suspicious'])
        
        if threats_found > 0:
            self.update_status(f"Scan completed: {threats_found} threats found in {total_files} files")
        else:
            self.update_status(f"Scan completed: All {total_files} files are safe")
        
        # Show completion message
        QMessageBox.information(
            self, 
            "Scan Complete", 
            f"Scanned {total_files} files.\n{threats_found} potential threats detected."
        )
    
    def export_pdf_report(self):
        """Export results as PDF report"""
        if not self.scan_results:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export PDF Report", "scan_report.pdf", "PDF Files (*.pdf)"
        )
        
        if filename:
            report_generator = ReportGenerator()
            success, message = report_generator.generate_scan_report(self.scan_results, filename)
            
            if success:
                QMessageBox.information(self, "Success", "PDF report exported successfully!")
            else:
                QMessageBox.critical(self, "Error", f"Failed to export PDF: {message}")
    
    def export_text_report(self):
        """Export results as text report"""
        if not self.scan_results:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Text Report", "scan_report.txt", "Text Files (*.txt)"
        )
        
        if filename:
            report_generator = ReportGenerator()
            success, message = report_generator.generate_text_report(self.scan_results, filename)
            
            if success:
                QMessageBox.information(self, "Success", "Text report exported successfully!")
            else:
                QMessageBox.critical(self, "Error", f"Failed to export text: {message}")
    
    def clear_results(self):
        """Clear scan results"""
        self.scan_results = []
        self.results_table.setRowCount(0)
        self.export_pdf_btn.setEnabled(False)
        self.export_text_btn.setEnabled(False)
        self.clear_results_btn.setEnabled(False)
        self.update_status("Results cleared")
    
    def export_report(self):
        """Export report (called from main menu)"""
        if self.scan_results:
            self.export_pdf_report()
        else:
            QMessageBox.information(self, "No Results", "No scan results to export.")
