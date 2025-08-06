# settings_tab.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLineEdit, QCheckBox, QGroupBox, QLabel, QSpinBox,
                           QTextEdit, QMessageBox, QListWidget, QInputDialog,
                           QFileDialog, QTabWidget)
from PyQt5.QtCore import Qt
from config import Config
import os

class SettingsTab(QWidget):
    """Settings tab widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.settings = Config.load_settings()
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize the settings tab UI"""
        layout = QVBoxLayout(self)
        
        # Create tab widget for organized settings
        self.tab_widget = QTabWidget()
        
        # API Settings tab
        self.api_tab = self.create_api_tab()
        self.tab_widget.addTab(self.api_tab, "🔑 API Settings")
        
        # Scan Settings tab
        self.scan_tab = self.create_scan_tab()
        self.tab_widget.addTab(self.scan_tab, "🔍 Scan Settings")
        
        # YARA Rules tab
        self.yara_tab = self.create_yara_tab()
        self.tab_widget.addTab(self.yara_tab, "📋 YARA Rules")
        
        layout.addWidget(self.tab_widget)
        
        # Save/Reset buttons
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("💾 Save Settings")
        self.reset_btn = QPushButton("🔄 Reset to Defaults")
        self.test_api_btn = QPushButton("🧪 Test API")
        
        self.save_btn.clicked.connect(self.save_settings)
        self.reset_btn.clicked.connect(self.reset_settings)
        self.test_api_btn.clicked.connect(self.test_api_connection)
        
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.reset_btn)
        button_layout.addWidget(self.test_api_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
    
    def create_api_tab(self):
        """Create API settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # VirusTotal API settings
        vt_group = QGroupBox("VirusTotal API Configuration")
        vt_layout = QVBoxLayout(vt_group)
        
        # API Key input
        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(QLabel("API Key:"))
        
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("Enter your VirusTotal API key")
        api_key_layout.addWidget(self.api_key_input)
        
        # Show/Hide button
        self.show_api_key_btn = QPushButton("👁️ Show")
        self.show_api_key_btn.clicked.connect(self.toggle_api_key_visibility)
        api_key_layout.addWidget(self.show_api_key_btn)
        
        vt_layout.addLayout(api_key_layout)
        
        # API info
        api_info = QLabel("""
        <b>How to get a VirusTotal API key:</b><br>
        1. Visit <a href="https://www.virustotal.com">virustotal.com</a><br>
        2. Create a free account<br>
        3. Go to your profile settings<br>
        4. Copy your API key<br><br>
        <b>Note:</b> Free API keys have rate limits (4 requests/minute)
        """)
        api_info.setWordWrap(True)
        api_info.setOpenExternalLinks(True)
        vt_layout.addWidget(api_info)
        
        layout.addWidget(vt_group)
        
        return widget
    
    def create_scan_tab(self):
        """Create scan settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # General scan settings
        general_group = QGroupBox("General Scan Settings")
        general_layout = QVBoxLayout(general_group)
        
        # Heuristics checkbox
        self.heuristics_cb = QCheckBox("Enable Heuristic Analysis")
        self.heuristics_cb.setToolTip("Enable custom rule-based threat detection")
        general_layout.addWidget(self.heuristics_cb)
        
        # Auto-quarantine checkbox
        self.auto_quarantine_cb = QCheckBox("Auto-quarantine malicious files")
        self.auto_quarantine_cb.setToolTip("Automatically move detected threats to quarantine")
        general_layout.addWidget(self.auto_quarantine_cb)
        
        # Scan archives checkbox
        self.scan_archives_cb = QCheckBox("Scan archive contents")
        self.scan_archives_cb.setToolTip("Extract and scan files inside archives")
        general_layout.addWidget(self.scan_archives_cb)
        
        layout.addWidget(general_group)
        
        # File size limits
        limits_group = QGroupBox("Scan Limits")
        limits_layout = QVBoxLayout(limits_group)
        
        # Max file size
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Maximum file size (MB):"))
        
        self.max_size_input = QSpinBox()
        self.max_size_input.setRange(1, 1000)
        self.max_size_input.setValue(100)
        self.max_size_input.setToolTip("Skip files larger than this size")
        size_layout.addWidget(self.max_size_input)
        
        limits_layout.addLayout(size_layout)
        layout.addWidget(limits_group)
        
        # Exclusions
        exclusions_group = QGroupBox("File Exclusions")
        exclusions_layout = QVBoxLayout(exclusions_group)
        
        exclusions_layout.addWidget(QLabel("Excluded file extensions:"))
        self.exclusions_input = QTextEdit()
        self.exclusions_input.setMaximumHeight(100)
        self.exclusions_input.setPlaceholderText("Enter file extensions to exclude, one per line (e.g., .txt, .log)")
        exclusions_layout.addWidget(self.exclusions_input)
        
        layout.addWidget(exclusions_group)
        
        return widget
    
    def create_yara_tab(self):
        """Create YARA rules management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # YARA rules list
        rules_group = QGroupBox("YARA Rules")
        rules_layout = QVBoxLayout(rules_group)
        
        # Rules list
        self.rules_list = QListWidget()
        self.load_yara_rules()
        rules_layout.addWidget(self.rules_list)
        
        # Rules buttons
        rules_buttons = QHBoxLayout()
        
        self.add_rule_btn = QPushButton("➕ Add Rule")
        self.edit_rule_btn = QPushButton("✏️ Edit Rule")
        self.delete_rule_btn = QPushButton("🗑️ Delete Rule")
        self.import_rule_btn = QPushButton("📥 Import Rules")
        
        self.add_rule_btn.clicked.connect(self.add_yara_rule)
        self.edit_rule_btn.clicked.connect(self.edit_yara_rule)
        self.delete_rule_btn.clicked.connect(self.delete_yara_rule)
        self.import_rule_btn.clicked.connect(self.import_yara_rules)
        
        rules_buttons.addWidget(self.add_rule_btn)
        rules_buttons.addWidget(self.edit_rule_btn)
        rules_buttons.addWidget(self.delete_rule_btn)
        rules_buttons.addWidget(self.import_rule_btn)
        
        rules_layout.addLayout(rules_buttons)
        layout.addWidget(rules_group)
        
        return widget
    
    def load_settings(self):
        """Load settings into UI controls"""
        # API settings
        encrypted_key = self.settings.get('vt_api_key', '')
        if encrypted_key:
            try:
                decrypted_key = Config.decrypt_data(encrypted_key)
                self.api_key_input.setText(decrypted_key)
            except:
                self.api_key_input.setText('')
        
        # Scan settings
        self.heuristics_cb.setChecked(self.settings.get('heuristics_enabled', True))
        self.auto_quarantine_cb.setChecked(self.settings.get('auto_quarantine', False))
        self.scan_archives_cb.setChecked(self.settings.get('scan_archives', True))
        
        # Limits
        max_size_mb = self.settings.get('max_file_size', 100 * 1024 * 1024) // (1024 * 1024)
        self.max_size_input.setValue(max_size_mb)
        
        # Exclusions
        exclusions = self.settings.get('excluded_extensions', [])
        self.exclusions_input.setPlainText('\n'.join(exclusions))
    
    def save_settings(self):
        """Save settings from UI controls"""
        try:
            # API settings
            api_key = self.api_key_input.text().strip()
            if api_key:
                encrypted_key = Config.encrypt_data(api_key)
                self.settings['vt_api_key'] = encrypted_key
            else:
                self.settings['vt_api_key'] = ''
            
            # Scan settings
            self.settings['heuristics_enabled'] = self.heuristics_cb.isChecked()
            self.settings['auto_quarantine'] = self.auto_quarantine_cb.isChecked()
            self.settings['scan_archives'] = self.scan_archives_cb.isChecked()
            
            # Limits
            self.settings['max_file_size'] = self.max_size_input.value() * 1024 * 1024
            
            # Exclusions
            exclusions_text = self.exclusions_input.toPlainText().strip()
            exclusions = [ext.strip() for ext in exclusions_text.split('\n') if ext.strip()]
            self.settings['excluded_extensions'] = exclusions
            
            # Save to file
            Config.save_settings(self.settings)
            
            QMessageBox.information(self, "Success", "Settings saved successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(
            self, 
            "Reset Settings", 
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Load default settings
            self.settings = {
                'vt_api_key': '',
                'heuristics_enabled': True,
                'auto_quarantine': False,
                'scan_archives': True,
                'max_file_size': 100 * 1024 * 1024,
                'excluded_extensions': ['.txt', '.md', '.log']
            }
            
            # Update UI
            self.load_settings()
            QMessageBox.information(self, "Success", "Settings reset to defaults!")
    
    def test_api_connection(self):
        """Test VirusTotal API connection"""
        api_key = self.api_key_input.text().strip()
        
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter an API key first.")
            return
        
        try:
            from scanner.virus_total import VirusTotalScanner
            import hashlib
            
            # Test with a known hash (EICAR test file)
            test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR SHA256
            
            scanner = VirusTotalScanner(api_key)
            result = scanner.scan_file_hash(test_hash)
            
            if 'error' in result:
                QMessageBox.critical(self, "API Test Failed", f"API Error: {result['error']}")
            else:
                QMessageBox.information(self, "API Test Successful", 
                                      f"API connection successful!\n"
                                      f"Test query returned: {result.get('response_code', 'Unknown')} response")
        
        except Exception as e:
            QMessageBox.critical(self, "API Test Failed", f"Test failed: {str(e)}")
    
    def toggle_api_key_visibility(self):
        """Toggle API key visibility"""
        if self.api_key_input.echoMode() == QLineEdit.Password:
            self.api_key_input.setEchoMode(QLineEdit.Normal)
            self.show_api_key_btn.setText("🙈 Hide")
        else:
            self.api_key_input.setEchoMode(QLineEdit.Password)
            self.show_api_key_btn.setText("👁️ Show")
    
    def load_yara_rules(self):
        """Load YARA rules list"""
        self.rules_list.clear()
        
        rules_dir = Config.RULES_DIR
        if rules_dir.exists():
            for rule_file in rules_dir.glob('*.yar'):
                self.rules_list.addItem(rule_file.name)
    
    def add_yara_rule(self):
        """Add new YARA rule"""
        rule_name, ok = QInputDialog.getText(self, "Add YARA Rule", "Enter rule name:")
        
        if ok and rule_name:
            # Create simple rule template
            rule_template = f'''rule {rule_name.replace(" ", "_")} {{
    meta:
        description = "Custom rule: {rule_name}"
        severity = "medium"
    
    strings:
        $s1 = "suspicious_string" ascii
    
    condition:
        $s1
}}'''
            
            # Save rule to file
            rule_file = Config.RULES_DIR / f"{rule_name.replace(' ', '_')}.yar"
            try:
                with open(rule_file, 'w') as f:
                    f.write(rule_template)
                
                self.load_yara_rules()
                QMessageBox.information(self, "Success", f"YARA rule '{rule_name}' created successfully!")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create rule: {str(e)}")
    
    def edit_yara_rule(self):
        """Edit selected YARA rule"""
        current_item = self.rules_list.currentItem()
        
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a rule to edit.")
            return
        
        rule_name = current_item.text()
        rule_file = Config.RULES_DIR / rule_name
        
        try:
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            # Simple text edit dialog (in a real app, you'd want a proper editor)
            from PyQt5.QtWidgets import QDialog, QTextEdit, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Edit YARA Rule: {rule_name}")
            dialog.setModal(True)
            dialog.resize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            editor = QTextEdit()
            editor.setPlainText(rule_content)
            layout.addWidget(editor)
            
            buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            if dialog.exec_() == QDialog.Accepted:
                # Save changes
                with open(rule_file, 'w') as f:
                    f.write(editor.toPlainText())
                
                QMessageBox.information(self, "Success", "Rule saved successfully!")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit rule: {str(e)}")
    
    def delete_yara_rule(self):
        """Delete selected YARA rule"""
        current_item = self.rules_list.currentItem()
        
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a rule to delete.")
            return
        
        rule_name = current_item.text()
        
        reply = QMessageBox.question(
            self, 
            "Delete Rule", 
            f"Are you sure you want to delete the rule '{rule_name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                rule_file = Config.RULES_DIR / rule_name
                rule_file.unlink()
                
                self.load_yara_rules()
                QMessageBox.information(self, "Success", f"Rule '{rule_name}' deleted successfully!")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete rule: {str(e)}")
    
    def import_yara_rules(self):
        """Import YARA rules from files"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Import YARA Rules", "", "YARA Rules (*.yar);;All Files (*.*)"
        )
        
        if files:
            imported_count = 0
            
            for file_path in files:
                try:
                    rule_name = os.path.basename(file_path)
                    destination = Config.RULES_DIR / rule_name
                    
                    # Copy file to rules directory
                    import shutil
                    shutil.copy2(file_path, destination)
                    imported_count += 1
                    
                except Exception as e:
                    QMessageBox.warning(self, "Import Warning", 
                                      f"Failed to import {file_path}: {str(e)}")
            
            if imported_count > 0:
                self.load_yara_rules()
                QMessageBox.information(self, "Success", 
                                      f"Successfully imported {imported_count} YARA rules!")
