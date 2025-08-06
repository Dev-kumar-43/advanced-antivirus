# main_window.py
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QVBoxLayout, 
                           QWidget, QMenuBar, QStatusBar, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

from gui.components.scanner_tab import ScannerTab
from gui.components.history_tab import HistoryTab
from gui.components.settings_tab import SettingsTab
from config import Config

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        Config.ensure_directories()
        self.init_ui()
        self.setup_menu()
        self.setup_status_bar()
        
    def init_ui(self):
        """Initialize the main UI"""
        self.setWindowTitle(f"{Config.APP_NAME} v{Config.VERSION}")
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(800, 600)
        
        # Set application font
        font = QFont("Segoe UI", 10)
        self.setFont(font)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        
        # Create tabs
        self.scanner_tab = ScannerTab(self)
        self.history_tab = HistoryTab(self)
        self.settings_tab = SettingsTab(self)
        
        # Add tabs to tab widget
        self.tab_widget.addTab(self.scanner_tab, "🔍 Scanner")
        self.tab_widget.addTab(self.history_tab, "📋 History")
        self.tab_widget.addTab(self.settings_tab, "⚙️ Settings")
        
        layout.addWidget(self.tab_widget)
        
        # Apply dark theme
        self.apply_dark_theme()
    
    def setup_menu(self):
        """Setup application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        file_menu.addAction('New Scan', self.scanner_tab.start_scan)
        file_menu.addSeparator()
        file_menu.addAction('Export Report', self.export_report)
        file_menu.addSeparator()
        file_menu.addAction('Exit', self.close)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        tools_menu.addAction('Quarantine Manager', self.show_quarantine_manager)
        tools_menu.addAction('Update YARA Rules', self.update_yara_rules)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        help_menu.addAction('About', self.show_about)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.statusBar().showMessage("Ready")
        
        # Add progress bar to status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress_bar)
    
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        dark_stylesheet = """
        QMainWindow {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #2b2b2b;
        }
        QTabWidget::tab-bar {
            alignment: center;
        }
        QTabBar::tab {
            background-color: #404040;
            color: #ffffff;
            padding: 8px 16px;
            margin: 2px;
            border-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #0078d4;
        }
        QTabBar::tab:hover {
            background-color: #505050;
        }
        QPushButton {
            background-color: #0078d4;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #106ebe;
        }
        QPushButton:pressed {
            background-color: #005a9e;
        }
        QPushButton:disabled {
            background-color: #404040;
            color: #888888;
        }
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 4px;
            border-radius: 4px;
        }
        QTableWidget {
            background-color: #353535;
            alternate-background-color: #404040;
            color: #ffffff;
            border: 1px solid #555555;
        }
        QHeaderView::section {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 6px;
        }
        QLabel {
            color: #ffffff;
        }
        QProgressBar {
            border: 1px solid #555555;
            border-radius: 4px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #0078d4;
            border-radius: 4px;
        }
        """
        self.setStyleSheet(dark_stylesheet)
    
    def export_report(self):
        """Export scan report"""
        self.scanner_tab.export_report()
    
    def show_quarantine_manager(self):
        """Show quarantine manager dialog"""
        from gui.components.quarantine_dialog import QuarantineDialog
        dialog = QuarantineDialog(self)
        dialog.exec_()
    
    def update_yara_rules(self):
        """Update YARA rules"""
        # Reload YARA rules
        self.scanner_tab.scanner_engine.yara_scanner.load_rules()
        QMessageBox.information(self, "Success", "YARA rules updated successfully!")
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        <h2>{Config.APP_NAME}</h2>
        <p>Version {Config.VERSION}</p>
        <p>A modern, comprehensive antivirus solution with:</p>
        <ul>
        <li>VirusTotal integration</li>
        <li>Heuristic analysis</li>
        <li>YARA rule support</li>
        <li>Quarantine management</li>
        <li>Threat reporting</li>
        </ul>
        <p>Built with Python and PyQt5</p>
        """
        QMessageBox.about(self, "About", about_text)
    
    def update_status(self, message):
        """Update status bar message"""
        self.statusBar().showMessage(message)
    
    def show_progress(self, show=True):
        """Show or hide progress bar"""
        self.progress_bar.setVisible(show)
    
    def update_progress(self, value):
        """Update progress bar value"""
        self.progress_bar.setValue(value)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(Config.APP_NAME)
    app.setApplicationVersion(Config.VERSION)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
