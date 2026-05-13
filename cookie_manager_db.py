# cookie_manager_db.py - MODIFIED FOR SQLITE (local testing)
import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
import sqlite3  # Changed from psycopg2
from contextlib import contextmanager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration - FORCE SQLITE for local testing
SESSIONS_DIR = os.getenv('SESSION_DIR', 'sessions')

class DatabaseManager:
    """Manages SQLite database connections"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or 'test_aol_vault.db'
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with automatic cleanup"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    @contextmanager
    def get_cursor(self):
        """Get a database cursor with automatic cleanup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
            finally:
                cursor.close()

# Global database manager instance
db_manager = DatabaseManager()

def sanitize_filename(name: str) -> str:
    """Convert email/username to safe filename."""
    safe = name.replace('@', '_at_').replace('.', '_')
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe)
    return safe

def write_txt_file(cookies_dict: dict, filepath: str) -> None:
    """Write cookies to TXT file in console-pasteable format"""
    with open(filepath, 'w') as f:
        f.write(f"// AOL Cookies - Copy and paste ALL lines into browser console (F12) on aol.com\n")
        f.write(f"// Generated: {datetime.now().isoformat()}\n")
        f.write(f"// Total cookies: {len(cookies_dict)}\n\n")
        
        for name, value in cookies_dict.items():
            # Use single quotes to avoid escaping issues
            f.write(f"document.cookie = '{name}={value}; domain=.aol.com; path=/; secure';\n\n")

def write_chrome_json(cookies_dict: dict, filepath: str) -> None:
    """Write cookies to JSON format compatible with Cookie-Editor extension"""
    cookie_list = []
    for name, value in cookies_dict.items():
        cookie_list.append({
            "domain": ".aol.com",
            "hostOnly": False,
            "httpOnly": False,
            "name": name,
            "path": "/",
            "sameSite": "unspecified",
            "secure": True,
            "session": True,
            "value": value
        })
    with open(filepath, 'w') as f:
        json.dump(cookie_list, f, indent=2)

def save_credential(email: str, password: str) -> bool:
    """
    Save or update a credential in the database
    Returns True if successful
    """
    try:
        with db_manager.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO credentials (email, password, last_updated)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (email, password))
            
            print(f"✅ Saved credential to database: {email}")
            return True
    except Exception as e:
        print(f"❌ Error saving credential: {e}")
        import traceback
        traceback.print_exc()
        return False

def save_user_cookies(username: str, cookies_dict: dict) -> Optional[Dict[str, str]]:
    """
    Save user's cookies to database AND files
    Returns dict with file paths or None if failed
    """
    if not cookies_dict:
        return None
    
    # Ensure sessions directory exists
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    
    safe_name = sanitize_filename(username)
    txt_path = os.path.join(SESSIONS_DIR, f"{safe_name}.txt")
    json_path = os.path.join(SESSIONS_DIR, f"{safe_name}.json")
    
    # Write files first
    try:
        write_txt_file(cookies_dict, txt_path)
        write_chrome_json(cookies_dict, json_path)
        print(f"✅ Wrote cookie files: {txt_path}")
    except Exception as e:
        print(f"Error writing cookie files: {e}")
        return None
    
    # Now update database
    try:
        with db_manager.get_cursor() as cursor:
            # First check if credential exists
            cursor.execute("SELECT email FROM credentials WHERE email = ?", (username,))
            credential_exists = cursor.fetchone()
            
            if not credential_exists:
                # Save credential first
                save_credential(username, "temp_password_placeholder")
            
            # Get file size
            file_size_bytes = os.path.getsize(txt_path) if os.path.exists(txt_path) else 0
            filename = f"{safe_name}.cookie"
            
            # Check if cookie file already exists
            cursor.execute("""
                SELECT id FROM cookie_files 
                WHERE email = ? AND filename = ?
            """, (username, filename))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                cursor.execute("""
                    UPDATE cookie_files 
                    SET cookie_count = ?, file_size_bytes = ?, txt_path = ?, 
                        json_path = ?, last_accessed = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (len(cookies_dict), file_size_bytes, txt_path, json_path, existing['id']))
                cookie_file_id = existing['id']
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO cookie_files (email, filename, cookie_count, file_size_bytes, txt_path, json_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, filename, len(cookies_dict), file_size_bytes, txt_path, json_path))
                cookie_file_id = cursor.lastrowid
            
            # Delete old individual cookies for this file
            cursor.execute("DELETE FROM individual_cookies WHERE cookie_file_id = ?", (cookie_file_id,))
            
            # Insert new individual cookies
            for name, value in cookies_dict.items():
                cursor.execute("""
                    INSERT INTO individual_cookies (email, cookie_file_id, cookie_name, cookie_value)
                    VALUES (?, ?, ?, ?)
                """, (username, cookie_file_id, name, value))
            
            print(f"✅ Saved {len(cookies_dict)} cookies to database for {username}")
    
    except Exception as e:
        print(f"❌ Error saving cookies to database: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    return {
        'txt_path': os.path.abspath(txt_path),
        'json_path': os.path.abspath(json_path),
        'cookie_count': len(cookies_dict)
    }

def get_all_credentials() -> Dict[str, Dict]:
    """
    Get all credentials with their cookie counts
    Returns dict in format: {email: {password: str, timestamp: str, total_cookies: int}}
    """
    with db_manager.get_cursor() as cursor:
        cursor.execute("""
            SELECT 
                c.email,
                c.password,
                c.timestamp,
                COUNT(DISTINCT cf.id) as total_cookie_files,
                COUNT(DISTINCT ic.id) as total_individual_cookies
            FROM credentials c
            LEFT JOIN cookie_files cf ON c.email = cf.email
            LEFT JOIN individual_cookies ic ON c.email = ic.email
            GROUP BY c.email, c.password, c.timestamp
            ORDER BY c.timestamp DESC
        """)
        
        results = cursor.fetchall()
        
        credentials = {}
        for row in results:
            credentials[row['email']] = {
                'password': row['password'],
                'timestamp': row['timestamp'],
                'total_cookies': row['total_cookie_files'] or 0,
                'total_individual_cookies': row['total_individual_cookies'] or 0
            }
        
        return credentials

def get_user_cookies(email: str) -> Optional[List[Dict]]:
    """Get all cookies for a specific user"""
    with db_manager.get_cursor() as cursor:
        cursor.execute("""
            SELECT cookie_name, cookie_value, cookie_domain, cookie_path, is_secure
            FROM individual_cookies
            WHERE email = ?
            ORDER BY cookie_name
        """, (email,))
        
        results = cursor.fetchall()
        
        if not results:
            return None
        
        cookies = {}
        for row in results:
            cookies[row['cookie_name']] = row['cookie_value']
        
        return cookies

def get_cookie_files_list() -> List[Dict]:
    """Get list of all cookie files with metadata"""
    with db_manager.get_cursor() as cursor:
        cursor.execute("""
            SELECT 
                cf.id,
                cf.email,
                cf.filename,
                cf.cookie_count,
                cf.file_size_bytes,
                cf.txt_path,
                cf.json_path,
                cf.created_at,
                EXISTS(SELECT 1 FROM credentials c WHERE c.email = cf.email) as has_credentials
            FROM cookie_files cf
            ORDER BY cf.created_at DESC
        """)
        
        results = cursor.fetchall()
        
        cookie_files = []
        for row in results:
            cookie_files.append({
                'id': row['id'],
                'email': row['email'],
                'filename': row['filename'],
                'cookie_count': row['cookie_count'],
                'file_size_bytes': row['file_size_bytes'],
                'txt_path': row['txt_path'],
                'json_path': row['json_path'],
                'created_at': row['created_at'],
                'has_credentials': row['has_credentials']
            })
        
        return cookie_files

def delete_credential(email: str) -> bool:
    """Delete a credential and all associated cookies"""
    with db_manager.get_cursor() as cursor:
        cursor.execute("DELETE FROM credentials WHERE email = ? RETURNING email", (email,))
        result = cursor.fetchone()
        return result is not None

def delete_cookie_file(filename: str) -> bool:
    """Delete a cookie file record and its individual cookies"""
    with db_manager.get_cursor() as cursor:
        cursor.execute("DELETE FROM cookie_files WHERE filename = ?", (filename,))
        return True

def update_all_cookies(email: str, password: str, cookies_dict: dict) -> bool:
    """Main function to save both credential and cookies atomically"""
    try:
        # First save/update credential
        save_credential(email, password)
        
        # Then save cookies
        result = save_user_cookies(email, cookies_dict)
        
        return result is not None
    except Exception as e:
        print(f"Error in update_all_cookies: {e}")
        return False

def test_connection() -> bool:
    """Test database connection"""
    try:
        with db_manager.get_cursor() as cursor:
            cursor.execute("SELECT 1")
            return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False

if __name__ == "__main__":
    # Test the module
    if test_connection():
        print("✓ Database connection successful")
        stats = get_all_credentials()
        print(f"Statistics: {len(stats)} credentials found")
    else:
        print("✗ Database connection failed")
