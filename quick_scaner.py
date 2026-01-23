"""
WORDPRESS SUPER SCANNER v3.2 - FULL DISPLAY WITH PROGRESS BAR
Kết hợp Speed của deeep.py + Depth & Display của wpscanIPs2.0.py
Real-time scanning với phân tích chi tiết và hiển thị đầy đủ
Progress bar cố định ở dưới cùng terminal
"""

import time
import random
import json
from urllib.parse import urlparse
from ddgs import DDGS
import re
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict, deque
import warnings
import sys
import ipaddress
import hashlib
from datetime import datetime
import math

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# =================== CONFIGURATION ===================
# TỐI ƯU TỐC ĐỘ CAO
NUM_RESULTS_PER_DORK = 75
OUTPUT_FILE = "wp_vn_domains.txt"
DOMAIN_VULN_FILE = "vulnerable_domains.txt"
ENHANCED_OUTPUT_FILE = "wp_enhanced_recon.json"
SUMMARY_FILE = "scan_summary.txt"

# TIMEOUT TỐI ƯU
DELAY_MIN = 1.5
DELAY_MAX = 3.0
MAX_WORKERS_DISCOVERY = 5
MAX_WORKERS_RECON = 8
TIMEOUT = 8

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

# =================== DORKS TỐI ƯU ===================
DORKS = [
    # CORE DORKS - HIỆU QUẢ CAO
    '"Powered by WordPress" site:.vn',
    '"Powered by WordPress" site:.com.vn',
    'intext:"WordPress" site:.vn generator:"WordPress"',
    'inurl:/wp-content/plugins/ site:.vn',
    'inurl:/wp-admin/ intitle:"Log In" site:.vn',
    'inurl:wp-login.php site:.vn',
    '"Powered by WordPress" inurl:.vn -inurl:(forum OR blogspot OR wordpress.com)',
    'inurl:/wp-content/themes/ site:.vn',
    
    # ADDITIONAL HIGH-VALUE DORKS
    'meta name="generator" content="WordPress" site:.vn',
    'inurl:/feed/ "WordPress" site:.vn',
    'inurl:wp-embed.min.js site:.vn',
    'inurl:admin-ajax.php "WordPress" site:.vn',
    '"just another WordPress site" site:.vn',
    'inurl:wp-json/wp/v2/ site:.vn',
    
    # PLUGIN-SPECIFIC DORKS
    'inurl:/wp-content/plugins/elementor/ site:.vn',
    'inurl:/wp-content/plugins/woocommerce/ site:.vn',
    'inurl:/wp-content/plugins/contact-form-7/ site:.vn',
    'inurl:/wp-content/plugins/yoast-seo/ site:.vn',
    'inurl:/wp-content/plugins/wordfence/ site:.vn',
]

# =================== ENHANCED DATABASES ===================
POPULAR_PLUGINS = {
    # 🔥 SEO & CONTENT
    'yoast-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
    'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
    'all-in-one-seo-pack': {'name': 'All in One SEO', 'category': 'SEO', 'installs': '3M+'},
    'seo-by-rank-math': {'name': 'Rank Math SEO', 'category': 'SEO', 'installs': '2M+'},
    
    # 🎨 PAGE BUILDERS
    'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
    'beaver-builder-lite-version': {'name': 'Beaver Builder', 'category': 'Page Builder', 'installs': '1M+'},
    'siteorigin-panels': {'name': 'SiteOrigin Page Builder', 'category': 'Page Builder', 'installs': '1M+'},
    
    # 📝 FORMS
    'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
    'wpforms-lite': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
    'wpforms': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
    'gravityforms': {'name': 'Gravity Forms', 'category': 'Forms', 'installs': '1M+'},
    'ninja-forms': {'name': 'Ninja Forms', 'category': 'Forms', 'installs': '1M+'},
    
    # ⚡ CACHE & PERFORMANCE
    'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
    'wp-rocket': {'name': 'WP Rocket', 'category': 'Performance', 'installs': '2M+'},
    'w3-total-cache': {'name': 'W3 Total Cache', 'category': 'Performance', 'installs': '2M+'},
    'wp-super-cache': {'name': 'WP Super Cache', 'category': 'Performance', 'installs': '2M+'},
    
    # 🛒 E-COMMERCE
    'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
    
    # 🔐 SECURITY
    'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
    'better-wp-security': {'name': 'iThemes Security', 'category': 'Security', 'installs': '1M+'},
    'sucuri-scanner': {'name': 'Sucuri Security', 'category': 'Security', 'installs': '800K+'},
    'all-in-one-wp-security-and-firewall': {'name': 'All In One WP Security', 'category': 'Security', 'installs': '1M+'},
    
    # 📧 EMAIL
    'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    
    # 🔄 BACKUP
    'updraftplus': {'name': 'UpdraftPlus', 'category': 'Backup', 'installs': '3M+'},
    'all-in-one-wp-migration': {'name': 'All-in-One WP Migration', 'category': 'Migration', 'installs': '5M+'},
    
    # 📊 ANALYTICS
    'google-site-kit': {'name': 'Site Kit by Google', 'category': 'Analytics', 'installs': '5M+'},
    'monsterinsights': {'name': 'MonsterInsights', 'category': 'Analytics', 'installs': '3M+'},
    
    # 🖼️ IMAGE OPTIMIZATION
    'smush': {'name': 'Smush Image Optimization', 'category': 'Performance', 'installs': '1M+'},
    'ewww-image-optimizer': {'name': 'EWWW Image Optimizer', 'category': 'Performance', 'installs': '800K+'},
    
    # 🎭 CUSTOMIZATION
    'advanced-custom-fields': {'name': 'Advanced Custom Fields', 'category': 'Custom Fields', 'installs': '2M+'},
    'custom-post-type-ui': {'name': 'Custom Post Type UI', 'category': 'Custom Post Types', 'installs': '1M+'},
    
    # 📄 SLIDERS
    'revslider': {'name': 'Revolution Slider', 'category': 'Slider', 'installs': '10M+'},
    'smart-slider-3': {'name': 'Smart Slider 3', 'category': 'Slider', 'installs': '1M+'},
}

CVE_DATABASE = {
    'wordpress': {
        '5.0-5.9': ['CVE-2020-28032', 'CVE-2021-44223'],
        '4.0-4.9': ['CVE-2019-17671', 'CVE-2020-11025'],
        '<4.0': ['CVE-2018-20148', 'CVE-2019-9787']
    },
    'elementor': {
        '<3.5.0': ['CVE-2022-29455'],
        '<3.2.0': ['CVE-2021-25028']
    },
    'revslider': {
        '<6.0.0': ['CVE-2021-38392'],
        '<5.0.0': ['CVE-2018-15505']
    },
    'woocommerce': {
        '<5.0.0': ['CVE-2021-24153'],
        '<4.0.0': ['CVE-2020-13225']
    },
    'contact-form-7': {
        '<5.4.0': ['CVE-2020-35489']
    },
    'wordfence': {
        '<7.5.0': ['CVE-2020-29245']
    },
    'wpforms': {
        '<1.7.0': ['CVE-2021-24275']
    }
}

stop_flag = False

# =================== UTILITY FUNCTIONS ===================
def is_ip(domain):
    """Kiểm tra IP address"""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def looks_like_cdn_or_api(domain):
    """Filter CDN/API domains - TỐI ƯU TỐC ĐỘ"""
    domain_lower = domain.lower()
    
    # Quick keyword check
    quick_keywords = ['cdn', 'api', 'cloudflare', 'akamai', 'fastly', 'cloudfront']
    if any(kw in domain_lower for kw in quick_keywords):
        return True
    
    # Too many subdomains
    if domain.count('.') >= 4:
        return True
    
    return False

def extract_domain_func(url):
    """Fast domain extraction"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Optimized regex
        if re.match(r'^[a-z0-9][a-z0-9.-]*\.(vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn)$', domain):
            return domain
        return None
    except:
        return None

def v12_discovery_filter(domain, source="ddg"):
    """Optimized filter - SPEED FOCUS"""
    if is_ip(domain):
        return {"accept": False, "scan_immediately": False}
    
    if looks_like_cdn_or_api(domain):
        return {"accept": False, "scan_immediately": False}
    
    # HIGH VALUE PATTERNS - SCAN NGAY
    high_value = [
        r'\.gov\.vn$', r'\.edu\.vn$', r'\.com\.vn$',
        r'bank', r'credit', r'payment', r'shop', r'store', r'vnp'
    ]
    
    for pattern in high_value:
        if re.search(pattern, domain, re.I):
            return {"accept": True, "scan_immediately": True, "priority": "HIGH"}
    
    return {"accept": True, "scan_immediately": False, "priority": "NORMAL"}

# =================== PROGRESS BAR MANAGER ===================
class ProgressBarManager:
    """Quản lý progress bar cố định ở dưới terminal"""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.progress_data = {
            'total_targets': 0,
            'scanned_targets': 0,
            'vulnerable_targets': 0,
            'current_status': 'Initializing...',
            'current_domain': '',
            'start_time': time.time(),
            'wp_detected': 0
        }
        self.last_progress_height = 0
        self.terminal_width = 80
        
    def update(self, **kwargs):
        """Cập nhật progress data"""
        with self.lock:
            for key, value in kwargs.items():
                if key in self.progress_data:
                    self.progress_data[key] = value
    
    def get_progress_line(self):
        """Tạo progress line"""
        with self.lock:
            data = self.progress_data.copy()
        
        total = data['total_targets']
        scanned = data['scanned_targets']
        vuln = data['vulnerable_targets']
        wp = data['wp_detected']
        
        if total == 0:
            return ""
        
        percentage = (scanned / total * 100) if total > 0 else 0
        bar_length = 30
        filled_length = int(bar_length * scanned // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Tính thời gian ước tính
        elapsed = time.time() - data['start_time']
        if scanned > 0:
            time_per_scan = elapsed / scanned
            remaining = max(0, int((total - scanned) * time_per_scan))
            eta = f"{remaining // 60:02d}:{remaining % 60:02d}"
        else:
            eta = "--:--"
        
        # Tạo progress line
        progress_line = (f"[{bar}] {scanned:3d}/{total:3d} "
                        f"({percentage:5.1f}%) | "
                        f"WP:{wp:3d} | Vuln:{vuln:3d} | "
                        f"ETA:{eta} | {data['current_status'][:20]}")
        
        return progress_line
    
    def display_fixed(self):
        """Hiển thị progress bar cố định ở dưới terminal"""
        progress_line = self.get_progress_line()
        if not progress_line:
            return
        
        # Di chuyển cursor xuống cuối terminal
        sys.stdout.write('\033[s')  # Save cursor position
        sys.stdout.write(f'\033[{self.last_progress_height + 1}B')  # Move down
        
        # Clear previous progress lines
        for _ in range(self.last_progress_height):
            sys.stdout.write('\033[K\n')  # Clear line and new line
        
        # Move back up
        sys.stdout.write(f'\033[{self.last_progress_height + 1}A')
        
        # Hiển thị progress bar
        sys.stdout.write('\033[K')  # Clear line
        sys.stdout.write(f"\r\033[94m{progress_line}\033[0m")  # Blue color
        
        # Save height for next update
        self.last_progress_height = 1
        
        sys.stdout.write('\033[u')  # Restore cursor position
        sys.stdout.flush()
    
    def display_scan_start(self, total):
        """Hiển thị khi bắt đầu scan"""
        with self.lock:
            self.progress_data = {
                'total_targets': total,
                'scanned_targets': 0,
                'vulnerable_targets': 0,
                'current_status': 'Starting scan...',
                'current_domain': '',
                'start_time': time.time(),
                'wp_detected': 0
            }
        
        print(f"\n\033[93m{'═' * 80}\033[0m")
        print(f"\033[93m🚀 SCANNING {total} DOMAINS\033[0m")
        print(f"\033[93m{'═' * 80}\033[0m\n")
        
        # Display initial progress bar
        self.display_fixed()

# =================== ENHANCED WORDPRESS RECON ===================
class WordPressSuperScanner:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"http://{domain}"
        self.https_url = f"https://{domain}"
        self.base_url = None
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.session.timeout = TIMEOUT
        
        # Theme detection
        self.theme_data = {'name': '', 'slug': '', 'version': '', 'version_source': ''}
        
        self.results = self._init_schema()
        
    def _init_schema(self):
        """Schema đầy đủ thông tin"""
        return {
            "target": self.domain,
            "scan_timestamp": datetime.now().isoformat(),
            "quick_scan": True,
            
            "wp": {
                "detected": False,
                "confidence": 0,
                "version": "",
                "version_source": "",
                "version_sources": []
            },
            
            "server": {
                "webserver": "",
                "webserver_version": "",
                "php": "",
                "php_source": "",
                "server_header": "",
                "headers": {}
            },
            
            "theme": {
                "name": "",
                "slug": "",
                "version": "",
                "version_source": "",
                "path": ""
            },
            
            "plugins": {
                "total": 0,
                "popular": 0,
                "list": [],
                "categories": defaultdict(int),
                "versions_found": 0
            },
            
            "security": {
                "waf_detected": "",
                "waf_type": "",
                "xmlrpc_enabled": False,
                "directory_listing": False,
                "sensitive_files": [],
                "user_enumeration": False
            },
            
            "vulnerabilities": {
                "risk_score": 0,
                "cve_matches": [],
                "issues": [],
                "outdated_wp": False,
                "outdated_php": False,
                "outdated_plugins": []
            },
            
            "performance": {
                "response_time": 0,
                "requests_made": 0,
                "scan_duration": 0
            }
        }
    
    def _make_request(self, url, method='GET', timeout=TIMEOUT, allow_redirects=True):
        """Optimized request với timeout ngắn hơn cho quick checks"""
        if stop_flag:
            return None
            
        start = time.time()
        try:
            response = self.session.request(
                method=method,
                url=url,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
            self.results['performance']['requests_made'] += 1
            self.results['performance']['response_time'] = time.time() - start
            return response
        except Exception as e:
            return None
    
    def _quick_wp_check(self):
        """PHÁT HIỆN NHANH WordPress"""
        for test_url in [self.https_url, self.url]:
            response = self._make_request(test_url, timeout=3)
            if response and response.status_code < 400:
                self.base_url = test_url
                
                # Lưu headers
                self.results['server']['headers'] = dict(response.headers)
                
                html = response.text.lower()
                quick_indicators = 0
                
                if '/wp-content/' in html:
                    quick_indicators += 1
                
                if 'wordpress' in html and 'generator' in html:
                    quick_indicators += 1
                
                if '/wp-includes/' in html:
                    quick_indicators += 1
                
                # Check wp-login QUICK
                login_check = self._make_request(f"{test_url}/wp-login.php", timeout=2)
                if login_check and login_check.status_code < 400:
                    quick_indicators += 1
                
                self.results['wp']['detected'] = quick_indicators >= 2
                self.results['wp']['confidence'] = min(quick_indicators * 25, 100)
                
                # Get server info từ response đầu tiên
                self._quick_server_info(response)
                
                return self.results['wp']['detected']
        
        return False
    
    def _quick_server_info(self, response):
        """Lấy server info chi tiết"""
        if not response:
            return
        
        headers = response.headers
        
        # Server header chi tiết
        server = headers.get('Server', '')
        self.results['server']['server_header'] = server
        if server:
            if '/' in server:
                self.results['server']['webserver'] = server.split('/')[0]
                self.results['server']['webserver_version'] = server.split('/')[1]
            else:
                self.results['server']['webserver'] = server
        
        # PHP version - multiple sources
        php_version = None
        php_source = ""
        
        # 1. X-Powered-By header
        php_header = headers.get('X-Powered-By', '')
        if 'PHP' in php_header:
            match = re.search(r'PHP/([\d.]+)', php_header)
            if match:
                php_version = match.group(1)
                php_source = 'X-Powered-By'
        
        # 2. X-PHP-Version header
        if not php_version:
            php_version_header = headers.get('X-PHP-Version', '')
            if php_version_header:
                php_version = php_version_header
                php_source = 'X-PHP-Version'
        
        # 3. Tìm trong HTML
        if not php_version:
            html = response.text
            php_patterns = [
                r'PHP/([\d.]+)',
                r'PHP Version: ([\d.]+)',
                r'php/([\d.]+)',
                r'PHP ([\d.]+)',
            ]
            
            for pattern in php_patterns:
                php_match = re.search(pattern, html, re.IGNORECASE)
                if php_match:
                    php_version = php_match.group(1)
                    php_source = 'HTML'
                    break
        
        if php_version:
            self.results['server']['php'] = php_version
            self.results['server']['php_source'] = php_source
    
    def _fast_wp_version_detect(self):
        """Phát hiện version WP với nhiều phương pháp"""
        if not self.base_url:
            return
        
        version_sources = []
        detected_version = ""
        
        # Method 1: Meta generator (nhanh nhất)
        response = self._make_request(self.base_url, timeout=2)
        if response:
            html = response.text
            meta_match = re.search(r'content=["\']WordPress ([\d.]+)["\']', html)
            if meta_match:
                detected_version = meta_match.group(1)
                version_sources.append(('meta', detected_version))
        
        # Method 2: Script version
        if not detected_version and response:
            script_match = re.search(r'wp-embed\.js\?ver=([\d.]+)', html)
            if script_match:
                detected_version = script_match.group(1)
                version_sources.append(('script', detected_version))
        
        # Method 3: RSS feed
        if not detected_version:
            rss_resp = self._make_request(f"{self.base_url}/feed/", timeout=2)
            if rss_resp and rss_resp.status_code == 200:
                match = re.search(r'generator>https://wordpress.org/\?v=([\d.]+)<', rss_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('rss', detected_version))
        
        # Method 4: Readme.html
        if not detected_version:
            readme_resp = self._make_request(f"{self.base_url}/readme.html", timeout=2)
            if readme_resp and readme_resp.status_code == 200:
                match = re.search(r'Version ([\d.]+)', readme_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('readme', detected_version))
        
        if detected_version:
            self.results['wp']['version'] = detected_version
            self.results['wp']['version_source'] = version_sources[0][0] if version_sources else 'unknown'
            self.results['wp']['version_sources'] = [f"{src[0]}:{src[1]}" for src in version_sources]
        
        # Check if outdated
        if detected_version:
            try:
                major = int(detected_version.split('.')[0])
                if major < 6:
                    self.results['vulnerabilities']['outdated_wp'] = True
                    self.results['vulnerabilities']['issues'].append(f"outdated_wp:{detected_version}")
            except:
                pass
    
    def _fast_theme_detection(self):
        """Phát hiện theme và version"""
        if not self.base_url:
            return
        
        response = self._make_request(self.base_url, timeout=3)
        if not response:
            return
        
        html = response.text
        
        # Tìm theme path
        theme_path = None
        path_match = re.search(r'/wp-content/themes/([^/]+)/', html)
        if path_match:
            theme_path = path_match.group(1)
        
        if theme_path:
            self.results['theme']['slug'] = theme_path
            self.results['theme']['path'] = theme_path
            
            # Lấy thông tin từ style.css
            style_url = f"{self.base_url}/wp-content/themes/{theme_path}/style.css"
            style_resp = self._make_request(style_url, timeout=2)
            
            if style_resp and style_resp.status_code == 200:
                style_content = style_resp.text
                
                # Theme name
                name_match = re.search(r'Theme Name:\s*(.+)', style_content, re.IGNORECASE)
                if name_match:
                    self.results['theme']['name'] = name_match.group(1).strip()
                
                # Theme version
                version_match = re.search(r'Version:\s*([\d.]+)', style_content, re.IGNORECASE)
                if version_match:
                    self.results['theme']['version'] = version_match.group(1).strip()
                    self.results['theme']['version_source'] = 'style.css'
    
    def _fast_plugin_detection(self):
        """Phát hiện plugin nhanh với version"""
        if not self.base_url:
            return
        
        response = self._make_request(self.base_url, timeout=3)
        if not response:
            return
        
        html = response.text
        
        # Tìm plugin slugs trong HTML
        plugin_slugs = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
        
        versions_found = 0
        
        # Giới hạn số plugin check
        for slug in list(plugin_slugs)[:15]:  # Tăng lên 15 plugin
            plugin_key = slug.lower().replace('_', '-')
            
            plugin_info = {
                "slug": slug,
                "name": POPULAR_PLUGINS.get(plugin_key, {}).get('name', slug),
                "detected": False,
                "version": None,
                "version_source": None,
                "popular": plugin_key in POPULAR_PLUGINS,
                "category": POPULAR_PLUGINS.get(plugin_key, {}).get('category', 'Unknown') 
                    if plugin_key in POPULAR_PLUGINS else 'Unknown',
                "installs": POPULAR_PLUGINS.get(plugin_key, {}).get('installs', 'Unknown')
            }
            
            # QUICK CHECK: thử readme.txt
            readme_url = f"{self.base_url}/wp-content/plugins/{slug}/readme.txt"
            readme_resp = self._make_request(readme_url, timeout=2)
            
            if readme_resp and readme_resp.status_code == 200:
                plugin_info["detected"] = True
                content = readme_resp.text
                
                # Tìm version
                version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.I)
                if version_match:
                    plugin_info["version"] = version_match.group(1).strip()
                    plugin_info["version_source"] = 'readme.txt'
                    versions_found += 1
                else:
                    # Thử tìm trong php file
                    php_url = f"{self.base_url}/wp-content/plugins/{slug}/{slug}.php"
                    php_resp = self._make_request(php_url, timeout=2)
                    if php_resp and php_resp.status_code == 200:
                        php_content = php_resp.text[:2000]  # Chỉ đọc đầu file
                        php_version_match = re.search(r'Version:\s*([\d.]+)', php_content, re.I)
                        if php_version_match:
                            plugin_info["version"] = php_version_match.group(1).strip()
                            plugin_info["version_source"] = 'php_header'
                            versions_found += 1
            
            if plugin_info["detected"]:
                self.results['plugins']['list'].append(plugin_info)
                if plugin_info["popular"]:
                    self.results['plugins']['popular'] += 1
                    self.results['plugins']['categories'][plugin_info["category"]] += 1
                    
                    # Check if plugin is outdated
                    if plugin_info["version"]:
                        # Simple outdated check - version < 1.0.0 or contains "beta", "alpha", "rc"
                        if any(x in plugin_info["version"].lower() for x in ['beta', 'alpha', 'rc']):
                            self.results['vulnerabilities']['outdated_plugins'].append(
                                f"{slug}:{plugin_info['version']}"
                            )
        
        self.results['plugins']['total'] = len(self.results['plugins']['list'])
        self.results['plugins']['versions_found'] = versions_found
    
    def _fast_security_checks(self):
        """Security checks đầy đủ"""
        if not self.base_url:
            return
        
        # 1. XML-RPC check
        xmlrpc_resp = self._make_request(f"{self.base_url}/xmlrpc.php", timeout=2)
        if xmlrpc_resp and xmlrpc_resp.status_code < 400:
            self.results['security']['xmlrpc_enabled'] = True
        
        # 2. Directory listing check
        uploads_resp = self._make_request(f"{self.base_url}/wp-content/uploads/", timeout=2)
        if uploads_resp and uploads_resp.status_code == 200:
            if 'Index of' in uploads_resp.text or '<title>Index of' in uploads_resp.text.lower():
                self.results['security']['directory_listing'] = True
        
        # 3. Sensitive files check
        sensitive_files = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/.env',
            '/debug.log',
            '/phpinfo.php'
        ]
        
        for file in sensitive_files:
            file_resp = self._make_request(f"{self.base_url}{file}", timeout=2)
            if file_resp and file_resp.status_code == 200:
                self.results['security']['sensitive_files'].append(file)
        
        # 4. WAF detection (detailed)
        response = self._make_request(self.base_url, timeout=2)
        if response:
            headers_str = str(response.headers).lower()
            server_str = str(response.headers.get('Server', '')).lower()
            
            if 'cloudflare' in headers_str or 'cf-ray' in headers_str:
                self.results['security']['waf_detected'] = 'Cloudflare'
                self.results['security']['waf_type'] = 'CDN/WAF'
            elif 'wordfence' in headers_str:
                self.results['security']['waf_detected'] = 'Wordfence'
                self.results['security']['waf_type'] = 'Security Plugin'
            elif 'sucuri' in headers_str:
                self.results['security']['waf_detected'] = 'Sucuri'
                self.results['security']['waf_type'] = 'Cloud WAF'
            elif 'akamai' in server_str:
                self.results['security']['waf_detected'] = 'Akamai'
                self.results['security']['waf_type'] = 'CDN'
    
    def _fast_cve_check(self):
        """CVE check chi tiết"""
        wp_version = self.results['wp']['version']
        cve_matches = []
        
        # Check WordPress core CVEs
        if wp_version:
            for version_range, cves in CVE_DATABASE.get('wordpress', {}).items():
                if self._check_version_in_range(wp_version, version_range):
                    for cve in cves:
                        cve_matches.append({
                            'component': 'wordpress', 
                            'version': wp_version,
                            'cve': cve,
                            'type': 'core'
                        })
        
        # Check plugin CVEs
        for plugin in self.results['plugins']['list']:
            if plugin.get('version') and plugin.get('slug'):
                plugin_slug = plugin['slug'].lower()
                plugin_version = plugin['version']
                
                for plugin_name in CVE_DATABASE:
                    if plugin_name != 'wordpress' and plugin_name in plugin_slug:
                        for version_range, cves in CVE_DATABASE[plugin_name].items():
                            if self._check_version_in_range(plugin_version, version_range):
                                for cve in cves:
                                    cve_matches.append({
                                        'component': plugin_name,
                                        'version': plugin_version,
                                        'cve': cve,
                                        'type': 'plugin'
                                    })
        
        self.results['vulnerabilities']['cve_matches'] = cve_matches
    
    def _calculate_risk_score_fast(self):
        """Tính risk score chi tiết"""
        risk = 0
        
        # WordPress cũ
        wp_version = self.results['wp']['version']
        if wp_version:
            try:
                major = int(wp_version.split('.')[0])
                if major < 6:
                    risk += 30
                    self.results['vulnerabilities']['outdated_wp'] = True
            except:
                pass
        
        # PHP cũ
        php_version = self.results['server']['php']
        if php_version:
            try:
                major = int(php_version.split('.')[0])
                if major < 8:
                    risk += 20
                    self.results['vulnerabilities']['outdated_php'] = True
            except:
                pass
        
        # Security issues
        if self.results['security']['xmlrpc_enabled']:
            risk += 15
        
        if self.results['security']['directory_listing']:
            risk += 10
        
        if self.results['security']['sensitive_files']:
            risk += len(self.results['security']['sensitive_files']) * 5
        
        # CVE matches
        risk += len(self.results['vulnerabilities']['cve_matches']) * 25
        
        # Outdated plugins
        risk += len(self.results['vulnerabilities']['outdated_plugins']) * 10
        
        # Confidence thấp
        if self.results['wp']['confidence'] < 40:
            risk += 10
        
        # Nhiều plugin
        if self.results['plugins']['total'] > 20:
            risk += 5
        
        self.results['vulnerabilities']['risk_score'] = min(risk, 100)
    
    def _check_version_in_range(self, version, version_range):
        """Helper for version range checking"""
        try:
            if version_range.startswith('<'):
                max_version = version_range[1:]
                return self._compare_versions(version, max_version) < 0
            elif '-' in version_range:
                min_ver, max_ver = version_range.split('-')
                return (self._compare_versions(version, min_ver) >= 0 and 
                       self._compare_versions(version, max_ver) <= 0)
            return False
        except:
            return False
    
    def _compare_versions(self, v1, v2):
        """So sánh version"""
        v1_parts = list(map(int, v1.split('.')[:3]))
        v2_parts = list(map(int, v2.split('.')[:3]))
        while len(v1_parts) < 3: v1_parts.append(0)
        while len(v2_parts) < 3: v2_parts.append(0)
        for i in range(3):
            if v1_parts[i] != v2_parts[i]:
                return v1_parts[i] - v2_parts[i]
        return 0
    
    def super_scan(self):
        """SUPER SCAN - Nhanh mà đầy đủ thông tin"""
        start_time = time.time()
        
        # Bước 1: Quick WordPress check
        if not self._quick_wp_check():
            self.results['performance']['scan_duration'] = time.time() - start_time
            return self.results
        
        # Bước 2: Fast version detection
        self._fast_wp_version_detect()
        
        # Bước 3: Fast theme detection
        self._fast_theme_detection()
        
        # Bước 4: Fast plugin detection
        self._fast_plugin_detection()
        
        # Bước 5: Fast security checks
        self._fast_security_checks()
        
        # Bước 6: Fast CVE check
        self._fast_cve_check()
        
        # Bước 7: Calculate risk score
        self._calculate_risk_score_fast()
        
        # Update performance metrics
        self.results['performance']['scan_duration'] = time.time() - start_time
        
        return self.results
    
    def get_display_summary(self):
        """Tạo summary để hiển thị ĐẦY ĐỦ THÔNG TIN"""
        if not self.results['wp']['detected']:
            return None
        
        summary = {
            'domain': self.domain,
            'wp_detected': self.results['wp']['detected'],
            'wp_confidence': self.results['wp']['confidence'],
            'wp_version': self.results['wp']['version'] or 'Unknown',
            'wp_version_source': self.results['wp']['version_source'] or 'Unknown',
            'wp_version_sources': self.results['wp']['version_sources'],
            
            'server_webserver': self.results['server']['webserver'] or 'Unknown',
            'server_webserver_version': self.results['server']['webserver_version'] or 'Unknown',
            'server_php': self.results['server']['php'] or 'Unknown',
            'server_php_source': self.results['server']['php_source'] or 'Unknown',
            'server_header': self.results['server']['server_header'] or 'Unknown',
            
            'theme_name': self.results['theme']['name'] or 'Unknown',
            'theme_slug': self.results['theme']['slug'] or 'Unknown',
            'theme_version': self.results['theme']['version'] or 'Unknown',
            'theme_version_source': self.results['theme']['version_source'] or 'Unknown',
            
            'plugins_total': self.results['plugins']['total'],
            'plugins_popular': self.results['plugins']['popular'],
            'plugins_versions_found': self.results['plugins']['versions_found'],
            'plugins_categories': dict(self.results['plugins']['categories']),
            'plugins_list': self.results['plugins']['list'][:10],  # Top 10 plugins
            
            'security_waf': self.results['security']['waf_detected'] or 'None',
            'security_waf_type': self.results['security']['waf_type'] or '',
            'security_xmlrpc': self.results['security']['xmlrpc_enabled'],
            'security_directory_listing': self.results['security']['directory_listing'],
            'security_sensitive_files': len(self.results['security']['sensitive_files']),
            'security_sensitive_files_list': self.results['security']['sensitive_files'][:5],
            
            'vuln_risk_score': self.results['vulnerabilities']['risk_score'],
            'vuln_cve_count': len(self.results['vulnerabilities']['cve_matches']),
            'vuln_cve_matches': self.results['vulnerabilities']['cve_matches'][:5],
            'vuln_outdated_wp': self.results['vulnerabilities']['outdated_wp'],
            'vuln_outdated_php': self.results['vulnerabilities']['outdated_php'],
            'vuln_outdated_plugins': self.results['vulnerabilities']['outdated_plugins'],
            'vuln_issues': self.results['vulnerabilities']['issues'],
            
            'performance_scan_time': f"{self.results['performance']['scan_duration']:.2f}s",
            'performance_requests': self.results['performance']['requests_made'],
            'performance_response_time': f"{self.results['performance']['response_time']:.2f}s"
        }
        
        return summary

# =================== FULL DISPLAY MANAGER ===================
class FullDisplayManager:
    """Quản lý hiển thị đầy đủ thông tin"""
    
    @staticmethod
    def display_domain_result(domain, summary, progress_bar=None):
        """Hiển thị kết quả CHI TIẾT cho từng domain"""
        if not summary:
            FullDisplayManager._display_non_wp(domain, progress_bar)
            return
        
        # Xác định màu sắc theo risk score
        risk_score = summary['vuln_risk_score']
        if risk_score >= 70:
            color = '\033[91m'  # RED - CRITICAL
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            color = '\033[93m'  # YELLOW - HIGH
            risk_level = "HIGH"
        elif risk_score >= 30:
            color = '\033[33m'  # ORANGE - MEDIUM
            risk_level = "MEDIUM"
        else:
            color = '\033[92m'  # GREEN - LOW
            risk_level = "LOW"
        
        # Hiển thị progress bar trước
        if progress_bar:
            progress_bar.display_fixed()
        
        # HEADER với màu risk
        print(f"\n{color}{'═' * 80}\033[0m")
        print(f"{color}📍 WORDPRESS SUPER SCAN: {domain}\033[0m")
        print(f"{color}{'═' * 80}\033[0m")
        
        # ========== WORDPRESS CORE ==========
        print(f"\n📦 \033[1mWORDPRESS CORE\033[0m")
        print(f"{'─' * 60}")
        wp_status = "✅ DETECTED" if summary['wp_detected'] else "❌ NOT DETECTED"
        print(f"  • Status: {wp_status}")
        print(f"  • Confidence: {summary['wp_confidence']}%")
        print(f"  • Version: \033[93m{summary['wp_version']}\033[0m")
        print(f"  • Source: {summary['wp_version_source']}")
        if summary['wp_version_sources']:
            print(f"  • Additional Sources: {', '.join(summary['wp_version_sources'][:2])}")
        if summary['vuln_outdated_wp']:
            print(f"  • ⚠️  Status: \033[91mOUTDATED\033[0m")
        
        # ========== SERVER INFORMATION ==========
        print(f"\n🖥️  \033[1mSERVER INFORMATION\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Web Server: {summary['server_webserver']}")
        if summary['server_webserver_version'] != 'Unknown':
            print(f"  • Server Version: {summary['server_webserver_version']}")
        print(f"  • PHP Version: \033[93m{summary['server_php']}\033[0m")
        if summary['server_php_source'] != 'Unknown':
            print(f"  • PHP Source: {summary['server_php_source']}")
        if summary['vuln_outdated_php']:
            print(f"  • ⚠️  PHP Status: \033[91mOUTDATED\033[0m")
        
        # ========== THEME INFORMATION ==========
        print(f"\n🎨 \033[1mTHEME INFORMATION\033[0m")
        print(f"{'─' * 60}")
        if summary['theme_name'] != 'Unknown':
            print(f"  • Theme Name: {summary['theme_name']}")
            print(f"  • Theme Slug: {summary['theme_slug']}")
            print(f"  • Theme Version: \033[93m{summary['theme_version']}\033[0m")
            if summary['theme_version_source'] != 'Unknown':
                print(f"  • Version Source: {summary['theme_version_source']}")
        else:
            print(f"  • Theme: \033[90mNot detected\033[0m")
        
        # ========== PLUGIN ANALYSIS ==========
        print(f"\n🔌 \033[1mPLUGIN ANALYSIS\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Total Plugins: {summary['plugins_total']}")
        print(f"  • Popular Plugins: {summary['plugins_popular']}")
        print(f"  • Versions Found: {summary['plugins_versions_found']}/{summary['plugins_total']}")
        
        if summary['plugins_categories']:
            print(f"  • Categories: {', '.join([f'{k}({v})' for k, v in summary['plugins_categories'].items()][:3])}")
        
        # Hiển thị top plugins với version
        if summary['plugins_list']:
            print(f"\n  \033[94mTOP PLUGINS DETECTED:\033[0m")
            for i, plugin in enumerate(summary['plugins_list'][:5], 1):
                version_display = f"\033[93mv{plugin['version']}\033[0m" if plugin['version'] else "\033[90mNo version\033[0m"
                popular_mark = "🔥 " if plugin['popular'] else "  "
                print(f"    {i}. {popular_mark}{plugin['name'][:25]:<25} {version_display:<15} ({plugin['category']})")
        
        # ========== SECURITY CHECKS ==========
        print(f"\n🔐 \033[1mSECURITY CHECKS\033[0m")
        print(f"{'─' * 60}")
        
        xmlrpc_status = "⚠️  \033[91mENABLED\033[0m" if summary['security_xmlrpc'] else "✅ \033[92mDISABLED\033[0m"
        print(f"  • XML-RPC: {xmlrpc_status}")
        
        dir_status = "⚠️  \033[91mENABLED\033[0m" if summary['security_directory_listing'] else "✅ \033[92mDISABLED\033[0m"
        print(f"  • Directory Listing: {dir_status}")
        
        waf_info = f"✅ {summary['security_waf']}" if summary['security_waf'] != 'None' else "❌ Not Detected"
        if summary['security_waf_type']:
            waf_info += f" ({summary['security_waf_type']})"
        print(f"  • WAF: {waf_info}")
        
        if summary['security_sensitive_files'] > 0:
            print(f"  • Sensitive Files: \033[91m{summary['security_sensitive_files']} found\033[0m")
            if summary['security_sensitive_files_list']:
                print(f"    - {', '.join(summary['security_sensitive_files_list'])}")
        
        # ========== VULNERABILITIES ==========
        print(f"\n⚠️  \033[1mVULNERABILITY ASSESSMENT\033[0m")
        print(f"{'─' * 60}")
        
        # Risk score với màu
        print(f"  • Risk Score: {color}{risk_score}/100 [{risk_level}]\033[0m")
        print(f"  • CVE Matches: {summary['vuln_cve_count']}")
        
        if summary['vuln_cve_matches']:
            print(f"\n  \033[91mCVE FOUND:\033[0m")
            for cve in summary['vuln_cve_matches'][:3]:
                print(f"    • {cve['cve']} - {cve['component']} v{cve['version']}")
        
        if summary['vuln_outdated_plugins']:
            print(f"\n  \033[93mOUTDATED PLUGINS:\033[0m")
            for plugin in summary['vuln_outdated_plugins'][:3]:
                print(f"    • {plugin}")
        
        # ========== PERFORMANCE ==========
        print(f"\n⚡ \033[1mPERFORMANCE\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Scan Time: {summary['performance_scan_time']}")
        print(f"  • Requests Made: {summary['performance_requests']}")
        print(f"  • Avg Response Time: {summary['performance_response_time']}")
        
        # ========== FOOTER ==========
        print(f"\n{color}{'═' * 80}\033[0m")
        
        # Hiển thị progress bar lại sau khi hiển thị kết quả
        if progress_bar:
            progress_bar.display_fixed()
    
    @staticmethod
    def _display_non_wp(domain, progress_bar=None):
        """Hiển thị domain không phải WordPress"""
        if progress_bar:
            progress_bar.display_fixed()
        
        print(f"\n\033[90m{'─' * 60}\033[0m")
        print(f"\033[90m✗ {domain:<40} | Not WordPress | Skipped\033[0m")
        print(f"\033[90m{'─' * 60}\033[0m")
        
        if progress_bar:
            progress_bar.display_fixed()
    
    @staticmethod
    def display_discovery_summary(total_domains, new_domains, old_domains):
        """Hiển thị summary discovery"""
        print(f"\n\033[92m{'═' * 80}\033[0m")
        print(f"\033[92m🔍 DISCOVERY COMPLETE\033[0m")
        print(f"\033[92m{'═' * 80}\033[0m")
        print(f"\n• Total Domains: {total_domains}")
        print(f"• New Domains: {new_domains}")
        print(f"• Existing Domains: {old_domains}")
        print(f"\033[92m{'═' * 80}\033[0m\n")
    
    @staticmethod
    def display_final_summary(stats):
        """Hiển thị tổng kết cuối cùng"""
        print(f"\n\n\033[96m{'=' * 80}\033[0m")
        print(f"\033[96m📊 SCAN SUMMARY REPORT\033[0m")
        print(f"\033[96m{'=' * 80}\033[0m")
        
        print(f"\n• Total Domains Scanned: {stats['total_scanned']}")
        print(f"• WordPress Detected: {stats['wp_detected']} ({stats['wp_percentage']:.1f}%)")
        print(f"• Vulnerable Domains: {stats['vulnerable_count']} ({stats['vuln_percentage']:.1f}% of WP)")
        print(f"• Average Risk Score: {stats['avg_risk']:.1f}/100")
        
        # Risk distribution
        print(f"\n• Risk Distribution:")
        print(f"  - \033[91mCRITICAL (≥70): {stats['critical_count']}\033[0m")
        print(f"  - \033[93mHIGH (50-69): {stats['high_count']}\033[0m")
        print(f"  - \033[33mMEDIUM (30-49): {stats['medium_count']}\033[0m")
        print(f"  - \033[92mLOW (<30): {stats['low_count']}\033[0m")
        
        # Plugin statistics
        if stats.get('plugins_stats'):
            print(f"\n• Plugin Statistics:")
            print(f"  - Average Plugins per Site: {stats['plugins_stats']['avg_plugins']:.1f}")
            print(f"  - Popular Plugins Found: {stats['plugins_stats']['popular_count']}")
            print(f"  - Versions Detected: {stats['plugins_stats']['versions_found']}")
        
        print(f"\n\033[96m{'=' * 80}\033[0m")

# =================== FAST DISCOVERY ENGINE ===================
class FastDiscoveryEngine:
    """Discovery engine siêu nhanh"""
    
    @staticmethod
    def collect_from_ddg_parallel():
        """Thu thập domain từ DDG siêu nhanh"""
        all_domains = set()
        rapiddns_seeds = set()
        
        lock = threading.Lock()
        
        def process_dork_fast(dork_idx, dork):
            """Xử lý dork nhanh"""
            local_domains = []
            
            try:
                time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
                
                with DDGS() as ddgs:
                    results = ddgs.text(
                        query=dork,
                        region="vn-vn",
                        safesearch="off",
                        max_results=NUM_RESULTS_PER_DORK,
                        timeout=10
                    )
                    
                    for result in results:
                        if stop_flag:
                            break
                        
                        url = result.get('href', '') or result.get('url', '')
                        if url:
                            domain = extract_domain_func(url)
                            if domain:
                                filter_result = v12_discovery_filter(domain)
                                if not filter_result["accept"]:
                                    continue
                                
                                with lock:
                                    if domain not in all_domains:
                                        all_domains.add(domain)
                                        local_domains.append(domain)
                                        
                                        if domain.count('.') <= 2:
                                            rapiddns_seeds.add(domain)
                        
                        time.sleep(random.uniform(0.2, 0.5))
                
                return dork_idx, len(local_domains), dork
                
            except Exception as e:
                return dork_idx, 0, dork
        
        print(f"\n🔍 FAST DISCOVERY: {len(DORKS)} dorks")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_DISCOVERY) as executor:
            futures = [executor.submit(process_dork_fast, i, d) 
                      for i, d in enumerate(DORKS) if not stop_flag]
            
            for future in as_completed(futures):
                dork_idx, new_count, dork = future.result()
                if new_count > 0:
                    print(f"  ✓ Dork {dork_idx+1:2d}: {new_count:3d} domains")
        
        return all_domains, rapiddns_seeds

# =================== MAIN SCAN MANAGER ===================
class SuperScanManager:
    """Quản lý scan tổng thể với progress bar"""
    
    def __init__(self):
        self.all_domains = set()
        self.scan_results = {}
        self.vulnerable_domains = []
        self.stats = {
            'total_scanned': 0,
            'wp_detected': 0,
            'vulnerable_count': 0,
            'risk_scores': [],
            'plugins_stats': {
                'total_plugins': 0,
                'popular_count': 0,
                'versions_found': 0,
                'scanned_sites': 0
            }
        }
        self.progress_bar = ProgressBarManager()
        
        # Load existing domains
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                self.all_domains = {line.strip() for line in f if line.strip()}
    
    def discover_domains(self):
        """Discovery phase - SIÊU NHANH"""
        print("\n" + "=" * 80)
        print("🚀 PHASE 1: SUPER FAST DISCOVERY")
        print("=" * 80)
        
        existing_count = len(self.all_domains)
        
        # 1. DuckDuckGo
        print("\n[1/2] DuckDuckGo Fast Collection...")
        ddg_domains, rapiddns_seeds = FastDiscoveryEngine.collect_from_ddg_parallel()
        self.all_domains.update(ddg_domains)
        
        # 2. RapidDNS Expansion
        if rapiddns_seeds:
            print("\n[2/2] RapidDNS Fast Expansion...")
            # Simplified version - just use seeds directly
            self.all_domains.update(rapiddns_seeds)
        
        # Save domains
        new_count = len(self.all_domains) - existing_count
        if self.all_domains:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                for domain in sorted(self.all_domains):
                    f.write(f"{domain}\n")
        
        FullDisplayManager.display_discovery_summary(
            len(self.all_domains), new_count, existing_count
        )
        
        return list(self.all_domains)
    
    def scan_domains_super_fast(self, domains, max_scan=30):
        """Scan phase với progress bar"""
        domains_to_scan = domains[:max_scan]
        total = len(domains_to_scan)
        
        self.progress_bar.display_scan_start(total)
        
        lock = threading.Lock()
        
        def scan_worker(domain):
            """Worker scan"""
            try:
                scanner = WordPressSuperScanner(domain)
                result = scanner.super_scan()
                
                with lock:
                    self.scan_results[domain] = result
                    self.stats['total_scanned'] += 1
                    
                    # Update progress
                    self.progress_bar.update(
                        scanned_targets=self.stats['total_scanned'],
                        current_domain=domain[:20],
                        current_status=f"Scanning: {domain[:15]}..."
                    )
                    
                    if result['wp']['detected']:
                        self.stats['wp_detected'] += 1
                        self.progress_bar.update(wp_detected=self.stats['wp_detected'])
                        
                        # Update plugin stats
                        self.stats['plugins_stats']['total_plugins'] += result['plugins']['total']
                        self.stats['plugins_stats']['popular_count'] += result['plugins']['popular']
                        self.stats['plugins_stats']['versions_found'] += result['plugins']['versions_found']
                        self.stats['plugins_stats']['scanned_sites'] += 1
                        
                        risk_score = result['vulnerabilities']['risk_score']
                        self.stats['risk_scores'].append(risk_score)
                        
                        summary = scanner.get_display_summary()
                        if summary:
                            if risk_score >= 30 or summary['vuln_cve_count'] > 0:
                                self.stats['vulnerable_count'] += 1
                                self.vulnerable_domains.append(domain)
                                self.progress_bar.update(vulnerable_targets=self.stats['vulnerable_count'])
                                
                                # Save vulnerable domain
                                with open(DOMAIN_VULN_FILE, "a", encoding="utf-8") as f:
                                    f.write(f"{domain}|Risk:{risk_score}|"
                                           f"WP:{summary['wp_version']}|"
                                           f"PHP:{summary['server_php']}|"
                                           f"CVE:{summary['vuln_cve_count']}|"
                                           f"Plugins:{summary['plugins_total']}|"
                                           f"Time:{summary['performance_scan_time']}\n")
                        
                        return domain, summary
                    
                    return domain, None
                    
            except Exception as e:
                return domain, None
        
        # Parallel scanning
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as executor:
            futures = {executor.submit(scan_worker, domain): domain for domain in domains_to_scan}
            
            for future in as_completed(futures):
                domain, summary = future.result()
                
                # Display result với progress bar
                FullDisplayManager.display_domain_result(domain, summary, self.progress_bar)
        
        # Clear progress bar
        print("\n" * (self.progress_bar.last_progress_height + 2))
        
        return self.stats
    
    def save_enhanced_results(self):
        """Lưu kết quả chi tiết"""
        if not self.scan_results:
            return
        
        # Tính plugin stats
        if self.stats['plugins_stats']['scanned_sites'] > 0:
            avg_plugins = self.stats['plugins_stats']['total_plugins'] / self.stats['plugins_stats']['scanned_sites']
            self.stats['plugins_stats']['avg_plugins'] = avg_plugins
        
        enhanced_data = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "total_domains": len(self.scan_results),
                "wp_detected": self.stats['wp_detected'],
                "vulnerable_domains": len(self.vulnerable_domains),
                "scan_type": "SUPER_FAST_FULL_SCAN"
            },
            "results": self.scan_results,
            "statistics": self._calculate_statistics()
        }
        
        with open(ENHANCED_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Enhanced results saved to: {ENHANCED_OUTPUT_FILE}")
    
    def _calculate_statistics(self):
        """Tính toán thống kê"""
        stats = {
            'total_scanned': self.stats['total_scanned'],
            'wp_detected': self.stats['wp_detected'],
            'wp_percentage': (self.stats['wp_detected'] / self.stats['total_scanned'] * 100) if self.stats['total_scanned'] > 0 else 0,
            'vulnerable_count': self.stats['vulnerable_count'],
            'vuln_percentage': (self.stats['vulnerable_count'] / self.stats['wp_detected'] * 100) if self.stats['wp_detected'] > 0 else 0,
            'avg_risk': sum(self.stats['risk_scores']) / len(self.stats['risk_scores']) if self.stats['risk_scores'] else 0,
            'critical_count': len([r for r in self.stats['risk_scores'] if r >= 70]),
            'high_count': len([r for r in self.stats['risk_scores'] if 50 <= r < 70]),
            'medium_count': len([r for r in self.stats['risk_scores'] if 30 <= r < 50]),
            'low_count': len([r for r in self.stats['risk_scores'] if r < 30]),
            'plugins_stats': self.stats['plugins_stats']
        }
        
        return stats
    
    def display_final_report(self):
        """Hiển thị báo cáo cuối"""
        stats = self._calculate_statistics()
        FullDisplayManager.display_final_summary(stats)
        
        # Hiển thị top vulnerable domains
        if self.vulnerable_domains:
            print(f"\n⚠️  TOP VULNERABLE DOMAINS:")
            for i, domain in enumerate(self.vulnerable_domains[:5], 1):
                result = self.scan_results.get(domain, {})
                risk = result.get('vulnerabilities', {}).get('risk_score', 0)
                wp_version = result.get('wp', {}).get('version', 'Unknown')
                php_version = result.get('server', {}).get('php', 'Unknown')
                cve_count = len(result.get('vulnerabilities', {}).get('cve_matches', []))
                
                print(f"  {i:2d}. {domain:<30}")
                print(f"       Risk: {risk:<3} | WP: {wp_version:<8} | PHP: {php_version:<6} | CVE: {cve_count}")
            
            if len(self.vulnerable_domains) > 5:
                print(f"  ... and {len(self.vulnerable_domains) - 5} more")
        
        print(f"\n📁 OUTPUT FILES:")
        print(f"  • Domain list: {OUTPUT_FILE}")
        print(f"  • Vulnerable domains: {DOMAIN_VULN_FILE}")
        print(f"  • Enhanced results: {ENHANCED_OUTPUT_FILE}")
        print(f"\n{'=' * 80}\n")

# =================== MAIN FUNCTION ===================
def main():
    """Hàm chính - Super Scanner với Full Display"""
    global stop_flag
    
    print("\n" + "=" * 80)
    print("🔥 WORDPRESS SUPER SCANNER v3.2 - FULL DISPLAY")
    print("⚡ Speed + Depth + Full Version Display + Progress Bar")
    print("=" * 80)
    
    try:
        # Khởi tạo manager
        manager = SuperScanManager()
        
        # Phase 1: Super Fast Discovery
        domains = manager.discover_domains()
        
        if not domains:
            print("❌ No domains found!")
            return
        
        # Phase 2: Super Fast Scanning với Full Display
        stats = manager.scan_domains_super_fast(domains, max_scan=20)
        
        # Phase 3: Save Results
        manager.save_enhanced_results()
        
        # Phase 4: Final Report
        manager.display_final_report()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Stopped by user")
        stop_flag = True
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()