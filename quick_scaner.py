"""
WORDPRESS SUPER SCANNER v3.0
Kết hợp Speed của deeep.py + Depth của wpscanIPs2.0.py
Real-time scanning với phân tích chi tiết
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

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# =================== CONFIGURATION ===================
# GIỮ TỐC ĐỘ CAO CỦA DEEP.PY
NUM_RESULTS_PER_DORK = 75
OUTPUT_FILE = "wp_vn_domains.txt"
DOMAIN_VULN_FILE = "vulnerable_domains.txt"
ENHANCED_OUTPUT_FILE = "wp_enhanced_recon.json"
SUMMARY_FILE = "scan_summary.txt"

# TỐI ƯU TIMEOUT - CÂN BẰNG SPEED/DEPTH
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
    
    # 🎨 PAGE BUILDERS
    'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
    
    # 📝 FORMS
    'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
    'wpforms-lite': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
    
    # ⚡ CACHE & PERFORMANCE
    'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
    'wp-rocket': {'name': 'WP Rocket', 'category': 'Performance', 'installs': '2M+'},
    
    # 🛒 E-COMMERCE
    'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
    
    # 🔐 SECURITY
    'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
    'better-wp-security': {'name': 'iThemes Security', 'category': 'Security', 'installs': '1M+'},
    
    # 📧 EMAIL
    'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    
    # 🔄 BACKUP
    'updraftplus': {'name': 'UpdraftPlus', 'category': 'Backup', 'installs': '3M+'},
    
    # 📊 ANALYTICS
    'google-site-kit': {'name': 'Site Kit by Google', 'category': 'Analytics', 'installs': '5M+'},
    
    # 🖼️ SLIDERS
    'revslider': {'name': 'Revolution Slider', 'category': 'Slider', 'installs': '10M+'},
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
        
        # Optimized - giảm số request không cần thiết
        self.quick_checks_done = False
        self.wp_detected_quick = False
        
        self.results = self._init_schema()
        
    def _init_schema(self):
        """Schema tối ưu - đầy đủ nhưng gọn"""
        return {
            "target": self.domain,
            "scan_timestamp": datetime.now().isoformat(),
            "quick_scan": True,  # Đánh dấu scan nhanh
            
            "wp": {
                "detected": False,
                "confidence": 0,
                "version": "",
                "version_source": ""
            },
            
            "server": {
                "webserver": "",
                "php": "",
                "server_header": ""
            },
            
            "plugins": {
                "total": 0,
                "popular": 0,
                "list": [],
                "categories": defaultdict(int)
            },
            
            "theme": {
                "name": "",
                "version": ""
            },
            
            "security": {
                "waf_detected": "",
                "xmlrpc_enabled": False,
                "directory_listing": False,
                "sensitive_files": []
            },
            
            "vulnerabilities": {
                "risk_score": 0,
                "cve_matches": [],
                "issues": [],
                "outdated_wp": False,
                "outdated_php": False
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
        """PHÁT HIỆN NHANH WordPress - SPEED FOCUS"""
        # Thử HTTPS trước, nếu fail thì HTTP
        for test_url in [self.https_url, self.url]:
            response = self._make_request(test_url, timeout=3)
            if response and response.status_code < 400:
                self.base_url = test_url
                
                # QUICK CHECK: 3 signature chính
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
                
                self.wp_detected_quick = quick_indicators >= 2
                self.results['wp']['detected'] = self.wp_detected_quick
                self.results['wp']['confidence'] = min(quick_indicators * 25, 100)
                
                # Get server info từ response đầu tiên
                self._quick_server_info(response)
                
                return self.wp_detected_quick
        
        return False
    
    def _quick_server_info(self, response):
        """Lấy server info nhanh"""
        if not response:
            return
        
        headers = response.headers
        
        # Server header
        server = headers.get('Server', '')
        self.results['server']['server_header'] = server
        if server:
            self.results['server']['webserver'] = server.split('/')[0] if '/' in server else server
        
        # PHP version - quick check
        php_header = headers.get('X-Powered-By', '')
        if 'PHP' in php_header:
            match = re.search(r'PHP/([\d.]+)', php_header)
            if match:
                self.results['server']['php'] = match.group(1)
    
    def _fast_wp_version_detect(self):
        """Phát hiện version nhanh"""
        if not self.base_url:
            return
        
        # Method 1: Meta generator (nhanh nhất)
        response = self._make_request(self.base_url, timeout=2)
        if response:
            html = response.text
            meta_match = re.search(r'content=["\']WordPress ([\d.]+)["\']', html)
            if meta_match:
                self.results['wp']['version'] = meta_match.group(1)
                self.results['wp']['version_source'] = 'meta'
                return
        
        # Method 2: Script version (nhanh)
        if response:
            script_match = re.search(r'wp-embed\.js\?ver=([\d.]+)', html)
            if script_match:
                self.results['wp']['version'] = script_match.group(1)
                self.results['wp']['version_source'] = 'script'
                return
    
    def _fast_plugin_detection(self):
        """Phát hiện plugin nhanh nhưng đầy đủ"""
        if not self.base_url:
            return
        
        response = self._make_request(self.base_url, timeout=3)
        if not response:
            return
        
        html = response.text
        
        # Tìm plugin slugs trong HTML
        plugin_slugs = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
        
        # Giới hạn số plugin check để tăng speed
        for slug in list(plugin_slugs)[:10]:  # Chỉ check 10 plugin đầu
            plugin_key = slug.lower().replace('_', '-')
            
            plugin_info = {
                "slug": slug,
                "detected": False,
                "popular": plugin_key in POPULAR_PLUGINS,
                "category": POPULAR_PLUGINS.get(plugin_key, {}).get('category', 'Unknown') 
                    if plugin_key in POPULAR_PLUGINS else 'Unknown'
            }
            
            # QUICK CHECK: thử readme.txt
            readme_url = f"{self.base_url}/wp-content/plugins/{slug}/readme.txt"
            readme_resp = self._make_request(readme_url, timeout=2)
            
            if readme_resp and readme_resp.status_code == 200:
                plugin_info["detected"] = True
                content = readme_resp.text
                
                # Tìm version nhanh
                version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.I)
                if version_match:
                    plugin_info["version"] = version_match.group(1).strip()
            
            if plugin_info["detected"]:
                self.results['plugins']['list'].append(plugin_info)
                if plugin_info["popular"]:
                    self.results['plugins']['popular'] += 1
                    self.results['plugins']['categories'][plugin_info["category"]] += 1
        
        self.results['plugins']['total'] = len(self.results['plugins']['list'])
    
    def _fast_security_checks(self):
        """Security checks nhanh nhưng quan trọng"""
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
        
        # 3. WAF detection (quick)
        response = self._make_request(self.base_url, timeout=2)
        if response:
            headers_str = str(response.headers).lower()
            if 'cloudflare' in headers_str or 'cf-ray' in headers_str:
                self.results['security']['waf_detected'] = 'Cloudflare'
            elif 'wordfence' in headers_str:
                self.results['security']['waf_detected'] = 'Wordfence'
    
    def _fast_cve_check(self):
        """CVE check nhanh"""
        wp_version = self.results['wp']['version']
        cve_matches = []
        
        # Check WordPress core CVEs
        if wp_version:
            for version_range, cves in CVE_DATABASE.get('wordpress', {}).items():
                if self._check_version_in_range(wp_version, version_range):
                    cve_matches.extend([{'component': 'wordpress', 'cve': cve} for cve in cves])
        
        # Check plugin CVEs (chỉ plugin phổ biến đã detect)
        for plugin in self.results['plugins']['list']:
            if plugin.get('version') and plugin.get('popular'):
                plugin_slug = plugin['slug'].lower()
                plugin_version = plugin['version']
                
                for plugin_name in CVE_DATABASE:
                    if plugin_name != 'wordpress' and plugin_name in plugin_slug:
                        for version_range, cves in CVE_DATABASE[plugin_name].items():
                            if self._check_version_in_range(plugin_version, version_range):
                                cve_matches.extend([{'component': plugin_name, 'cve': cve} for cve in cves])
        
        self.results['vulnerabilities']['cve_matches'] = cve_matches
    
    def _calculate_risk_score_fast(self):
        """Tính risk score nhanh"""
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
        
        # CVE matches
        risk += len(self.results['vulnerabilities']['cve_matches']) * 25
        
        # Confidence thấp
        if self.results['wp']['confidence'] < 40:
            risk += 10
        
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
        """SUPER SCAN - Nhanh mà vẫn đầy đủ"""
        start_time = time.time()
        
        # Bước 1: Quick WordPress check (SIÊU NHANH)
        if not self._quick_wp_check():
            self.results['performance']['scan_duration'] = time.time() - start_time
            return self.results
        
        # Bước 2: Fast version detection
        self._fast_wp_version_detect()
        
        # Bước 3: Fast plugin detection
        self._fast_plugin_detection()
        
        # Bước 4: Fast security checks
        self._fast_security_checks()
        
        # Bước 5: Fast CVE check
        self._fast_cve_check()
        
        # Bước 6: Calculate risk score
        self._calculate_risk_score_fast()
        
        # Update performance metrics
        self.results['performance']['scan_duration'] = time.time() - start_time
        
        return self.results
    
    def get_display_summary(self):
        """Tạo summary để hiển thị đẹp - KIỂU WPSCAN"""
        if not self.results['wp']['detected']:
            return None
        
        summary = {
            'domain': self.domain,
            'wp_detected': self.results['wp']['detected'],
            'wp_confidence': self.results['wp']['confidence'],
            'wp_version': self.results['wp']['version'] or 'Unknown',
            'server': self.results['server']['webserver'] or 'Unknown',
            'php': self.results['server']['php'] or 'Unknown',
            'xmlrpc': self.results['security']['xmlrpc_enabled'],
            'directory_listing': self.results['security']['directory_listing'],
            'waf': self.results['security']['waf_detected'] or 'None',
            'plugins_count': self.results['plugins']['total'],
            'popular_plugins': self.results['plugins']['popular'],
            'cve_count': len(self.results['vulnerabilities']['cve_matches']),
            'risk_score': self.results['vulnerabilities']['risk_score'],
            'scan_time': f"{self.results['performance']['scan_duration']:.2f}s",
            'categories': dict(self.results['plugins']['categories'])
        }
        
        return summary

# =================== REAL-TIME DISPLAY ===================
class RealTimeDisplay:
    """Hiển thị real-time đẹp như wpscan"""
    
    @staticmethod
    def display_domain_result(domain, summary):
        """Hiển thị kết quả chi tiết cho từng domain"""
        if not summary:
            RealTimeDisplay._display_non_wp(domain)
            return
        
        # Xác định màu sắc theo risk score
        risk_score = summary['risk_score']
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
        
        # HEADER với màu risk
        print(f"\n{color}{'═' * 80}\033[0m")
        print(f"{color}📍 WORDPRESS SCAN REPORT: {domain}\033[0m")
        print(f"{color}{'═' * 80}\033[0m")
        
        # BASIC INFO SECTION
        print(f"\n📋 \033[1mBASIC INFORMATION\033[0m")
        print(f"{'─' * 60}")
        print(f"  • WordPress: {'✅ DETECTED' if summary['wp_detected'] else '❌ NOT DETECTED'}")
        print(f"  • Confidence: {summary['wp_confidence']}%")
        print(f"  • Version: {summary['wp_version']}")
        
        # SERVER INFO
        print(f"\n🖥️  \033[1mSERVER INFORMATION\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Web Server: {summary['server']}")
        print(f"  • PHP Version: {summary['php']}")
        
        # PLUGIN INFO
        print(f"\n🔌 \033[1mPLUGIN ANALYSIS\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Total Plugins: {summary['plugins_count']}")
        print(f"  • Popular Plugins: {summary['popular_plugins']}")
        
        if summary['categories']:
            print(f"  • Top Categories: {', '.join([f'{k}({v})' for k, v in summary['categories'].items()][:3])}")
        
        # SECURITY SECTION
        print(f"\n🔐 \033[1mSECURITY CHECKS\033[0m")
        print(f"{'─' * 60}")
        
        xmlrpc_status = "⚠️  ENABLED" if summary['xmlrpc'] else "✅ DISABLED"
        print(f"  • XML-RPC: {xmlrpc_status}")
        
        dir_status = "⚠️  ENABLED" if summary['directory_listing'] else "✅ DISABLED"
        print(f"  • Directory Listing: {dir_status}")
        
        waf_info = f"✅ {summary['waf']}" if summary['waf'] != 'None' else "❌ Not Detected"
        print(f"  • WAF: {waf_info}")
        
        # VULNERABILITY SECTION
        print(f"\n⚠️  \033[1mVULNERABILITY ASSESSMENT\033[0m")
        print(f"{'─' * 60}")
        
        # Risk score với màu
        print(f"  • Risk Score: {color}{risk_score}/100 [{risk_level}]\033[0m")
        print(f"  • CVE Matches: {summary['cve_count']}")
        
        # PERFORMANCE
        print(f"\n⚡ \033[1mPERFORMANCE\033[0m")
        print(f"{'─' * 60}")
        print(f"  • Scan Time: {summary['scan_time']}")
        
        # FOOTER
        print(f"\n{color}{'═' * 80}\033[0m")
    
    @staticmethod
    def _display_non_wp(domain):
        """Hiển thị domain không phải WordPress"""
        print(f"\n\033[90m{'─' * 60}\033[0m")
        print(f"\033[90m✗ {domain:<40} | Not WordPress | Skipped\033[0m")
        print(f"\033[90m{'─' * 60}\033[0m")
    
    @staticmethod
    def display_scan_header(total_targets):
        """Hiển thị header scan"""
        print("\n" + "=" * 80)
        print("🚀 WORDPRESS SUPER SCANNER v3.0")
        print(f"📊 Targets: {total_targets} | Workers: {MAX_WORKERS_RECON}")
        print("=" * 80 + "\n")
    
    @staticmethod
    def display_progress_bar(current, total, vuln_count, status=""):
        """Hiển thị progress bar"""
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        percentage = (current / total * 100) if total > 0 else 0
        
        sys.stdout.write(f"\r\033[K[{bar}] {current:3d}/{total:3d} "
                        f"({percentage:5.1f}%) | Vuln: {vuln_count:2d} | {status[:40]}")
        sys.stdout.flush()
    
    @staticmethod
    def display_final_summary(stats):
        """Hiển thị tổng kết cuối cùng"""
        print(f"\n\n{'=' * 80}")
        print("📊 SCAN SUMMARY")
        print(f"{'=' * 80}")
        
        print(f"\n• Total Domains: {stats['total_domains']}")
        print(f"• WordPress Detected: {stats['wp_detected']} ({stats['wp_percentage']:.1f}%)")
        print(f"• Vulnerable Domains: {stats['vulnerable_count']} ({stats['vuln_percentage']:.1f}%)")
        print(f"• Average Risk Score: {stats['avg_risk']:.1f}/100")
        
        # Risk distribution
        print(f"\n• Risk Distribution:")
        print(f"  - CRITICAL (≥70): {stats['critical_count']}")
        print(f"  - HIGH (50-69): {stats['high_count']}")
        print(f"  - MEDIUM (30-49): {stats['medium_count']}")
        print(f"  - LOW (<30): {stats['low_count']}")
        
        print(f"\n{'=' * 80}")

# =================== FAST DISCOVERY ENGINE ===================
class FastDiscoveryEngine:
    """Discovery engine siêu nhanh từ deeep.py"""
    
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
                                # Fast filtering
                                filter_result = v12_discovery_filter(domain)
                                if not filter_result["accept"]:
                                    continue
                                
                                with lock:
                                    if domain not in all_domains:
                                        all_domains.add(domain)
                                        local_domains.append(domain)
                                        
                                        # Add to seeds for DNS expansion
                                        if domain.count('.') <= 2:  # Chỉ root domains
                                            rapiddns_seeds.add(domain)
                        
                        # Tiny delay để không bị block
                        time.sleep(random.uniform(0.2, 0.5))
                
                return dork_idx, len(local_domains), dork
                
            except Exception as e:
                return dork_idx, 0, dork
        
        # Xử lý song song
        print(f"\n🔍 FAST DISCOVERY: {len(DORKS)} dorks")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_DISCOVERY) as executor:
            futures = [executor.submit(process_dork_fast, i, d) 
                      for i, d in enumerate(DORKS) if not stop_flag]
            
            for future in as_completed(futures):
                dork_idx, new_count, dork = future.result()
                if new_count > 0:
                    print(f"  ✓ Dork {dork_idx+1:2d}: {new_count:3d} domains")
        
        return all_domains, rapiddns_seeds
    
    @staticmethod
    def collect_from_rapiddns_fast(seeds, max_seeds=20):
        """RapidDNS expansion nhanh"""
        domains = set()
        
        print(f"\n🌐 RAPIDDNS EXPANSION: {min(len(seeds), max_seeds)} seeds")
        
        def fetch_seed(seed):
            try:
                url = f"https://rapiddns.io/subdomain/{seed}?full=1"
                resp = requests.get(url, headers=HEADERS, timeout=6, verify=False)
                if resp.status_code == 200:
                    matches = re.findall(
                        r'([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))',
                        resp.text
                    )
                    seed_domains = {d.lower().replace("www.", "") for d in matches}
                    return seed, seed_domains
            except:
                pass
            return seed, set()
        
        # Giới hạn số seeds để tăng speed
        seeds_list = list(seeds)[:max_seeds]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_seed, seed): seed for seed in seeds_list}
            
            for future in as_completed(futures):
                seed, seed_domains = future.result()
                domains.update(seed_domains)
                print(f"\r\033[K  Processing {seed} → {len(seed_domains)} domains", end="")
        
        print()  # New line
        return domains
    
    @staticmethod
    def v12_discovery_source_fast():
        """V12 source nhanh"""
        discovered = set()
        
        sources = [
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
            "https://rapiddns.io/subdomain/wp-content?full=1"
        ]
        
        for src in sources:
            try:
                r = requests.get(src, timeout=8, verify=False)
                raw_domains = re.findall(
                    r'([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))',
                    r.text
                )
                
                for d in raw_domains:
                    domain = d.lower().replace("www.", "")
                    if extract_domain_func(domain):
                        filter_result = v12_discovery_filter(domain)
                        if filter_result["accept"]:
                            discovered.add(domain)
                
            except:
                continue
        
        return discovered

# =================== MAIN SCAN MANAGER ===================
class SuperScanManager:
    """Quản lý scan tổng thể"""
    
    def __init__(self):
        self.all_domains = set()
        self.scan_results = {}
        self.vulnerable_domains = []
        self.stats = {
            'total_scanned': 0,
            'wp_detected': 0,
            'vulnerable_count': 0,
            'risk_scores': []
        }
        
        # Load existing domains
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                self.all_domains = {line.strip() for line in f if line.strip()}
    
    def discover_domains(self):
        """Discovery phase - SIÊU NHANH"""
        print("\n" + "=" * 80)
        print("🚀 PHASE 1: SUPER FAST DISCOVERY")
        print("=" * 80)
        
        # 1. V12 source
        print("\n[1/3] V12 Discovery Source...")
        v12_domains = FastDiscoveryEngine.v12_discovery_source_fast()
        self.all_domains.update(v12_domains)
        print(f"  ✓ Found: {len(v12_domains)} domains")
        
        # 2. DuckDuckGo
        print("\n[2/3] DuckDuckGo Fast Collection...")
        ddg_domains, rapiddns_seeds = FastDiscoveryEngine.collect_from_ddg_parallel()
        self.all_domains.update(ddg_domains)
        print(f"  ✓ Found: {len(ddg_domains)} domains")
        
        # 3. RapidDNS Expansion
        if rapiddns_seeds:
            print("\n[3/3] RapidDNS Fast Expansion...")
            rapiddns_domains = FastDiscoveryEngine.collect_from_rapiddns_fast(rapiddns_seeds)
            self.all_domains.update(rapiddns_domains)
            print(f"  ✓ Found: {len(rapiddns_domains)} domains")
        
        # Save domains
        if self.all_domains:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                for domain in sorted(self.all_domains):
                    f.write(f"{domain}\n")
        
        print(f"\n✅ TOTAL DOMAINS DISCOVERED: {len(self.all_domains)}")
        return list(self.all_domains)
    
    def scan_domains_super_fast(self, domains, max_scan=50):
        """Scan phase - SIÊU NHANH nhưng đầy đủ"""
        print(f"\n" + "=" * 80)
        print(f"🚀 PHASE 2: SUPER FAST SCANNING")
        print(f"📊 Targets: {min(len(domains), max_scan)} domains")
        print("=" * 80 + "\n")
        
        # Giới hạn số domain scan
        domains_to_scan = domains[:max_scan]
        total = len(domains_to_scan)
        
        RealTimeDisplay.display_scan_header(total)
        
        lock = threading.Lock()
        
        def scan_worker(domain):
            """Worker scan siêu nhanh"""
            try:
                scanner = WordPressSuperScanner(domain)
                result = scanner.super_scan()
                
                with lock:
                    self.scan_results[domain] = result
                    self.stats['total_scanned'] += 1
                    
                    if result['wp']['detected']:
                        self.stats['wp_detected'] += 1
                        self.stats['risk_scores'].append(result['vulnerabilities']['risk_score'])
                        
                        summary = scanner.get_display_summary()
                        if summary:
                            risk_score = summary['risk_score']
                            
                            if risk_score >= 30 or summary['cve_count'] > 0:
                                self.stats['vulnerable_count'] += 1
                                self.vulnerable_domains.append(domain)
                                
                                # Save vulnerable domain
                                with open(DOMAIN_VULN_FILE, "a", encoding="utf-8") as f:
                                    f.write(f"{domain}|Risk:{risk_score}|"
                                           f"WP:{summary['wp_version']}|"
                                           f"CVE:{summary['cve_count']}|"
                                           f"Plugins:{summary['plugins_count']}\n")
                        
                        return domain, summary
                    
                    return domain, None
                    
            except Exception as e:
                return domain, None
        
        # Parallel scanning
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as executor:
            futures = {executor.submit(scan_worker, domain): domain for domain in domains_to_scan}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                domain, summary = future.result()
                
                # Update progress
                status = f"Scanning: {domain[:30]}..."
                RealTimeDisplay.display_progress_bar(
                    completed, total, 
                    self.stats['vulnerable_count'],
                    status
                )
                
                # Display result
                if summary:
                    RealTimeDisplay.display_domain_result(domain, summary)
        
        # Clear progress bar
        sys.stdout.write('\r\033[K')
        
        return self.stats
    
    def save_enhanced_results(self):
        """Lưu kết quả chi tiết"""
        if not self.scan_results:
            return
        
        enhanced_data = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "total_domains": len(self.scan_results),
                "wp_detected": self.stats['wp_detected'],
                "vulnerable_domains": len(self.vulnerable_domains),
                "scan_type": "SUPER_FAST_SCAN"
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
            'total_domains': len(self.scan_results),
            'wp_detected': self.stats['wp_detected'],
            'wp_percentage': (self.stats['wp_detected'] / len(self.scan_results) * 100) if self.scan_results else 0,
            'vulnerable_count': self.stats['vulnerable_count'],
            'vuln_percentage': (self.stats['vulnerable_count'] / self.stats['wp_detected'] * 100) if self.stats['wp_detected'] > 0 else 0,
            'avg_risk': sum(self.stats['risk_scores']) / len(self.stats['risk_scores']) if self.stats['risk_scores'] else 0,
            'critical_count': len([r for r in self.stats['risk_scores'] if r >= 70]),
            'high_count': len([r for r in self.stats['risk_scores'] if 50 <= r < 70]),
            'medium_count': len([r for r in self.stats['risk_scores'] if 30 <= r < 50]),
            'low_count': len([r for r in self.stats['risk_scores'] if r < 30])
        }
        
        return stats
    
    def display_final_report(self):
        """Hiển thị báo cáo cuối"""
        stats = self._calculate_statistics()
        RealTimeDisplay.display_final_summary(stats)
        
        # Hiển thị top vulnerable domains
        if self.vulnerable_domains:
            print(f"\n⚠️  TOP VULNERABLE DOMAINS:")
            for i, domain in enumerate(self.vulnerable_domains[:10], 1):
                result = self.scan_results.get(domain, {})
                risk = result.get('vulnerabilities', {}).get('risk_score', 0)
                cve_count = len(result.get('vulnerabilities', {}).get('cve_matches', []))
                
                print(f"  {i:2d}. {domain:<40} Risk: {risk:<3} CVE: {cve_count}")
            
            if len(self.vulnerable_domains) > 10:
                print(f"  ... and {len(self.vulnerable_domains) - 10} more")
        
        print(f"\n📁 OUTPUT FILES:")
        print(f"  • Domain list: {OUTPUT_FILE}")
        print(f"  • Vulnerable domains: {DOMAIN_VULN_FILE}")
        print(f"  • Enhanced results: {ENHANCED_OUTPUT_FILE}")
        print(f"\n{'=' * 80}\n")

# =================== MAIN FUNCTION ===================
def main():
    """Hàm chính - Super Scanner"""
    global stop_flag
    
    print("\n" + "=" * 80)
    print("🔥 WORDPRESS SUPER SCANNER v3.0")
    print("⚡ Speed of deeep.py + Depth of wpscanIPs2.0.py")
    print("=" * 80)
    
    try:
        # Khởi tạo manager
        manager = SuperScanManager()
        
        # Phase 1: Super Fast Discovery
        domains = manager.discover_domains()
        
        if not domains:
            print("❌ No domains found!")
            return
        
        # Phase 2: Super Fast Scanning
        stats = manager.scan_domains_super_fast(domains, max_scan=50)
        
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