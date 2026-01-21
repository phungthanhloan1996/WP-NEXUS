# wpscanIPs2.1_plugin_analysis_enhanced_fixed.py
# Thu thập domain WordPress (.vn variants) với phân tích plugin phổ biến - Phiên bản sửa lỗi hiển thị

import time
import random
import json
from urllib.parse import urlparse
from ddgs import DDGS
from tqdm import tqdm
import re
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict
import warnings
import sys
from bs4 import BeautifulSoup 
import re

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Cấu hình
DORKS = [
    '"Powered by WordPress" site:.vn',
    '"Powered by WordPress" site:.com.vn',
    'intext:"WordPress" site:.vn generator:"WordPress"',
    '"index of" inurl:wp-content site:.vn',
    'inurl:/wp-content/plugins/ site:.vn',
    'inurl:/wp-admin/ intitle:"Log In" site:.vn',
    'inurl:wp-login.php site:.vn',
    '"Powered by WordPress" inurl:.vn -inurl:(forum OR blogspot OR wordpress.com)',
    'inurl:/wp-content/themes/ site:.vn',
    'inurl:wp-config.php site:.vn',
    '"index of /wp-content/uploads/" site:.vn',
    'inurl:/wp-content/plugins/elementor/ site:.vn',
    'inurl:/wp-content/plugins/woocommerce/ site:.vn',
    'inurl:/wp-content/plugins/contact-form-7/ site:.vn',
    'inurl:/wp-content/plugins/revslider/ site:.vn',
    'site:.com.vn "WordPress"',
    'site:.vn inurl:wp-json',
    'site:.vn "xmlrpc.php"',
]

# DANH SÁCH PLUGIN PHỔ BIẾN (TOP 50+) - Giữ nguyên
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
    'visual-composer': {'name': 'Visual Composer', 'category': 'Page Builder', 'installs': '100K+'},
    
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
    'autoptimize': {'name': 'Autoptimize', 'category': 'Performance', 'installs': '1M+'},
    
    # 🛒 E-COMMERCE
    'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
    
    # 🔐 SECURITY
    'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
    'better-wp-security': {'name': 'iThemes Security', 'category': 'Security', 'installs': '1M+'},
    'sucuri-scanner': {'name': 'Sucuri Security', 'category': 'Security', 'installs': '800K+'},
    'all-in-one-wp-security-and-firewall': {'name': 'All In One WP Security', 'category': 'Security', 'installs': '1M+'},
    
    # 📧 EMAIL
    'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    'contact-form-7-to-database-extension': {'name': 'CF7 to Database', 'category': 'Forms', 'installs': '200K+'},
    
    # 🔄 BACKUP & MIGRATION
    'updraftplus': {'name': 'UpdraftPlus', 'category': 'Backup', 'installs': '3M+'},
    'all-in-one-wp-migration': {'name': 'All-in-One WP Migration', 'category': 'Migration', 'installs': '5M+'},
    'duplicator': {'name': 'Duplicator', 'category': 'Migration', 'installs': '1M+'},
    'backupbuddy': {'name': 'BackupBuddy', 'category': 'Backup', 'installs': '500K+'},
    
    # 📊 ANALYTICS
    'google-site-kit': {'name': 'Site Kit by Google', 'category': 'Analytics', 'installs': '5M+'},
    'monsterinsights': {'name': 'MonsterInsights', 'category': 'Analytics', 'installs': '3M+'},
    
    # 🖼️ IMAGE OPTIMIZATION
    'smush': {'name': 'Smush Image Optimization', 'category': 'Performance', 'installs': '1M+'},
    'ewww-image-optimizer': {'name': 'EWWW Image Optimizer', 'category': 'Performance', 'installs': '800K+'},
    'imagify': {'name': 'Imagify', 'category': 'Performance', 'installs': '500K+'},
    
    # 🔧 EDITORS
    'classic-editor': {'name': 'Classic Editor', 'category': 'Editor', 'installs': '9M+'},
    'tinymce-advanced': {'name': 'Advanced Editor Tools', 'category': 'Editor', 'installs': '2M+'},
    
    # 🛠️ UTILITIES
    'akismet': {'name': 'Akismet Anti-Spam', 'category': 'Security', 'installs': '6M+'},
    'cookie-notice': {'name': 'Cookie Notice', 'category': 'Compliance', 'installs': '2M+'},
    'really-simple-ssl': {'name': 'Really Simple SSL', 'category': 'Security', 'installs': '5M+'},
    
    # 📄 SLIDERS
    'revslider': {'name': 'Revolution Slider', 'category': 'Slider', 'installs': '10M+'},
    'smart-slider-3': {'name': 'Smart Slider 3', 'category': 'Slider', 'installs': '1M+'},
    'ml-slider': {'name': 'MetaSlider', 'category': 'Slider', 'installs': '1M+'},
    
    # 🎭 CUSTOMIZATION
    'advanced-custom-fields': {'name': 'Advanced Custom Fields', 'category': 'Custom Fields', 'installs': '2M+'},
    'custom-post-type-ui': {'name': 'Custom Post Type UI', 'category': 'Custom Post Types', 'installs': '1M+'},
}

# CVE Database cho WordPress và plugin phổ biến
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
    }
}

NUM_RESULTS_PER_DORK = 100
OUTPUT_FILE = "wp_vn_domains.txt"
DOMAIN_VULN_FILE = "vulnerable_domains.txt"
ENHANCED_OUTPUT_FILE = "wp_enhanced_recon.json"
DELAY_MIN = 2.0
DELAY_MAX = 5.0
MAX_WORKERS_DISCOVERY = 3  # Giảm để ổn định hơn
MAX_WORKERS_RECON = 5
TIMEOUT = 10
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

# Biến toàn cục để quản lý dừng chương trình
stop_flag = False

class WordPressReconEnhanced:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"http://{domain}"
        self.https_url = f"https://{domain}"
        self.base_url = None
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.confidence = 0
        self.wp_signatures = []
        self.results = self._init_schema()
        
    def _init_schema(self):
        """Khởi tạo schema JSON theo chuẩn mới"""
        return {
            "target": self.domain,
            "scan_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "wp": {
                "detected": False,
                "confidence": 0,
                "confidence_sources": [],
                "version": "",
                "version_source": "",
                "version_sources": []
            },
            "server": {
                "webserver": "",
                "webserver_version": "",
                "php": "",
                "php_source": "",
                "server_full": ""
            },
            "plugins": [],
            "theme": {
                "name": "",
                "slug": "",
                "version": "",
                "version_source": "",
                "detected_version": ""
            },
            "endpoints": {
                "xmlrpc": False,
                "xmlrpc_status": "",
                "rest_api": False,
                "rest_api_status": "",
                "rest_api_endpoints": [],
                "wp_login": False,
                "wp_admin": False,
                "upload_dir_listing": False,
                "upload_status": ""
            },
            "security_indicators": {
                "waf_detected": "",
                "waf_type": "",
                "directory_listing": False,
                "sensitive_files": [],
                "user_enumeration": False,
                "xmlrpc_enabled": False
            },
            "vulnerability_indicators": {
                "outdated_wp": False,
                "outdated_php": False,
                "outdated_plugins": [],
                "potential_issues": [],
                "cve_matches": [],
                "risk_score": 0
            },
            "plugin_analysis": {
                "popular_plugins_found": 0,
                "categories": defaultdict(int),
                "plugin_combinations": []
            },
            "scan_metadata": {
                "duration": 0,
                "requests_made": 0,
                "status": "pending"
            }
        }
    
    def _make_request(self, url, method='GET', allow_redirects=True, timeout=TIMEOUT):
        """Thực hiện HTTP request an toàn"""
        if stop_flag:
            return None
            
        try:
            response = self.session.request(
                method=method,
                url=url,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
            self.results['scan_metadata']['requests_made'] += 1
            return response
        except Exception as e:
            return None
    
    def _calculate_wp_confidence(self):
        """Tính confidence score cho WordPress detection"""
        confidence = 0
        sources = []
        
        # Mỗi signature có trọng số khác nhau
        signature_weights = {
            'wp_content_structure': 20,
            'wp_login_page': 25,
            'wp_admin_redirect': 25,
            'wp_json_api': 15,
            'wp_generator_tag': 10,
            'wp_feed': 10,
            'wp_includes': 15,
            'wp_config_indicators': 20
        }
        
        for signature in self.wp_signatures:
            if signature in signature_weights:
                confidence += signature_weights[signature]
                sources.append(signature)
        
        self.results['wp']['confidence'] = min(confidence, 100)
        self.results['wp']['confidence_sources'] = sources
        
        # Xác định nếu là WordPress
        self.results['wp']['detected'] = confidence >= 30  # Ngưỡng tối thiểu
        
    def _detect_wp_signatures(self):
        """Phát hiện các signature của WordPress"""
        # Kiểm tra homepage
        response = self._make_request(self.base_url)
        if not response:
            return False
        
        html = response.text
        headers = response.headers
        
        # 1. Kiểm tra /wp-content/ structure
        if '/wp-content/' in html:
            self.wp_signatures.append('wp_content_structure')
        
        # 2. Kiểm tra /wp-login.php
        login_response = self._make_request(f"{self.base_url}/wp-login.php")
        if login_response:
            self.results['endpoints']['wp_login'] = True
            if login_response.status_code < 400:
                self.wp_signatures.append('wp_login_page')
        
        # 3. Kiểm tra /wp-admin/ redirect
        admin_response = self._make_request(f"{self.base_url}/wp-admin/", allow_redirects=False)
        if admin_response:
            self.results['endpoints']['wp_admin'] = True
            if admin_response.status_code in [301, 302, 307, 308]:
                self.wp_signatures.append('wp_admin_redirect')
        
        # 4. Kiểm tra WordPress REST API
        rest_response = self._make_request(f"{self.base_url}/wp-json/")
        if rest_response:
            self.results['endpoints']['rest_api'] = True
            self.results['endpoints']['rest_api_status'] = f"{rest_response.status_code}"
            
            if rest_response.status_code == 200:
                self.wp_signatures.append('wp_json_api')
                try:
                    data = rest_response.json()
                    if 'routes' in data:
                        self.results['endpoints']['rest_api_endpoints'] = list(data['routes'].keys())[:10]
                except:
                    pass
        
        # 5. Kiểm tra WordPress generator tag
        if 'WordPress' in html and 'generator' in html.lower():
            self.wp_signatures.append('wp_generator_tag')
        
        # 6. Kiểm tra RSS feed
        feed_response = self._make_request(f"{self.base_url}/feed/")
        if feed_response and feed_response.status_code == 200 and 'WordPress' in feed_response.text:
            self.wp_signatures.append('wp_feed')
        
        # 7. Kiểm tra /wp-includes/
        if '/wp-includes/' in html:
            self.wp_signatures.append('wp_includes')
        
        # 8. Kiểm tra các indicators khác
        wp_indicators = [
            'wp-embed.min.js',
            'wp-emoji-release.min.js',
            'admin-ajax.php',
            'wp_pass_req'
        ]
        
        for indicator in wp_indicators:
            if indicator in html:
                self.wp_signatures.append('wp_config_indicators')
                break
        
        return len(self.wp_signatures) > 0
    
    def _detect_server_info(self, response):
        """Phát hiện thông tin server"""
        headers = response.headers
        
        # Web server
        server_header = headers.get('Server', '')
        if server_header:
            self.results['server']['server_full'] = server_header
            if '/' in server_header:
                self.results['server']['webserver'] = server_header.split('/')[0]
                self.results['server']['webserver_version'] = server_header.split('/')[1]
            else:
                self.results['server']['webserver'] = server_header
        
        # PHP version - CẢI THIỆN
        php_found = False
        
        # Method 1: X-Powered-By header
        php_header = headers.get('X-Powered-By', '')
        if 'PHP' in php_header:
            match = re.search(r'PHP/([\d.]+)', php_header)
            if match:
                self.results['server']['php'] = match.group(1)
                self.results['server']['php_source'] = 'header'
                php_found = True
        
        # Method 2: X-PHP-Version header (một số host dùng)
        if not php_found:
            php_version_header = headers.get('X-PHP-Version', '')
            if php_version_header:
                self.results['server']['php'] = php_version_header
                self.results['server']['php_source'] = 'x_php_version'
                php_found = True
        
        # Method 3: Tìm trong HTML
        if not php_found:
            html = response.text
            # Tìm PHP version trong HTML (thường trong comment hoặc generator)
            php_patterns = [
                r'PHP/([\d.]+)',
                r'PHP Version: ([\d.]+)',
                r'php/([\d.]+)',
                r'PHP ([\d.]+)',
            ]
            
            for pattern in php_patterns:
                php_match = re.search(pattern, html, re.IGNORECASE)
                if php_match:
                    self.results['server']['php'] = php_match.group(1)
                    self.results['server']['php_source'] = 'html'
                    php_found = True
                    break
        
        # Method 4: Kiểm tra headers khác
        if not php_found:
            # Kiểm tra tất cả headers
            for header_name, header_value in headers.items():
                if 'php' in header_name.lower():
                    match = re.search(r'([\d.]+)', header_value)
                    if match:
                        self.results['server']['php'] = match.group(1)
                        self.results['server']['php_source'] = f'header_{header_name}'
                        php_found = True
                        break
    
    def _detect_wp_version_enhanced(self):
        """Phát hiện WordPress version với nhiều phương pháp"""
        version_sources = []
        detected_version = ""
        
        # 0. Kiểm tra bằng API wp-json (phương pháp mới)
        try:
            api_resp = self._make_request(f"{self.base_url}/wp-json/wp/v2/")
            if api_resp and api_resp.status_code == 200:
                # Lấy version từ headers của wp-json
                for header_name, header_value in api_resp.headers.items():
                    if 'wp' in header_name.lower() or 'wordpress' in header_name.lower():
                        match = re.search(r'([\d.]+)', header_value)
                        if match:
                            detected_version = match.group(1)
                            version_sources.append(('wp_json_header', detected_version))
                            break
        except:
            pass
        
        # 1. Từ meta generator (độ chính xác cao nhất)
        if not detected_version:
            response = self._make_request(self.base_url)
            if response:
                html = response.text
                meta_match = re.search(r'content=["\']WordPress ([\d.]+)["\']', html)
                if meta_match:
                    detected_version = meta_match.group(1)
                    version_sources.append(('meta', detected_version))
        
        # 2. Tìm trong script tags
        if not detected_version and response:
            script_match = re.search(r'wp-embed\.js\?ver=([\d.]+)', html)
            if script_match:
                detected_version = script_match.group(1)
                version_sources.append(('script_ver', detected_version))
        
        # 3. Tìm trong comment HTML
        if not detected_version and response:
            comment_match = re.search(r'WordPress ([\d.]+)', html)
            if comment_match:
                detected_version = comment_match.group(1)
                version_sources.append(('html_comment', detected_version))
        
        # 4. Từ CSS version (style.min.css)
        if not detected_version:
            css_urls = [
                f"{self.base_url}/wp-includes/css/dist/block-library/style.min.css",
                f"{self.base_url}/wp-includes/css/dist/block-library/style.css",
                f"{self.base_url}/wp-content/themes/twentytwentyfour/style.css"
            ]
            
            for css_url in css_urls:
                css_resp = self._make_request(css_url)
                if css_resp and css_resp.status_code == 200:
                    # Kiểm tra URL có parameter ver
                    if '?' in css_resp.url:
                        match = re.search(r'ver=([\d.]+)', css_resp.url)
                        if match:
                            detected_version = match.group(1)
                            version_sources.append(('css_url', detected_version))
                            break
        
        # 5. Từ RSS feed
        if not detected_version:
            rss_resp = self._make_request(f"{self.base_url}/feed/")
            if rss_resp and rss_resp.status_code == 200:
                match = re.search(r'generator>https://wordpress.org/\?v=([\d.]+)<', rss_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('rss', detected_version))
        
        # 6. Từ readme.html
        if not detected_version:
            readme_resp = self._make_request(f"{self.base_url}/readme.html")
            if readme_resp and readme_resp.status_code == 200:
                match = re.search(r'Version ([\d.]+)', readme_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('readme', detected_version))
        
        # Lưu tất cả sources
        if version_sources:
            self.results['wp']['version'] = detected_version
            self.results['wp']['version_source'] = version_sources[0][0] if version_sources else 'unknown'
            self.results['wp']['version_sources'] = [
                f"{src[0]}:{src[1]}" for src in version_sources
            ]
        else:
            self.results['wp']['version'] = ""
            self.results['wp']['version_source'] = "not_found"
            self.results['wp']['version_sources'] = []
        
        # Kiểm tra version cũ
        try:
            if detected_version:
                major = int(detected_version.split('.')[0])
                if major < 6:
                    self.results['vulnerability_indicators']['outdated_wp'] = True
                    self.results['vulnerability_indicators']['potential_issues'].append(
                        f"outdated_wp:{detected_version}"
                    )
        except:
            pass
    
    def _detect_theme_enhanced(self):
        """Phát hiện theme với version chính xác"""
        response = self._make_request(self.base_url)
        if not response:
            return
        
        html = response.text
        
        # Tìm theme path từ HTML
        theme_path = None
        path_match = re.search(r'/wp-content/themes/([^/]+)/', html)
        if path_match:
            theme_path = path_match.group(1)
        else:
            # Thử tìm trong các links
            all_paths = re.findall(r'/wp-content/themes/([^/]+)/', html)
            if all_paths:
                theme_path = all_paths[0]
        
        if theme_path:
            self.results['theme']['slug'] = theme_path
            self.results['theme']['detected_version'] = theme_path
            
            # Lấy thông tin chi tiết từ style.css
            style_url = f"{self.base_url}/wp-content/themes/{theme_path}/style.css"
            style_resp = self._make_request(style_url)
            
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
    
    def _detect_plugins_enhanced(self):
        """
        Phát hiện plugin WordPress + version (clean, scalable, CVE-ready)
        """
        plugins_found = []
        popular_count = 0
        categories = defaultdict(int)
        scanned_slugs = set()

        # 1️⃣ Detect plugin từ HTML (passive)
        response = self._make_request(self.base_url)
        if response:
            html = response.text
            html_slugs = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
            scanned_slugs.update(list(html_slugs)[:30])  # Tăng giới hạn

        # 2️⃣ Chủ động probe plugin phổ biến (active)
        for slug in list(POPULAR_PLUGINS.keys())[:20]:  # Tăng số plugin phổ biến
            scanned_slugs.add(slug)

        # 3️⃣ Scan từng plugin
        for plugin_slug in scanned_slugs:
            # Tạo plugin data structure
            plugin_data = {
                "slug": plugin_slug,
                "detected": False,
                "version": None,
                "version_source": None,
                "confidence": "low",
                "category": "Unknown",
                "popular": False,
                "popular_info": None
            }

            # Popular plugin mapping
            plugin_key = plugin_slug.lower().replace('_', '-')
            if plugin_key in POPULAR_PLUGINS:
                plugin_data["popular"] = True
                plugin_data["popular_info"] = POPULAR_PLUGINS[plugin_key]
                plugin_data["category"] = POPULAR_PLUGINS[plugin_key]["category"]

            # 4️⃣ Kiểm tra plugin có tồn tại không (bằng cách thử truy cập readme.txt hoặc .php)
            plugin_exists = False
            
            # Kiểm tra readme.txt
            readme_url = f"{self.base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
            readme_resp = self._make_request(readme_url, timeout=5)
            
            # Kiểm tra main php file
            php_url = f"{self.base_url}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php"
            php_resp = self._make_request(php_url, timeout=5)
            
            if (readme_resp and readme_resp.status_code == 200) or \
               (php_resp and php_resp.status_code == 200):
                plugin_exists = True
                plugin_data["detected"] = True
                
                # 5️⃣ Cố gắng lấy version nếu plugin tồn tại
                version_info = self._detect_plugin_version(plugin_slug)
                
                if version_info.get("detected", False):
                    plugin_data["version"] = version_info.get("version")
                    plugin_data["version_source"] = version_info.get("source")
                    plugin_data["confidence"] = version_info.get("confidence", "low")
            
            # 6️⃣ Thêm vào danh sách nếu plugin tồn tại
            if plugin_exists:
                plugins_found.append(plugin_data)
                
                # Thống kê
                if plugin_data["popular"]:
                    popular_count += 1
                    categories[plugin_data["category"]] += 1

        # 7️⃣ Update results
        self.results["plugins"] = plugins_found
        self.results["plugin_analysis"]["popular_plugins_found"] = popular_count
        self.results["plugin_analysis"]["categories"] = dict(categories)

        # 8️⃣ Plugin combination analysis
        popular_slugs = [p["slug"] for p in plugins_found if p["popular"]]
        if len(popular_slugs) >= 2:
            self.results["plugin_analysis"]["plugin_combinations"] = \
                self._find_common_combinations(popular_slugs)
    


    def _detect_plugin_version(self, plugin_slug):
        """Detect plugin version không cần module ngoài"""
        base_url = self.base_url
        
        # 1. Kiểm tra readme.txt (cách đáng tin cậy nhất)
        readme_url = f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
        response = self._make_request(readme_url)
        
        if response and response.status_code == 200:
            content = response.text
            # Tìm Stable tag trong readme.txt
            version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.IGNORECASE)
            if version_match:
                return {
                    "detected": True,
                    "version": version_match.group(1).strip(),
                    "source": "readme.txt",
                    "confidence": "high"
                }
        
        # 2. Kiểm tra file PHP chính (thường là [slug].php hoặc [slug].php)
        php_files = [
            f"{base_url}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php",
            f"{base_url}/wp-content/plugins/{plugin_slug}/plugin.php",
            f"{base_url}/wp-content/plugins/{plugin_slug}/main.php",
        ]
        
        for php_url in php_files:
            response = self._make_request(php_url)
            if response and response.status_code == 200:
                content = response.text[:5000]  # Chỉ đọc đầu file
                # Tìm Version trong comment PHP
                version_match = re.search(r'Version:\s*([\d.]+)', content, re.IGNORECASE)
                if version_match:
                    return {
                        "detected": True,
                        "version": version_match.group(1).strip(),
                        "source": "php_header",
                        "confidence": "medium"
                    }
        
        # 3. Kiểm tra trong CSS/JS files (tìm ver= parameter)
        asset_urls = [
            f"{base_url}/wp-content/plugins/{plugin_slug}/assets/",
            f"{base_url}/wp-content/plugins/{plugin_slug}/css/",
            f"{base_url}/wp-content/plugins/{plugin_slug}/js/",
        ]
        
        for asset_url in asset_urls:
            response = self._make_request(asset_url, timeout=5)
            if response and response.status_code == 200:
                # Tìm version trong URL
                version_match = re.search(r'ver=([\d.]+)', response.text)
                if version_match:
                    return {
                        "detected": True,
                        "version": version_match.group(1),
                        "source": "asset_param",
                        "confidence": "low"
                    }
        
        # 4. Kiểm tra changelog.txt
        changelog_url = f"{base_url}/wp-content/plugins/{plugin_slug}/changelog.txt"
        response = self._make_request(changelog_url)
        if response and response.status_code == 200:
            content = response.text
            # Tìm version đầu tiên trong changelog
            version_match = re.search(r'=\s*([\d.]+)\s*=', content)
            if version_match:
                return {
                    "detected": True,
                    "version": version_match.group(1).strip(),
                    "source": "changelog",
                    "confidence": "medium"
                }
        
        # Không tìm thấy version
        return {
            "detected": False,
            "version": None,
            "source": None,
            "confidence": "low"
        }






    def _check_cve_vulnerabilities(self):
        """Kiểm tra CVE dựa trên version"""
        cve_matches = []
        
        # Kiểm tra WordPress core
        wp_version = self.results['wp']['version']
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
        
        # Kiểm tra plugins
        for plugin in self.results['plugins']:
            if plugin.get('version') and plugin.get('slug'):
                plugin_slug = plugin['slug']
                plugin_version = plugin['version']
                
                for plugin_name in CVE_DATABASE.keys():
                    if plugin_name != 'wordpress' and plugin_name in plugin_slug.lower():
                        for version_range, cves in CVE_DATABASE.get(plugin_name, {}).items():
                            if self._check_version_in_range(plugin_version, version_range):
                                for cve in cves:
                                    cve_matches.append({
                                        'component': plugin_name,
                                        'version': plugin_version,
                                        'cve': cve,
                                        'type': 'plugin'
                                    })
        
        self.results['vulnerability_indicators']['cve_matches'] = cve_matches
    
    def _check_version_in_range(self, version, version_range):
        """Kiểm tra version có nằm trong range không"""
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
        """So sánh hai version string"""
        v1_parts = list(map(int, v1.split('.')[:3]))
        v2_parts = list(map(int, v2.split('.')[:3]))
        
        # Padding với 0 nếu cần
        while len(v1_parts) < 3:
            v1_parts.append(0)
        while len(v2_parts) < 3:
            v2_parts.append(0)
        
        for i in range(3):
            if v1_parts[i] != v2_parts[i]:
                return v1_parts[i] - v2_parts[i]
        return 0
    
    def _calculate_risk_score(self):
        """Tính điểm risk tổng thể"""
        risk_score = 0
        
        # WordPress cũ
        if self.results['vulnerability_indicators']['outdated_wp']:
            risk_score += 30
        
        # PHP cũ
        if self.results['vulnerability_indicators']['outdated_php']:
            risk_score += 20
        
        # XMLRPC enabled
        if self.results['security_indicators']['xmlrpc_enabled']:
            risk_score += 15
        
        # Directory listing
        if self.results['security_indicators']['directory_listing']:
            risk_score += 10
        
        # User enumeration
        if self.results['security_indicators']['user_enumeration']:
            risk_score += 10
        
        # Sensitive files
        risk_score += len(self.results['security_indicators']['sensitive_files']) * 5
        
        # CVE matches
        risk_score += len(self.results['vulnerability_indicators']['cve_matches']) * 25
        
        # Confidence thấp
        if self.results['wp']['confidence'] < 40:
            risk_score += 10
        
        # Nhiều plugin
        if len(self.results['plugins']) > 30:
            risk_score += 5
        
        self.results['vulnerability_indicators']['risk_score'] = min(risk_score, 100)
    
    def _find_common_combinations(self, plugin_slugs):
        """Tìm các combination phổ biến giữa các plugin"""
        combinations = []
        
        # SEO + Form + Page Builder
        seo_plugins = ['yoast-seo', 'wordpress-seo', 'all-in-one-seo-pack', 'seo-by-rank-math']
        form_plugins = ['contact-form-7', 'wpforms', 'wpforms-lite', 'gravityforms', 'ninja-forms']
        page_builders = ['elementor', 'beaver-builder-lite-version', 'visual-composer']
        
        has_seo = any(p in plugin_slugs for p in seo_plugins)
        has_form = any(p in plugin_slugs for p in form_plugins)
        has_builder = any(p in plugin_slugs for p in page_builders)
        
        if has_seo and has_form and has_builder:
            combinations.append("SEO + Form + Page Builder")
        
        # Security stack
        security_plugins = ['wordfence', 'better-wp-security', 'sucuri-scanner', 'all-in-one-wp-security-and-firewall']
        cache_plugins = ['litespeed-cache', 'wp-rocket', 'w3-total-cache', 'wp-super-cache']
        
        has_security = any(p in plugin_slugs for p in security_plugins)
        has_cache = any(p in plugin_slugs for p in cache_plugins)
        
        if has_security and has_cache:
            combinations.append("Security + Cache")
        
        # E-commerce stack
        if 'woocommerce' in plugin_slugs:
            combinations.append("E-commerce Base")
            if has_seo:
                combinations.append("WooCommerce + SEO")
        
        return combinations
    
    def _check_security_endpoints(self):
        """Kiểm tra các endpoint liên quan đến bảo mật"""
        # XML-RPC
        xmlrpc_resp = self._make_request(f"{self.base_url}/xmlrpc.php")
        if xmlrpc_resp:
            self.results['endpoints']['xmlrpc'] = True
            self.results['endpoints']['xmlrpc_status'] = f"{xmlrpc_resp.status_code}"
            if xmlrpc_resp.status_code < 400:
                self.results['security_indicators']['xmlrpc_enabled'] = True
        
        # Directory listing
        uploads_resp = self._make_request(f"{self.base_url}/wp-content/uploads/")
        if uploads_resp:
            self.results['endpoints']['upload_status'] = f"{uploads_resp.status_code}"
            if uploads_resp.status_code == 200:
                if 'Index of' in uploads_resp.text or '<title>Index of' in uploads_resp.text.lower():
                    self.results['endpoints']['upload_dir_listing'] = True
                    self.results['security_indicators']['directory_listing'] = True
        
        # Sensitive files
        sensitive_files = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php~',
            '/.env',
            '/.git/HEAD',
            '/backup.zip',
            '/phpinfo.php',
            '/debug.log'
        ]
        
        for file_path in sensitive_files:
            file_resp = self._make_request(f"{self.base_url}{file_path}")
            if file_resp and file_resp.status_code == 200:
                self.results['security_indicators']['sensitive_files'].append(file_path)
        
        # User enumeration via REST API
        if self.results['endpoints']['rest_api']:
            users_resp = self._make_request(f"{self.base_url}/wp-json/wp/v2/users")
            if users_resp and users_resp.status_code == 200:
                try:
                    users_data = users_resp.json()
                    if len(users_data) > 0:
                        self.results['security_indicators']['user_enumeration'] = True
                except:
                    pass
        
        # WAF Detection
        response = self._make_request(self.base_url)
        if response:
            headers_str = str(response.headers).lower()
            server_str = str(response.headers.get('Server', '')).lower()
            
            if 'cloudflare' in headers_str or 'cf-ray' in headers_str:
                self.results['security_indicators']['waf_detected'] = 'Cloudflare'
                self.results['security_indicators']['waf_type'] = 'CDN/WAF'
            elif 'wordfence' in headers_str:
                self.results['security_indicators']['waf_detected'] = 'Wordfence'
                self.results['security_indicators']['waf_type'] = 'Security Plugin'
            elif 'sucuri' in headers_str:
                self.results['security_indicators']['waf_detected'] = 'Sucuri'
                self.results['security_indicators']['waf_type'] = 'Cloud WAF'
            elif 'akamai' in server_str:
                self.results['security_indicators']['waf_detected'] = 'Akamai'
                self.results['security_indicators']['waf_type'] = 'CDN'
            elif 'imperva' in headers_str or 'incapsula' in headers_str:
                self.results['security_indicators']['waf_detected'] = 'Imperva'
                self.results['security_indicators']['waf_type'] = 'WAF'
    
    def _assess_vulnerabilities(self):
        """Đánh giá vulnerabilities tổng thể"""
        # Kiểm tra PHP version cũ
        php_ver = self.results['server']['php']
        if php_ver:
            try:
                major = int(php_ver.split('.')[0])
                if major < 8:
                    self.results['vulnerability_indicators']['outdated_php'] = True
                    self.results['vulnerability_indicators']['potential_issues'].append(
                        f"outdated_php:{php_ver}"
                    )
            except:
                pass
        
        # Kiểm tra số lượng plugin lớn
        if len(self.results['plugins']) > 30:
            self.results['vulnerability_indicators']['potential_issues'].append(
                "many_plugins"
            )
        
        # Kiểm tra nếu có xmlrpc và directory listing cùng lúc
        if (self.results['security_indicators']['xmlrpc_enabled'] and 
            self.results['security_indicators']['directory_listing']):
            self.results['vulnerability_indicators']['potential_issues'].append(
                "xmlrpc_with_directory_listing"
            )
    
    def scan(self):
        """Thực hiện recon đầy đủ với schema mới"""
        start_time = time.time()
        
        # Bước 1: Detect base URL
        base_found = False
        for test_url in [self.https_url, self.url]:
            response = self._make_request(test_url)
            if response and response.status_code < 400:
                self.base_url = test_url
                base_found = True
                break
        
        if not base_found:
            self.results['scan_metadata']['status'] = 'failed_no_access'
            return self.results
        
        # Bước 2: Detect WordPress signatures và tính confidence
        self._detect_wp_signatures()
        self._calculate_wp_confidence()
        
        # Nếu không phải WordPress (confidence thấp), dừng sớm
        if not self.results['wp']['detected']:
            self.results['scan_metadata']['status'] = 'failed_not_wordpress'
            self.results['scan_metadata']['duration'] = time.time() - start_time
            return self.results
        
        # Bước 3: Detect server info
        response = self._make_request(self.base_url)
        if response:
            self._detect_server_info(response)
        
        # Bước 4: Detect WordPress version
        self._detect_wp_version_enhanced()
        
        # Bước 5: Detect theme
        self._detect_theme_enhanced()
        
        # Bước 6: Detect plugins
        self._detect_plugins_enhanced()
        
        # Bước 7: Check security endpoints
        self._check_security_endpoints()
        
        # Bước 8: Check CVE vulnerabilities
        self._check_cve_vulnerabilities()
        
        # Bước 9: Calculate risk score
        self._calculate_risk_score()
        
        # Bước 10: Assess vulnerabilities
        self._assess_vulnerabilities()
        
        # Cập nhật metadata
        self.results['scan_metadata']['duration'] = round(time.time() - start_time, 2)
        self.results['scan_metadata']['status'] = 'completed'
        
        return self.results
    
    def get_summary(self, show_all=False):
        """Trả về summary ngắn gọn để hiển thị"""
        if not self.results['wp']['detected']:
            return None
        
        summary = {
            'domain': self.domain,
            'wp_detected': self.results['wp']['detected'],
            'wp_confidence': self.results['wp']['confidence'],
            'wp_version': self.results['wp']['version'] or 'Unknown',
            'wp_core_version': self.results['wp']['version'] or 'Unknown',
            'theme': self.results['theme']['name'] or 'Unknown',
            'theme_version': self.results['theme']['version'] or 'Unknown',
            'server': self.results['server']['webserver'] or 'Unknown',
            'server_full': self.results['server']['server_full'] or 'Unknown',
            'php': self.results['server']['php'] or 'Unknown',
            'php_source': self.results['server']['php_source'] or 'Unknown',
            'xmlrpc': self.results['endpoints']['xmlrpc'],
            'xmlrpc_status': self.results['endpoints']['xmlrpc_status'],
            'rest_api': self.results['endpoints']['rest_api'],
            'rest_status': self.results['endpoints']['rest_api_status'],
            'rest_endpoints_count': len(self.results['endpoints']['rest_api_endpoints']),
            'wp_login': self.results['endpoints']['wp_login'],
            'wp_admin': self.results['endpoints']['wp_admin'],
            'upload_listing': self.results['endpoints']['upload_dir_listing'],
            'upload_status': self.results['endpoints']['upload_status'],
            'waf': self.results['security_indicators']['waf_detected'] or 'None',
            'waf_type': self.results['security_indicators']['waf_type'] or '',
            'directory_listing': self.results['security_indicators']['directory_listing'],
            'sensitive_files_count': len(self.results['security_indicators']['sensitive_files']),
            'user_enumeration': self.results['security_indicators']['user_enumeration'],
            'xmlrpc_enabled': self.results['security_indicators']['xmlrpc_enabled'],
            'outdated_wp': self.results['vulnerability_indicators']['outdated_wp'],
            'outdated_php': self.results['vulnerability_indicators']['outdated_php'],
            'plugins_count': len(self.results['plugins']),
            'popular_plugins': self.results['plugin_analysis']['popular_plugins_found'],
            'categories': dict(self.results['plugin_analysis']['categories']),
            'plugin_combinations': self.results['plugin_analysis']['plugin_combinations'],
            'cve_count': len(self.results['vulnerability_indicators']['cve_matches']),
            'cve_matches': self.results['vulnerability_indicators']['cve_matches'],
            'risk_score': self.results['vulnerability_indicators']['risk_score'],
            'potential_issues': self.results['vulnerability_indicators']['potential_issues'],
            'vulnerability_indicators': len(self.results['vulnerability_indicators']['potential_issues']),
            'security_issues': sum([
                1 if self.results['security_indicators']['directory_listing'] else 0,
                1 if self.results['security_indicators']['xmlrpc_enabled'] else 0,
                1 if self.results['security_indicators']['user_enumeration'] else 0,
                len(self.results['security_indicators']['sensitive_files'])
            ]),
            'detected_plugins': [],  # Thêm danh sách plugin
            'popular_plugin_details': []  # Thêm chi tiết plugin phổ biến
        }
        
        # Thêm danh sách plugin phát hiện được
        for plugin in self.results['plugins']:
            if plugin.get('detected'):
                plugin_info = {
                    'slug': plugin.get('slug'),
                    'version': plugin.get('version'),
                    'category': plugin.get('category'),
                    'popular': plugin.get('popular')
                }
                summary['detected_plugins'].append(plugin_info)
                
                if plugin.get('popular'):
                    summary['popular_plugin_details'].append({
                        'name': plugin.get('slug'),
                        'version': plugin.get('version'),
                        'category': plugin.get('category')
                    })
        
        # Thêm top plugin categories
        if summary['categories']:
            top_categories = sorted(summary['categories'].items(), key=lambda x: x[1], reverse=True)[:3]
            summary['top_categories'] = [f"{cat}:{count}" for cat, count in top_categories]
        
        return summary

def extract_domain(url):
    """Trích xuất domain từ URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace()
        if re.match(r'^[a-z0-9][a-z00-9.-]*\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn|info\.vn|biz\.vn)$', domain):
            return domain
        return None
    except:
        return None

def collect_wp_domains_parallel():
    """Thu thập domain WordPress với xử lý song song thời gian thực"""
    global stop_flag
    
    all_domains = set()
    
    # Load domain cũ nếu có
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            all_domains = {line.strip() for line in f if line.strip()}
        print(f"✓ Đã load {len(all_domains):,} domain cũ")
    
    print(f"\n{'='*60}")
    print(f"BẮT ĐẦU THU THẬP DOMAIN WORDPRESS")
    print(f"Dorks: {len(DORKS)} | Workers: {MAX_WORKERS_DISCOVERY}")
    print(f"{'='*60}\n")
    
    # Shared variables
    lock = threading.Lock()
    new_domains_queue = []
    processed_dorks = 0
    total_dorks = len(DORKS)
    enhanced_results = {}
    scan_count = 0
    vulnerable_domains = []
    
    # Tạo file để ghi domain yếu ngay khi phát hiện
    if os.path.exists(DOMAIN_VULN_FILE):
        os.remove(DOMAIN_VULN_FILE)
    
    # Progress tracking
    progress_data = {
        'total_targets': 0,
        'scanned_targets': 0,
        'vulnerable_targets': 0,
        'current_status': 'Initializing...'
    }
    
    def update_progress_display():
        """Cập nhật hiển thị progress bar"""
        with lock:
            if progress_data['total_targets'] == 0:
                return
            
            scanned = progress_data['scanned_targets']
            total = progress_data['total_targets']
            vuln = progress_data['vulnerable_targets']
            percentage = (scanned / total * 100) if total > 0 else 0
            
            bar_length = 40
            filled_length = int(bar_length * scanned // total)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            
            status_line = (f"\r\033[K[{bar}] {scanned:3d}/{total:3d} "
                          f"({percentage:5.1f}%) | Vuln: {vuln:2d} | "
                          f"{progress_data['current_status'][:40]}")
            
            sys.stdout.write(status_line)
            sys.stdout.flush()
    
    def collect_from_rapiddns(domain_keyword):
        """Lấy domain từ RapidDNS.io"""
        domains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{domain_keyword}?full=1"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                # Regex tìm domain .vn
                matches = re.findall(r'<td>([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))</td>', resp.text)
                for match in matches:  # ĐÃ SỬA: match là string, không phải tuple
                    domain = match.lower().replace("www.", "")  # Sửa: match thay vì match[0]
                    if re.match(r'^[a-z0-9][a-z0-9.-]*\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn)$', domain):
                        domains.add(domain)
        except Exception as e:
            print(f"  [!] RapidDNS error: {e}")
        return domains

    def collect_from_dnsdumpster(domain_keyword):
        """Lấy domain từ DNSDumpster.com"""
        domains = set()
        try:
            # DNSDumpster cần CSRF token, đơn giản hóa: chỉ lấy từ cached page
            url = f"https://dnsdumpster.com/"
            # Gửi POST request với domain (cần xử lý token thực tế)
            # Tạm thời skip phần phức tạp, chỉ demo cấu trúc
            pass
        except Exception as e:
            print(f"  [!] DNSDumpster error: {e}")
        return domains




    def process_dork(dork_idx, dork):
        nonlocal processed_dorks, new_domains_queue, progress_data
        
        if stop_flag:
            return dork_idx, 0, dork
        
        try:
            local_new_domains = []
            
            # PHẦN 1: XỬ LÝ DOMAIN KEYWORD (cho RapidDNS)
            # Nếu dork là domain đơn (ví dụ: example.vn, target.com.vn)
            if "site:" not in dork and re.match(r'^[a-z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn)$', dork.lower()):
                progress_data['current_status'] = f"RapidDNS: {dork[:30]}..."
                update_progress_display()
                
                # Lấy domain từ RapidDNS
                try:
                    rapiddns_url = f"https://rapiddns.io/subdomain/{dork}?full=1"
                    
                    resp = requests.get(
                        rapiddns_url, 
                        headers=HEADERS,  # Sử dụng HEADERS có sẵn
                        timeout=15, 
                        verify=False
                    )
                    
                    if resp.status_code == 200:
                        # Cách đơn giản hơn: dùng regex trực tiếp
                        domains_found = re.findall(
                            r'<td>([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))</td>',
                            resp.text
                        )
                        
                        for raw_domain in domains_found:
                            domain = raw_domain.lower().replace("www.", "")
                            # Kiểm tra domain hợp lệ bằng hàm extract_domain có sẵn
                            if extract_domain(f"http://{domain}"):
                                with lock:
                                    if domain not in all_domains:
                                        all_domains.add(domain)
                                        local_new_domains.append(domain)
                                        new_domains_queue.append(domain)
                                        progress_data['total_targets'] += 1
                        
                        if domains_found:
                            print(f"\r\033[K  [+] RapidDNS: {len(domains_found)} subdomains cho {dork}")
                    
                    # Delay để tránh bị block
                    time.sleep(random.uniform(1.0, 2.0))
                    
                except Exception as e:
                    print(f"\r\033[K  [!] RapidDNS error for {dork}: {str(e)[:50]}")
            
            # PHẦN 2: XỬ LÝ DUCKDUCKGO (giữ nguyên)
            progress_data['current_status'] = f"DuckDuckGo: {dork[:40]}..."
            update_progress_display()
            
            with DDGS() as ddgs:
                results = ddgs.text(
                    query=dork,
                    region="vn-vn",
                    safesearch="off",
                    max_results=NUM_RESULTS_PER_DORK
                )
                
                for result in results:
                    if stop_flag:
                        break
                        
                    url = result.get('href', '') or result.get('url', '')
                    if url:
                        domain = extract_domain(url)
                        if domain:
                            with lock:
                                if domain not in all_domains:
                                    all_domains.add(domain)
                                    local_new_domains.append(domain)
                                    new_domains_queue.append(domain)
                                    progress_data['total_targets'] += 1
            
            with lock:
                processed_dorks += 1
            
            update_progress_display()
            return dork_idx, len(local_new_domains), dork
        
            
        except Exception as e:
            with lock:
                processed_dorks += 1
            return dork_idx, 0, dork
    
    def perform_enhanced_recon(domain):
        """Thực hiện enhanced recon trên một domain"""
        nonlocal enhanced_results, scan_count, progress_data, vulnerable_domains
        
        if stop_flag:
            return
        
        try:
            progress_data['current_status'] = f"Scanning: {domain[:30]}..."
            update_progress_display()
            
            recon = WordPressReconEnhanced(domain)
            result = recon.scan()
            
            with lock:
                enhanced_results[domain] = result
                scan_count += 1
                progress_data['scanned_targets'] += 1
            
            if result['wp']['detected']:
                summary = recon.get_summary()
                if summary:
                    total_issues = summary['vulnerability_indicators'] + summary['security_issues']
                    risk_score = summary['risk_score']
                    
                    # CHỈ HIỂN THỊ NẾU CÓ VẤN ĐỀ BẢO MẬT HOẶC RISK CAO
                    if total_issues > 0 or risk_score >= 30 or summary['wp_confidence'] < 40:
                        with lock:
                            vulnerable_domains.append(domain)
                            progress_data['vulnerable_targets'] += 1
                        
                        # Hiển thị chi tiết domain có vuln
                        print(f"\n\033[K")  # Xóa dòng progress
                        
                        # Risk level color
                        if risk_score >= 70:
                            risk_color = "\033[91m"  # Red
                            risk_level = "CRITICAL"
                        elif risk_score >= 50:
                            risk_color = "\033[93m"  # Yellow
                            risk_level = "HIGH"
                        elif risk_score >= 30:
                            risk_color = "\033[33m"  # Orange
                            risk_level = "MEDIUM"
                        else:
                            risk_color = "\033[92m"  # Green
                            risk_level = "LOW"
                        
                        # ========================================================
                        # HIỂN THỊ ĐẦY ĐỦ THÔNG TIN
                        # ========================================================
                        
                        print(f"{risk_color}{'='*100}\033[0m")
                        print(f"{risk_color}📍 WORDPRESS SECURITY REPORT: {domain}\033[0m")
                        print(f"{risk_color}{'='*100}\033[0m")
                        
                        # 1. BASIC INFORMATION
                        print(f"\n\033[1m📋 BASIC INFORMATION\033[0m")
                        print(f"{'-'*90}")
                        print(f"  • WordPress Detected: {'✅ YES' if summary['wp_detected'] else '❌ NO'}")
                        print(f"  • Confidence Level: {summary['wp_confidence']}%")
                        print(f"  • WordPress Version: {summary['wp_version']}")
                        if summary.get('outdated_wp', False):
                            print(f"  • WordPress Status: ⚠️  OUTDATED")
                        
                        print(f"  • Theme: {summary['theme']} v{summary['theme_version']}")
                        
                        # 2. SERVER INFORMATION
                        print(f"\n\033[1m🖥️  SERVER INFORMATION\033[0m")
                        print(f"{'-'*90}")
                        print(f"  • Web Server: {summary['server']}")
                        if summary.get('server_full'):
                            print(f"  • Server Header: {summary['server_full']}")
                        
                        print(f"  • PHP Version: {summary['php']}")
                        if summary.get('outdated_php', False):
                            print(f"  • PHP Status: ⚠️  OUTDATED")
                        
                        # 3. PLUGIN ANALYSIS (CHI TIẾT)
                        print(f"\n\033[1m🔌 PLUGIN ANALYSIS\033[0m")
                        print(f"{'-'*90}")
                        print(f"  • Total Plugins Detected: {summary['plugins_count']}")
                        print(f"  • Popular Plugins Found: {summary['popular_plugins']}")
                        
                        # Hiển thị categories
                        if summary['categories']:
                            print(f"  • Plugin Categories: {', '.join([f'{k} ({v})' for k, v in summary['categories'].items()])}")
                        




                        # Hiển thị danh sách plugin PHỔ BIẾN đã phát hiện
                        if 'plugins' in result and result['plugins']:
                            # Lấy tất cả plugin đã phát hiện (không chỉ popular)
                            detected_plugins = [p for p in result['plugins'] if p.get('detected')]
                            
                            if detected_plugins:
                                print(f"\n  \033[1m📊 DETECTED PLUGINS:\033[0m")
                                
                                # Hiển thị popular plugins trước
                                popular_plugins = [p for p in detected_plugins if p.get('popular')]
                                if popular_plugins:
                                    print(f"  \033[1m🔥 POPULAR PLUGINS:\033[0m")
                                    for i, plugin in enumerate(popular_plugins[:10], 1):
                                        name = plugin.get('slug', 'Unknown')[:30]
                                        version = plugin.get('version', 'Unknown')
                                        category = plugin.get('category', 'Unknown')
                                        version_display = f"v{version}" if version else "No version"
                                        print(f"    {i:2d}. {name:<30} {version_display:<15} [{category}]")
                                
                                # Hiển thị other plugins
                                other_plugins = [p for p in detected_plugins if not p.get('popular')]
                                if other_plugins:
                                    print(f"  \033[1m📦 OTHER PLUGINS:\033[0m")
                                    for i, plugin in enumerate(other_plugins[:5], 1):
                                        name = plugin.get('slug', 'Unknown')[:30]
                                        version = plugin.get('version', 'Unknown')
                                        version_display = f"v{version}" if version else "No version"
                                        print(f"    {i:2d}. {name:<30} {version_display}")
                        







                        # 4. ENDPOINTS & SECURITY
                        print(f"\n\033[1m🔐 SECURITY ENDPOINTS\033[0m")
                        print(f"{'-'*90}")
                        
                        # XML-RPC
                        xmlrpc_status = "⚠️  ENABLED" if summary.get('xmlrpc_enabled', False) else "✅ DISABLED"
                        print(f"  • XML-RPC: {xmlrpc_status} (Status: {summary['xmlrpc_status']})")
                        
                        # REST API
                        rest_status = "✅ ENABLED" if summary['rest_api'] else "❌ DISABLED"
                        print(f"  • REST API: {rest_status} (Status: {summary['rest_status']})")
                        
                        # Upload Directory
                        upload_status = "⚠️  ENABLED" if summary['upload_listing'] else "✅ DISABLED"
                        print(f"  • Upload Dir Listing: {upload_status} (Status: {summary['upload_status']})")
                        
                        # User Enumeration
                        user_enum = "⚠️  POSSIBLE" if summary.get('user_enumeration', False) else "✅ NOT POSSIBLE"
                        print(f"  • User Enumeration: {user_enum}")
                        
                        # WAF Detection
                        waf_info = f"{summary['waf']} ({summary['waf_type']})" if summary['waf'] != 'None' else "Not Detected"
                        print(f"  • WAF Detected: {waf_info}")
                        
                        # Sensitive Files
                        sensitive_files = result['security_indicators'].get('sensitive_files', [])
                        print(f"  • Sensitive Files Found: {len(sensitive_files)}")
                        if sensitive_files:
                            print(f"  \033[1m📁 SENSITIVE FILES:\033[0m")
                            for file in sensitive_files[:5]:
                                print(f"    - {file}")
                        
                        # 5. VULNERABILITY ASSESSMENT
                        print(f"\n\033[1m⚠️  VULNERABILITY ASSESSMENT\033[0m")
                        print(f"{'-'*90}")
                        
                        # Risk Score với màu
                        print(f"  • Risk Score: {risk_color}{risk_score}/100 [{risk_level}]\033[0m")
                        
                        # CVE Matches
                        print(f"  • CVE Matches Found: {summary['cve_count']}")
                        cve_matches = result['vulnerability_indicators'].get('cve_matches', [])
                        if cve_matches:
                            print(f"  \033[1m🔴 CVE VULNERABILITIES:\033[0m")
                            for i, cve in enumerate(cve_matches[:5], 1):
                                cve_id = cve.get('cve', 'CVE-UNKNOWN')
                                component = cve.get('component', 'Unknown')
                                version = cve.get('version', 'Unknown')
                                cve_type = cve.get('type', 'vulnerability').upper()
                                print(f"    {i}. {cve_id} - {component} v{version} ({cve_type})")
                        
                        # Security Issues
                        print(f"  • Security Issues: {summary['security_issues']}")
                        print(f"  • Vulnerability Indicators: {summary['vulnerability_indicators']}")
                        
                        # Potential Issues
                        potential_issues = result['vulnerability_indicators'].get('potential_issues', [])
                        if potential_issues:
                            print(f"  \033[1m🔍 POTENTIAL ISSUES:\033[0m")
                            for issue in potential_issues[:5]:
                                print(f"    - {issue}")
                        
                        # 6. PLUGIN COMBINATIONS
                        plugin_combos = result['plugin_analysis'].get('plugin_combinations', [])
                        if plugin_combos:
                            print(f"\n\033[1m🎯 PLUGIN COMBINATIONS DETECTED\033[0m")
                            print(f"{'-'*90}")
                            for combo in plugin_combos:
                                print(f"  • {combo}")
                        
                        # 7. SCAN METADATA
                        print(f"\n\033[1m📊 SCAN METADATA\033[0m")
                        print(f"{'-'*90}")
                        print(f"  • Scan Duration: {result['scan_metadata']['duration']} seconds")
                        print(f"  • Requests Made: {result['scan_metadata']['requests_made']}")
                        print(f"  • Scan Status: {result['scan_metadata']['status'].upper()}")
                        
                        print(f"\n{risk_color}{'='*100}\033[0m\n")
                        
                        # ========================================================
                        # GHI VÀO FILE VULN
                        # ========================================================
                        with lock:
                            with open(DOMAIN_VULN_FILE, "a", encoding="utf-8") as f:
                                # Ghi thông tin chi tiết hơn
                                plugin_list = []
                                if 'plugins' in result:
                                    plugin_list = [p.get('slug', '') for p in result['plugins'] if p.get('detected')]
                                
                                cve_list = []
                                if cve_matches:
                                    cve_list = [cve.get('cve', '') for cve in cve_matches]
                                
                                f.write(f"{domain}|"
                                       f"Risk:{risk_score}|"
                                       f"WP:{summary['wp_version']}|"
                                       f"PHP:{summary['php']}|"
                                       f"Server:{summary['server']}|"
                                       f"WAF:{summary['waf']}|"
                                       f"XMLRPC:{summary['xmlrpc']}|"
                                       f"REST:{summary['rest_api']}|"
                                       f"Upload:{summary['upload_listing']}|"
                                       f"CVE:{','.join(cve_list[:3])}|"
                                       f"Plugins:{summary['plugins_count']}|"
                                       f"Popular:{summary['popular_plugins']}|"
                                       f"Issues:{total_issues}\n")
                    else:
                        # Hiển thị dòng status cho domain bình thường (CLEAN)
                        print(f"\r\033[K\033[92m✓\033[0m {domain[:40]:<40} | "
                              f"WP:{summary['wp_version'][:8]:<8} | "
                              f"Plugins:{summary['plugins_count']:<3} | "
                              f"Risk:{summary['risk_score']:<3} | "
                              f"✅ Clean")
            else:
                # Domain không phải WordPress
                print(f"\r\033[K\033[90m✗\033[0m {domain[:40]:<40} | "
                      f"Not WordPress | "
                      f"Confidence: {result['wp']['confidence']}%")
        
        except Exception as e:
            # Hiển thị lỗi
            error_msg = str(e)
            if "Connection" in error_msg or "timeout" in error_msg.lower():
                print(f"\r\033[K\033[93m⚠\033[0m {domain[:40]:<40} | Connection Error")
            else:
                print(f"\r\033[K\033[91m✗\033[0m {domain[:40]:<40} | Error: {error_msg[:30]}")
            
            with lock:
                progress_data['scanned_targets'] += 1
        
        finally:
            update_progress_display()


        # ============================================================
    # THÊM PHẦN NÀY ĐỂ THỰC SỰ CHẠY CÁC HÀM CON
    # ============================================================
    
    print(f"\n{'='*60}")
    print("THỰC HIỆN THU THẬP DOMAIN...")
    print(f"{'='*60}")
    
    # 1. Chạy process_dork cho mỗi dork trong DORKS
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_DISCOVERY) as executor:
            futures = []
            for dork_idx, dork in enumerate(DORKS):
                future = executor.submit(process_dork, dork_idx, dork)
                futures.append(future)
            
            # Chờ tất cả dork hoàn thành
            for future in tqdm(as_completed(futures), total=len(futures), desc="Processing dorks"):
                dork_idx, new_count, dork = future.result()
                if new_count > 0:
                    print(f"  ✓ Dork {dork_idx+1:2d}: {dork[:50]:<50} → {new_count} domain")
    
    except Exception as e:
        print(f"  [!] Lỗi trong quá trình thu thập: {e}")
    
    # 2. Lưu domain mới vào file
    if new_domains_queue:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for domain in new_domains_queue:
                f.write(f"{domain}\n")
        print(f"\n✓ Đã lưu {len(new_domains_queue)} domain mới vào {OUTPUT_FILE}")
    
    # 3. Chạy enhanced recon trên các domain
    print(f"\n{'='*60}")
    print(f"THỰC HIỆN ENHANCED RECON SCAN...")
    print(f"Tổng domain: {len(all_domains)}")
    print(f"{'='*60}")
    
    if all_domains:
        # Giới hạn số domain để scan (ví dụ 20 domain đầu tiên)
        domains_to_scan = list(all_domains)[:20]
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as executor:
            futures = {}
            for domain in domains_to_scan:
                future = executor.submit(perform_enhanced_recon, domain)
                futures[future] = domain
            
            # Chờ tất cả scan hoàn thành
            for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning domains"):
                future.result()  # Chờ kết quả
        
        # 4. Lưu kết quả enhanced recon
        if enhanced_results:
            with open(ENHANCED_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "total_domains": len(enhanced_results),
                    "results": enhanced_results
                }, f, indent=2, ensure_ascii=False)
            print(f"\n✓ Đã lưu {len(enhanced_results)} kết quả scan vào {ENHANCED_OUTPUT_FILE}")
    
    # ============================================================
    # KẾT THÚC PHẦN THÊM
    # ============================================================
    
    return all_domains, scan_count, len(vulnerable_domains)




def analyze_results():
    """Phân tích kết quả"""
    if not os.path.exists(ENHANCED_OUTPUT_FILE):
        print("⚠️  Không có file kết quả enhanced để phân tích")
        return None
    
    try:
        with open(ENHANCED_OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        results = data.get("results", {})
        if not results:
            print("⚠️  Không có kết quả nào để phân tích")
            return None
        
        wp_detected = 0
        vulnerable_count = 0
        plugin_stats = defaultdict(int)
        risk_scores = []
        
        for domain, result in results.items():
            if result['wp']['detected']:
                wp_detected += 1
                
                # Đếm domain có vấn đề
                issues = len(result['vulnerability_indicators']['potential_issues'])
                security_issues = sum([
                    1 if result['security_indicators']['directory_listing'] else 0,
                    1 if result['security_indicators']['xmlrpc_enabled'] else 0,
                    1 if result['security_indicators']['user_enumeration'] else 0,
                    len(result['security_indicators']['sensitive_files'])
                ])
                
                risk_score = result['vulnerability_indicators']['risk_score']
                risk_scores.append(risk_score)
                
                if issues > 0 or security_issues > 0 or risk_score >= 30:
                    vulnerable_count += 1
                
                # Thống kê plugin
                for plugin in result['plugins']:
                    if plugin.get('popular'):
                        plugin_name = plugin.get('slug', 'Unknown')
                        plugin_stats[plugin_name] += 1
        
        # Tính risk trung bình
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        print(f"\n📊 PHÂN TÍCH KẾT QUẢ:")
        print(f"  • Tổng domain scan: {len(results)}")
        print(f"  • WordPress detected: {wp_detected} ({wp_detected/len(results)*100:.1f}%)")
        print(f"  • Domain có vấn đề: {vulnerable_count} ({vulnerable_count/wp_detected*100:.1f}% of WP)")
        print(f"  • Risk score trung bình: {avg_risk:.1f}/100")
        
        # Phân phối risk
        if risk_scores:
            high_risk = len([r for r in risk_scores if r >= 70])
            med_risk = len([r for r in risk_scores if 50 <= r < 70])
            low_risk = len([r for r in risk_scores if r < 50])
            
            print(f"  • Risk phân phối: CRITICAL({high_risk}) HIGH({med_risk}) LOW({low_risk})")
        
        if plugin_stats:
            print(f"\n🔥 TOP 5 PLUGIN PHỔ BIẾN:")
            for i, (plugin_name, count) in enumerate(sorted(plugin_stats.items(), 
                                                          key=lambda x: x[1], reverse=True)[:5], 1):
                percentage = (count / wp_detected) * 100 if wp_detected > 0 else 0
                print(f"  {i}. {plugin_name:<25} {count:3d} sites ({percentage:.1f}%)")
        
        return {
            "total_scanned": len(results),
            "wp_detected": wp_detected,
            "vulnerable": vulnerable_count,
            "avg_risk": avg_risk
        }
        
    except Exception as e:
        print(f"⚠️  Lỗi phân tích: {e}")
        return None

def main():
    """Hàm chính"""
    global stop_flag
    
    print("=" * 80)
    print("WORDPRESS DOMAIN COLLECTOR & ENHANCED PLUGIN ANALYSIS")
    print("VERSION 2.2 - WITH CVE MAPPING & RISK SCORING")
    print("=" * 80)
    
    try:
        # Bước 1: Thu thập domain và recon song song
        domains, scanned_count, vuln_count = collect_wp_domains_parallel()
        
        if not domains:
            print("Không có domain nào để scan!")
            return
        
        print(f"\n{'='*60}")
        print("TỔNG KẾT QUẢ")
        print(f"{'='*60}")
        
        # Bước 2: Phân tích kết quả
        stats = analyze_results()
        
        if stats:
            print(f"\n✅ KẾT QUẢ CUỐI CÙNG:")
            print(f"  • Tổng domain thu thập: {len(domains)}")
            print(f"  • Đã scan: {stats['total_scanned']}")
            print(f"  • WordPress phát hiện: {stats['wp_detected']}")
            print(f"  • Domain có vấn đề: {stats['vulnerable']}")
            print(f"  • Risk score trung bình: {stats['avg_risk']:.1f}")
        
        # Hiển thị domain có vấn đề
        if os.path.exists(DOMAIN_VULN_FILE):
            with open(DOMAIN_VULN_FILE, "r", encoding="utf-8") as f:
                vuln_lines = f.readlines()
            
            if vuln_lines:
                print(f"\n⚠️  DOMAIN CÓ VẤN ĐỀ BẢO MẬT ({len(vuln_lines)}):")
                for i, line in enumerate(vuln_lines[:10], 1):
                    parts = line.strip().split('|')
                    if len(parts) >= 2:
                        domain = parts[0]
                        risk = parts[1] if len(parts) > 1 else ""
                        print(f"  {i:2d}. {domain:<30} {risk}")
                
                if len(vuln_lines) > 10:
                    print(f"  ... và {len(vuln_lines) - 10} domain khác")
        
        print(f"\n📁 KẾT QUẢ LƯU TẠI:")
        print(f"  • Danh sách domain: {OUTPUT_FILE}")
        print(f"  • Domain có vấn đề: {DOMAIN_VULN_FILE}")
        print(f"  • Kết quả scan đầy đủ: {ENHANCED_OUTPUT_FILE}")
        print(f"{'='*60}\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Đã dừng theo yêu cầu người dùng")
        stop_flag = True
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")

if __name__ == "__main__":
    main()