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
        
        # PHP version
        php_header = headers.get('X-Powered-By', '')
        if 'PHP' in php_header:
            match = re.search(r'PHP/([\d.]+)', php_header)
            if match:
                self.results['server']['php'] = match.group(1)
                self.results['server']['php_source'] = 'header'
        else:
            # Thử tìm trong HTML
            html = response.text
            php_match = re.search(r'PHP/([\d.]+)', html)
            if php_match:
                self.results['server']['php'] = php_match.group(1)
                self.results['server']['php_source'] = 'html'
    
    def _detect_wp_version_enhanced(self):
        """Phát hiện WordPress version với nhiều phương pháp"""
        version_sources = []
        detected_version = ""
        
        # 1. Từ meta generator (độ chính xác cao nhất)
        response = self._make_request(self.base_url)
        if response:
            html = response.text
            meta_match = re.search(r'content=["\']WordPress ([\d.]+)["\']', html)
            if meta_match:
                detected_version = meta_match.group(1)
                version_sources.append(('meta', detected_version))
                self.results['wp']['version'] = detected_version
                self.results['wp']['version_source'] = 'meta'
        
        # 2. Từ CSS version (style.min.css)
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
                            self.results['wp']['version'] = detected_version
                            self.results['wp']['version_source'] = 'css_url'
                            break
        
        # 3. Từ RSS feed
        if not detected_version:
            rss_resp = self._make_request(f"{self.base_url}/feed/")
            if rss_resp and rss_resp.status_code == 200:
                match = re.search(r'generator>https://wordpress.org/\?v=([\d.]+)<', rss_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('rss', detected_version))
                    self.results['wp']['version'] = detected_version
                    self.results['wp']['version_source'] = 'rss'
        
        # 4. Từ readme.html
        if not detected_version:
            readme_resp = self._make_request(f"{self.base_url}/readme.html")
            if readme_resp and readme_resp.status_code == 200:
                match = re.search(r'Version ([\d.]+)', readme_resp.text)
                if match:
                    detected_version = match.group(1)
                    version_sources.append(('readme', detected_version))
                    self.results['wp']['version'] = detected_version
                    self.results['wp']['version_source'] = 'readme'
        
        # Lưu tất cả sources
        if version_sources:
            self.results['wp']['version_sources'] = [
                f"{src[0]}:{src[1]}" for src in version_sources
            ]
            
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
        # Import tại đây để tránh lỗi nếu không có module
        try:
            from plugin_version import detect_plugin_version
        except ImportError:
            # Fallback nếu không có module plugin_version
            def detect_plugin_version(base_url, plugin_slug):
                return {"detected": False, "version": None, "source": None, "confidence": "low"}
        
        plugins_found = []
        popular_count = 0
        categories = defaultdict(int)

        scanned_slugs = set()

        # 1️⃣ Detect plugin từ HTML (passive)
        response = self._make_request(self.base_url)
        if response:
            html = response.text
            html_slugs = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
            scanned_slugs.update(list(html_slugs)[:20])  # giới hạn

        # 2️⃣ Chủ động probe plugin phổ biến (active)
        for slug in list(POPULAR_PLUGINS.keys())[:15]:
            scanned_slugs.add(slug)

        # 3️⃣ Scan từng plugin
        for plugin_slug in scanned_slugs:
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

            # 4️⃣ Lấy version bằng module chuẩn
            try:
                version_info = detect_plugin_version(self.base_url, plugin_slug)
            except Exception:
                version_info = {"detected": False}

            if not version_info["detected"]:
                continue  # plugin không tồn tại thật

            plugin_data["detected"] = True
            plugin_data["version"] = version_info.get("version")
            plugin_data["version_source"] = version_info.get("source")
            plugin_data["confidence"] = version_info.get("confidence", "low")

            plugins_found.append(plugin_data)

            # Thống kê
            if plugin_data["popular"]:
                popular_count += 1
                categories[plugin_data["category"]] += 1

        # 5️⃣ Update results
        self.results["plugins"] = plugins_found
        self.results["plugin_analysis"]["popular_plugins_found"] = popular_count
        self.results["plugin_analysis"]["categories"] = dict(categories)

        # 6️⃣ Plugin combination analysis
        popular_slugs = [p["slug"] for p in plugins_found if p["popular"]]
        if len(popular_slugs) >= 2:
            self.results["plugin_analysis"]["plugin_combinations"] = \
                self._find_common_combinations(popular_slugs)
    
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
    
    def get_summary(self):
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
            'xmlrpc': self.results['endpoints']['xmlrpc'],
            'xmlrpc_status': self.results['endpoints']['xmlrpc_status'],
            'rest_api': self.results['endpoints']['rest_api'],
            'rest_status': self.results['endpoints']['rest_api_status'],
            'upload_listing': self.results['endpoints']['upload_dir_listing'],
            'upload_status': self.results['endpoints']['upload_status'],
            'waf': self.results['security_indicators']['waf_detected'] or 'None',
            'waf_type': self.results['security_indicators']['waf_type'] or '',
            'plugins_count': len(self.results['plugins']),
            'popular_plugins': self.results['plugin_analysis']['popular_plugins_found'],
            'categories': dict(self.results['plugin_analysis']['categories']),
            'cve_count': len(self.results['vulnerability_indicators']['cve_matches']),
            'risk_score': self.results['vulnerability_indicators']['risk_score'],
            'vulnerability_indicators': len(self.results['vulnerability_indicators']['potential_issues']),
            'security_issues': sum([
                1 if self.results['security_indicators']['directory_listing'] else 0,
                1 if self.results['security_indicators']['xmlrpc_enabled'] else 0,
                1 if self.results['security_indicators']['user_enumeration'] else 0,
                len(self.results['security_indicators']['sensitive_files'])
            ])
        }
        
        # Thêm top plugin categories
        if summary['categories']:
            top_categories = sorted(summary['categories'].items(), key=lambda x: x[1], reverse=True)[:3]
            summary['top_categories'] = [f"{cat}:{count}" for cat, count in top_categories]
        
        return summary

def extract_domain(url):
    """Trích xuất domain từ URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
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
    
    def process_dork(dork_idx, dork):
        nonlocal processed_dorks, new_domains_queue, progress_data
        
        if stop_flag:
            return dork_idx, 0, dork
        
        try:
            progress_data['current_status'] = f"Dork: {dork[:40]}..."
            update_progress_display()
            
            with DDGS() as ddgs:
                results = ddgs.text(
                    query=dork,
                    region="vn-vn",
                    safesearch="off",
                    max_results=NUM_RESULTS_PER_DORK
                )
                
                local_new_domains = []
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
                        
                        # Hiển thị thông tin chi tiết
                        print(f"{risk_color}{'='*80}\033[0m")
                        print(f"{risk_color}⚠️  VULNERABLE DOMAIN DETECTED: {domain}\033[0m")
                        print(f"{risk_color}┌─{'─'*78}┐\033[0m")
                        
                        # Basic Info
                        print(f"{risk_color}│\033[0m \033[1mBasic Information:\033[0m")
                        print(f"{risk_color}│\033[0m   • WP Version: {summary['wp_version']} | Confidence: {summary['wp_confidence']}%")
                        print(f"{risk_color}│\033[0m   • Theme: {summary['theme']} v{summary['theme_version']}")
                        print(f"{risk_color}│\033[0m   • Server: {summary['server']} | PHP: {summary['php']}")
                        
                        # Security Status
                        print(f"{risk_color}│\033[0m \033[1mSecurity Status:\033[0m")
                        print(f"{risk_color}│\033[0m   • XML-RPC: {'✅ Enabled' if summary['xmlrpc'] else '❌ Disabled'} "
                              f"(Status: {summary['xmlrpc_status']})")
                        print(f"{risk_color}│\033[0m   • REST API: {'✅ Enabled' if summary['rest_api'] else '❌ Disabled'} "
                              f"(Status: {summary['rest_status']})")
                        print(f"{risk_color}│\033[0m   • Upload Listing: {'⚠️  Enabled' if summary['upload_listing'] else '✅ Disabled'} "
                              f"(Status: {summary['upload_status']})")
                        print(f"{risk_color}│\033[0m   • WAF: {summary['waf']} ({summary['waf_type']})")
                        
                        # Vulnerabilities
                        print(f"{risk_color}│\033[0m \033[1mVulnerability Assessment:\033[0m")
                        print(f"{risk_color}│\033[0m   • Risk Score: {risk_score}/100 \033[1m[{risk_level}]\033[0m")
                        print(f"{risk_color}│\033[0m   • CVE Matches: {summary['cve_count']}")
                        print(f"{risk_color}│\033[0m   • Security Issues: {summary['security_issues']}")
                        print(f"{risk_color}│\033[0m   • Total Indicators: {total_issues}")
                        
                        # Plugins
                        if summary['plugins_count'] > 0:
                            print(f"{risk_color}│\033[0m \033[1mPlugin Analysis:\033[0m")
                            print(f"{riskColor}│\033[0m   • Total Plugins: {summary['plugins_count']}")
                            print(f"{risk_color}│\033[0m   • Popular Plugins: {summary['popular_plugins']}")
                            if summary.get('top_categories'):
                                print(f"{risk_color}│\033[0m   • Top Categories: {', '.join(summary['top_categories'])}")
                        
                        print(f"{risk_color}└─{'─'*78}┘\033[0m")
                        print(f"{risk_color}{'='*80}\033[0m\n")
                        
                        # Ghi domain yếu vào file
                        with lock:
                            with open(DOMAIN_VULN_FILE, "a", encoding="utf-8") as f:
                                f.write(f"{domain}|Risk:{risk_score}|"
                                       f"WP:{summary['wp_version']}|PHP:{summary['php']}|"
                                       f"Server:{summary['server']}|WAF:{summary['waf']}|"
                                       f"XMLRPC:{summary['xmlrpc']}|REST:{summary['rest_api']}|"
                                       f"Upload:{summary['upload_listing']}|"
                                       f"CVE:{summary['cve_count']}|Plugins:{summary['plugins_count']}\n")
                    else:
                        # Hiển thị dòng status cho domain bình thường
                        print(f"\r\033[K\033[92m✓\033[0m {domain[:40]:<40} | "
                              f"WP:{summary['wp_version'][:8]:<8} | "
                              f"Risk:{summary['risk_score']:<3} | "
                              f"✅ Clean")
        
        except Exception as e:
            # Hiển thị lỗi
            print(f"\r\033[K\033[91m✗\033[0m {domain[:40]:<40} | Error: {str(e)[:30]}")
            with lock:
                progress_data['scanned_targets'] += 1
        
        finally:
            update_progress_display()
    
    print("\nInitializing scan...\n")
    
    # Xử lý dorks song song
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_DISCOVERY) as executor:
        futures = {executor.submit(process_dork, idx, dork): (idx, dork) 
                  for idx, dork in enumerate(DORKS, 1)}
        
        for future in as_completed(futures):
            if stop_flag:
                break
                
            dork_idx, domains_found, dork = future.result()
            
            # Thực hiện scan cho domain mới tìm thấy
            if domains_found > 0 and not stop_flag:
                # Lấy domain mới từ queue và scan
                with lock:
                    domains_to_scan = []
                    while new_domains_queue and len(domains_to_scan) < 10:  # Giới hạn mỗi lần
                        domains_to_scan.append(new_domains_queue.pop(0))
                
                # Scan các domain này
                if domains_to_scan:
                    with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as recon_executor:
                        recon_futures = [recon_executor.submit(perform_enhanced_recon, domain) 
                                        for domain in domains_to_scan]
                        
                        # Không cần chờ tất cả, để chạy nền
                        for recon_future in recon_futures:
                            try:
                                recon_future.result(timeout=30)
                            except:
                                pass
            
            # Delay ngẫu nhiên
            if not stop_flag and dork_idx < len(DORKS):
                time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
    
    # Scan các domain còn lại trong queue
    if not stop_flag and new_domains_queue:
        progress_data['current_status'] = f"Scanning remaining {len(new_domains_queue)} domains..."
        update_progress_display()
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as recon_executor:
            recon_futures = []
            for domain in new_domains_queue:
                if stop_flag:
                    break
                recon_futures.append(recon_executor.submit(perform_enhanced_recon, domain))
            
            # Chờ tất cả hoàn thành
            for recon_future in recon_futures:
                try:
                    recon_future.result(timeout=60)
                except:
                    pass
    
    print("\n\033[K")  # Xóa dòng progress cuối cùng
    
    # Lưu tất cả domain
    if not stop_flag:
        sorted_domains = sorted(all_domains)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for domain in sorted_domains:
                f.write(domain + "\n")
        
        # Lưu kết quả enhanced
        if enhanced_results:
            enhanced_data = {
                "metadata": {
                    "total_domains": len(all_domains),
                    "scanned_domains": scan_count,
                    "vulnerable_domains": len(vulnerable_domains),
                    "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "schema_version": "2.2"
                },
                "results": enhanced_results
            }
            
            with open(ENHANCED_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n✓ Đã lưu {scan_count} kết quả enhanced vào {ENHANCED_OUTPUT_FILE}")
    
    return sorted_domains, scan_count, len(vulnerable_domains)

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