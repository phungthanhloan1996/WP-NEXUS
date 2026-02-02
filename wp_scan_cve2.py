#!/usr/bin/env python3
"""
WordPress Ultimate Security Scanner - Unified Edition (2026)
Combines best features from all versions:
1. Advanced WordPress/Plugin/Theme/PHP detection (from wp_scan_cve.py)
2. Real-time CVE checking via API (from wp_scan_cve1.py)
3. Pentester mindset with write primitive detection (from wp_scan_cve2.py)
4. Behavioral observation and correlation analysis
5. Comprehensive reporting and scoring
"""

import requests
import sys
import re
import json
import time
import hashlib
import sqlite3
import concurrent.futures
from urllib.parse import urljoin, quote, urlparse, parse_qs
from datetime import datetime, timedelta
from colorama import init, Fore, Style, Back
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict, Counter
import os
import random
import string

init(autoreset=True)

# ===============================
# CONFIGURATION
# ===============================

class Config:
    """Centralized configuration"""
    
    # API Tokens
    WPSCAN_API_TOKEN = "a9lVr6KNCHaGAlJ5sUb7N8f3yrB6Yfo8POuOe7WERQI"
    WPSCAN_API_URL = "https://wpscan.com/api/v3"
    NVD_API_KEY = "ce07fc36-0413-4fa8-8433-d6316e9adf8c"  # ✅ THÊM NÀY
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Timeouts
    REQUEST_TIMEOUT = 8
    API_TIMEOUT = 12
    DEEP_SCAN_TIMEOUT = 15
    
    # Rate limiting
    REQUESTS_PER_SECOND = 1
    API_CALLS_PER_MINUTE = 20
    
    # Cache
    CACHE_DURATION_HOURS = 24
    DB_PATH = "wp_ultimate_db.sqlite"
    
    # Output
    OUTPUT_DIR = "wp_ultimate_results"
    
    # Detection patterns
    PLUGIN_PATTERNS = [
        'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo', 'akismet',
        'wpforms-lite', 'all-in-one-seo-pack', 'jetpack', 'wordfence',
        'litespeed-cache', 'rank-math', 'wp-rocket', 'classic-editor',
        'wp-mail-smtp', 'updraftplus', 'monsterinsights-lite', 'smush',
        'autoptimize', 'redirection', 'wp-optimize', 'complianz-gdpr',
        'mailchimp-for-wp', 'ninja-forms', 'tablepress', 'better-search-replace',
        'duplicate-post', 'google-site-kit', 'really-simple-ssl'
    ]
    
    # Security headers
    SECURITY_HEADERS = {
        'strict-transport-security': {'weight': 25, 'name': 'HSTS'},
        'content-security-policy': {'weight': 25, 'name': 'CSP'},
        'x-frame-options': {'weight': 20, 'name': 'X-Frame-Options'},
        'x-content-type-options': {'weight': 15, 'name': 'X-Content-Type-Options'},
        'x-xss-protection': {'weight': 10, 'name': 'X-XSS-Protection'},
        'referrer-policy': {'weight': 5, 'name': 'Referrer-Policy'},
    }
    
    # Write primitive patterns
    UPLOAD_PATTERNS = [
        r'(upload|file|image|media|attachment)\.php',
        r'async-upload\.php',
        r'media-upload\.php',
        r'admin-ajax\.php.*action=(upload|save_file|add_media)',
    ]
    
    # Backup files patterns
    BACKUP_PATTERNS = [
        r'backup.*\.(sql|zip|tar\.gz|7z|rar|bak|dump)',
        r'db.*backup.*\.(sql|dump|gz)',
        r'.*_backup_\d{8,14}\.(sql|zip|tar)',
    ]

# ===============================
# DATABASE MANAGER
# ===============================

class DatabaseManager:
    """Unified database manager"""
    
    def __init__(self, api_token=None, nvd_key=None):
        self.api_token = api_token or Config.WPSCAN_API_TOKEN
        self.nvd_key = nvd_key or Config.NVD_API_KEY
        self.db_path = Config.DB_PATH
        self.init_database()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WP-Ultimate-Scanner/1.0',
            'Authorization': f'Token token={self.api_token}' if self.api_token else ''
        })
    
    def init_database(self):
        """Initialize all database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # WordPress Core CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wp_core_cves (
                version TEXT PRIMARY KEY,
                cves_json TEXT,
                last_updated TIMESTAMP,
                source TEXT
            )
        ''')
        
        # Plugin CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS plugin_cves (
                plugin_slug TEXT PRIMARY KEY,
                cves_json TEXT,
                last_updated TIMESTAMP,
                source TEXT
            )
        ''')
        
        # Theme CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS theme_cves (
                theme_slug TEXT PRIMARY KEY,
                cves_json TEXT,
                last_updated TIMESTAMP,
                source TEXT
            )
        ''')
        
        # Scan History
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                scan_date TIMESTAMP,
                wp_version TEXT,
                php_version TEXT,
                plugins_found INTEGER,
                themes_found INTEGER,
                vulnerabilities_found INTEGER,
                risk_score INTEGER
            )
        ''')
        
        # Write Primitives
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS write_primitives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                endpoint TEXT,
                primitive_type TEXT,
                risk_score INTEGER,
                discovered_at TIMESTAMP,
                UNIQUE(target_url, endpoint)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_wordpress_cves(self, version: str) -> List[Dict]:
        """Get WordPress core CVEs"""
        if not version:
            return []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM wp_core_cves WHERE version = ?",
            (version,)
        )
        result = cursor.fetchone()
        
        # Check cache validity
        if result and self._is_cache_valid(result[1]):
            conn.close()
            return json.loads(result[0])
        
        # Fetch from API
        if not self.api_token:
            conn.close()
            return []
        
        try:
            url = f"{Config.WPSCAN_API_URL}/wordpresses/{version}"
            response = self.session.get(url, timeout=Config.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                cves = data.get(version, {}).get('vulnerabilities', [])
                
                cursor.execute(
                    "INSERT OR REPLACE INTO wp_core_cves VALUES (?, ?, ?, ?)",
                    (version, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
        except Exception as e:
            print(f"{Fore.RED}✗ Error fetching WordPress CVEs: {str(e)}")
        
        conn.close()
        return []
    
    def get_plugin_cves(self, plugin_slug: str) -> List[Dict]:
        """Get plugin CVEs"""
        if not plugin_slug:
            return []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM plugin_cves WHERE plugin_slug = ?",
            (plugin_slug,)
        )
        result = cursor.fetchone()
        
        if result and self._is_cache_valid(result[1]):
            conn.close()
            return json.loads(result[0])
        
        if not self.api_token:
            conn.close()
            return []
        
        try:
            url = f"{Config.WPSCAN_API_URL}/plugins/{plugin_slug}"
            response = self.session.get(url, timeout=Config.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                cves = data.get(plugin_slug, {}).get('vulnerabilities', [])
                
                cursor.execute(
                    "INSERT OR REPLACE INTO plugin_cves VALUES (?, ?, ?, ?)",
                    (plugin_slug, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
        except:
            pass
        
        conn.close()
        return []
    
    def get_theme_cves(self, theme_slug: str) -> List[Dict]:
        """Get theme CVEs"""
        if not theme_slug:
            return []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM theme_cves WHERE theme_slug = ?",
            (theme_slug,)
        )
        result = cursor.fetchone()
        
        if result and self._is_cache_valid(result[1]):
            conn.close()
            return json.loads(result[0])
        
        if not self.api_token:
            conn.close()
            return []
        
        try:
            url = f"{Config.WPSCAN_API_URL}/themes/{theme_slug}"
            response = self.session.get(url, timeout=Config.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                cves = data.get(theme_slug, {}).get('vulnerabilities', [])
                
                cursor.execute(
                    "INSERT OR REPLACE INTO theme_cves VALUES (?, ?, ?, ?)",
                    (theme_slug, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
        except:
            pass
        
        conn.close()
        return []
    
    def _is_cache_valid(self, last_updated):
        """Check if cache is still valid"""
        if not last_updated:
            return False
        cache_time = datetime.fromisoformat(last_updated)
        return (datetime.now() - cache_time).total_seconds() < (Config.CACHE_DURATION_HOURS * 3600)

# ===============================
# ADVANCED DETECTION ENGINE
# ===============================

class AdvancedDetector:
    """Advanced detection for WordPress, PHP, plugins, themes"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_all(self) -> Dict:
        """Detect everything: WordPress, PHP, plugins, themes"""
        print(f"{Fore.CYAN}🔍 Starting comprehensive detection...")
        
        results = {
            'wordpress': self.detect_wordpress_version(),
            'php': self.detect_php_version(),
            'plugins': self.detect_plugins_comprehensive(),
            'themes': self.detect_themes_comprehensive(),
            'write_primitives': self.detect_write_primitives(),
            'security_headers': self.check_security_headers(),
            'exposed_files': self.check_exposed_files()
        }
        
        return results
    
    def detect_wordpress_version(self) -> Dict:
        """Advanced WordPress version detection using 7+ methods"""
        print(f"  Detecting WordPress version...")
        
        version_info = {
            'detected': False,
            'version': None,
            'confidence': 'unknown',
            'methods': [],
            'evidence': []
        }
        
        try:
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            # Check if it's WordPress
            wp_indicators = ['wp-content', 'wp-includes', 'wp-json', 'wordpress']
            if not any(x in html.lower() for x in wp_indicators):
                return version_info
            
            version_info['detected'] = True
            all_versions = []
            
            # Method 1: Generator meta tag (HIGH confidence)
            generator_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d\.]+)["\']',
                html,
                re.IGNORECASE
            )
            if generator_match:
                version = generator_match.group(1)
                version_info['version'] = version
                version_info['confidence'] = 'high'
                version_info['methods'].append('generator_meta')
                version_info['evidence'].append(f'Generator meta: WordPress {version}')
                all_versions.append(('high', version))
            
            # Method 2: readme.html file (HIGH confidence)
            readme_url = urljoin(self.target, '/readme.html')
            try:
                readme_resp = self.session.get(readme_url, timeout=5)
                if readme_resp.status_code == 200:
                    readme_match = re.search(
                        r'Version\s*([\d\.]+)',
                        readme_resp.text,
                        re.IGNORECASE
                    )
                    if readme_match:
                        version = readme_match.group(1)
                        version_info['methods'].append('readme_file')
                        version_info['evidence'].append(f'readme.html: Version {version}')
                        all_versions.append(('high', version))
                        
                        if not version_info['version']:
                            version_info['version'] = version
                            version_info['confidence'] = 'high'
            except:
                pass
            
            # Method 3: Asset versions (MEDIUM confidence)
            version_patterns = [
                r'/wp-includes/js/jquery/jquery-migrate\.js\?ver=([\d\.]+)',
                r'/wp-includes/js/wp-embed\.min\.js\?ver=([\d\.]+)',
                r'/wp-includes/css/dist/block-library/style\.min\.css\?ver=([\d\.]+)',
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, html)
                for match in matches[:2]:
                    if match and match.count('.') >= 1:
                        if not (match.startswith('1.') or match.startswith('2.') or match.startswith('3.')):
                            version_info['methods'].append('asset_version')
                            version_info['evidence'].append(f'Asset version: {match}')
                            all_versions.append(('medium', match))
                            
                            if not version_info['version']:
                                version_info['version'] = match
                                version_info['confidence'] = 'medium'
                            break
            
            # Method 4: RDF feed
            rdf_match = re.search(
                r'<admin:generatorAgent.*rdf:resource="http://wordpress.org/\?v=([\d\.]+)"',
                html,
                re.IGNORECASE | re.DOTALL
            )
            if rdf_match:
                version = rdf_match.group(1)
                version_info['methods'].append('rdf_feed')
                version_info['evidence'].append(f'RDF feed: WordPress {version}')
                all_versions.append(('medium', version))
            
            # Method 5: WordPress feed
            feed_url = urljoin(self.target, '/feed/')
            try:
                feed_resp = self.session.get(feed_url, timeout=5)
                if feed_resp.status_code == 200:
                    feed_match = re.search(
                        r'<generator>https://wordpress\.org/\?v=([\d\.]+)</generator>',
                        feed_resp.text,
                        re.IGNORECASE
                    )
                    if feed_match:
                        version = feed_match.group(1)
                        version_info['methods'].append('feed_generator')
                        version_info['evidence'].append(f'Feed generator: WordPress {version}')
                        all_versions.append(('medium', version))
                        
                        if not version_info['version']:
                            version_info['version'] = version
                            version_info['confidence'] = 'medium'
            except:
                pass
            
            # Method 6: Login page
            login_url = urljoin(self.target, '/wp-login.php')
            try:
                login_resp = self.session.get(login_url, timeout=5)
                if login_resp.status_code == 200:
                    login_match = re.search(
                        r'ver=([\d\.]+)',
                        login_resp.text
                    )
                    if login_match:
                        version = login_match.group(1)
                        version_info['methods'].append('login_page')
                        version_info['evidence'].append(f'Login page: Version {version}')
                        all_versions.append(('low', version))
                        
                        if not version_info['version']:
                            version_info['version'] = version
                            version_info['confidence'] = 'low'
            except:
                pass
            
            # Method 7: wp-links-opml.php (WordPress < 3.5)
            opml_url = urljoin(self.target, '/wp-links-opml.php')
            try:
                opml_resp = self.session.get(opml_url, timeout=5)
                if opml_resp.status_code == 200 and 'opml' in opml_resp.text.lower():
                    version_info['methods'].append('deprecated_file')
                    version_info['evidence'].append('wp-links-opml.php present (WordPress < 3.5)')
            except:
                pass
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error detecting WordPress: {str(e)}")
        
        return version_info
    
    def detect_php_version(self) -> Dict:
        """Detect PHP version from headers"""
        print(f"  Detecting PHP version...")
        
        php_version = None
        sources = []
        
        endpoints = [
            '/',
            '/wp-login.php',
            '/wp-admin/',
            '/xmlrpc.php',
            '/wp-json/',
            '/readme.html'
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.target, endpoint)
                resp = self.session.get(url, timeout=5)
                
                # Check X-Powered-By header
                powered_by = resp.headers.get('X-Powered-By', '')
                if 'PHP/' in powered_by:
                    php_match = re.search(r'PHP/([\d\.]+)', powered_by)
                    if php_match:
                        php_version = php_match.group(1)
                        sources.append(f'X-Powered-By from {endpoint}')
                        break
                
                # Check Server header
                server = resp.headers.get('Server', '')
                if 'PHP/' in server:
                    php_match = re.search(r'PHP/([\d\.]+)', server)
                    if php_match:
                        php_version = php_match.group(1)
                        sources.append(f'Server header from {endpoint}')
                        break
                        
            except:
                continue
        
        return {
            'version': php_version,
            'sources': sources,
            'detected': php_version is not None
        }
    
    def detect_plugins_comprehensive(self) -> List[Dict]:
        """Comprehensive plugin detection"""
        print(f"  Detecting plugins...")
        
        plugins = []
        detected_slugs = set()
        
        try:
            # Get main page HTML
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            # Method 1: Extract from HTML
            html_slugs = re.findall(r'/wp-content/plugins/([^/\'"?]+)', html)
            print(f"{Fore.GREEN}✅ Found {len(plugins)} plugins:")
            for slug in html_slugs:
                if slug not in detected_slugs:
                    self._check_plugin_details(slug, plugins, 'html_reference')
                    detected_slugs.add(slug)
            
            # Method 2: Try wp-json API
            try:
                api_url = urljoin(self.target, '/wp-json/wp/v2/plugins')
                api_resp = self.session.get(api_url, timeout=5)
                if api_resp.status_code == 200:
                    plugin_data = api_resp.json()
                    for plugin in plugin_data:
                        if 'plugin' in plugin:
                            slug = plugin['plugin'].split('/')[0]
                            if slug not in detected_slugs:
                                self._check_plugin_details(slug, plugins, 'wp_json_api')
                                detected_slugs.add(slug)
            except:
                pass
            
            # Method 3: Check common plugins list
            for slug in Config.PLUGIN_PATTERNS[:15]:
                if slug in detected_slugs:
                    continue
                
                # Check readme.txt
                plugin_url = urljoin(self.target, f'/wp-content/plugins/{slug}/readme.txt')
                try:
                    plugin_resp = self.session.head(plugin_url, timeout=2)
                    if plugin_resp.status_code == 200:
                        self._check_plugin_details(slug, plugins, 'common_list')
                        detected_slugs.add(slug)
                except:
                    pass
            
            # Method 4: Check directory existence
            for slug in list(detected_slugs)[:20]:
                plugin_dir = urljoin(self.target, f'/wp-content/plugins/{slug}/')
                try:
                    resp = self.session.head(plugin_dir, timeout=2, allow_redirects=False)
                    if resp.status_code in (200, 403):
                        # Update plugin with directory info
                        for plugin in plugins:
                            if plugin['slug'] == slug:
                                plugin['directory_exists'] = True
                                break
                except:
                    pass
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error detecting plugins: {str(e)}")
        
        return plugins
    
    def _check_plugin_details(self, slug: str, plugins: List, source: str):
        """Check plugin details and add to list"""
        try:
            # Try readme.txt first
            readme_url = urljoin(self.target, f'/wp-content/plugins/{slug}/readme.txt')
            readme_resp = self.session.get(readme_url, timeout=3)
            
            if readme_resp.status_code == 200:
                text = readme_resp.text
                
                # Extract version
                version_match = re.search(r'Stable tag:\s*([\d\.]+)', text, re.IGNORECASE)
                version = version_match.group(1) if version_match else None
                
                # Extract name
                name_match = re.search(r'===\s*(.+?)\s*===', text)
                name = name_match.group(1).strip() if name_match else slug
                
                # Extract description
                desc_match = re.search(r'Description:\s*(.+?)(?=\n\n|\n==)', text, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else ''
                
                plugins.append({
                    'slug': slug,
                    'name': name,
                    'version': version,
                    'description': description[:100] if description else '',
                    'detected_via': source,
                    'readme_found': True
                })
                return
            
            # Try main plugin file
            main_file_url = urljoin(self.target, f'/wp-content/plugins/{slug}/{slug}.php')
            main_resp = self.session.get(main_file_url, timeout=3)
            
            if main_resp.status_code == 200:
                text = main_resp.text
                
                # Extract version from PHP header
                version_match = re.search(r'Version:\s*([\d\.]+)', text, re.IGNORECASE)
                version = version_match.group(1) if version_match else None
                
                # Extract name
                name_match = re.search(r'Plugin Name:\s*(.+)', text, re.IGNORECASE)
                name = name_match.group(1).strip() if name_match else slug
                
                plugins.append({
                    'slug': slug,
                    'name': name,
                    'version': version,
                    'detected_via': source,
                    'main_file_found': True
                })
                return
            
            # If nothing found, add basic entry
            plugins.append({
                'slug': slug,
                'name': slug,
                'version': None,
                'detected_via': source
            })
            
        except:
            # Add basic entry on error
            plugins.append({
                'slug': slug,
                'name': slug,
                'version': None,
                'detected_via': f'{source}_error'
            })
    
    def detect_themes_comprehensive(self) -> List[Dict]:
        """Comprehensive theme detection"""
        print(f"  Detecting themes...")
        
        themes = []
        
        try:
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            # Extract theme slugs from HTML
            theme_slugs = re.findall(r'/wp-content/themes/([^/\'"?]+)', html)
            print(f"{Fore.GREEN}✅ Found {len(themes)} themes:")
            for slug in set(theme_slugs):
                try:
                    style_url = urljoin(self.target, f'/wp-content/themes/{slug}/style.css')
                    style_resp = self.session.get(style_url, timeout=3)
                    
                    if style_resp.status_code == 200:
                        text = style_resp.text
                        
                        # Extract version
                        version_match = re.search(r'Version:\s*([\d\.]+)', text, re.IGNORECASE)
                        version = version_match.group(1) if version_match else None
                        
                        # Extract name
                        name_match = re.search(r'Theme Name:\s*(.+?)[\r\n]', text, re.IGNORECASE)
                        name = name_match.group(1).strip() if name_match else slug
                        
                        # Extract description
                        desc_match = re.search(r'Description:\s*(.+?)(?=\n\n|\n==)', text, re.DOTALL)
                        description = desc_match.group(1).strip() if desc_match else ''
                        
                        themes.append({
                            'slug': slug,
                            'name': name,
                            'version': version,
                            'description': description[:100] if description else '',
                            'detected_via': 'style.css',
                            'active': 'active' in html.lower()  # Simple check
                        })
                    else:
                        themes.append({
                            'slug': slug,
                            'name': slug,
                            'version': None,
                            'detected_via': 'html_reference'
                        })
                        
                except:
                    themes.append({
                        'slug': slug,
                        'name': slug,
                        'version': None,
                        'detected_via': 'html_reference_error'
                    })
        
        except Exception as e:
            print(f"{Fore.RED}✗ Error detecting themes: {str(e)}")
        
        return themes
    
    def detect_write_primitives(self) -> Dict:
        """Detect write/upload endpoints"""
        print(f"  Detecting write primitives...")
        
        primitives = {
            'upload_handlers': [],
            'import_endpoints': [],
            'admin_pages': [],
            'total': 0
        }
        
        # Check upload handlers
        upload_endpoints = [
            '/wp-admin/async-upload.php',
            '/wp-admin/media-upload.php',
            '/wp-admin/admin-ajax.php?action=upload',
            '/wp-content/plugins/contact-form-7/includes/file.php',
        ]
        
        for endpoint in upload_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                resp = self.session.head(url, timeout=2)
                
                if resp.status_code in [200, 403, 405]:
                    primitives['upload_handlers'].append({
                        'endpoint': endpoint,
                        'status': resp.status_code,
                        'risk_score': 85
                    })
                    primitives['total'] += 1
            except:
                continue
        
        # Check admin pages
        admin_pages = [
            '/wp-admin/post-new.php',
            '/wp-admin/user-new.php',
            '/wp-admin/theme-editor.php',
            '/wp-admin/plugin-editor.php',
        ]
        
        for page in admin_pages:
            try:
                url = urljoin(self.target, page)
                resp = self.session.head(url, timeout=2, allow_redirects=False)
                
                if resp.status_code in [200, 302, 403]:
                    primitives['admin_pages'].append({
                        'endpoint': page,
                        'status': resp.status_code,
                        'risk_score': 50
                    })
                    primitives['total'] += 1
            except:
                continue
        
        return primitives
    
    def check_security_headers(self) -> Dict:
        """Check security headers"""
        try:
            resp = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            results = {
                'score': 0,
                'max_score': 100,
                'headers': {},
                'missing': []
            }
            
            for header_key, header_config in Config.SECURITY_HEADERS.items():
                if header_key in headers:
                    results['score'] += header_config['weight']
                    results['headers'][header_config['name']] = {
                        'present': True,
                        'value': headers[header_key],
                        'weight': header_config['weight']
                    }
                else:
                    results['missing'].append(header_config['name'])
                    results['headers'][header_config['name']] = {
                        'present': False,
                        'weight': header_config['weight']
                    }
            
            return results
        except:
            return {'score': 0, 'max_score': 100, 'headers': {}, 'missing': []}
    
    def check_exposed_files(self) -> Dict:
        """Check for exposed sensitive files"""
        print(f"  Checking for exposed files...")
        
        findings = {
            'backup_files': [],
            'sensitive_files': [],
            'directory_listings': []
        }
        
        # Check backup files
        backup_patterns = [
            'backup.sql', 'backup.zip', 'backup.tar.gz',
            'db_backup.sql', 'wordpress.sql', 'dump.sql',
            'wp_backup.zip', 'database.sql',
        ]
        
        for filename in backup_patterns:
            try:
                url = urljoin(self.target, f'/{filename}')
                resp = self.session.head(url, timeout=2)
                if resp.status_code == 200:
                    findings['backup_files'].append({
                        'file': filename,
                        'url': url,
                        'size': resp.headers.get('Content-Length', 'Unknown')
                    })
            except:
                continue
        
        # Check sensitive files
        sensitive_files = [
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
            '.env', '.env.production', '.htaccess',
            'error_log', 'debug.log',
        ]
        
        for filename in sensitive_files:
            try:
                url = urljoin(self.target, f'/{filename}')
                resp = self.session.head(url, timeout=2)
                if resp.status_code == 200:
                    findings['sensitive_files'].append({
                        'file': filename,
                        'url': url
                    })
            except:
                continue
        
        # Check directory listings
        directories = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
        ]
        
        for directory in directories:
            try:
                url = urljoin(self.target, directory)
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200 and 'Index of' in resp.text:
                    findings['directory_listings'].append({
                        'directory': directory,
                        'url': url
                    })
            except:
                continue
        
        return findings

# ===============================
# BEHAVIORAL ANALYZER
# ===============================

class BehavioralAnalyzer:
    """Analyze server behavior and responses"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze_behavior(self) -> Dict:
        """Analyze server behavior patterns"""
        print(f"{Fore.CYAN}🧪 Analyzing server behavior...")
        
        behaviors = {
            'rate_handling': self.observe_rate_handling(),
            'error_responses': self.observe_error_responses(),
            'authentication_patterns': self.check_authentication_patterns(),
            'debug_mode': self.check_debug_mode(),
            'xmlrpc_status': self.check_xmlrpc()
        }
        
        return behaviors
    
    def observe_rate_handling(self) -> Dict:
        """Observe how server handles sequential requests"""
        observations = []
        
        for i in range(3):
            try:
                start = time.time()
                resp = self.session.get(self.target, timeout=5)
                elapsed = time.time() - start
                
                observations.append({
                    'request': i + 1,
                    'status': resp.status_code,
                    'time': round(elapsed, 3),
                    'length': len(resp.text)
                })
                
                time.sleep(0.5)
            except:
                observations.append({
                    'request': i + 1,
                    'error': 'Request failed'
                })
        
        # Analyze patterns
        if len(observations) >= 2:
            times = [obs.get('time', 0) for obs in observations if 'time' in obs]
            if times:
                consistent = max(times) - min(times) < 0.5
                return {
                    'observations': observations,
                    'consistent': consistent,
                    'average_time': round(sum(times) / len(times), 3)
                }
        
        return {'observations': observations}
    
    def observe_error_responses(self) -> Dict:
        """Observe error response patterns"""
        test_cases = [
            {'path': '/nonexistent-page-test-12345', 'type': 'non_existent_page'},
            {'path': '/?test_param=../../../etc/passwd', 'type': 'path_traversal'},
            {'path': '/wp-admin/admin-ajax.php?action=test_nonce_123', 'type': 'invalid_ajax'},
        ]
        
        observations = []
        
        for test in test_cases:
            try:
                url = urljoin(self.target, test['path'])
                resp = self.session.get(url, timeout=5)
                
                # Analyze response
                analysis = {
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'has_errors': any(pattern in resp.text.lower() 
                                     for pattern in ['error', 'warning', 'notice', 'exception']),
                    'has_paths': any(pattern in resp.text 
                                    for pattern in ['/var/www/', '/home/', '/etc/', 'C:\\', 'D:\\']),
                    'has_stacktrace': 'stack trace' in resp.text.lower()
                }
                
                observations.append({
                    'test': test['type'],
                    'url': url,
                    'analysis': analysis
                })
                
            except:
                observations.append({
                    'test': test['type'],
                    'error': 'Request failed'
                })
            
            time.sleep(0.5)
        
        return {'observations': observations}
    
    def check_authentication_patterns(self) -> Dict:
        """Check authentication boundary patterns"""
        paths = [
            {'path': '/wp-admin/', 'expected': 'protected'},
            {'path': '/wp-admin/users.php', 'expected': 'protected'},
            {'path': '/wp-login.php', 'expected': 'public'},
            {'path': '/wp-content/uploads/', 'expected': 'public'},
        ]
        
        observations = []
        
        for item in paths:
            try:
                url = urljoin(self.target, item['path'])
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                
                access_level = 'unknown'
                if resp.status_code == 200:
                    if 'wp-admin' in url and 'login' not in url:
                        if 'password' in resp.text.lower() and 'input' in resp.text.lower():
                            access_level = 'login_required'
                        else:
                            access_level = 'direct_access'
                    else:
                        access_level = 'public_access'
                elif resp.status_code in [301, 302]:
                    access_level = 'redirected'
                elif resp.status_code == 403:
                    access_level = 'forbidden'
                elif resp.status_code == 404:
                    access_level = 'not_found'
                
                observations.append({
                    'path': item['path'],
                    'expected': item['expected'],
                    'status': resp.status_code,
                    'access_level': access_level,
                    'redirects': len(resp.history) > 0
                })
                
            except:
                observations.append({
                    'path': item['path'],
                    'error': 'Request failed'
                })
            
            time.sleep(0.5)
        
        return {'observations': observations}
    
    def check_debug_mode(self) -> Dict:
        """Check if debug mode is enabled"""
        try:
            resp = self.session.get(self.target, timeout=5)
            text = resp.text.lower()
            
            indicators = [
                'wp_debug',
                'notice:',
                'warning:',
                'fatal error:',
                'stack trace:',
                'php warning',
                'php notice',
            ]
            
            found = [ind for ind in indicators if ind in text]
            
            return {
                'enabled': len(found) > 0,
                'indicators': found[:3],
                'risk_level': 'HIGH' if found else 'LOW'
            }
        except:
            return {'enabled': False, 'error': 'Check failed'}
    
    def check_xmlrpc(self) -> Dict:
        """Check XML-RPC status"""
        try:
            url = urljoin(self.target, '/xmlrpc.php')
            resp = self.session.head(url, timeout=3)
            
            return {
                'enabled': resp.status_code == 200,
                'status': resp.status_code,
                'risk_level': 'MEDIUM' if resp.status_code == 200 else 'LOW'
            }
        except:
            return {'enabled': False, 'error': 'Check failed'}

# ===============================
# CORRELATION ENGINE
# ===============================

class CorrelationEngine:
    """Correlate findings for intelligent analysis"""
    
    def __init__(self):
        self.correlations = []
    
    def analyze_correlations(self, findings: Dict) -> List[Dict]:
        """Find correlations between different findings"""
        print(f"{Fore.CYAN}🧠 Analyzing correlations...")
        
        correlations = []
        
        # Correlation 1: Old WordPress + No security headers
        wp_version = findings.get('detection', {}).get('wordpress', {}).get('version')
        header_score = findings.get('detection', {}).get('security_headers', {}).get('score', 0)
        
        if wp_version and header_score < 50:
            try:
                major_version = int(wp_version.split('.')[0])
                if major_version < 5:
                    correlations.append({
                        'type': 'OLD_WORDPRESS_WEAK_HEADERS',
                        'description': f'Old WordPress ({wp_version}) combined with weak security headers ({header_score}/100)',
                        'risk': 'HIGH',
                        'components': ['WordPress', 'Security Headers'],
                        'recommendation': 'Upgrade WordPress and implement security headers immediately'
                    })
            except:
                pass
        
        # Correlation 2: Many plugins + Debug mode
        plugins_count = len(findings.get('detection', {}).get('plugins', []))
        debug_enabled = findings.get('behavior', {}).get('debug_mode', {}).get('enabled', False)
        
        if plugins_count > 10 and debug_enabled:
            correlations.append({
                'type': 'MANY_PLUGINS_DEBUG_MODE',
                'description': f'Many plugins ({plugins_count}) with debug mode enabled',
                'risk': 'HIGH',
                'components': ['Plugins', 'Debug Mode'],
                'recommendation': 'Disable debug mode and audit plugins for security'
            })
        
        # Correlation 3: Write primitives + No authentication
        write_primitives = findings.get('detection', {}).get('write_primitives', {}).get('total', 0)
        auth_issues = findings.get('behavior', {}).get('authentication_patterns', {}).get('observations', [])
        
        if write_primitives > 0:
            public_admin = any(
                obs.get('access_level') == 'direct_access' 
                for obs in auth_issues 
                if 'wp-admin' in obs.get('path', '')
            )
            
            if public_admin:
                correlations.append({
                    'type': 'WRITE_PRIMITIVES_PUBLIC_ADMIN',
                    'description': f'Write primitives ({write_primitives}) with potential public admin access',
                    'risk': 'CRITICAL',
                    'components': ['Write Primitives', 'Authentication'],
                    'recommendation': 'Immediately secure admin areas and audit write endpoints'
                })
        
        # Correlation 4: Exposed files + Directory listing
        exposed_backups = len(findings.get('detection', {}).get('exposed_files', {}).get('backup_files', []))
        directory_listings = len(findings.get('detection', {}).get('exposed_files', {}).get('directory_listings', []))
        
        if exposed_backups > 0 and directory_listings > 0:
            correlations.append({
                'type': 'EXPOSED_FILES_DIRECTORY_LISTING',
                'description': f'Exposed backup files ({exposed_backups}) with directory listing enabled',
                'risk': 'HIGH',
                'components': ['Exposed Files', 'Directory Listing'],
                'recommendation': 'Remove backup files and disable directory listing'
            })
        
        # Correlation 5: Old PHP + Known vulnerabilities
        php_version = findings.get('detection', {}).get('php', {}).get('version')
        cve_count = len(findings.get('vulnerabilities', {}).get('wordpress', [])) + \
                   len(findings.get('vulnerabilities', {}).get('plugins', [])) + \
                   len(findings.get('vulnerabilities', {}).get('themes', []))
        
        if php_version and cve_count > 0:
            try:
                php_major = int(php_version.split('.')[0])
                if php_major < 7:
                    correlations.append({
                        'type': 'OLD_PHP_WITH_CVES',
                        'description': f'Old PHP ({php_version}) with {cve_count} known vulnerabilities',
                        'risk': 'CRITICAL',
                        'components': ['PHP', 'CVEs'],
                        'recommendation': 'Upgrade PHP immediately and patch all vulnerabilities'
                    })
            except:
                pass
        
        self.correlations = correlations
        return correlations

# ===============================
# SCORING ENGINE
# ===============================

class ScoringEngine:
    """Calculate comprehensive risk scores"""
    
    def calculate_overall_score(self, findings: Dict) -> Dict:
        """Calculate overall risk score"""
        
        scores = {
            'detection_score': self._calculate_detection_score(findings.get('detection', {})),
            'vulnerability_score': self._calculate_vulnerability_score(findings.get('vulnerabilities', {})),
            'behavior_score': self._calculate_behavior_score(findings.get('behavior', {})),
            'correlation_score': self._calculate_correlation_score(findings.get('correlations', []))
        }
        
        # Weighted total
        total_score = (
            scores['detection_score'] * 0.3 +
            scores['vulnerability_score'] * 0.3 +
            scores['behavior_score'] * 0.2 +
            scores['correlation_score'] * 0.2
        )
        
        # Determine risk level
        if total_score >= 80:
            risk_level = 'CRITICAL'
            color = 'RED'
        elif total_score >= 60:
            risk_level = 'HIGH'
            color = 'YELLOW'
        elif total_score >= 40:
            risk_level = 'MEDIUM'
            color = 'CYAN'
        elif total_score >= 20:
            risk_level = 'LOW'
            color = 'GREEN'
        else:
            risk_level = 'INFO'
            color = 'BLUE'
        
        scores['total_score'] = round(total_score, 1)
        scores['risk_level'] = risk_level
        scores['color'] = color
        
        return scores
    
    def _calculate_detection_score(self, detection: Dict) -> float:
        """Score based on detection findings"""
        score = 0
        
        # WordPress age
        wp_version = detection.get('wordpress', {}).get('version')
        if wp_version:
            try:
                major = int(wp_version.split('.')[0])
                if major < 4:
                    score += 30
                elif major < 5:
                    score += 20
                elif major < 6:
                    score += 10
            except:
                pass
        
        # PHP age
        php_version = detection.get('php', {}).get('version')
        if php_version:
            try:
                major = int(php_version.split('.')[0])
                if major < 7:
                    score += 25
                elif major < 8:
                    score += 10
            except:
                pass
        
        # Many plugins (attack surface)
        plugins_count = len(detection.get('plugins', []))
        if plugins_count > 15:
            score += 15
        elif plugins_count > 10:
            score += 10
        elif plugins_count > 5:
            score += 5
        
        # Write primitives
        write_count = detection.get('write_primitives', {}).get('total', 0)
        score += write_count * 5
        
        # Exposed files
        exposed_files = detection.get('exposed_files', {})
        score += len(exposed_files.get('backup_files', [])) * 10
        score += len(exposed_files.get('sensitive_files', [])) * 8
        score += len(exposed_files.get('directory_listings', [])) * 5
        
        # Security headers
        header_score = detection.get('security_headers', {}).get('score', 0)
        score += (100 - header_score) * 0.3
        
        return min(score, 100)
    
    def _calculate_vulnerability_score(self, vulnerabilities: Dict) -> float:
        """Score based on vulnerabilities"""
        score = 0
        
        # WordPress CVEs
        wp_cves = vulnerabilities.get('wordpress', [])
        for cve in wp_cves:
            severity = cve.get('severity', 'medium').lower()
            if severity == 'critical':
                score += 15
            elif severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 5
            else:
                score += 2
        
        # Plugin CVEs
        plugin_cves = vulnerabilities.get('plugins', [])
        for cve in plugin_cves:
            severity = cve.get('severity', 'medium').lower()
            if severity == 'critical':
                score += 12
            elif severity == 'high':
                score += 8
            elif severity == 'medium':
                score += 4
            else:
                score += 1
        
        # Theme CVEs
        theme_cves = vulnerabilities.get('themes', [])
        for cve in theme_cves:
            severity = cve.get('severity', 'medium').lower()
            if severity == 'critical':
                score += 10
            elif severity == 'high':
                score += 6
            elif severity == 'medium':
                score += 3
            else:
                score += 1
        
        return min(score, 100)
    
    def _calculate_behavior_score(self, behavior: Dict) -> float:
        """Score based on behavior"""
        score = 0
        
        # Debug mode
        if behavior.get('debug_mode', {}).get('enabled'):
            score += 25
        
        # XML-RPC enabled
        if behavior.get('xmlrpc_status', {}).get('enabled'):
            score += 15
        
        # Authentication issues
        auth_obs = behavior.get('authentication_patterns', {}).get('observations', [])
        for obs in auth_obs:
            if obs.get('access_level') == 'direct_access' and 'wp-admin' in obs.get('path', ''):
                score += 20
                break
        
        # Error disclosure
        error_obs = behavior.get('error_responses', {}).get('observations', [])
        for obs in error_obs:
            analysis = obs.get('analysis', {})
            if analysis.get('has_errors') or analysis.get('has_stacktrace'):
                score += 15
                break
        
        # Inconsistent response times
        rate = behavior.get('rate_handling', {})
        if not rate.get('consistent', True):
            score += 10
        
        return min(score, 100)
    
    def _calculate_correlation_score(self, correlations: List[Dict]) -> float:
        """Score based on correlations"""
        if not correlations:
            return 0
        
        score = 0
        for corr in correlations:
            risk = corr.get('risk', 'medium').upper()
            if risk == 'CRITICAL':
                score += 25
            elif risk == 'HIGH':
                score += 15
            elif risk == 'MEDIUM':
                score += 8
            else:
                score += 3
        
        return min(score, 100)

# ===============================
# MAIN AUDIT ENGINE
# ===============================

class UltimateWordPressAudit:
    """Main audit engine combining all features"""
    
    def __init__(self, target_url, api_token=None, nvd_key=None):
        self.target = target_url.rstrip('/')
        self.api_token = api_token or os.environ.get('WPSCAN_API_TOKEN') or Config.WPSCAN_API_TOKEN
        self.nvd_key = nvd_key or Config.NVD_API_KEY 
        # Initialize components
        self.detector = AdvancedDetector(target_url)
        self.behavior_analyzer = BehavioralAnalyzer(target_url)
        self.correlation_engine = CorrelationEngine()
        self.scoring_engine = ScoringEngine()
        self.db = DatabaseManager(self.api_token, self.nvd_key)
        
        # Results storage
        self.results = {
            'target': target_url,
            'scan_date': datetime.now().isoformat(),
            'detection': {},
            'vulnerabilities': {
                'wordpress': [],
                'plugins': [],
                'themes': [],
                'php': []
            },
            'behavior': {},
            'correlations': [],
            'scoring': {},
            'summary': {},
            'recommendations': []
        }
    
    def run_complete_audit(self):
        """Run complete audit with all features"""
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"{' '*30}🚀 WORDPRESS ULTIMATE SECURITY SCANNER")
        print(f"{' '*25}Advanced Detection + CVE Checking + Behavioral Analysis")
        print(f"{'='*100}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}🎯 Target: {self.target}")
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔑 API Token: {'✅ Provided' if self.api_token else '⚠️ Limited (get free token: https://wpscan.com/api)'}")
        print(f"🧠 Features: WordPress/Plugin/Theme/PHP detection + CVE checking + Behavioral analysis\n")
        
        # PHASE 1: COMPREHENSIVE DETECTION
        print(f"{Fore.YELLOW}[PHASE 1/5] COMPREHENSIVE DETECTION...")
        self.results['detection'] = self.detector.detect_all()
        
        # Check if WordPress detected
        if not self.results['detection']['wordpress']['detected']:
            print(f"{Fore.RED}✗ WordPress not detected. Exiting.\n")
            return
        
        wp_version = self.results['detection']['wordpress']['version']
        plugins_count = len(self.results['detection']['plugins'])
        themes_count = len(self.results['detection']['themes'])
        
        print(f"{Fore.GREEN}✅ WordPress {wp_version} detected")
        print(f"✅ {plugins_count} plugins found")
        print(f"✅ {themes_count} themes found")
        
        if self.results['detection']['php']['version']:
            print(f"✅ PHP {self.results['detection']['php']['version']} detected")
        
        print()
        
        # PHASE 2: CVE CHECKING
        print(f"{Fore.YELLOW}[PHASE 2/5] CVE CHECKING...")
        self.check_all_vulnerabilities()
        
        # PHASE 3: BEHAVIORAL ANALYSIS
        print(f"{Fore.YELLOW}[PHASE 3/5] BEHAVIORAL ANALYSIS...")
        self.results['behavior'] = self.behavior_analyzer.analyze_behavior()
        
        # PHASE 4: CORRELATION ANALYSIS
        print(f"{Fore.YELLOW}[PHASE 4/5] CORRELATION ANALYSIS...")
        self.results['correlations'] = self.correlation_engine.analyze_correlations(self.results)
        
        # PHASE 5: SCORING & REPORTING
        print(f"{Fore.YELLOW}[PHASE 5/5] SCORING & REPORTING...")
        self.results['scoring'] = self.scoring_engine.calculate_overall_score(self.results)
        self.generate_recommendations()
        self.generate_summary()
        
        # Save and display results
        self.save_comprehensive_reports()
        self.display_executive_summary()
        
        print(f"\n{Fore.GREEN}{'='*100}")
        print(f"✅ AUDIT COMPLETED SUCCESSFULLY!")
        print(f"{'='*100}{Style.RESET_ALL}\n")
    
    def check_all_vulnerabilities(self):
        """Check for vulnerabilities in all components"""
        total_vulns = 0
        
        # WordPress Core
        wp_version = self.results['detection']['wordpress']['version']
        php_version = self.results['detection']['php']['version']
        if wp_version:
            print(f"  Checking WordPress {wp_version}...", end=' ')
            wp_cves = self.db.get_wordpress_cves(wp_version)
            self.results['vulnerabilities']['wordpress'] = wp_cves
            
            if wp_cves:
                print(f"{Fore.RED}✗ {len(wp_cves)} CVEs")
                total_vulns += len(wp_cves)
            else:
                print(f"{Fore.GREEN}✓")
        
        # Plugins
        for plugin in self.results['detection']['plugins']:
            slug = plugin['slug']
            print(f"  Checking plugin '{slug}'...", end=' ')
            
            plugin_cves = self.db.get_plugin_cves(slug)
            if plugin_cves:
                plugin['vulnerabilities'] = plugin_cves
                self.results['vulnerabilities']['plugins'].extend(plugin_cves)
                print(f"{Fore.RED}✗ {len(plugin_cves)} CVEs")
                total_vulns += len(plugin_cves)
            else:
                print(f"{Fore.GREEN}✓")
            
            time.sleep(0.1)  # Rate limiting
        
        # Themes
        for theme in self.results['detection']['themes']:
            slug = theme['slug']
            print(f"  Checking theme '{slug}'...", end=' ')
            
            theme_cves = self.db.get_theme_cves(slug)
            if theme_cves:
                theme['vulnerabilities'] = theme_cves
                self.results['vulnerabilities']['themes'].extend(theme_cves)
                print(f"{Fore.RED}✗ {len(theme_cves)} CVEs")
                total_vulns += len(theme_cves)
            else:
                print(f"{Fore.GREEN}✓")
            
            time.sleep(0.1)
        
        print(f"\n{Fore.WHITE}  Total vulnerabilities found: {total_vulns}\n")
    
    def generate_recommendations(self):
        """Generate actionable recommendations"""
        recommendations = []
        
        # WordPress recommendations
        wp_version = self.results['detection']['wordpress']['version']
        if wp_version:
            try:
                major = int(wp_version.split('.')[0])
                if major < 6:
                    recommendations.append({
                        'priority': 'HIGH',
                        'category': 'WordPress',
                        'action': f'Upgrade WordPress from {wp_version} to latest version',
                        'reason': 'Old versions have known vulnerabilities and missing security patches'
                    })
            except:
                pass
        
        # PHP recommendations
        php_version = self.results['detection']['php']['version']
        if php_version:
            try:
                major = int(php_version.split('.')[0])
                if major < 8:
                    recommendations.append({
                        'priority': 'HIGH',
                        'category': 'PHP',
                        'action': f'Upgrade PHP from {php_version} to PHP 8.x',
                        'reason': 'Old PHP versions are EOL and have security vulnerabilities'
                    })
            except:
                pass
        
        # Security headers recommendations
        header_score = self.results['detection']['security_headers']['score']
        if header_score < 80:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Security Headers',
                'action': 'Implement missing security headers',
                'reason': f'Current security header score is {header_score}/100'
            })
        
        # Debug mode recommendations
        if self.results['behavior']['debug_mode']['enabled']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Configuration',
                'action': 'Disable debug mode in production',
                'reason': 'Debug mode exposes sensitive information and error details'
            })
        
        # Exposed files recommendations
        exposed = self.results['detection']['exposed_files']
        if exposed['backup_files'] or exposed['sensitive_files']:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Files',
                'action': 'Remove exposed backup and sensitive files',
                'reason': f'Found {len(exposed["backup_files"])} backup files and {len(exposed["sensitive_files"])} sensitive files'
            })
        
        # Plugin vulnerability recommendations
        vuln_plugins = []
        for plugin in self.results['detection']['plugins']:
            if 'vulnerabilities' in plugin and plugin['vulnerabilities']:
                vuln_plugins.append(plugin['slug'])
        
        if vuln_plugins:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Plugins',
                'action': f'Update or remove vulnerable plugins: {", ".join(vuln_plugins[:3])}',
                'reason': f'Found {len(vuln_plugins)} plugins with known vulnerabilities'
            })
        
        # Write primitives recommendations
        write_count = self.results['detection']['write_primitives']['total']
        if write_count > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Endpoints',
                'action': 'Audit write/upload endpoints for security',
                'reason': f'Found {write_count} write/upload endpoints'
            })
        
        self.results['recommendations'] = recommendations
    
    def generate_summary(self):
        """Generate executive summary"""
        detection = self.results['detection']
        vulnerabilities = self.results['vulnerabilities']
        scoring = self.results['scoring']
        php_vulns = vulnerabilities.get('php', [])
        self.results['summary'] = {
            'wordpress_version': detection['wordpress']['version'],
            'php_version': detection['php']['version'],
            'plugins_found': len(detection['plugins']),
            'themes_found': len(detection['themes']),
            'write_primitives': detection['write_primitives']['total'],
            'exposed_files': {
                'backup': len(detection['exposed_files']['backup_files']),
                'sensitive': len(detection['exposed_files']['sensitive_files']),
                'directory_listings': len(detection['exposed_files']['directory_listings'])
            },
            'vulnerabilities': {
                'wordpress': len(vulnerabilities['wordpress']),
                'plugins': len(vulnerabilities['plugins']),
                'themes': len(vulnerabilities['themes']),
                'total': len(vulnerabilities['wordpress']) + len(vulnerabilities['plugins']) + len(vulnerabilities['themes'])
            },
            'security_headers_score': detection['security_headers']['score'],
            'debug_mode_enabled': self.results['behavior']['debug_mode']['enabled'],
            'xmlrpc_enabled': self.results['behavior']['xmlrpc_status']['enabled'],
            'risk_score': scoring['total_score'],
            'risk_level': scoring['risk_level'],
            'correlations_found': len(self.results['correlations']),
            'recommendations_count': len(self.results['recommendations']),
            'scan_duration': 'N/A'  # Would be calculated with timestamps
        }
    
    def save_comprehensive_reports(self):
        """Save comprehensive reports"""
        output_dir = Path(Config.OUTPUT_DIR)
        output_dir.mkdir(exist_ok=True)
        
        # Create target-specific directory
        target_name = self.target.replace("://", "_").replace("/", "_").replace(":", "_").replace(".", "_")
        if target_name.endswith("_"):
            target_name = target_name[:-1]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_dir = output_dir / f"{target_name}_{timestamp}"
        target_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_file = target_dir / "complete_report.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Save executive summary
        summary_file = target_dir / "executive_summary.txt"
        self._save_executive_summary(summary_file)
        
        # Save detailed findings
        details_file = target_dir / "detailed_findings.txt"
        self._save_detailed_findings(details_file)
        
        print(f"{Fore.GREEN}📁 Reports saved to: {target_dir}")
        print(f"  📄 Complete report: {json_file}")
        print(f"  📝 Executive summary: {summary_file}")
        print(f"  🔍 Detailed findings: {details_file}")
    
    def _save_executive_summary(self, filename: Path):
        """Save executive summary to file"""
        summary = self.results['summary']
        scoring = self.results['scoring']
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{'='*100}\n")
            f.write(f"WORDPRESS SECURITY AUDIT - EXECUTIVE SUMMARY\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*100}\n\n")
            
            f.write(f"📊 RISK ASSESSMENT\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Risk Score: {scoring['total_score']}/100\n")
            f.write(f"Risk Level: {scoring['risk_level']}\n\n")
            
            f.write(f"🔍 KEY FINDINGS\n")
            f.write(f"{'-'*50}\n")
            f.write(f"WordPress Version: {summary['wordpress_version'] or 'Not detected'}\n")
            f.write(f"PHP Version: {summary['php_version'] or 'Not detected'}\n")
            f.write(f"Plugins Found: {summary['plugins_found']}\n")
            f.write(f"Themes Found: {summary['themes_found']}\n")
            f.write(f"Vulnerabilities: {summary['vulnerabilities']['total']}\n")
            f.write(f"Write Primitives: {summary['write_primitives']}\n")
            f.write(f"Exposed Files: {summary['exposed_files']['backup'] + summary['exposed_files']['sensitive']}\n")
            f.write(f"Security Headers: {summary['security_headers_score']}/100\n")
            f.write(f"Debug Mode: {'Enabled' if summary['debug_mode_enabled'] else 'Disabled'}\n")
            f.write(f"XML-RPC: {'Enabled' if summary['xmlrpc_enabled'] else 'Disabled'}\n\n")
            
            if self.results['recommendations']:
                f.write(f"🚀 TOP RECOMMENDATIONS\n")
                f.write(f"{'-'*50}\n")
                for i, rec in enumerate(self.results['recommendations'][:5], 1):
                    f.write(f"{i}. [{rec['priority']}] {rec['action']}\n")
                f.write("\n")
    
    def _save_detailed_findings(self, filename: Path):
        """Save detailed findings to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{'='*100}\n")
            f.write(f"DETAILED FINDINGS\n")
            f.write(f"{'='*100}\n\n")
            
            # WordPress info
            wp_info = self.results['detection']['wordpress']
            f.write(f"WORDPRESS DETECTION\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Version: {wp_info['version'] or 'Not detected'}\n")
            f.write(f"Confidence: {wp_info['confidence']}\n")
            f.write(f"Methods: {', '.join(wp_info['methods'])}\n\n")
            
            # PHP info
            php_info = self.results['detection']['php']
            f.write(f"PHP DETECTION\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Version: {php_info['version'] or 'Not detected'}\n")
            f.write(f"Sources: {', '.join(php_info['sources'])}\n\n")
            
            # Plugins
            plugins = self.results['detection']['plugins']
            f.write(f"PLUGINS ({len(plugins)} found)\n")
            f.write(f"{'-'*50}\n")
            for plugin in plugins[:20]:  # First 20 plugins
                vuln_count = len(plugin.get('vulnerabilities', []))
                f.write(f"• {plugin['name']} ({plugin['slug']})\n")
                f.write(f"  Version: {plugin.get('version', 'Unknown')}\n")
                if vuln_count > 0:
                    f.write(f"  Vulnerabilities: {vuln_count} CVEs\n")
                f.write(f"  Detected via: {plugin.get('detected_via', 'Unknown')}\n\n")
            
            # Themes
            themes = self.results['detection']['themes']
            f.write(f"THEMES ({len(themes)} found)\n")
            f.write(f"{'-'*50}\n")
            for theme in themes[:10]:  # First 10 themes
                vuln_count = len(theme.get('vulnerabilities', []))
                f.write(f"• {theme['name']} ({theme['slug']})\n")
                f.write(f"  Version: {theme.get('version', 'Unknown')}\n")
                if vuln_count > 0:
                    f.write(f"  Vulnerabilities: {vuln_count} CVEs\n")
                f.write(f"  Active: {theme.get('active', 'Unknown')}\n\n")
    
    def display_executive_summary(self):
        """Display executive summary in console"""
        summary = self.results['summary']
        scoring = self.results['scoring']
        
        color = getattr(Fore, scoring['color'])
        
        print(f"\n{color}{'='*100}")
        print(f"{' '*30}📊 EXECUTIVE SUMMARY")
        print(f"{'='*100}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}🎯 Target: {self.target}")
        print(f"📅 Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"{color}📈 RISK SCORE: {scoring['total_score']}/100")
        print(f"{color}⚠️  RISK LEVEL: {scoring['risk_level']}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}🔍 DETECTION SUMMARY:{Style.RESET_ALL}")
        print(f"  WordPress: {summary['wordpress_version'] or 'Not detected'}")
        print(f"  PHP: {summary['php_version'] or 'Not detected'}")
        
        # ✅ HIỂN THỊ CHI TIẾT PLUGINS VÀ THEMES
        print(f"  Plugins: {summary['plugins_found']}")
        if self.results['detection']['plugins']:
            vulnerable_plugins = [p for p in self.results['detection']['plugins'] if p.get('vulnerabilities')]
            if vulnerable_plugins:
                print(f"    ⚠ Vulnerable: {len(vulnerable_plugins)} plugins")
                for plugin in vulnerable_plugins[:3]:
                    print(f"      • {plugin['name']} ({len(plugin.get('vulnerabilities', []))} CVEs)")
        
        print(f"  Themes: {summary['themes_found']}")
        if self.results['detection']['themes']:
            vulnerable_themes = [t for t in self.results['detection']['themes'] if t.get('vulnerabilities')]
            if vulnerable_themes:
                print(f"    ⚠ Vulnerable: {len(vulnerable_themes)} themes")
        
        print(f"\n{Fore.YELLOW}⚠️  SECURITY FINDINGS:{Style.RESET_ALL}")
        print(f"  Total CVEs: {summary['vulnerabilities']['total']}")
        print(f"    • WordPress: {summary['vulnerabilities']['wordpress']}")
        print(f"    • Plugins: {summary['vulnerabilities']['plugins']}")
        print(f"    • Themes: {summary['vulnerabilities']['themes']}")
        
        # ✅ SỬA LỖI Ở ĐÂY: KIỂM TRA KEY 'php' CÓ TỒN TẠI KHÔNG
        php_vulns = self.results['vulnerabilities'].get('php', [])
        print(f"    • PHP: {len(php_vulns)}")
        
        print(f"  Write Primitives: {summary['write_primitives']}")
        print(f"  Exposed Files: {summary['exposed_files']['backup']} backups, {summary['exposed_files']['sensitive']} sensitive")
        print(f"  Security Headers: {summary['security_headers_score']}/100")
        print(f"  Debug Mode: {'Enabled 🔴' if summary['debug_mode_enabled'] else 'Disabled ✅'}")
        print(f"  XML-RPC: {'Enabled ⚠️' if summary['xmlrpc_enabled'] else 'Disabled ✅'}")
        
        if self.results['recommendations']:
            print(f"\n{Fore.GREEN}🚀 TOP RECOMMENDATIONS:{Style.RESET_ALL}")
            for i, rec in enumerate(self.results['recommendations'][:3], 1):
                priority_color = Fore.RED if rec['priority'] == 'CRITICAL' else Fore.YELLOW if rec['priority'] == 'HIGH' else Fore.CYAN
                print(f"{priority_color}  {i}. [{rec['priority']}] {rec['action']}{Style.RESET_ALL}")

# ===============================
# MAIN EXECUTION
# ===============================

def main():
    """Main execution"""
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description='WordPress Ultimate Security Scanner - Unified Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
🌟 FEATURES:
  • Advanced WordPress/PHP/Plugin/Theme detection
  • Real-time CVE checking via WPScan API and NVD
  • Behavioral analysis and correlation
  • Write primitive detection (pentester mindset)
  • Comprehensive risk scoring
  • Detailed reporting

Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --api-token YOUR_TOKEN
  %(prog)s https://example.com --nvd-key YOUR_NVD_KEY
  %(prog)s --file targets.txt
  
Get free WPScan API token: https://wpscan.com/api
Get free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
        '''
    )
    
    parser.add_argument('target', nargs='?', help='Target URL')
    parser.add_argument('--file', help='File containing target URLs (one per line)')
    parser.add_argument('--api-token', help='WPScan API token for CVE data')
    parser.add_argument('--nvd-key', help='NVD API key for additional CVE data')  # ✅ THÊM DÒNG NÀY
    parser.add_argument('--output-dir', help='Custom output directory')
    parser.add_argument('--no-cache', action='store_true', help='Disable cache')
    
    args = parser.parse_args()
    
    # Set API tokens
    api_token = args.api_token or os.environ.get('WPSCAN_API_TOKEN')
    nvd_key = args.nvd_key or os.environ.get('NVD_API_KEY') or Config.NVD_API_KEY  # ✅ ĐÃ CÓ ĐỐI SỐ NÀY
    if args.output_dir:
        Config.OUTPUT_DIR = args.output_dir
    
    if args.no_cache:
        Config.CACHE_DURATION_HOURS = 0
    
    targets = []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File '{args.file}' not found.{Style.RESET_ALL}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        sys.exit(1)
    
    if not targets:
        print(f"{Fore.RED}Error: No targets specified.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Add http:// if missing
    targets = [t if t.startswith(('http://', 'https://')) else f'http://{t}' for t in targets]
    
    # Process targets
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{Fore.CYAN}{'='*100}")
            print(f"Processing target {i}/{len(targets)}: {target}")
            print(f"{'='*100}{Style.RESET_ALL}")
        
        try:
            audit = UltimateWordPressAudit(target, api_token, nvd_key)  # ✅ TRUYỀN CẢ HAI API KEY
            audit.run_complete_audit()
            
            # Delay between targets
            if i < len(targets):
                print(f"\n{Fore.WHITE}Waiting 3 seconds before next target...")
                time.sleep(3)
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Audit interrupted by user.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Fore.RED}Error auditing {target}: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            continue
    
    if len(targets) > 1:
        print(f"\n{Fore.GREEN}{'='*100}")
        print(f"✅ All {len(targets)} targets processed successfully!")
        print(f"{'='*100}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()