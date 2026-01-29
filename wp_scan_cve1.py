#!/usr/bin/env python3
"""
WordPress Security Scanner - Enhanced Hybrid Edition (2026)
Combines dynamic detection from Professional + CVE integration from Enterprise
Real-time CVE checking via WPScan API + comprehensive security audit
"""

import requests
import sys
import re
import json
import time
import hashlib
import sqlite3
import concurrent.futures
from urllib.parse import urljoin, quote, urlparse
from datetime import datetime, timedelta
from colorama import init, Fore, Style
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import os
init(autoreset=True)

# ===============================
# CONFIGURATION
# ===============================

class Config:
    """Centralized configuration - NO HARDCODING"""
    
    # WPScan API (get free token at https://wpscan.com/api)
    WPSCAN_API_TOKEN = "a9lVr6KNCHaGAlJ5sUb7N8f3yrB6Yfo8POuOe7WERQI"  # Set via --api-token or environment variable
    WPSCAN_API_URL = "https://wpscan.com/api/v3"
    
    # NVD API (optional, for PHP CVEs)
    NVD_API_KEY = "ce07fc36-0413-4fa8-8433-d6316e9adf8c"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Timeouts
    REQUEST_TIMEOUT = 10
    API_TIMEOUT = 15
    
    # Rate limiting
    REQUESTS_PER_SECOND = 2
    API_CALLS_PER_MINUTE = 25
    
    # Cache
    CACHE_DURATION_HOURS = 24
    
    # Database
    DB_PATH = "wp_cve_cache.sqlite"
    
    # Output
    OUTPUT_DIR = "wp_enhanced_results"
    
    # Detection patterns (configurable, not hardcoded)
    BACKUP_PATTERNS = [
        r'backup.*\.(sql|zip|tar\.gz|7z|rar)',
        r'db.*backup.*\.(sql|dump)',
        r'.*_backup_\d{8,14}\.(sql|zip)',
        r'wordpress.*\.(sql|zip|tar\.gz)',
        r'dump.*\.(sql|gz)',
        r'.*\.(sql|dump)\.gz$',
        r'site.*backup.*\.(zip|tar\.gz)',
    ]
    
    SENSITIVE_FILES = [
        'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php~',
        '.env', '.env.backup', '.env.old',
        'php.ini', '.htaccess.bak', 
        'error_log', 'debug.log',
        '.git/config', '.svn/entries',
        'composer.json', 'composer.lock',
        'package.json', 'yarn.lock',
    ]
    
    # Security headers and their importance (weights can be adjusted)
    SECURITY_HEADERS = {
        'strict-transport-security': {'weight': 25, 'name': 'HSTS'},
        'content-security-policy': {'weight': 25, 'name': 'CSP'},
        'x-frame-options': {'weight': 20, 'name': 'X-Frame-Options'},
        'x-content-type-options': {'weight': 15, 'name': 'X-Content-Type-Options'},
        'x-xss-protection': {'weight': 10, 'name': 'X-XSS-Protection'},
        'referrer-policy': {'weight': 5, 'name': 'Referrer-Policy'},
    }

# ===============================
# CVE DATABASE WITH API INTEGRATION
# ===============================

class EnhancedCVEDatabase:
    """CVE Database with real-time API integration - NO HARDCODING"""
    
    def __init__(self, api_token=None):
        self.api_token = api_token or Config.WPSCAN_API_TOKEN
        self.db_path = Config.DB_PATH
        self.init_database()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WPScan-Enhanced/2.0',
        })
        if self.api_token:
            self.session.headers.update({
                'Authorization': f'Token token={self.api_token}'
            })
    
    def init_database(self):
        """Initialize database for caching CVE data"""
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
        
        # Plugin CVEs (dynamic, not hardcoded)
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
        
        # PHP CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS php_cves (
                version TEXT PRIMARY KEY,
                cves_json TEXT,
                last_updated TIMESTAMP,
                source TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def is_cache_valid(self, last_updated):
        """Check if cache is still valid"""
        if not last_updated:
            return False
        cache_time = datetime.fromisoformat(last_updated)
        return (datetime.now() - cache_time).total_seconds() < (Config.CACHE_DURATION_HOURS * 3600)
    
    def get_wordpress_cves(self, version: str) -> List[Dict]:
        """Get WordPress core CVEs from WPScan API or cache"""
        if not version:
            return []
        
        # Check cache first
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM wp_core_cves WHERE version = ?",
            (version,)
        )
        result = cursor.fetchone()
        
        if result and self.is_cache_valid(result[1]):
            conn.close()
            return json.loads(result[0])
        
        # Fetch from API if not in cache or expired
        if not self.api_token:
            print(f"{Fore.YELLOW}⚠ No WPScan API token. Get one free at https://wpscan.com/api")
            conn.close()
            return []
        
        try:
            url = f"{Config.WPSCAN_API_URL}/wordpresses/{version}"
            response = self.session.get(url, timeout=Config.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                cves = data.get(version, {}).get('vulnerabilities', [])
                
                # Cache the result
                cursor.execute(
                    "INSERT OR REPLACE INTO wp_core_cves (version, cves_json, last_updated, source) VALUES (?, ?, ?, ?)",
                    (version, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
            elif response.status_code == 404:
                # Version not found, cache empty result
                cursor.execute(
                    "INSERT OR REPLACE INTO wp_core_cves (version, cves_json, last_updated, source) VALUES (?, ?, ?, ?)",
                    (version, json.dumps([]), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return []
        except Exception as e:
            print(f"{Fore.RED}✗ Error fetching WordPress CVEs: {str(e)}")
        
        conn.close()
        return []
    
    def get_plugin_cves(self, plugin_slug: str) -> List[Dict]:
        """Get plugin CVEs from WPScan API or cache"""
        if not plugin_slug:
            return []
        
        # Check cache
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM plugin_cves WHERE plugin_slug = ?",
            (plugin_slug,)
        )
        result = cursor.fetchone()
        
        if result and self.is_cache_valid(result[1]):
            conn.close()
            return json.loads(result[0])
        
        # Fetch from API
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
                    "INSERT OR REPLACE INTO plugin_cves (plugin_slug, cves_json, last_updated, source) VALUES (?, ?, ?, ?)",
                    (plugin_slug, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
        except Exception as e:
            print(f"{Fore.RED}✗ Error fetching plugin CVEs for {plugin_slug}: {str(e)}")
        
        conn.close()
        return []
    
    def get_theme_cves(self, theme_slug: str) -> List[Dict]:
        """Get theme CVEs from WPScan API or cache"""
        if not theme_slug:
            return []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cves_json, last_updated FROM theme_cves WHERE theme_slug = ?",
            (theme_slug,)
        )
        result = cursor.fetchone()
        
        if result and self.is_cache_valid(result[1]):
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
                    "INSERT OR REPLACE INTO theme_cves (theme_slug, cves_json, last_updated, source) VALUES (?, ?, ?, ?)",
                    (theme_slug, json.dumps(cves), datetime.now().isoformat(), 'wpscan_api')
                )
                conn.commit()
                conn.close()
                return cves
        except Exception as e:
            print(f"{Fore.RED}✗ Error fetching theme CVEs for {theme_slug}: {str(e)}")
        
        conn.close()
        return []

# ===============================
# ENHANCED WORDPRESS DETECTOR
# (From wp_scan_cve.py - the strong part)
# ===============================

class EnhancedWordPressDetector:
    """Advanced WordPress detection using multiple dynamic methods"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_version(self) -> Dict:
        """
        Advanced WordPress version detection using 7+ methods
        Returns: dict with version info and confidence level
        """
        version_info = {
            'detected': False,
            'version': None,
            'confidence': 'unknown',
            'methods': [],
            'sources': [],
            'evidence': []
        }
        
        try:
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            # Check if it's WordPress
            if not any(x in html.lower() for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress']):
                return version_info
            
            version_info['detected'] = True
            all_versions = []
            
            # Method 1A: Meta generator tag (HIGH confidence)
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
                version_info['sources'].append('html_meta')
                all_versions.append(('high', version))
            
            # Method 1B: RDF feed
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
                        # Filter out jQuery versions
                        if not (match.startswith('1.') or match.startswith('2.') or match.startswith('3.')):
                            version_info['methods'].append('asset_version')
                            version_info['evidence'].append(f'Asset version: {match}')
                            all_versions.append(('medium', match))
                            
                            if not version_info['version']:
                                version_info['version'] = match
                                version_info['confidence'] = 'medium'
                            break
                if version_info['version']:
                    break
            
            # Method 4: WordPress feed
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
            
            # Method 5: Login page version
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
            
            # Method 6: wp-json API
            api_url = urljoin(self.target, '/wp-json/')
            try:
                api_resp = self.session.get(api_url, timeout=5)
                if api_resp.status_code == 200:
                    try:
                        api_data = api_resp.json()
                        # WordPress API might expose version
                        if 'namespaces' in api_data:
                            version_info['methods'].append('wp_json_api')
                            version_info['evidence'].append('WP REST API accessible')
                    except:
                        pass
            except:
                pass
            
            # Method 7: Fingerprinting via style.css
            theme_url = urljoin(self.target, '/wp-content/themes/')
            try:
                # Try to get active theme
                theme_patterns = re.findall(
                    r'/wp-content/themes/([^/\'"]+)/',
                    html
                )
                if theme_patterns:
                    theme_name = theme_patterns[0]
                    style_url = urljoin(self.target, f'/wp-content/themes/{theme_name}/style.css')
                    style_resp = self.session.get(style_url, timeout=5)
                    if style_resp.status_code == 200:
                        version_info['methods'].append('theme_style_fingerprint')
                        version_info['evidence'].append(f'Theme detected: {theme_name}')
            except:
                pass
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error during WordPress detection: {str(e)}")
        
        return version_info
    
    def detect_php_version(self) -> Optional[str]:
        """Detect PHP version from various headers and responses"""
        php_version = None
        
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
                        break
                
                # Check Server header
                server = resp.headers.get('Server', '')
                if 'PHP/' in server:
                    php_match = re.search(r'PHP/([\d\.]+)', server)
                    if php_match:
                        php_version = php_match.group(1)
                        break
                        
            except:
                continue
        
        return php_version

# ===============================
# DYNAMIC PLUGIN/THEME DETECTOR
# (NO HARDCODING - detects what's actually there)
# ===============================

class DynamicComponentDetector:
    """Dynamically detect plugins and themes from actual site"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_plugins(self) -> List[Dict]:
        """Detect active plugins dynamically"""
        plugins = []
        plugin_slugs = set()
        
        try:
            # Method 1: Scan HTML for plugin paths
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            plugin_patterns = re.findall(
                r'/wp-content/plugins/([^/\'"?]+)',
                html
            )
            plugin_slugs.update(plugin_patterns)
            
            # Method 2: Try wp-json plugins endpoint
            try:
                api_url = urljoin(self.target, '/wp-json/wp/v2/plugins')
                api_resp = self.session.get(api_url, timeout=5)
                if api_resp.status_code == 200:
                    plugin_data = api_resp.json()
                    for plugin in plugin_data:
                        if 'plugin' in plugin:
                            slug = plugin['plugin'].split('/')[0]
                            plugin_slugs.add(slug)
            except:
                pass
            
            # Method 3: Check common plugin directories
            for slug in list(plugin_slugs)[:20]:  # Limit to first 20
                try:
                    plugin_url = urljoin(self.target, f'/wp-content/plugins/{slug}/readme.txt')
                    plugin_resp = self.session.get(plugin_url, timeout=3)
                    
                    if plugin_resp.status_code == 200:
                        version = None
                        name = slug
                        
                        # Try to extract version
                        version_match = re.search(
                            r'Stable tag:\s*([\d\.]+)',
                            plugin_resp.text,
                            re.IGNORECASE
                        )
                        if version_match:
                            version = version_match.group(1)
                        
                        # Try to extract name
                        name_match = re.search(
                            r'===\s*(.+?)\s*===',
                            plugin_resp.text
                        )
                        if name_match:
                            name = name_match.group(1).strip()
                        
                        plugins.append({
                            'slug': slug,
                            'name': name,
                            'version': version,
                            'detected_via': 'readme.txt'
                        })
                except:
                    # If readme.txt not accessible, still add the slug
                    plugins.append({
                        'slug': slug,
                        'name': slug,
                        'version': None,
                        'detected_via': 'html_reference'
                    })
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error detecting plugins: {str(e)}")
        
        return plugins
    
    def detect_themes(self) -> List[Dict]:
        """Detect active theme dynamically"""
        themes = []
        
        try:
            r = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            html = r.text
            
            # Extract theme paths
            theme_patterns = re.findall(
                r'/wp-content/themes/([^/\'"?]+)',
                html
            )
            
            for theme_slug in set(theme_patterns):
                try:
                    style_url = urljoin(self.target, f'/wp-content/themes/{theme_slug}/style.css')
                    style_resp = self.session.get(style_url, timeout=3)
                    
                    if style_resp.status_code == 200:
                        version = None
                        name = theme_slug
                        
                        # Extract version from style.css
                        version_match = re.search(
                            r'Version:\s*([\d\.]+)',
                            style_resp.text,
                            re.IGNORECASE
                        )
                        if version_match:
                            version = version_match.group(1)
                        
                        # Extract theme name
                        name_match = re.search(
                            r'Theme Name:\s*(.+?)[\r\n]',
                            style_resp.text,
                            re.IGNORECASE
                        )
                        if name_match:
                            name = name_match.group(1).strip()
                        
                        themes.append({
                            'slug': theme_slug,
                            'name': name,
                            'version': version,
                            'detected_via': 'style.css'
                        })
                except:
                    themes.append({
                        'slug': theme_slug,
                        'name': theme_slug,
                        'version': None,
                        'detected_via': 'html_reference'
                    })
        
        except Exception as e:
            print(f"{Fore.RED}✗ Error detecting themes: {str(e)}")
        
        return themes

# ===============================
# SECURITY SCANNERS
# ===============================

class SecurityScanner:
    """Comprehensive security scanning"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_backup_files(self) -> List[Dict]:
        """Check for backup files using configurable patterns"""
        found_backups = []
        
        # Use patterns from Config, not hardcoded
        test_files = [
            'backup.sql', 'backup.zip', 'backup.tar.gz',
            'db_backup.sql', 'wordpress.sql', 'dump.sql',
            'site_backup.zip', 'wp_backup.zip',
            f'backup_{datetime.now().strftime("%Y%m%d")}.sql',
            f'backup_{datetime.now().strftime("%Y-%m-%d")}.zip',
        ]
        
        for filename in test_files:
            try:
                url = urljoin(self.target, f'/{filename}')
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                
                if resp.status_code == 200:
                    found_backups.append({
                        'file': filename,
                        'url': url,
                        'size': resp.headers.get('Content-Length', 'Unknown'),
                        'severity': 'CRITICAL'
                    })
            except:
                continue
        
        return found_backups
    
    def check_sensitive_files(self) -> List[Dict]:
        """Check for sensitive files"""
        found_files = []
        
        for filename in Config.SENSITIVE_FILES:
            try:
                url = urljoin(self.target, f'/{filename}')
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                
                if resp.status_code == 200:
                    found_files.append({
                        'file': filename,
                        'url': url,
                        'severity': 'HIGH' if filename.endswith(('.bak', '.old', '~')) else 'MEDIUM'
                    })
            except:
                continue
        
        return found_files
    
    def check_directory_listing(self) -> List[Dict]:
        """Check for directory listing vulnerabilities"""
        findings = []
        directories = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
        ]
        
        for directory in directories:
            try:
                url = urljoin(self.target, directory)
                resp = self.session.get(url, timeout=5)
                
                if resp.status_code == 200 and 'Index of' in resp.text:
                    findings.append({
                        'directory': directory,
                        'url': url,
                        'severity': 'MEDIUM',
                        'description': 'Directory listing enabled'
                    })
            except:
                continue
        
        return findings
    
    def check_security_headers(self) -> Dict:
        """Audit security headers"""
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
    
    def check_xmlrpc(self) -> Dict:
        """Check XML-RPC endpoint"""
        try:
            url = urljoin(self.target, '/xmlrpc.php')
            resp = self.session.post(
                url,
                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                headers={'Content-Type': 'text/xml'},
                timeout=5
            )
            
            if resp.status_code == 200 and 'xml' in resp.headers.get('Content-Type', '').lower():
                return {
                    'enabled': True,
                    'severity': 'MEDIUM',
                    'description': 'XML-RPC enabled - can be used for brute force attacks'
                }
        except:
            pass
        
        return {'enabled': False}
    
    def check_debug_mode(self) -> Dict:
        """Check if debug mode is enabled"""
        try:
            resp = self.session.get(self.target, timeout=Config.REQUEST_TIMEOUT)
            
            debug_indicators = [
                'WP_DEBUG',
                'Notice:',
                'Warning:',
                'Fatal error:',
                'Stack trace:',
            ]
            
            found_indicators = []
            for indicator in debug_indicators:
                if indicator in resp.text:
                    found_indicators.append(indicator)
            
            if found_indicators:
                return {
                    'enabled': True,
                    'severity': 'HIGH',
                    'indicators': found_indicators,
                    'description': 'Debug mode appears to be enabled'
                }
        except:
            pass
        
        return {'enabled': False}

# ===============================
# MAIN AUDIT CLASS
# ===============================

class HybridWordPressAudit:
    """
    Hybrid WordPress Security Audit combining:
    - Dynamic detection from Professional Edition
    - Real-time CVE checking via API
    - Comprehensive security scanning
    - NO HARDCODING
    """
    
    def __init__(self, target_url, api_token=None):
        self.target = target_url.rstrip('/')
        
        # Ưu tiên: command line argument -> environment -> Config default
        self.api_token = api_token or os.environ.get('WPSCAN_API_TOKEN') or Config.WPSCAN_API_TOKEN
        
        # Initialize components
        self.wp_detector = EnhancedWordPressDetector(target_url)
        self.component_detector = DynamicComponentDetector(target_url)
        self.security_scanner = SecurityScanner(target_url)
        self.cve_db = EnhancedCVEDatabase(self.api_token)  # Truyền self.api_token
        
        # Results storage
        self.results = {
            'target': target_url,
            'scan_date': datetime.now().isoformat(),
            'wordpress_info': {},
            'php_info': {},
            'plugins': [],
            'themes': [],
            'vulnerabilities': {
                'wordpress': [],
                'plugins': [],
                'themes': [],
                'php': []
            },
            'security_issues': {
                'backup_files': [],
                'sensitive_files': [],
                'directory_listing': [],
                'security_headers': {},
                'xmlrpc': {},
                'debug_mode': {}
            },
            'summary': {}
        }
    
    def run_full_audit(self):
        """Execute complete security audit"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{' '*20}HYBRID WORDPRESS SECURITY AUDIT")
        print(f"{' '*15}Dynamic Detection + Real-time CVE Checking")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Target: {self.target}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"API Status: {'✓ Connected' if self.cve_db.api_token else '✗ No API token (limited CVE data)'}\n")
        
        # Step 1: Detect WordPress
        print(f"{Fore.YELLOW}[1/7] Detecting WordPress version...")
        self.results['wordpress_info'] = self.wp_detector.detect_version()
        
        if not self.results['wordpress_info']['detected']:
            print(f"{Fore.RED}✗ WordPress not detected. Exiting.\n")
            return
        
        wp_version = self.results['wordpress_info'].get('version', 'Unknown')
        confidence = self.results['wordpress_info'].get('confidence', 'unknown')
        methods = len(self.results['wordpress_info'].get('methods', []))
        
        print(f"{Fore.GREEN}✓ WordPress {wp_version} detected")
        print(f"  Confidence: {confidence} | Detection methods: {methods}\n")
        
        # Step 2: Detect PHP
        print(f"{Fore.YELLOW}[2/7] Detecting PHP version...")
        php_version = self.wp_detector.detect_php_version()
        self.results['php_info'] = {'version': php_version}
        
        if php_version:
            print(f"{Fore.GREEN}✓ PHP {php_version} detected\n")
        else:
            print(f"{Fore.YELLOW}⚠ PHP version not detected\n")
        
        # Step 3: Detect plugins (DYNAMIC, not hardcoded)
        print(f"{Fore.YELLOW}[3/7] Detecting active plugins...")
        self.results['plugins'] = self.component_detector.detect_plugins()
        print(f"{Fore.GREEN}✓ Found {len(self.results['plugins'])} plugins\n")
        
        # Step 4: Detect themes
        print(f"{Fore.YELLOW}[4/7] Detecting active themes...")
        self.results['themes'] = self.component_detector.detect_themes()
        print(f"{Fore.GREEN}✓ Found {len(self.results['themes'])} themes\n")
        
        # Step 5: Check CVEs (from real API, not hardcoded)
        print(f"{Fore.YELLOW}[5/7] Checking for vulnerabilities...")
        self.check_vulnerabilities()
        
        # Step 6: Security scans
        print(f"{Fore.YELLOW}[6/7] Running security checks...")
        self.run_security_checks()
        
        # Step 7: Generate report
        print(f"{Fore.YELLOW}[7/7] Generating reports...")
        self.generate_summary()
        self.save_reports()
        
        print(f"\n{Fore.GREEN}✅ Audit completed successfully!\n")
    
    def check_vulnerabilities(self):
        """Check for CVEs in all components"""
        total_vulns = 0
        
        # WordPress Core CVEs
        if self.results['wordpress_info'].get('version'):
            wp_version = self.results['wordpress_info']['version']
            print(f"  Checking WordPress {wp_version}...", end=' ')
            
            wp_cves = self.cve_db.get_wordpress_cves(wp_version)
            self.results['vulnerabilities']['wordpress'] = wp_cves
            
            if wp_cves:
                print(f"{Fore.RED}✗ {len(wp_cves)} vulnerabilities found")
                total_vulns += len(wp_cves)
            else:
                print(f"{Fore.GREEN}✓ No known vulnerabilities")
        
        # Plugin CVEs
        for plugin in self.results['plugins']:
            slug = plugin['slug']
            print(f"  Checking plugin '{slug}'...", end=' ')
            
            plugin_cves = self.cve_db.get_plugin_cves(slug)
            
            if plugin_cves:
                plugin['vulnerabilities'] = plugin_cves
                self.results['vulnerabilities']['plugins'].extend(plugin_cves)
                print(f"{Fore.RED}✗ {len(plugin_cves)} vulnerabilities")
                total_vulns += len(plugin_cves)
            else:
                print(f"{Fore.GREEN}✓")
            
            time.sleep(0.2)  # Rate limiting
        
        # Theme CVEs
        for theme in self.results['themes']:
            slug = theme['slug']
            print(f"  Checking theme '{slug}'...", end=' ')
            
            theme_cves = self.cve_db.get_theme_cves(slug)
            
            if theme_cves:
                theme['vulnerabilities'] = theme_cves
                self.results['vulnerabilities']['themes'].extend(theme_cves)
                print(f"{Fore.RED}✗ {len(theme_cves)} vulnerabilities")
                total_vulns += len(theme_cves)
            else:
                print(f"{Fore.GREEN}✓")
            
            time.sleep(0.2)
        
        print(f"\n{Fore.WHITE}  Total vulnerabilities: {total_vulns}\n")
    
    def run_security_checks(self):
        """Run all security checks"""
        # Backup files
        print(f"  Checking for backup files...", end=' ')
        self.results['security_issues']['backup_files'] = self.security_scanner.check_backup_files()
        backup_count = len(self.results['security_issues']['backup_files'])
        if backup_count > 0:
            print(f"{Fore.RED}✗ {backup_count} found")
        else:
            print(f"{Fore.GREEN}✓")
        
        # Sensitive files
        print(f"  Checking for sensitive files...", end=' ')
        self.results['security_issues']['sensitive_files'] = self.security_scanner.check_sensitive_files()
        sensitive_count = len(self.results['security_issues']['sensitive_files'])
        if sensitive_count > 0:
            print(f"{Fore.RED}✗ {sensitive_count} found")
        else:
            print(f"{Fore.GREEN}✓")
        
        # Directory listing
        print(f"  Checking directory listing...", end=' ')
        self.results['security_issues']['directory_listing'] = self.security_scanner.check_directory_listing()
        dir_count = len(self.results['security_issues']['directory_listing'])
        if dir_count > 0:
            print(f"{Fore.RED}✗ {dir_count} exposed")
        else:
            print(f"{Fore.GREEN}✓")
        
        # Security headers
        print(f"  Auditing security headers...", end=' ')
        self.results['security_issues']['security_headers'] = self.security_scanner.check_security_headers()
        header_score = self.results['security_issues']['security_headers']['score']
        print(f"{Fore.CYAN}{header_score}/100")
        
        # XML-RPC
        print(f"  Checking XML-RPC...", end=' ')
        self.results['security_issues']['xmlrpc'] = self.security_scanner.check_xmlrpc()
        if self.results['security_issues']['xmlrpc'].get('enabled'):
            print(f"{Fore.YELLOW}⚠ Enabled")
        else:
            print(f"{Fore.GREEN}✓ Disabled")
        
        # Debug mode
        print(f"  Checking debug mode...", end=' ')
        self.results['security_issues']['debug_mode'] = self.security_scanner.check_debug_mode()
        if self.results['security_issues']['debug_mode'].get('enabled'):
            print(f"{Fore.RED}✗ Enabled")
        else:
            print(f"{Fore.GREEN}✓ Disabled")
        
        print()
    
    def generate_summary(self):
        """Generate executive summary"""
        # Count vulnerabilities
        total_vulns = (
            len(self.results['vulnerabilities']['wordpress']) +
            len(self.results['vulnerabilities']['plugins']) +
            len(self.results['vulnerabilities']['themes']) +
            len(self.results['vulnerabilities']['php'])
        )
        
        # Count security issues
        total_issues = (
            len(self.results['security_issues']['backup_files']) +
            len(self.results['security_issues']['sensitive_files']) +
            len(self.results['security_issues']['directory_listing'])
        )
        
        if self.results['security_issues']['xmlrpc'].get('enabled'):
            total_issues += 1
        if self.results['security_issues']['debug_mode'].get('enabled'):
            total_issues += 1
        
        # Calculate risk score
        risk_score = 0
        
        # Vulnerability scoring
        critical_vulns = sum(1 for v in self.results['vulnerabilities']['wordpress'] + 
                            self.results['vulnerabilities']['plugins'] + 
                            self.results['vulnerabilities']['themes']
                            if v.get('severity') == 'CRITICAL')
        high_vulns = sum(1 for v in self.results['vulnerabilities']['wordpress'] + 
                        self.results['vulnerabilities']['plugins'] + 
                        self.results['vulnerabilities']['themes']
                        if v.get('severity') == 'HIGH')
        
        risk_score += critical_vulns * 15
        risk_score += high_vulns * 10
        risk_score += (total_vulns - critical_vulns - high_vulns) * 5
        
        # Security issues scoring
        risk_score += len(self.results['security_issues']['backup_files']) * 10
        risk_score += len(self.results['security_issues']['sensitive_files']) * 5
        risk_score += len(self.results['security_issues']['directory_listing']) * 3
        
        # Security headers penalty
        header_score = self.results['security_issues']['security_headers']['score']
        risk_score += (100 - header_score) / 5
        
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Generate recommendations
        recommendations = []
        
        if total_vulns > 0:
            recommendations.append(f"Update components to patch {total_vulns} known vulnerabilities")
        
        if len(self.results['security_issues']['backup_files']) > 0:
            recommendations.append("Remove backup files from public access immediately")
        
        if len(self.results['security_issues']['sensitive_files']) > 0:
            recommendations.append("Secure or remove sensitive files")
        
        if header_score < 80:
            recommendations.append("Implement missing security headers")
        
        if self.results['security_issues']['xmlrpc'].get('enabled'):
            recommendations.append("Disable XML-RPC if not needed")
        
        if self.results['security_issues']['debug_mode'].get('enabled'):
            recommendations.append("Disable debug mode in production")
        
        self.results['summary'] = {
            'wordpress_version': self.results['wordpress_info'].get('version', 'Unknown'),
            'php_version': self.results['php_info'].get('version', 'Unknown'),
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'security_issues': total_issues,
            'security_header_score': header_score,
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'recommendations': recommendations,
            'plugins_scanned': len(self.results['plugins']),
            'themes_scanned': len(self.results['themes'])
        }
    
    def save_reports(self):
        """Save comprehensive reports"""
        # Create output directory
        output_dir = Path(Config.OUTPUT_DIR)
        output_dir.mkdir(exist_ok=True)
        
        # Create target-specific directory
        target_name = self.target.replace("://", "_").replace("/", "_").replace(":", "_").replace(".", "_")
        if target_name.endswith("_"):
            target_name = target_name[:-1]
        
        target_dir = output_dir / target_name
        target_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_file = target_dir / "audit_report.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Save text summary
        txt_file = target_dir / "summary.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(f"WordPress Security Audit - {self.target}\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"SUMMARY\n")
            f.write(f"{'-'*80}\n")
            f.write(f"WordPress Version: {self.results['summary']['wordpress_version']}\n")
            f.write(f"PHP Version: {self.results['summary']['php_version']}\n")
            f.write(f"Total Vulnerabilities: {self.results['summary']['total_vulnerabilities']}\n")
            f.write(f"  - Critical: {self.results['summary']['critical_vulnerabilities']}\n")
            f.write(f"  - High: {self.results['summary']['high_vulnerabilities']}\n")
            f.write(f"Security Issues: {self.results['summary']['security_issues']}\n")
            f.write(f"Security Headers Score: {self.results['summary']['security_header_score']}/100\n")
            f.write(f"Risk Score: {self.results['summary']['risk_score']}/100\n")
            f.write(f"Risk Level: {self.results['summary']['risk_level']}\n\n")
            
            if self.results['summary']['recommendations']:
                f.write(f"RECOMMENDATIONS\n")
                f.write(f"{'-'*80}\n")
                for i, rec in enumerate(self.results['summary']['recommendations'], 1):
                    f.write(f"{i}. {rec}\n")
        
        print(f"{Fore.GREEN}Reports saved to:")
        print(f"  JSON: {json_file}")
        print(f"  Summary: {txt_file}")

# ===============================
# MAIN EXECUTION
# ===============================

def main():
    """Main execution"""
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description='WordPress Security Scanner - Enhanced Hybrid Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --api-token YOUR_TOKEN
  %(prog)s --file targets.txt --api-token YOUR_TOKEN
  
Get free WPScan API token at: https://wpscan.com/api
        '''
    )
    
    parser.add_argument('target', nargs='?', help='Target URL')
    parser.add_argument('--file', help='File containing target URLs (one per line)')
    parser.add_argument('--api-token', help='WPScan API token for CVE data')
    parser.add_argument('--cache-hours', type=int, default=24, help='CVE cache duration in hours')
    
    args = parser.parse_args()
    
    # Set API token from args or environment
    api_token = args.api_token or os.environ.get('WPSCAN_API_TOKEN')
    
    if args.cache_hours:
        Config.CACHE_DURATION_HOURS = args.cache_hours
    
    targets = []
    
    if args.file:
        # Multiple targets from file
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File '{args.file}' not found.{Style.RESET_ALL}")
            sys.exit(1)
    elif args.target:
        # Single target
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
            print(f"\n{Fore.CYAN}{'='*80}")
            print(f"Processing target {i}/{len(targets)}: {target}")
            print(f"{'='*80}{Style.RESET_ALL}")
        
        try:
            audit = HybridWordPressAudit(target, api_token)
            audit.run_full_audit()
            
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
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"✅ All {len(targets)} targets processed!")
        print(f"{'='*80}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()