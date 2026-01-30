#!/usr/bin/env python3
"""
WORDPRESS ULTIMATE SCANNER v4.0
Tổng hợp tất cả tính năng tốt nhất từ: deeep.py, pipline.py, quick_scaner.py, wpscanIPs3_0.py

Tính năng:
- Multi-source discovery (DuckDuckGo, RapidDNS, Custom sources)
- Real-time processing & display với progress bar
- Deep enumeration (plugins, themes, users, vulnerabilities)
- Async/sync hybrid architecture
- Smart filtering & CDN detection
- CVE matching & risk scoring
- Multiple output formats (JSON, TXT, CSV)
- Fully configurable via CLI & config file
"""

import asyncio
import aiohttp
import aiodns
import time
import random
import json
import re
import os
import sys
import ipaddress
import hashlib
import warnings
import argparse
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, Tuple
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

# Optional imports với fallback
try:
    from ddgs import DDGS
    DDGS_AVAILABLE = True
except ImportError:
    DDGS_AVAILABLE = False
    print("⚠️  Warning: duckduckgo-search not installed. DuckDuckGo discovery disabled.")
    print("   Install: pip install duckduckgo-search")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  Warning: requests not installed. Some features may be limited.")
    print("   Install: pip install requests")

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

warnings.filterwarnings('ignore')

# =================== CONFIGURATION CLASS ===================
class ScanConfig:
    """Centralized configuration - có thể load từ file hoặc CLI"""
    
    def __init__(self, config_file: Optional[str] = None):
        # Default values
        self.load_defaults()
        
        # Load from config file if provided
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
    
    def load_defaults(self):
        """Load default configuration"""
        # General settings
        self.max_concurrent_tasks = 30
        self.request_timeout = 8
        self.dns_timeout = 2
        
        # Discovery settings
        self.num_results_per_dork = 75
        self.delay_min = 1.5
        self.delay_max = 3.0
        self.max_workers_discovery = 5
        self.max_workers_scan = 8
        
        # Target settings
        self.target_tlds = ['.vn', '.com.vn', '.net.vn', '.org.vn', '.edu.vn', '.gov.vn']
        
        # Dorks for discovery
        self.dorks = [
            '"Powered by WordPress" site:.vn',
            '"Powered by WordPress" site:.com.vn',
            'intext:"WordPress" site:.vn generator:"WordPress"',
            'inurl:/wp-content/plugins/ site:.vn',
            'inurl:/wp-admin/ intitle:"Log In" site:.vn',
            'inurl:wp-login.php site:.vn',
            'inurl:/wp-content/themes/ site:.vn',
            'meta name="generator" content="WordPress" site:.vn',
            'inurl:wp-json/wp/v2/ site:.vn',
            'inurl:/wp-content/plugins/elementor/ site:.vn',
            'inurl:/wp-content/plugins/woocommerce/ site:.vn',
            'inurl:/wp-content/plugins/contact-form-7/ site:.vn',
        ]
        
        # Popular plugins database
        self.popular_plugins = {
            'yoast-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
            'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
            'all-in-one-seo-pack': {'name': 'All in One SEO', 'category': 'SEO', 'installs': '3M+'},
            'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
            'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
            'wpforms-lite': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
            'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
            'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
            'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
            'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
            'revslider': {'name': 'Revolution Slider', 'category': 'Slider', 'installs': '10M+'},
            'akismet': {'name': 'Akismet', 'category': 'Security', 'installs': '5M+'},
            'wp-rocket': {'name': 'WP Rocket', 'category': 'Performance', 'installs': '2M+'},
            'updraftplus': {'name': 'UpdraftPlus', 'category': 'Backup', 'installs': '3M+'},
            'google-site-kit': {'name': 'Site Kit by Google', 'category': 'Analytics', 'installs': '5M+'},
        }
        
        # CVE Database
        self.cve_database = {
            'wordpress': {
                '6.1': {'<6.1.1': ['CVE-2023-28121', 'CVE-2023-28122']},
                '6.0': {'<6.0.5': ['CVE-2023-0031', 'CVE-2022-35945']},
                '5.9': {'<5.9.5': ['CVE-2022-35944', 'CVE-2022-35943']},
                '5.8': {'<5.8.5': ['CVE-2022-21662', 'CVE-2022-21661']},
                '5.0-5.9': ['CVE-2020-28032', 'CVE-2021-44223'],
                '4.0-4.9': ['CVE-2019-17671', 'CVE-2020-11025'],
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
        
        # PHP vulnerabilities
        self.php_vulnerabilities = {
            '7.4': {
                '<7.4.30': ['CVE-2022-31626', 'CVE-2022-31625'],
                '<7.4.28': ['CVE-2022-22776'],
            },
            '8.0': {
                '<8.0.20': ['CVE-2022-31626'],
                '<8.0.19': ['CVE-2022-27778'],
            },
            '8.1': {
                '<8.1.7': ['CVE-2022-31629'],
                '<8.1.6': ['CVE-2022-29187'],
            }
        }
        
        # Blacklist patterns
        self.blacklist_patterns = [
            'wordpress.com', 'blogspot.com', 'wixsite.com', 'weebly.com',
            'shopify.com', 'squarespace.com', 'medium.com', 'github.com',
            'cloudflare', 'akamai', 'fastly', 'googleusercontent',
        ]
        
        # Headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        # Output settings
        self.output_dir = 'scan_results'
        self.output_formats = ['json', 'txt', 'csv']
        self.save_vulnerable_only = False
        
    def load_from_file(self, config_file: str):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                
            # Update attributes từ config file
            for key, value in config_data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                    
            print(f"✓ Loaded config from {config_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file: {e}")
    
    def save_to_file(self, config_file: str):
        """Save current configuration to file"""
        config_data = {
            key: value for key, value in self.__dict__.items()
            if not key.startswith('_')
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved config to {config_file}")

# =================== DISPLAY MANAGER ===================
class DisplayManager:
    """Quản lý hiển thị real-time với màu sắc và progress"""
    
    COLORS = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[33m',    # Orange
        'low': '\033[92m',       # Green
        'info': '\033[94m',      # Blue
        'wp': '\033[96m',        # Cyan
        'success': '\033[92m',   # Green
        'warning': '\033[93m',   # Yellow
        'error': '\033[91m',     # Red
        'reset': '\033[0m',
    }
    
    def __init__(self):
        self.stats = {
            'total_discovered': 0,
            'total_scanned': 0,
            'wp_detected': 0,
            'vulnerable': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def print_banner(self):
        """Display banner"""
        banner = f"""
{self.COLORS['wp']}╔══════════════════════════════════════════════════════════════════╗
║          WORDPRESS ULTIMATE SCANNER v4.0                       ║
║          Multi-Source Discovery + Deep Enumeration             ║
║          Real-time Processing + Smart Filtering                ║
╚══════════════════════════════════════════════════════════════════╝{self.COLORS['reset']}
        """
        print(banner)
    
    def print_phase(self, phase: str, description: str):
        """Print phase header"""
        print(f"\n{self.COLORS['info']}[PHASE {phase}] {description}{self.COLORS['reset']}")
        print(f"{self.COLORS['info']}{'─' * 70}{self.COLORS['reset']}")
    
    def print_discovery(self, domain: str, source: str):
        """Print discovered domain"""
        with self.lock:
            self.stats['total_discovered'] += 1
        print(f"{self.COLORS['success']}[+] {domain:<45} ({source}){self.COLORS['reset']}")
    
    def print_wp_detected(self, domain: str, confidence: int, version: str = ''):
        """Print WordPress detection"""
        with self.lock:
            self.stats['wp_detected'] += 1
        
        color = self.COLORS['wp'] if confidence >= 80 else self.COLORS['medium']
        version_str = f"v{version}" if version else "Unknown"
        print(f"{color}✓ WP{self.COLORS['reset']} {domain:<40} Conf:{confidence:>3}% Ver:{version_str}")
    
    def print_vulnerability(self, domain: str, risk_score: int, details: Dict):
        """Print vulnerability finding"""
        with self.lock:
            self.stats['vulnerable'] += 1
            if risk_score >= 80:
                self.stats['critical'] += 1
                level = 'CRITICAL'
                color = self.COLORS['critical']
            elif risk_score >= 60:
                self.stats['high'] += 1
                level = 'HIGH'
                color = self.COLORS['high']
            elif risk_score >= 40:
                self.stats['medium'] += 1
                level = 'MEDIUM'
                color = self.COLORS['medium']
            else:
                self.stats['low'] += 1
                level = 'LOW'
                color = self.COLORS['low']
        
        print(f"\n{color}{'═' * 70}{self.COLORS['reset']}")
        print(f"{color}🚨 VULNERABILITY: {domain} [{level}]{self.COLORS['reset']}")
        print(f"{color}   Risk Score: {risk_score}/100{self.COLORS['reset']}")
        
        if 'wp_version' in details:
            print(f"{color}   WordPress: {details['wp_version']}{self.COLORS['reset']}")
        if 'cves' in details and details['cves']:
            print(f"{color}   CVEs: {', '.join(details['cves'][:3])}{self.COLORS['reset']}")
        if 'plugins' in details:
            print(f"{color}   Plugins: {details['plugins']}{self.COLORS['reset']}")
        
        print(f"{color}{'═' * 70}{self.COLORS['reset']}\n")
    
    def print_stats(self):
        """Print final statistics"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{self.COLORS['wp']}{'═' * 70}{self.COLORS['reset']}")
        print(f"{self.COLORS['wp']}📊 SCAN STATISTICS ({elapsed:.1f}s){self.COLORS['reset']}")
        print(f"{self.COLORS['wp']}{'═' * 70}{self.COLORS['reset']}")
        print(f"Total Domains Discovered:  {self.stats['total_discovered']}")
        print(f"Total Scanned:             {self.stats['total_scanned']}")
        print(f"WordPress Sites:           {self.stats['wp_detected']}")
        print(f"Vulnerable Sites:          {self.stats['vulnerable']}")
        print(f"\n{self.COLORS['critical']}Risk Distribution:{self.COLORS['reset']}")
        print(f"  • CRITICAL: {self.stats['critical']}")
        print(f"  • HIGH:     {self.stats['high']}")
        print(f"  • MEDIUM:   {self.stats['medium']}")
        print(f"  • LOW:      {self.stats['low']}")
        print(f"{self.COLORS['wp']}{'═' * 70}{self.COLORS['reset']}\n")

# =================== UTILITY FUNCTIONS ===================
class Utils:
    """Utility functions"""
    
    @staticmethod
    def is_ip(domain: str) -> bool:
        """Check if domain is IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract clean domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.replace('www.', '')
            
            # Remove port
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain if domain and '.' in domain else None
        except:
            return None
    
    @staticmethod
    def looks_like_cdn(domain: str, config: ScanConfig) -> bool:
        """Check if domain looks like CDN/API"""
        domain_lower = domain.lower()
        
        # Quick keyword check
        cdn_keywords = ['cdn', 'api', 'cloudflare', 'akamai', 'fastly', 'cloudfront',
                       'azureedge', 'gstatic', 'googleapis', 'amazonaws']
        
        if any(kw in domain_lower for kw in cdn_keywords):
            return True
        
        # Too many subdomains
        if domain.count('.') >= 4:
            return True
        
        # Check blacklist
        for pattern in config.blacklist_patterns:
            if pattern in domain_lower:
                return True
        
        return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format"""
        if not domain or len(domain) < 4:
            return False
        
        # Basic validation
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False
        
        return True

# =================== DOMAIN DISCOVERER ===================
class DomainDiscoverer:
    """Multi-source domain discovery"""
    
    def __init__(self, config: ScanConfig, display: DisplayManager):
        self.config = config
        self.display = display
        self.discovered_domains = set()
        self.lock = threading.Lock()
    
    def discover_from_duckduckgo(self) -> Set[str]:
        """Discover domains using DuckDuckGo"""
        if not DDGS_AVAILABLE:
            print("⚠️  DuckDuckGo discovery skipped (library not installed)")
            return set()
        
        print(f"[*] Running {len(self.config.dorks)} DuckDuckGo dorks...")
        domains = set()
        
        def process_dork(dork: str) -> Set[str]:
            local_domains = set()
            try:
                time.sleep(random.uniform(self.config.delay_min, self.config.delay_max))
                
                with DDGS() as ddgs:
                    results = ddgs.text(
                        query=dork,
                        region="vn-vn",
                        safesearch="off",
                        max_results=self.config.num_results_per_dork,
                        timeout=10
                    )
                    
                    for result in results:
                        url = result.get('href', '') or result.get('url', '')
                        if url:
                            domain = Utils.extract_domain(url)
                            if domain and Utils.is_valid_domain(domain):
                                if not Utils.looks_like_cdn(domain, self.config):
                                    local_domains.add(domain)
                                    self.display.print_discovery(domain, 'DDG')
            except Exception as e:
                pass
            
            return local_domains
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers_discovery) as executor:
            futures = [executor.submit(process_dork, dork) for dork in self.config.dorks]
            
            for future in as_completed(futures):
                result_domains = future.result()
                domains.update(result_domains)
        
        return domains
    
    def discover_from_rapiddns(self, seed_domains: Set[str]) -> Set[str]:
        """Discover domains using RapidDNS"""
        if not REQUESTS_AVAILABLE:
            return set()
        
        print(f"[*] Expanding {len(seed_domains)} seeds via RapidDNS...")
        domains = set()
        
        for seed in list(seed_domains)[:50]:  # Limit seeds
            try:
                base_domain = seed.replace('www.', '')
                url = f"https://rapiddns.io/subdomain/{base_domain}?full=1"
                
                response = requests.get(url, timeout=10, headers=self.config.headers)
                if response.status_code == 200:
                    found = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', response.text)
                    
                    for match in found:
                        domain = match[0].rstrip('.')
                        if Utils.is_valid_domain(domain) and not Utils.looks_like_cdn(domain, self.config):
                            if any(domain.endswith(tld) for tld in self.config.target_tlds):
                                domains.add(domain)
                
                time.sleep(random.uniform(0.5, 1.0))
            except:
                pass
        
        print(f"[*] RapidDNS found {len(domains)} additional domains")
        return domains
    
    def discover_from_file(self, filepath: str) -> Set[str]:
        """Load domains from file"""
        domains = set()
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domain = Utils.extract_domain(line)
                        if domain and Utils.is_valid_domain(domain):
                            domains.add(domain)
                            self.display.print_discovery(domain, 'FILE')
            
            print(f"[*] Loaded {len(domains)} domains from {filepath}")
        except Exception as e:
            print(f"⚠️  Error loading file: {e}")
        
        return domains
    
    def discover_all(self, targets_file: Optional[str] = None) -> Set[str]:
        """Run all discovery methods"""
        all_domains = set()
        
        # From file if provided
        if targets_file:
            file_domains = self.discover_from_file(targets_file)
            all_domains.update(file_domains)
        
        # From DuckDuckGo
        ddg_domains = self.discover_from_duckduckgo()
        all_domains.update(ddg_domains)
        
        # RapidDNS expansion on DDG results
        if ddg_domains:
            rapid_domains = self.discover_from_rapiddns(ddg_domains)
            all_domains.update(rapid_domains)
        
        return all_domains

# =================== WORDPRESS DETECTOR ===================
class WordPressDetector:
    """Async WordPress detection với confidence scoring"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = None
    
    async def create_session(self):
        """Create aiohttp session"""
        connector = aiohttp.TCPConnector(limit=50, ssl=False, force_close=True)
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.config.headers
        )
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.25)
    
    async def detect(self, domain: str) -> Dict[str, Any]:
        """Detect WordPress on domain"""
        result = {
            'domain': domain,
            'is_wp': False,
            'confidence': 0,
            'version': '',
            'base_url': '',
            'signals': []
        }
        
        if not self.session:
            await self.create_session()
        
        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:
            url = f"{protocol}://{domain}"
            
            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    if resp.status >= 400:
                        continue
                    
                    result['base_url'] = str(resp.url)
                    html = await resp.text()
                    headers = resp.headers
                    
                    # Check signals
                    confidence = 0
                    signals = []
                    
                    # Signal 1: wp-content in HTML (20 points)
                    if '/wp-content/' in html:
                        confidence += 20
                        signals.append('wp-content')
                    
                    # Signal 2: wp-includes (15 points)
                    if '/wp-includes/' in html:
                        confidence += 15
                        signals.append('wp-includes')
                    
                    # Signal 3: Generator meta tag (15 points)
                    if 'WordPress' in html and 'generator' in html.lower():
                        confidence += 15
                        signals.append('generator-tag')
                        
                        # Extract version
                        version_match = re.search(r'content=["\']WordPress\s+([\d.]+)', html, re.I)
                        if version_match:
                            result['version'] = version_match.group(1)
                    
                    # Signal 4: wp-login.php (25 points)
                    try:
                        login_url = urljoin(result['base_url'], '/wp-login.php')
                        async with self.session.get(login_url, allow_redirects=False) as login_resp:
                            if login_resp.status < 400:
                                confidence += 25
                                signals.append('wp-login')
                    except:
                        pass
                    
                    # Signal 5: wp-json API (15 points)
                    try:
                        api_url = urljoin(result['base_url'], '/wp-json/')
                        async with self.session.get(api_url) as api_resp:
                            if api_resp.status == 200:
                                confidence += 15
                                signals.append('wp-json')
                                
                                # Try to get version from API
                                if not result['version']:
                                    try:
                                        api_data = await api_resp.json()
                                        if 'namespaces' in api_data and 'wp/v2' in api_data['namespaces']:
                                            result['version'] = api_data.get('_links', {}).get('wp:featuredmedia', [{}])[0].get('version', '')
                                    except:
                                        pass
                    except:
                        pass
                    
                    # Signal 6: X-Powered-By header
                    if 'X-Powered-By' in headers:
                        powered_by = headers['X-Powered-By'].lower()
                        if 'wordpress' in powered_by:
                            confidence += 10
                            signals.append('x-powered-by')
                    
                    result['confidence'] = min(confidence, 100)
                    result['signals'] = signals
                    result['is_wp'] = confidence >= 30
                    
                    if result['is_wp']:
                        break
                    
            except Exception as e:
                continue
        
        return result

# =================== DEEP ENUMERATOR ===================
class DeepEnumerator:
    """Deep enumeration: plugins, themes, users, etc."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = None
    
    async def create_session(self):
        """Create aiohttp session"""
        connector = aiohttp.TCPConnector(limit=50, ssl=False, force_close=True)
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.config.headers
        )
    
    async def close_session(self):
        """Close session"""
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.25)
    
    async def enumerate(self, wp_info: Dict) -> Dict[str, Any]:
        """Deep enumeration"""
        if not self.session:
            await self.create_session()
        
        base_url = wp_info['base_url']
        result = {
            'plugins': [],
            'theme': {},
            'users': [],
            'endpoints': {
                'xmlrpc': False,
                'rest_api': False,
            },
            'server_info': {}
        }
        
        # Enumerate plugins
        plugins = await self._enumerate_plugins(base_url)
        result['plugins'] = plugins
        
        # Detect theme
        theme = await self._detect_theme(base_url)
        result['theme'] = theme
        
        # Check endpoints
        result['endpoints']['xmlrpc'] = await self._check_xmlrpc(base_url)
        result['endpoints']['rest_api'] = await self._check_rest_api(base_url)
        
        # Get server info
        server_info = await self._get_server_info(base_url)
        result['server_info'] = server_info
        
        # Enumerate users (if REST API available)
        if result['endpoints']['rest_api']:
            users = await self._enumerate_users(base_url)
            result['users'] = users
        
        return result
    
    async def _enumerate_plugins(self, base_url: str) -> List[Dict]:
        """Enumerate plugins"""
        plugins = []
        
        # Check popular plugins first
        for plugin_slug in list(self.config.popular_plugins.keys())[:20]:
            try:
                plugin_url = urljoin(base_url, f'/wp-content/plugins/{plugin_slug}/')
                
                async with self.session.get(plugin_url, allow_redirects=False) as resp:
                    if resp.status in [200, 403]:
                        plugin_info = self.config.popular_plugins[plugin_slug].copy()
                        plugin_info['slug'] = plugin_slug
                        plugin_info['detected'] = True
                        
                        # Try to get version
                        version = await self._get_plugin_version(base_url, plugin_slug)
                        if version:
                            plugin_info['version'] = version
                        
                        plugins.append(plugin_info)
            except:
                pass
        
        # Try to enumerate from HTML
        try:
            async with self.session.get(base_url) as resp:
                html = await resp.text()
                
                plugin_matches = re.findall(r'/wp-content/plugins/([^/\'"]+)', html)
                for plugin_slug in set(plugin_matches):
                    if plugin_slug not in [p['slug'] for p in plugins]:
                        plugins.append({
                            'slug': plugin_slug,
                            'name': plugin_slug.replace('-', ' ').title(),
                            'detected': True
                        })
        except:
            pass
        
        return plugins
    
    async def _get_plugin_version(self, base_url: str, plugin_slug: str) -> Optional[str]:
        """Try to get plugin version"""
        # Common version files
        version_files = [
            f'/wp-content/plugins/{plugin_slug}/readme.txt',
            f'/wp-content/plugins/{plugin_slug}/README.txt',
            f'/wp-content/plugins/{plugin_slug}/readme.md'
        ]
        
        for file_path in version_files:
            try:
                url = urljoin(base_url, file_path)
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        version_match = re.search(r'Stable tag:\s*([0-9.]+)', content, re.I)
                        if version_match:
                            return version_match.group(1)
            except:
                pass
        
        return None
    
    async def _detect_theme(self, base_url: str) -> Dict:
        """Detect active theme"""
        theme_info = {}
        
        try:
            async with self.session.get(base_url) as resp:
                html = await resp.text()
                
                # Find theme from HTML
                theme_match = re.search(r'/wp-content/themes/([^/\'"]+)', html)
                if theme_match:
                    theme_slug = theme_match.group(1)
                    theme_info['slug'] = theme_slug
                    theme_info['name'] = theme_slug.replace('-', ' ').title()
                    
                    # Try to get version
                    version = await self._get_theme_version(base_url, theme_slug)
                    if version:
                        theme_info['version'] = version
        except:
            pass
        
        return theme_info
    
    async def _get_theme_version(self, base_url: str, theme_slug: str) -> Optional[str]:
        """Get theme version"""
        try:
            style_url = urljoin(base_url, f'/wp-content/themes/{theme_slug}/style.css')
            async with self.session.get(style_url) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    version_match = re.search(r'Version:\s*([0-9.]+)', content, re.I)
                    if version_match:
                        return version_match.group(1)
        except:
            pass
        
        return None
    
    async def _check_xmlrpc(self, base_url: str) -> bool:
        """Check if XML-RPC is enabled"""
        try:
            url = urljoin(base_url, '/xmlrpc.php')
            async with self.session.post(url, data='') as resp:
                if resp.status == 405:  # Method Not Allowed = exists
                    return True
                if resp.status == 200:
                    text = await resp.text()
                    return 'XML-RPC' in text
        except:
            pass
        
        return False
    
    async def _check_rest_api(self, base_url: str) -> bool:
        """Check if REST API is accessible"""
        try:
            url = urljoin(base_url, '/wp-json/')
            async with self.session.get(url) as resp:
                return resp.status == 200
        except:
            pass
        
        return False
    
    async def _get_server_info(self, base_url: str) -> Dict:
        """Get server information"""
        info = {}
        
        try:
            async with self.session.get(base_url) as resp:
                headers = resp.headers
                
                if 'Server' in headers:
                    info['webserver'] = headers['Server']
                
                if 'X-Powered-By' in headers:
                    powered_by = headers['X-Powered-By']
                    info['powered_by'] = powered_by
                    
                    # Extract PHP version
                    php_match = re.search(r'PHP/([\d.]+)', powered_by)
                    if php_match:
                        info['php_version'] = php_match.group(1)
        except:
            pass
        
        return info
    
    async def _enumerate_users(self, base_url: str) -> List[Dict]:
        """Enumerate users via REST API"""
        users = []
        
        try:
            url = urljoin(base_url, '/wp-json/wp/v2/users')
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    users_data = await resp.json()
                    for user in users_data[:10]:  # Limit to 10 users
                        users.append({
                            'id': user.get('id'),
                            'name': user.get('name'),
                            'slug': user.get('slug'),
                            'url': user.get('url')
                        })
        except:
            pass
        
        return users

# =================== VULNERABILITY ANALYZER ===================
class VulnerabilityAnalyzer:
    """Analyze vulnerabilities and calculate risk score"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
    
    def analyze(self, wp_info: Dict, enum_data: Dict) -> Dict[str, Any]:
        """Analyze vulnerabilities"""
        result = {
            'risk_score': 0,
            'cves': [],
            'findings': [],
            'recommendations': []
        }
        
        risk_score = 0
        
        # 1. WordPress version vulnerabilities
        wp_version = wp_info.get('version', '')
        if wp_version:
            wp_cves = self._check_wp_cves(wp_version)
            if wp_cves:
                result['cves'].extend(wp_cves)
                risk_score += len(wp_cves) * 10
                result['findings'].append(f"WordPress {wp_version} has {len(wp_cves)} known CVEs")
        
        # 2. Plugin vulnerabilities
        for plugin in enum_data.get('plugins', []):
            plugin_slug = plugin.get('slug', '')
            plugin_version = plugin.get('version', '')
            
            if plugin_slug in self.config.cve_database:
                plugin_cves = self._check_plugin_cves(plugin_slug, plugin_version)
                if plugin_cves:
                    result['cves'].extend(plugin_cves)
                    risk_score += len(plugin_cves) * 8
                    result['findings'].append(f"Plugin {plugin_slug} has {len(plugin_cves)} CVEs")
        
        # 3. Old WordPress version
        if wp_version:
            try:
                major_version = float('.'.join(wp_version.split('.')[:2]))
                if major_version < 6.0:
                    risk_score += 15
                    result['findings'].append(f"Outdated WordPress version: {wp_version}")
                    result['recommendations'].append("Update WordPress to latest version")
            except:
                pass
        
        # 4. PHP version vulnerabilities
        php_version = enum_data.get('server_info', {}).get('php_version', '')
        if php_version:
            php_cves = self._check_php_cves(php_version)
            if php_cves:
                result['cves'].extend(php_cves)
                risk_score += len(php_cves) * 6
                result['findings'].append(f"PHP {php_version} has {len(php_cves)} CVEs")
        
        # 5. XML-RPC enabled
        if enum_data.get('endpoints', {}).get('xmlrpc', False):
            risk_score += 10
            result['findings'].append("XML-RPC endpoint is enabled (DDoS/brute-force risk)")
            result['recommendations'].append("Disable XML-RPC if not needed")
        
        # 6. Users enumeration
        if enum_data.get('users', []):
            risk_score += 8
            result['findings'].append(f"User enumeration possible ({len(enum_data['users'])} users exposed)")
            result['recommendations'].append("Disable REST API user endpoint")
        
        # 7. No security plugin detected
        security_plugins = ['wordfence', 'better-wp-security', 'sucuri-scanner', 
                          'all-in-one-wp-security-and-firewall']
        has_security = any(p.get('slug') in security_plugins for p in enum_data.get('plugins', []))
        
        if not has_security:
            risk_score += 5
            result['findings'].append("No security plugin detected")
            result['recommendations'].append("Install a security plugin (Wordfence, iThemes Security)")
        
        result['risk_score'] = min(risk_score, 100)
        
        return result
    
    def _check_wp_cves(self, version: str) -> List[str]:
        """Check WordPress CVEs"""
        cves = []
        
        try:
            major_minor = '.'.join(version.split('.')[:2])
            
            if major_minor in self.config.cve_database.get('wordpress', {}):
                version_cves = self.config.cve_database['wordpress'][major_minor]
                
                for version_range, cve_list in version_cves.items():
                    if version_range.startswith('<'):
                        threshold = version_range[1:]
                        if self._version_compare(version, threshold) < 0:
                            cves.extend(cve_list)
                    else:
                        cves.extend(cve_list)
        except:
            pass
        
        return list(set(cves))
    
    def _check_plugin_cves(self, plugin_slug: str, version: str) -> List[str]:
        """Check plugin CVEs"""
        cves = []
        
        if plugin_slug in self.config.cve_database:
            plugin_cves = self.config.cve_database[plugin_slug]
            
            for version_range, cve_list in plugin_cves.items():
                if version_range.startswith('<') and version:
                    threshold = version_range[1:]
                    if self._version_compare(version, threshold) < 0:
                        cves.extend(cve_list)
                else:
                    cves.extend(cve_list)
        
        return list(set(cves))
    
    def _check_php_cves(self, php_version: str) -> List[str]:
        """Check PHP CVEs"""
        cves = []
        
        try:
            major_minor = '.'.join(php_version.split('.')[:2])
            
            if major_minor in self.config.php_vulnerabilities:
                version_cves = self.config.php_vulnerabilities[major_minor]
                
                for version_range, cve_list in version_cves.items():
                    if version_range.startswith('<'):
                        threshold = version_range[1:]
                        if self._version_compare(php_version, threshold) < 0:
                            cves.extend(cve_list)
        except:
            pass
        
        return list(set(cves))
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad to same length
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            
            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0

# =================== OUTPUT MANAGER ===================
class OutputManager:
    """Manage multiple output formats"""
    
    def __init__(self, output_dir: str, formats: List[str]):
        self.output_dir = output_dir
        self.formats = formats
        self.results = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def add_result(self, result: Dict):
        """Add scan result"""
        self.results.append(result)
    
    def save_all(self):
        """Save to all formats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if 'json' in self.formats:
            self._save_json(timestamp)
        
        if 'txt' in self.formats:
            self._save_txt(timestamp)
        
        if 'csv' in self.formats:
            self._save_csv(timestamp)
    
    def _save_json(self, timestamp: str):
        """Save as JSON"""
        filepath = os.path.join(self.output_dir, f'scan_results_{timestamp}.json')
        
        data = {
            'scan_metadata': {
                'timestamp': timestamp,
                'total_results': len(self.results),
                'wp_sites': len([r for r in self.results if r.get('is_wp', False)]),
                'vulnerable': len([r for r in self.results if r.get('vulnerabilities', {}).get('risk_score', 0) >= 30])
            },
            'results': self.results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ JSON saved: {filepath}")
    
    def _save_txt(self, timestamp: str):
        """Save as TXT"""
        filepath = os.path.join(self.output_dir, f'vulnerable_domains_{timestamp}.txt')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# WordPress Vulnerability Scan Results\n")
            f.write(f"# Timestamp: {timestamp}\n")
            f.write(f"# Total results: {len(self.results)}\n\n")
            
            for result in self.results:
                if not result.get('is_wp', False):
                    continue
                
                risk_score = result.get('vulnerabilities', {}).get('risk_score', 0)
                if risk_score < 30:
                    continue
                
                domain = result.get('domain', '')
                wp_version = result.get('version', 'Unknown')
                cves = result.get('vulnerabilities', {}).get('cves', [])
                
                f.write(f"{domain}|Risk:{risk_score}|WP:{wp_version}|CVEs:{len(cves)}\n")
        
        print(f"✓ TXT saved: {filepath}")
    
    def _save_csv(self, timestamp: str):
        """Save as CSV"""
        filepath = os.path.join(self.output_dir, f'scan_results_{timestamp}.csv')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write("Domain,Is_WordPress,Confidence,Version,Risk_Score,CVE_Count,Plugins_Count\n")
            
            # Data
            for result in self.results:
                domain = result.get('domain', '')
                is_wp = result.get('is_wp', False)
                confidence = result.get('confidence', 0)
                version = result.get('version', '')
                risk_score = result.get('vulnerabilities', {}).get('risk_score', 0)
                cve_count = len(result.get('vulnerabilities', {}).get('cves', []))
                plugins_count = len(result.get('enumeration', {}).get('plugins', []))
                
                f.write(f'"{domain}",{is_wp},{confidence},"{version}",{risk_score},{cve_count},{plugins_count}\n')
        
        print(f"✓ CSV saved: {filepath}")

# =================== MAIN SCANNER ===================
class WordPressUltimateScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.display = DisplayManager()
        self.output_manager = OutputManager(config.output_dir, config.output_formats)
        
        # Components
        self.discoverer = DomainDiscoverer(config, self.display)
        self.detector = WordPressDetector(config)
        self.enumerator = DeepEnumerator(config)
        self.analyzer = VulnerabilityAnalyzer(config)
    
    async def scan_domain(self, domain: str) -> Dict:
        """Scan single domain"""
        result = {'domain': domain}
        
        try:
            # Phase 1: WordPress detection
            wp_info = await self.detector.detect(domain)
            result.update(wp_info)
            
            if not wp_info['is_wp']:
                return result
            
            self.display.print_wp_detected(
                domain, 
                wp_info['confidence'], 
                wp_info.get('version', '')
            )
            
            # Phase 2: Deep enumeration
            enum_data = await self.enumerator.enumerate(wp_info)
            result['enumeration'] = enum_data
            
            # Phase 3: Vulnerability analysis
            vuln_data = self.analyzer.analyze(wp_info, enum_data)
            result['vulnerabilities'] = vuln_data
            
            # Display if vulnerable
            if vuln_data['risk_score'] >= 30:
                details = {
                    'wp_version': wp_info.get('version', ''),
                    'cves': vuln_data['cves'],
                    'plugins': len(enum_data.get('plugins', []))
                }
                self.display.print_vulnerability(domain, vuln_data['risk_score'], details)
            
            with self.display.lock:
                self.display.stats['total_scanned'] += 1
            
        except Exception as e:
            pass
        
        return result
    
    async def scan_batch(self, domains: List[str], max_concurrent: int = 10):
        """Scan batch of domains"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_limit(domain):
            async with semaphore:
                return await self.scan_domain(domain)
        
        tasks = [scan_with_limit(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict):
                self.output_manager.add_result(result)
    
    async def run(self, targets_file: Optional[str] = None, max_domains: int = 1000):
        """Run complete scan"""
        try:
            self.display.print_banner()
            
            # Phase 1: Discovery
            self.display.print_phase("1", "DOMAIN DISCOVERY")
            domains = self.discoverer.discover_all(targets_file)
            
            if not domains:
                print("❌ No domains found!")
                return
            
            domains = list(domains)[:max_domains]
            print(f"\n[*] Will scan {len(domains)} domains")
            
            # Phase 2: Scanning
            self.display.print_phase("2", "WORDPRESS DETECTION & DEEP ENUMERATION")
            
            await self.detector.create_session()
            await self.enumerator.create_session()
            
            # Process in batches
            batch_size = 50
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                print(f"\n[*] Processing batch {i//batch_size + 1}/{(len(domains)-1)//batch_size + 1}")
                await self.scan_batch(batch, self.config.max_concurrent_tasks)
            
            # Cleanup
            await self.detector.close_session()
            await self.enumerator.close_session()
            
            # Phase 3: Output
            self.display.print_phase("3", "SAVING RESULTS")
            self.output_manager.save_all()
            
            # Final stats
            self.display.print_stats()
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Ensure cleanup
            try:
                await self.detector.close_session()
                await self.enumerator.close_session()
            except:
                pass

# =================== CLI INTERFACE ===================
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='WordPress Ultimate Scanner v4.0 - Multi-source discovery + Deep enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Full scan with discovery
  python wordpress_ultimate_scanner.py

  # Scan from file
  python wordpress_ultimate_scanner.py --targets domains.txt

  # Custom config
  python wordpress_ultimate_scanner.py --config myconfig.json

  # Limit domains and workers
  python wordpress_ultimate_scanner.py --max-domains 100 --workers 5

  # Save config template
  python wordpress_ultimate_scanner.py --save-config template.json
        '''
    )
    
    parser.add_argument('--targets', '-t', type=str,
                       help='File containing target domains (one per line)')
    
    parser.add_argument('--config', '-c', type=str,
                       help='Configuration file (JSON)')
    
    parser.add_argument('--max-domains', type=int, default=1000,
                       help='Maximum domains to scan (default: 1000)')
    
    parser.add_argument('--workers', '-w', type=int,
                       help='Number of concurrent workers (overrides config)')
    
    parser.add_argument('--output-dir', '-o', type=str,
                       help='Output directory (overrides config)')
    
    parser.add_argument('--formats', type=str, nargs='+',
                       choices=['json', 'txt', 'csv'],
                       help='Output formats (default: json txt csv)')
    
    parser.add_argument('--save-config', type=str,
                       help='Save current config to file and exit')
    
    parser.add_argument('--no-discovery', action='store_true',
                       help='Skip discovery phase (only use targets file)')
    
    return parser.parse_args()

# =================== MAIN ===================
async def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Load configuration
    config = ScanConfig(args.config)
    
    # Override with CLI arguments
    if args.workers:
        config.max_concurrent_tasks = args.workers
        config.max_workers_scan = args.workers
    
    if args.output_dir:
        config.output_dir = args.output_dir
    
    if args.formats:
        config.output_formats = args.formats
    
    # Save config and exit if requested
    if args.save_config:
        config.save_to_file(args.save_config)
        return
    
    # Validate targets file
    if args.targets and not os.path.exists(args.targets):
        print(f"❌ Target file not found: {args.targets}")
        return
    
    # Create and run scanner
    scanner = WordPressUltimateScanner(config)
    
    # Run scan
    targets_file = args.targets if not args.no_discovery else args.targets
    await scanner.run(targets_file, args.max_domains)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Scan stopped by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🏁 Scan completed")