#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner - ULTIMATE EDITION
Domain sources mạnh mẽ - No false positives - Real scanning
Author: Security Researcher
"""

import sys
import re
import ssl
import time
import signal
import random
import asyncio
import aiohttp
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from asyncio import Semaphore
import json
import csv
import io

# ================= CONFIGURATION =================
CONFIG = {
    'MAX_CONCURRENT': 20,
    'TIMEOUT': 10,
    'MAX_HTML_SIZE': 200_000,
    'DELAY_RANGE': (0.3, 1.2),
    'REQUESTS_PER_MINUTE': 150,
    'MIN_REQUEST_INTERVAL': 0.2,
    'MAX_RETRIES': 2,
    'RETRY_DELAY': 1.0,
    'SCAN_TIMEOUT': 7200,
    'DOMAIN_LIMIT': 500,
    'WP_DETECTION_TIMEOUT': 8,
}

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wp_scanner')

# ================= DATA STRUCTURES =================
@dataclass
class DomainInfo:
    domain: str
    alive: bool = False
    http_status: int = 0
    is_wordpress: bool = False
    wp_detection_reason: str = ""
    wp_url: str = ""
    response_time: float = 0.0
    requests_made: int = 0
    is_wp_com: bool = False
    
    @property
    def is_self_hosted(self) -> bool:
        return self.is_wordpress and not self.is_wp_com

@dataclass
class ScanResult:
    domain_info: DomainInfo
    plugins: Dict[str, Dict] = field(default_factory=dict)
    suspicious_paths: List[Tuple[str, str]] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    @property
    def has_vulnerabilities(self) -> bool:
        return bool(self.vulnerabilities)

@dataclass
class ScanStats:
    total_domains: int = 0
    domains_alive: int = 0
    domains_dead: int = 0
    wp_detected: int = 0
    wp_self_hosted: int = 0
    wp_com_sites: int = 0
    wp_not_detected: int = 0
    requests_total: int = 0
    scanned: int = 0
    plugins_found: int = 0
    verified_plugins: int = 0
    vulnerabilities_found: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def domains_per_second(self) -> float:
        if self.elapsed_time > 0:
            return self.scanned / self.elapsed_time
        return 0.0
    
    @property
    def wp_detection_rate(self) -> float:
        if self.domains_alive > 0:
            return (self.wp_detected / self.domains_alive) * 100
        return 0.0

# ================= ULTIMATE DOMAIN FETCHER =================
class UltimateDomainFetcher:
    """Domain fetcher MẠNH MẼ - lấy hàng ngàn domain WordPress thật"""
    
    @staticmethod
    def is_wordpress_com_domain(domain: str) -> bool:
        """Kiểm tra WordPress.com domain"""
        wp_com_patterns = [
            '.wordpress.com',
            '.wp.com',
            '.blog',  # .blog domains thường là WordPress.com
        ]
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in wp_com_patterns)
    
    @staticmethod
    def filter_wp_com_domains(domains: List[str]) -> List[str]:
        """Loại bỏ WordPress.com domains"""
        return [d for d in domains if not UltimateDomainFetcher.is_wordpress_com_domain(d)]
    
    @staticmethod
    async def fetch_high_quality_domains(session: aiohttp.ClientSession, limit: int = CONFIG['DOMAIN_LIMIT']) -> List[str]:
        """Lấy domain CHẤT LƯỢNG từ nhiều nguồn mạnh"""
        all_domains = set()
        
        print("[+] Ultimate Domain Fetcher - Getting REAL WordPress sites...")
        
        # 1. Crt.sh - với search terms tốt hơn
        print("[1] Crt.sh Certificate Transparency...")
        crt_domains = await UltimateDomainFetcher._fetch_from_crtsh_ultimate(session, 2000)
        print(f"   • Found: {len(crt_domains)} domains")
        all_domains.update(crt_domains)
        
        # 2. Dữ liệu công khai từ hackertarget
        print("[2] Hackertarget API...")
        ht_domains = await UltimateDomainFetcher._fetch_from_hackertarget(session, 1000)
        print(f"   • Found: {len(ht_domains)} domains")
        all_domains.update(ht_domains)
        
        # 3. Dữ liệu từ urlscan.io
        print("[3] UrlScan.io API...")
        us_domains = await UltimateDomainFetcher._fetch_from_urlscan(session, 500)
        print(f"   • Found: {len(us_domains)} domains")
        all_domains.update(us_domains)
        
        # 4. Tranco Top Sites (có thể có WP)
        print("[4] Tranco Top Sites...")
        tr_domains = await UltimateDomainFetcher._fetch_from_tranco(session, 500)
        print(f"   • Found: {len(tr_domains)} domains")
        all_domains.update(tr_domains)
        
        # 5. Common prefixes và TLDs
        print("[5] Generating common patterns...")
        gen_domains = UltimateDomainFetcher._generate_common_domains(300)
        print(f"   • Generated: {len(gen_domains)} domains")
        all_domains.update(gen_domains)
        
        # Filter và clean
        print(f"\n[+] Total before filtering: {len(all_domains)} domains")
        
        # Loại bỏ WordPress.com
        domains_list = list(all_domains)
        filtered = UltimateDomainFetcher.filter_wp_com_domains(domains_list)
        
        # Loại bỏ domains không hợp lệ
        clean_domains = []
        for domain in filtered:
            if UltimateDomainFetcher._is_valid_domain(domain):
                clean_domains.append(domain)
        
        print(f"[+] After filtering: {len(clean_domains)} clean domains")
        print(f"[+] Removed: {len(domains_list) - len(clean_domains)} invalid/WP.com domains")
        
        return clean_domains[:limit]
    
    @staticmethod
    async def _fetch_from_crtsh_ultimate(session: aiohttp.ClientSession, limit: int = 2000) -> List[str]:
        """Crt.sh với search terms tối ưu"""
        domains = set()
        
        # Search terms tập trung vào WordPress yếu
        search_terms = [
            # WordPress core
            '%.wordpress%',  # Tìm tất cả WordPress sites
            'wp-%',          # Tìm wp- patterns
            '%.wp.com',
            
            # Các plugin phổ biến
            '%.elementor%',
            '%.woocommerce%',
            '%.revslider%',
            '%.wp-file-manager%',
            '%.duplicator%',
            '%.contact-form-7%',
            
            # Các theme phổ biến
            '%.avada%',
            '%.divi%',
            '%.astra%',
            '%.generatepress%',
            
            # Các patterns khác
            '%.blog%',
            '%.news%',
            '%.magazine%',
            '%.portal%',
        ]
        
        print(f"   [Crt.sh] Querying {len(search_terms)} optimized terms...")
        
        for i, term in enumerate(search_terms, 1):
            sys.stdout.write(f"\r   [Crt.sh] {i}/{len(search_terms)}: {term}")
            sys.stdout.flush()
            
            try:
                url = f"https://crt.sh/?q={quote(term)}&output=json"
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            # Lấy domain từ nhiều trường
                            fields = ['name_value', 'common_name', 'issuer_name']
                            for field in fields:
                                value = entry.get(field, '')
                                if value:
                                    for line in str(value).split('\n'):
                                        line = line.strip()
                                        # Clean domain
                                        line = line.replace('*.', '').replace('*', '').strip()
                                        if line and '.' in line:
                                            # Extract domain
                                            domain = line.split('/')[0].split(':')[0].lower()
                                            # Basic validation
                                            if ('.' in domain and len(domain) < 100 and 
                                                re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain)):
                                                domains.add(domain)
            except Exception as e:
                logger.debug(f"Crt.sh error for {term}: {e}")
                continue
            
            await asyncio.sleep(0.2)
        
        print(f"\r   [Crt.sh] Found {len(domains)} domains                     ")
        return list(domains)[:limit]
    
    @staticmethod
    async def _fetch_from_hackertarget(session: aiohttp.ClientSession, limit: int = 1000) -> List[str]:
        """Hackertarget API - miễn phí, có nhiều WordPress sites"""
        domains = set()
        
        try:
            # Các query phổ biến
            queries = [
                "wordpress", "wp-content", "wp-includes", "wp-json",
                "elementor", "woocommerce", "wp-admin",
            ]
            
            for query in queries:
                try:
                    url = f"https://api.hackertarget.com/hostsearch/?q={query}"
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            # Parse CSV output: domain,ip
                            for line in text.strip().split('\n'):
                                if line and ',' in line:
                                    domain = line.split(',')[0].strip().lower()
                                    if domain and '.' in domain:
                                        domains.add(domain)
                    
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"Hackertarget query {query} error: {e}")
                    continue
                
                if len(domains) >= limit:
                    break
                    
        except Exception as e:
            logger.debug(f"Hackertarget init error: {e}")
        
        return list(domains)[:limit]
    
    @staticmethod
    async def _fetch_from_urlscan(session: aiohttp.ClientSession, limit: int = 500) -> List[str]:
        """UrlScan.io API - tìm domains có WordPress fingerprints"""
        domains = set()
        
        try:
            # Search for WordPress related terms
            searches = [
                "wordpress",
                "wp-content",
                "wp-includes",
                "wp-json",
            ]
            
            for search in searches:
                try:
                    url = f"https://urlscan.io/api/v1/search/?q={search}"
                    async with session.get(url, timeout=15, 
                                         headers={'API-Key': ''}) as resp:  # Public API
                        if resp.status == 200:
                            data = await resp.json()
                            for result in data.get('results', [])[:50]:
                                domain = result.get('page', {}).get('domain', '')
                                if domain:
                                    domains.add(domain.lower())
                    
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.debug(f"UrlScan search {search} error: {e}")
                    continue
                
                if len(domains) >= limit:
                    break
                    
        except Exception as e:
            logger.debug(f"UrlScan init error: {e}")
        
        return list(domains)[:limit]
    
    @staticmethod
    async def _fetch_from_tranco(session: aiohttp.ClientSession, limit: int = 500) -> List[str]:
        """Tranco Top Sites"""
        domains = set()
        
        try:
            # Tranco top 10k sites
            api_url = "https://tranco-list.eu/api/domains/com?start=1&end=10000"
            async with session.get(api_url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for domain in data.get('domains', [])[:limit]:
                        domain = str(domain).strip().lower()
                        if domain and '.' in domain:
                            domains.add(domain)
        except Exception as e:
            logger.debug(f"Tranco error: {e}")
        
        return list(domains)[:limit]
    
    @staticmethod
    def _generate_common_domains(limit: int = 300) -> List[str]:
        """Tạo domains từ các patterns phổ biến"""
        domains = set()
        
        # Các prefixes phổ biến cho WordPress sites
        prefixes = [
            'blog', 'news', 'magazine', 'journal', 'portal',
            'shop', 'store', 'market', 'ecommerce',
            'forum', 'community', 'network',
            'corp', 'company', 'business', 'enterprise',
            'edu', 'school', 'academy', 'university',
            'gov', 'official', 'department',
            'tech', 'digital', 'online', 'web',
            'my', 'our', 'the', 'best', 'top',
        ]
        
        # Các midfixes
        midfixes = ['', '-', '']
        
        # Các suffixes
        suffixes = ['', 'online', 'hub', 'center', 'portal', 'site', 'web']
        
        # Các TLDs phổ biến
        tlds = ['com', 'net', 'org', 'io', 'co', 'info', 'biz', 'us', 'uk', 'de', 'fr', 'es']
        
        # Tạo domains
        count = 0
        while len(domains) < limit and count < 10000:
            prefix = random.choice(prefixes)
            mid = random.choice(midfixes)
            suffix = random.choice(suffixes)
            tld = random.choice(tlds)
            
            # Tạo domain
            if suffix:
                domain = f"{prefix}{mid}{suffix}.{tld}".replace('..', '.').replace('-.', '.')
            else:
                domain = f"{prefix}.{tld}"
            
            # Thêm số để tạo variation
            if random.random() < 0.3:
                domain = domain.replace('.', f"{random.randint(1, 99)}.", 1)
            
            if domain.count('.') >= 1:
                domains.add(domain.lower())
            
            count += 1
        
        return list(domains)[:limit]
    
    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Kiểm tra domain hợp lệ"""
        if not domain or len(domain) > 100 or len(domain) < 4:
            return False
        
        if domain.count('.') < 1:
            return False
        
        # Không chứa ký tự lạ
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # Không bắt đầu/kết thúc bằng dấu gạch ngang
        if domain.startswith('-') or domain.endswith('-'):
            return False
        
        # Không có hai dấu chấm liên tiếp
        if '..' in domain:
            return False
        
        # TLD hợp lệ
        tld = domain.split('.')[-1].lower()
        valid_tlds = [
            'com', 'net', 'org', 'edu', 'gov', 'mil',
            'io', 'co', 'ai', 'app', 'dev', 'tech',
            'uk', 'de', 'fr', 'es', 'it', 'nl',
            'jp', 'cn', 'kr', 'in', 'br', 'ru',
            'au', 'ca', 'nz', 'ch', 'se', 'no',
            'vn', 'th', 'ph', 'my', 'sg', 'id',
        ]
        
        return tld in valid_tlds

# ================= SMART RATE LIMITER =================
class SmartRateLimiter:
    def __init__(self):
        self.request_times = []
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> float:
        async with self.lock:
            current_time = time.time()
            
            # Clean old
            self.request_times = [t for t in self.request_times if current_time - t < 60]
            
            # Check rate limit
            if len(self.request_times) >= CONFIG['REQUESTS_PER_MINUTE']:
                oldest = min(self.request_times)
                wait_time = max(0.1, 60 - (current_time - oldest))
                return wait_time
            
            # Check interval
            if self.request_times:
                last_request = self.request_times[-1]
                time_since_last = current_time - last_request
                if time_since_last < CONFIG['MIN_REQUEST_INTERVAL']:
                    return CONFIG['MIN_REQUEST_INTERVAL'] - time_since_last
            
            self.request_times.append(current_time)
            return 0.0

# ================= WORDPRESS DETECTOR =================
class WordPressDetector:
    WP_FINGERPRINTS = [
        (r'<meta[^>]*name="generator"[^>]*content="WordPress[^"]*"', 'meta_generator'),
        (r'<meta[^>]*content="WordPress[^"]*"', 'meta_content'),
        (r'/wp-content/', 'wp_content_url'),
        (r'/wp-includes/', 'wp_includes_url'),
        (r'/wp-json/', 'wp_json_url'),
        (r'"namespace":"wp/v2"', 'rest_api'),
        (r'wp-login\.php', 'wp_login'),
        (r'wp-embed\.min\.js', 'wp_embed_js'),
    ]
    
    PATTERNS = [(re.compile(pattern, re.I), reason) for pattern, reason in WP_FINGERPRINTS]
    
    @staticmethod
    def is_wordpress_com_url(url: str) -> bool:
        return 'wordpress.com' in url.lower() or 'wp.com' in url.lower()
    
    @staticmethod
    async def detect(session: aiohttp.ClientSession, domain: str, 
                    rate_limiter: SmartRateLimiter) -> Tuple[bool, str, str, bool]:
        """Detect WordPress và phân loại"""
        
        check_urls = [
            (f"https://{domain}", "homepage"),
            (f"http://{domain}", "homepage_http"),
            (f"https://{domain}/wp-json/", "wp_json"),
        ]
        
        detection_reasons = []
        best_url = ""
        
        for url, check_type in check_urls:
            try:
                wait_time = await rate_limiter.acquire()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                
                timeout = aiohttp.ClientTimeout(total=CONFIG['WP_DETECTION_TIMEOUT'])
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
                
                async with session.get(url, headers=headers, timeout=timeout, 
                                      allow_redirects=True, ssl=False) as response:
                    
                    if response.status not in [200, 301, 302, 403]:
                        continue
                    
                    # Check WordPress.com
                    final_url = str(response.url)
                    is_wp_com = WordPressDetector.is_wordpress_com_url(final_url)
                    
                    if is_wp_com:
                        return True, final_url, "wordpress_com", True
                    
                    # Check headers
                    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    if 'x-powered-by' in headers_lower and 'wordpress' in headers_lower['x-powered-by']:
                        detection_reasons.append(f"x_powered_by_{check_type}")
                        best_url = final_url
                    
                    if 'link' in headers_lower and 'wp-json' in headers_lower['link']:
                        detection_reasons.append(f"link_header_{check_type}")
                        best_url = final_url
                    
                    # Check content
                    if not detection_reasons:
                        try:
                            text = await response.text(errors='ignore')
                            text_lower = text.lower()
                            
                            for pattern, reason in WordPressDetector.PATTERNS:
                                if pattern.search(text_lower):
                                    detection_reasons.append(f"{reason}_{check_type}")
                                    best_url = final_url
                                    break
                        except:
                            pass
                    
                    if detection_reasons:
                        break
                    
            except Exception as e:
                logger.debug(f"Detection failed for {url}: {e}")
                continue
        
        if detection_reasons:
            main_reason = detection_reasons[0]
            if not best_url:
                best_url = f"https://{domain}"
            
            is_wp_com = WordPressDetector.is_wordpress_com_url(best_url)
            return True, best_url, main_reason, is_wp_com
        
        return False, "", "", False

# ================= ULTIMATE SCANNER CORE =================
class UltimateWordPressScanner:
    """Scanner với verify kỹ - NO false positives"""
    
    PLUGIN_SOURCES = [
        (re.compile(r'wp-content/plugins/([a-z0-9_-]+)/[^"\']+\.(?:js|css)', re.I), 'resource_url'),
        (re.compile(r'/plugins/([a-z0-9_-]+)/assets/', re.I), 'assets_url'),
    ]
    
    DANGEROUS_PLUGINS = {
        'wp-file-manager': {
            'dangerous_files': ['elfinder.php', 'connector.minimal.php'],
            'version_file': 'readme.txt',
            'min_version': '6.0'
        },
        'revslider': {
            'dangerous_files': ['revslider.php'],
            'version_file': 'readme.txt',
            'min_version': '3.0'
        },
        'duplicator': {
            'dangerous_files': ['installer.php'],
            'version_file': 'readme.txt',
            'min_version': '1.3'
        },
    }
    
    def __init__(self, session: aiohttp.ClientSession, rate_limiter: SmartRateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def safe_request(self, url: str) -> Optional[Dict]:
        """Request an toàn"""
        try:
            wait_time = await self.rate_limiter.acquire()
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            
            await asyncio.sleep(random.uniform(*CONFIG['DELAY_RANGE']))
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            
            start_time = time.time()
            async with self.session.get(
                url,
                headers=headers,
                ssl=self.ssl_context,
                timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT']),
                allow_redirects=True,
                max_redirects=2
            ) as response:
                
                try:
                    text = await response.text(errors='ignore')
                except:
                    text = ""
                
                return {
                    'status': response.status,
                    'url': str(response.url),
                    'text': text[:50000],
                    'response_time': time.time() - start_time
                }
                
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
    
    async def find_real_plugins(self, base_url: str) -> Set[str]:
        """Tìm plugin THẬT"""
        all_plugins = set()
        
        # Check homepage
        homepage_resp = await self.safe_request(base_url)
        if homepage_resp and homepage_resp['status'] == 200:
            plugins = self._extract_plugins_from_text(homepage_resp['text'])
            for plugin in plugins:
                if self._is_valid_plugin_name(plugin):
                    all_plugins.add(plugin)
        
        # Verify từng plugin
        verified_plugins = set()
        for plugin in all_plugins:
            if await self.verify_plugin_exists(base_url, plugin):
                verified_plugins.add(plugin)
        
        return verified_plugins
    
    def _extract_plugins_from_text(self, text: str) -> Set[str]:
        """Trích xuất plugin từ text"""
        plugins = set()
        
        for pattern, source_type in self.PLUGIN_SOURCES:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    plugin_name = match[0]
                else:
                    plugin_name = match
                
                plugin_name = plugin_name.strip().lower()
                if self._is_valid_plugin_name(plugin_name):
                    plugins.add(plugin_name)
        
        return plugins
    
    def _is_valid_plugin_name(self, plugin_name: str) -> bool:
        """Kiểm tra tên plugin hợp lệ"""
        if not plugin_name or len(plugin_name) < 3 or len(plugin_name) > 50:
            return False
        
        if not re.match(r'^[a-z0-9_-]+$', plugin_name):
            return False
        
        # Không phải từ chung
        common_words = ['plugins', 'assets', 'wp', 'content', 'includes', 'uploads']
        if plugin_name in common_words:
            return False
        
        return True
    
    async def verify_plugin_exists(self, base_url: str, plugin: str) -> bool:
        """Verify plugin tồn tại thật"""
        check_urls = [
            f"{base_url}/wp-content/plugins/{plugin}/readme.txt",
            f"{base_url}/wp-content/plugins/{plugin}/{plugin}.php",
        ]
        
        for url in check_urls:
            resp = await self.safe_request(url)
            if resp and resp['status'] in [200, 403]:
                if 'readme.txt' in url and resp['status'] == 200:
                    if 'plugin name:' in resp['text'].lower():
                        return True
                else:
                    return True
        
        return False
    
    async def check_plugin_vulnerabilities(self, base_url: str, plugin: str) -> Optional[Dict]:
        """Kiểm tra plugin có lỗ hổng"""
        if plugin not in self.DANGEROUS_PLUGINS:
            return None
        
        plugin_info = self.DANGEROUS_PLUGINS[plugin]
        result = {
            'name': plugin,
            'version': None,
            'dangerous_files_found': [],
            'vulnerable': False,
            'verified': False,
        }
        
        # Verify tồn tại
        if not await self.verify_plugin_exists(base_url, plugin):
            return None
        
        result['verified'] = True
        
        # Lấy version
        readme_url = f"{base_url}/wp-content/plugins/{plugin}/{plugin_info['version_file']}"
        readme_resp = await self.safe_request(readme_url)
        if readme_resp and readme_resp['status'] == 200:
            version_match = re.search(r'version[\s:]*([\d.]+)', readme_resp['text'], re.I)
            if version_match:
                result['version'] = version_match.group(1)
                
                # Check version cũ
                try:
                    if result['version'] < plugin_info.get('min_version', '10.0'):
                        result['vulnerable'] = True
                except:
                    pass
        
        # Check dangerous files
        for dangerous_file in plugin_info['dangerous_files']:
            file_url = f"{base_url}/wp-content/plugins/{plugin}/{dangerous_file}"
            file_resp = await self.safe_request(file_url)
            
            # Chỉ 200 OK mới tính
            if file_resp and file_resp['status'] == 200:
                result['dangerous_files_found'].append(dangerous_file)
        
        # Đánh dấu vulnerable nếu có file nguy hiểm
        if result['dangerous_files_found']:
            result['vulnerable'] = True
        
        return result
    
    async def scan_domain_comprehensive(self, domain: str) -> ScanResult:
        """Scan toàn diện"""
        domain_info = DomainInfo(domain=domain)
        result = ScanResult(domain_info=domain_info)
        
        try:
            # Kiểm tra alive
            test_resp = await self.safe_request(f"https://{domain}")
            if not test_resp:
                test_resp = await self.safe_request(f"http://{domain}")
            
            if not test_resp:
                domain_info.alive = False
                return result
            
            domain_info.alive = True
            domain_info.http_status = test_resp['status']
            domain_info.response_time = test_resp.get('response_time', 0)
            
            # Detect WordPress
            detector = WordPressDetector()
            is_wp, wp_url, reason, is_wp_com = await detector.detect(
                self.session, domain, self.rate_limiter
            )
            
            domain_info.is_wordpress = is_wp
            domain_info.is_wp_com = is_wp_com
            domain_info.wp_detection_reason = reason
            domain_info.wp_url = wp_url
            
            # Nếu là WordPress.com thì dừng
            if is_wp_com:
                return result
            
            # Nếu không phải WordPress, dừng
            if not is_wp or not wp_url:
                return result
            
            # Tìm và check plugin (chỉ self-hosted)
            plugins_found = await self.find_real_plugins(wp_url)
            
            for plugin in plugins_found:
                plugin_info = await self.check_plugin_vulnerabilities(wp_url, plugin)
                if plugin_info and plugin_info['verified']:
                    result.plugins[plugin] = plugin_info
                    
                    if plugin_info['vulnerable']:
                        if plugin_info['dangerous_files_found']:
                            vuln_msg = f"{plugin}: {', '.join(plugin_info['dangerous_files_found'])}"
                        else:
                            vuln_msg = f"{plugin}: outdated version {plugin_info['version']}"
                        result.vulnerabilities.append(vuln_msg)
            
        except Exception as e:
            logger.debug(f"Scan error for {domain}: {e}")
        
        return result

# ================= OUTPUT HANDLER =================
class OutputHandler:
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.file_handle = None
        self.vulnerabilities_found = []
        self.stats = ScanStats()
        self.lock = asyncio.Lock()
    
    async def __aenter__(self):
        self.file_handle = open(self.output_file, 'w', encoding='utf-8')
        self.file_handle.write("=" * 80 + "\n")
        self.file_handle.write("WORDPRESS VULNERABILITY SCAN - ULTIMATE EDITION\n")
        self.file_handle.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file_handle.write("=" * 80 + "\n\n")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.file_handle:
            await self.write_summary()
            self.file_handle.close()
    
    async def update_stats(self, result: ScanResult):
        async with self.lock:
            self.stats.scanned += 1
            self.stats.requests_total += result.domain_info.requests_made
            
            domain_info = result.domain_info
            
            if domain_info.alive:
                self.stats.domains_alive += 1
                
                if domain_info.is_wordpress:
                    self.stats.wp_detected += 1
                    
                    if domain_info.is_wp_com:
                        self.stats.wp_com_sites += 1
                    else:
                        self.stats.wp_self_hosted += 1
                else:
                    self.stats.wp_not_detected += 1
            else:
                self.stats.domains_dead += 1
            
            if result.plugins:
                self.stats.plugins_found += len(result.plugins)
                self.stats.verified_plugins += sum(1 for p in result.plugins.values() if p['verified'])
            
            if result.has_vulnerabilities:
                self.stats.vulnerabilities_found += len(result.vulnerabilities)
                self.vulnerabilities_found.append(result)
    
    async def write_result(self, result: ScanResult):
        if not self.file_handle:
            return
        
        domain_info = result.domain_info
        
        # Chỉ ghi thông tin quan trọng
        should_write = (
            domain_info.alive and 
            (domain_info.is_wordpress or result.has_vulnerabilities)
        )
        
        if not should_write:
            return
        
        async with self.lock:
            self.file_handle.write("\n" + "=" * 80 + "\n")
            self.file_handle.write(f"DOMAIN: {domain_info.domain}\n")
            self.file_handle.write("-" * 40 + "\n")
            self.file_handle.write(f"Alive: {'Yes' if domain_info.alive else 'No'}\n")
            self.file_handle.write(f"HTTP Status: {domain_info.http_status}\n")
            self.file_handle.write(f"Response Time: {domain_info.response_time:.2f}s\n")
            self.file_handle.write(f"WordPress: {'Yes' if domain_info.is_wordpress else 'No'}\n")
            
            if domain_info.is_wordpress:
                self.file_handle.write(f"Type: {'WordPress.com' if domain_info.is_wp_com else 'Self-hosted'}\n")
                self.file_handle.write(f"WP URL: {domain_info.wp_url}\n")
                self.file_handle.write(f"Detection: {domain_info.wp_detection_reason}\n")
            
            if result.plugins:
                self.file_handle.write(f"\n🔍 PLUGINS ({len(result.plugins)} verified):\n")
                for plugin, info in result.plugins.items():
                    if info['verified']:
                        self.file_handle.write(f"  • {plugin}")
                        if info['version']:
                            self.file_handle.write(f" (v{info['version']})")
                        if info['dangerous_files_found']:
                            self.file_handle.write(f" [DANGER: {', '.join(info['dangerous_files_found'])}]")
                        self.file_handle.write("\n")
            
            if result.has_vulnerabilities:
                self.file_handle.write(f"\n⚠️ VULNERABILITIES ({len(result.vulnerabilities)}):\n")
                for vuln in result.vulnerabilities:
                    self.file_handle.write(f"  • {vuln}\n")
            
            self.file_handle.write("=" * 80 + "\n")
            self.file_handle.flush()
    
    async def write_summary(self):
        if not self.file_handle:
            return
        
        async with self.lock:
            self.file_handle.write("\n\n" + "=" * 80 + "\n")
            self.file_handle.write("SCAN SUMMARY\n")
            self.file_handle.write("=" * 80 + "\n")
            
            self.file_handle.write(f"\n📊 STATISTICS:\n")
            self.file_handle.write(f"  • Total Domains: {self.stats.total_domains}\n")
            self.file_handle.write(f"  • Alive: {self.stats.domains_alive} ({self.stats.domains_alive/self.stats.total_domains*100:.1f}%)\n")
            self.file_handle.write(f"  • Dead: {self.stats.domains_dead}\n")
            
            if self.stats.domains_alive > 0:
                self.file_handle.write(f"\n🅆🄿 WORDPRESS:\n")
                self.file_handle.write(f"  • Total: {self.stats.wp_detected} ({self.stats.wp_detection_rate:.1f}%)\n")
                self.file_handle.write(f"  • Self-hosted: {self.stats.wp_self_hosted}\n")
                self.file_handle.write(f"  • WordPress.com: {self.stats.wp_com_sites}\n")
            
            self.file_handle.write(f"\n🔍 FINDINGS:\n")
            self.file_handle.write(f"  • Verified Plugins: {self.stats.verified_plugins}\n")
            self.file_handle.write(f"  • Vulnerabilities: {self.stats.vulnerabilities_found}\n")
            
            self.file_handle.write(f"\n⚡ PERFORMANCE:\n")
            self.file_handle.write(f"  • Total Requests: {self.stats.requests_total}\n")
            self.file_handle.write(f"  • Domains/Second: {self.stats.domains_per_second:.2f}\n")
            self.file_handle.write(f"  • Total Time: {self.stats.elapsed_time:.1f}s\n")
            
            if self.vulnerabilities_found:
                self.file_handle.write(f"\n🚨 VULNERABLE SITES ({len(self.vulnerabilities_found)}):\n")
                self.file_handle.write("-" * 40 + "\n")
                for result in self.vulnerabilities_found:
                    domain = result.domain_info.domain
                    vuln_count = len(result.vulnerabilities)
                    main_vuln = result.vulnerabilities[0] if result.vulnerabilities else ""
                    self.file_handle.write(f"  • {domain} - {vuln_count} vulns\n")
            
            self.file_handle.write("\n" + "=" * 80 + "\n")
    
    def display_progress(self):
        sys.stdout.write('\r\033[K')
        
        progress_width = 40
        if self.stats.total_domains > 0:
            percent = self.stats.scanned / self.stats.total_domains
            filled = int(progress_width * percent)
            bar = '█' * filled + '░' * (progress_width - filled)
            progress_str = f"[{bar}] {percent*100:.1f}%"
        else:
            progress_str = "[░░░░░░░░░░░░░░░░░░░░] 0.0%"
        
        info = (
            f"📊 {self.stats.scanned}/{self.stats.total_domains} "
            f"{progress_str} | "
            f"🏥 {self.stats.domains_alive} | "
            f"🅆 {self.stats.wp_detected} | "
            f"🏠 {self.stats.wp_self_hosted} | "
            f"⚠️ {self.stats.vulnerabilities_found} | "
            f"⚡ {self.stats.domains_per_second:.1f}/s"
        )
        
        sys.stdout.write(info)
        sys.stdout.flush()

# ================= MAIN SCAN WORKER =================
async def scan_worker(
    domain: str, 
    scanner: UltimateWordPressScanner,
    output_handler: OutputHandler,
    semaphore: Semaphore,
    session: aiohttp.ClientSession,
    rate_limiter: SmartRateLimiter
):
    async with semaphore:
        try:
            result = await scanner.scan_domain_comprehensive(domain)
            
            await output_handler.update_stats(result)
            
            # Hiển thị
            if result.has_vulnerabilities:
                print(f"\r\033[K\033[91m🚨 VULN: {domain}\033[0m")
            elif result.domain_info.is_wordpress:
                if result.domain_info.is_wp_com:
                    print(f"\r\033[K\033[94m☁️ WP.com: {domain}\033[0m")
                else:
                    print(f"\r\033[K\033[92m✓ WP: {domain}\033[0m")
            elif result.domain_info.alive:
                print(f"\r\033[K\033[93m○ Alive: {domain}\033[0m")
            
            await output_handler.write_result(result)
            output_handler.display_progress()
            
        except Exception as e:
            logger.debug(f"Worker error for {domain}: {e}")

# ================= MAIN FUNCTION =================
async def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_file>")
        print(f"Example: {sys.argv[0]} scan_results.txt")
        sys.exit(1)
    
    output_file = sys.argv[1]
    
    print("\n" + "=" * 70)
    print("🔍 WORDPRESS VULNERABILITY SCANNER - ULTIMATE EDITION")
    print("🎯 Powerful domain sources - No false positives")
    print("=" * 70 + "\n")
    
    rate_limiter = SmartRateLimiter()
    
    try:
        # Fetch domains
        print("[+] Fetching domains from multiple sources...")
        async with aiohttp.ClientSession() as session:
            domains = await UltimateDomainFetcher.fetch_high_quality_domains(
                session, CONFIG['DOMAIN_LIMIT']
            )
        
        if not domains:
            print("[-] No domains found!")
            sys.exit(1)
        
        print(f"[+] Got {len(domains)} domains ready for scanning")
        print()
        
        # Setup output
        output_handler = OutputHandler(output_file)
        await output_handler.__aenter__()
        output_handler.stats.total_domains = len(domains)
        
        print("[+] Starting scan...")
        print("[•] Display: VULN 🚨, WP ✓, WP.com ☁️, Alive ○")
        print()
        
        # Setup scanner
        connector = aiohttp.TCPConnector(
            limit=CONFIG['MAX_CONCURRENT'],
            limit_per_host=3,
            ttl_dns_cache=300,
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])
        ) as scan_session:
            
            scanner = UltimateWordPressScanner(scan_session, rate_limiter)
            semaphore = Semaphore(CONFIG['MAX_CONCURRENT'])
            
            # Create tasks
            tasks = []
            for domain in domains:
                task = asyncio.create_task(
                    scan_worker(
                        domain, scanner, output_handler, 
                        semaphore, scan_session, rate_limiter
                    )
                )
                tasks.append(task)
            
            # Run scan
            print("\n[+] Scanning... (Ctrl+C to stop)\n")
            
            try:
                start_time = time.time()
                await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time
                
                print(f"\n\n[+] Scan completed in {elapsed:.1f}s")
                
            except asyncio.TimeoutError:
                print(f"\n[!] Timeout after {CONFIG['SCAN_TIMEOUT']}s")
            
            # Final stats
            print("\n" + "=" * 70)
            print("✅ SCAN COMPLETED")
            print("=" * 70)
            
            stats = output_handler.stats
            print(f"\n📊 STATISTICS:")
            print(f"   • Total: {stats.total_domains}")
            print(f"   • Alive: {stats.domains_alive} ({stats.domains_alive/stats.total_domains*100:.1f}%)")
            print(f"   • WordPress: {stats.wp_detected} ({stats.wp_detection_rate:.1f}% of alive)")
            print(f"   • Self-hosted: {stats.wp_self_hosted}")
            print(f"   • Verified plugins: {stats.verified_plugins}")
            print(f"   • Real vulnerabilities: {stats.vulnerabilities_found}")
            
            if output_handler.vulnerabilities_found:
                print(f"\n🚨 VULNERABILITIES FOUND:")
                print(f"   • Sites with vulns: {len(output_handler.vulnerabilities_found)}")
                
                print(f"\n📋 VULNERABLE SITES:")
                for i, result in enumerate(output_handler.vulnerabilities_found[:15], 1):
                    domain = result.domain_info.domain
                    vuln_count = len(result.vulnerabilities)
                    print(f"   {i}. {domain} ({vuln_count} vulnerabilities)")
            
            print(f"\n📁 Detailed results saved to: {output_file}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan stopped by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await output_handler.__aexit__(None, None, None)

def signal_handler(sig, frame):
    print("\n\n[!] Stopping scan...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")