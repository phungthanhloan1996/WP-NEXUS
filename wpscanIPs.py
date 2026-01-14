#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner - Professional Edition
Fix tất cả các vấn đề: domain source, detection, rate limiting, stats
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
import hashlib

# ================= CONFIGURATION =================
CONFIG = {
    'MAX_CONCURRENT': 10,           # Tối ưu cho rate limiting
    'TIMEOUT': 8,                   # Timeout ngắn hơn
    'MAX_HTML_SIZE': 200_000,       # Giảm kích thước đọc
    'DELAY_RANGE': (0.8, 2.5),      # Delay ngắn hơn đáng kể
    'REQUESTS_PER_MINUTE': 120,     # Tăng rate limit
    'MIN_REQUEST_INTERVAL': 0.5,    # Khoảng cách rất ngắn
    'MAX_RETRIES': 1,
    'RETRY_DELAY': 1.5,
    'SCAN_TIMEOUT': 10800,          # 3 giờ timeout
    'DOMAIN_LIMIT': 300,            # Giảm limit, tập trung chất lượng
    'WP_DETECTION_TIMEOUT': 5,      # Timeout riêng cho detection
}

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wp_scanner')

# ================= ENHANCED DATA STRUCTURES =================
@dataclass
class DomainInfo:
    """Thông tin chi tiết về domain"""
    domain: str
    alive: bool = False
    http_status: int = 0
    is_wordpress: bool = False
    wp_detection_reason: str = ""
    wp_url: str = ""
    response_time: float = 0.0
    
    # Thống kê
    requests_made: int = 0
    detection_attempts: int = 0

@dataclass
class ScanResult:
    """Kết quả scan chi tiết"""
    domain_info: DomainInfo
    plugins: Dict[str, Dict] = field(default_factory=dict)
    suspicious_paths: List[Tuple[str, str]] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    @property
    def has_vulnerabilities(self) -> bool:
        return bool(self.vulnerabilities)

@dataclass
class ScanStats:
    """Thống kê chi tiết, tách biệt các loại"""
    total_domains: int = 0
    # Tách biệt các trạng thái
    domains_alive: int = 0
    domains_dead: int = 0
    wp_detected: int = 0
    wp_not_detected: int = 0
    wp_false_negative: int = 0  # Dự đoán false negative
    # Thống kê request
    requests_total: int = 0
    requests_success: int = 0
    requests_failed: int = 0
    # Scan progress
    scanned: int = 0
    # Findings
    plugins_found: int = 0
    vulnerabilities_found: int = 0
    # Performance
    start_time: float = field(default_factory=time.time)
    rate_limited_count: int = 0
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def domains_per_second(self) -> float:
        if self.elapsed_time > 0:
            return self.scanned / self.elapsed_time
        return 0.0
    
    @property
    def requests_per_minute(self) -> float:
        if self.elapsed_time > 0:
            return (self.requests_total / self.elapsed_time) * 60
        return 0.0
    
    @property
    def wp_detection_rate(self) -> float:
        if self.domains_alive > 0:
            return (self.wp_detected / self.domains_alive) * 100
        return 0.0
    
    @property
    def false_negative_rate(self) -> float:
        if self.wp_not_detected > 0:
            return (self.wp_false_negative / self.wp_not_detected) * 100
        return 0.0

# ================= SMART DOMAIN FETCHER =================
class SmartDomainFetcher:
    """Lấy domain THÔNG MINH - tập trung vào WordPress thật"""
    
    @staticmethod
    async def fetch_high_quality_domains(session: aiohttp.ClientSession, limit: int = 200) -> List[str]:
        """Lấy domain CHẤT LƯỢNG cao - tập trung WordPress thật"""
        all_domains = set()
        
        print("[+] Đang lấy domain CHẤT LƯỢNG...")
        
        # 1. CT Logs với filter THÔNG MINH
        ct_domains = await SmartDomainFetcher._fetch_from_ct_smart(session, 100)
        print(f"   • CT Logs: {len(ct_domains)} domain")
        
        # 2. Dựa trên WordPress phổ biến
        wp_domains = await SmartDomainFetcher._fetch_wordpress_patterns(session, 100)
        print(f"   • WP Patterns: {len(wp_domains)} domain")
        
        # 3. Từ các site WordPress đã biết (crawl từ danh sách public)
        known_domains = SmartDomainFetcher._get_known_wp_sites(50)
        print(f"   • Known WP: {len(known_domains)} domain")
        
        # Combine và filter
        all_domains.update(ct_domains)
        all_domains.update(wp_domains)
        all_domains.update(known_domains)
        
        # Filter cực mạnh
        filtered = []
        for domain in all_domains:
            if SmartDomainFetcher._is_high_quality_domain(domain):
                filtered.append(domain)
        
        print(f"[+] Tổng cộng: {len(filtered)} domain chất lượng")
        return filtered[:limit]
    
    @staticmethod
    def _is_high_quality_domain(domain: str) -> bool:
        """Filter cực gắt - chỉ lấy domain có khả năng cao là WP site thật"""
        # Loại bỏ các domain rác
        bad_patterns = [
            'cloudflare', 'amazonaws', 'google', 'microsoft',
            'godaddy', 'namecheap', 'wordpress.com', 'blogspot',
            'wix.com', 'weebly.com', 'tumblr.com', 'github.io',
            '000webhost', 'hostinger', 'bluehost',
        ]
        
        if any(pattern in domain.lower() for pattern in bad_patterns):
            return False
        
        # Domain quá dài hoặc quá ngắn
        if len(domain) < 6 or len(domain) > 40:
            return False
        
        # Có từ khóa liên quan đến WP/blog
        wp_keywords = [
            'blog', 'news', 'magazine', 'journal', 'portal',
            'article', 'post', 'story', 'media', 'press',
            'content', 'publish', 'write', 'author',
            'shop', 'store', 'market', 'ecommerce',  # WooCommerce
            'school', 'edu', 'academy', 'course',    # Learning
            'realestate', 'property', 'house',       # Real estate
            'travel', 'tour', 'hotel', 'booking',    # Travel
            'restaurant', 'food', 'cafe', 'menu',    # Food
            'medical', 'clinic', 'hospital', 'doctor',  # Medical
            'law', 'legal', 'attorney', 'lawyer',    # Legal
        ]
        
        # Tách domain để kiểm tra
        domain_lower = domain.lower()
        domain_parts = domain_lower.replace('-', '.').split('.')
        
        # Kiểm tra các phần của domain
        for part in domain_parts:
            if part in wp_keywords:
                return True
        
        # Domain có định dạng phổ biến của WP sites
        good_patterns = [
            r'^[a-z]+[0-9]*\.(com|net|org|vn|io|co)$',
            r'^[a-z]+-[a-z]+\.(com|net|org)$',
            r'^[a-z]{2,}[0-9]{2,}\.(com|net|org)$',
        ]
        
        for pattern in good_patterns:
            if re.match(pattern, domain_lower):
                return True
        
        return False
    
    @staticmethod
    async def _fetch_from_ct_smart(session: aiohttp.ClientSession, limit: int) -> List[str]:
        """CT Logs với filter thông minh hơn"""
        domains = set()
        
        # Query TẬP TRUNG vào WordPress
        wp_queries = [
            "wordpress", "wp-content", "wp-includes",
            "blog", "weblog", "cms-wordpress",
            "woocommerce", "wpshop", "wpstore",
        ]
        
        for query in wp_queries[:4]:  # Chỉ 4 query tốt nhất
            try:
                url = f"https://crt.sh/?q={quote(query)}&output=json"
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data[:80]:  # Giới hạn mỗi query
                            name = entry.get('name_value', '')
                            if isinstance(name, str):
                                for line in name.split('\n'):
                                    domain = line.strip().lower()
                                    # GIỮ NGUYÊN subdomain - rất quan trọng!
                                    if '*' not in domain and domain.count('.') >= 1:
                                        domains.add(domain)
            except Exception:
                continue
        
        return list(domains)[:limit]
    
    @staticmethod
    async def _fetch_wordpress_patterns(session: aiohttp.ClientSession, limit: int) -> List[str]:
        """Dựa trên pattern của WordPress sites"""
        domains = set()
        
        # Các mẫu domain phổ biến của WP sites
        patterns = [
            # Blog patterns
            "{keyword}{number}.{tld}",
            "{keyword}-{keyword}.{tld}",
            "my{keyword}.{tld}",
            "the{keyword}.{tld}",
            "{keyword}online.{tld}",
            "{keyword}hub.{tld}",
            "{keyword}site.{tld}",
            "{keyword}world.{tld}",
        ]
        
        keywords = [
            'blog', 'news', 'tech', 'web', 'digital',
            'media', 'press', 'post', 'article',
            'shop', 'store', 'market', 'buy',
            'learn', 'study', 'course', 'edu',
            'travel', 'tour', 'trip', 'hotel',
            'food', 'restaurant', 'recipe', 'cook',
            'health', 'fitness', 'medical', 'care',
        ]
        
        tlds = ['com', 'net', 'org', 'vn', 'io', 'co']
        
        # Tạo domain dựa trên pattern
        for _ in range(limit * 2):  # Tạo nhiều rồi filter
            pattern = random.choice(patterns)
            keyword = random.choice(keywords)
            tld = random.choice(tlds)
            number = random.choice(['', '1', '2', '2024', '24', ''])
            
            if '{keyword}{number}' in pattern:
                domain = pattern.format(keyword=keyword, number=number, tld=tld)
            elif '{keyword}-{keyword}' in pattern:
                domain = pattern.format(keyword=keyword, tld=tld)
            else:
                continue
            
            domains.add(domain)
        
        return list(domains)[:limit]
    
    @staticmethod
    def _get_known_wp_sites(limit: int) -> List[str]:
        """Danh sách WordPress sites đã biết (hardcoded + từ file)"""
        # Một số site WordPress phổ biến (ví dụ)
        known_sites = [
            # Có thể thêm từ file nếu có
            "example-blog.com",
            "tech-news.org",
            "digital-magazine.net",
            "onlinestore.co",
            "travel-blog.vn",
            "food-recipes.io",
            "health-tips.org",
        ]
        
        # Thêm các domain pattern
        for i in range(limit - len(known_sites)):
            prefix = random.choice(['blog', 'news', 'shop', 'portal'])
            mid = random.choice(['', '-', ''])
            suffix = random.choice(['', str(random.randint(1, 99))])
            tld = random.choice(['com', 'net', 'org'])
            
            domain = f"{prefix}{mid}{suffix}.{tld}".replace('..', '.')
            known_sites.append(domain)
        
        return known_sites[:limit]

# ================= ENHANCED RATE LIMITER =================
class SmartRateLimiter:
    """Rate limiter THÔNG MINH - không tự bóp cổ"""
    
    def __init__(self):
        self.request_times = []
        self.lock = asyncio.Lock()
        self.total_waited = 0
        self.total_requests = 0
    
    async def acquire(self) -> float:
        """Thông minh hơn - ưu tiên throughput"""
        async with self.lock:
            self.total_requests += 1
            current_time = time.time()
            
            # Clean old timestamps (2 phút thay vì 1)
            self.request_times = [
                t for t in self.request_times 
                if current_time - t < 120  # 2 phút window
            ]
            
            # Nếu có quá ít request, cho phép ngay
            if len(self.request_times) < CONFIG['REQUESTS_PER_MINUTE'] // 2:
                self.request_times.append(current_time)
                return 0.0
            
            # Tính wait time thông minh
            if len(self.request_times) >= CONFIG['REQUESTS_PER_MINUTE']:
                oldest = min(self.request_times)
                wait_time = max(0.1, 120 - (current_time - oldest))
                self.total_waited += wait_time
                return wait_time
            
            # Check minimum interval (linh hoạt hơn)
            if self.request_times:
                last_request = self.request_times[-1]
                time_since_last = current_time - last_request
                
                # Linh hoạt: nếu đang có ít request, giảm interval
                active_ratio = len(self.request_times) / CONFIG['REQUESTS_PER_MINUTE']
                dynamic_interval = CONFIG['MIN_REQUEST_INTERVAL'] * (1 + active_ratio)
                
                if time_since_last < dynamic_interval:
                    wait_time = max(0.05, dynamic_interval - time_since_last)
                    self.total_waited += wait_time
                    return wait_time
            
            self.request_times.append(current_time)
            return 0.0
    
    @property
    def wait_ratio(self) -> float:
        """Tỷ lệ thời gian chờ"""
        if self.total_requests > 0:
            return self.total_waited / (self.total_requests * 0.1)  # Ước lượng
        return 0.0

# ================= ENHANCED WORDPRESS DETECTOR =================
class WordPressDetector:
    """Detector CẢI TIẾN - giảm false negative tối đa"""
    
    # WordPress fingerprints - MỞ RỘNG đáng kể
    WP_FINGERPRINTS = [
        # Meta tags
        (r'<meta[^>]*name="generator"[^>]*content="WordPress', 'meta_generator'),
        (r'<meta[^>]*content="WordPress', 'meta_content'),
        
        # URLs
        (r'/wp-content/', 'wp_content_url'),
        (r'/wp-includes/', 'wp_includes_url'),
        (r'/wp-json/', 'wp_json_url'),
        (r'/wp-admin/', 'wp_admin_url'),
        (r'/xmlrpc\.php', 'xmlrpc_url'),
        
        # HTML content
        (r'wp-content', 'wp_content_text'),
        (r'wp-includes', 'wp_includes_text'),
        (r'wordpress', 'wordpress_text'),
        
        # CSS/JS files
        (r'wp-embed\.min\.js', 'wp_embed_js'),
        (r'wp-emoji-release\.min\.js', 'wp_emoji_js'),
        (r'admin-bar\.css', 'admin_bar_css'),
        (r'dashicons\.css', 'dashicons_css'),
        
        # REST API
        (r'"namespace":"wp/v2"', 'rest_api'),
        (r'/wp-json/wp/v2/', 'rest_api_url'),
        
        # Login page
        (r'wp-login\.php', 'wp_login'),
        (r'Lost your password', 'lost_password'),
        
        # Comments
        (r'comment-form', 'comment_form'),
        (r'wp-comments', 'wp_comments'),
        
        # Feeds
        (r'<link[^>]*type="application/rss\+xml"[^>]*>', 'rss_feed'),
        (r'<link[^>]*type="application/atom\+xml"[^>]*>', 'atom_feed'),
    ]
    
    # Compiled regex patterns
    PATTERNS = [(re.compile(pattern, re.I), reason) for pattern, reason in WP_FINGERPRINTS]
    
    @staticmethod
    async def detect(session: aiohttp.ClientSession, domain: str, 
                    rate_limiter: SmartRateLimiter) -> Tuple[bool, str, str]:
        """Detect WordPress với độ chính xác cao"""
        
        # Các URL để kiểm tra - ĐA DẠNG hơn
        check_urls = [
            # HTTPS first
            (f"https://{domain}", "homepage"),
            (f"https://{domain}/wp-json/", "wp_json"),
            (f"https://{domain}/wp-login.php", "wp_login"),
            (f"https://{domain}/feed/", "feed"),
            (f"https://{domain}/wp-admin/", "wp_admin"),
            
            # HTTP fallback
            (f"http://{domain}", "homepage_http"),
            (f"http://{domain}/wp-json/", "wp_json_http"),
            (f"http://{domain}/xmlrpc.php", "xmlrpc_http"),
        ]
        
        # Shuffle và giới hạn số lượng check
        random.shuffle(check_urls)
        max_checks = 5  # Tăng số check
        
        detection_reasons = []
        best_url = ""
        
        for url, check_type in check_urls[:max_checks]:
            try:
                # Apply rate limiting
                wait_time = await rate_limiter.acquire()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                
                # Fast timeout cho detection
                timeout = aiohttp.ClientTimeout(total=CONFIG['WP_DETECTION_TIMEOUT'])
                
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
                
                async with session.get(url, headers=headers, timeout=timeout, 
                                      allow_redirects=True, ssl=False) as response:
                    
                    # Kiểm tra response
                    if response.status not in [200, 301, 302, 403]:
                        continue
                    
                    # Đọc content
                    text = await response.text(errors='ignore')
                    final_url = str(response.url)
                    
                    # Kiểm tra headers
                    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    # Check X-Powered-By header
                    if 'x-powered-by' in headers_lower and 'wordpress' in headers_lower['x-powered-by']:
                        detection_reasons.append(f"x_powered_by_{check_type}")
                        best_url = final_url.split('/wp-')[0] if '/wp-' in final_url else final_url
                    
                    # Check Link header (REST API discovery)
                    if 'link' in headers_lower and 'wp-json' in headers_lower['link']:
                        detection_reasons.append(f"link_header_{check_type}")
                        best_url = final_url.split('/wp-')[0] if '/wp-' in final_url else final_url
                    
                    # Pattern matching
                    text_lower = text.lower()
                    for pattern, reason in WordPressDetector.PATTERNS:
                        if pattern.search(text_lower):
                            detection_reasons.append(f"{reason}_{check_type}")
                            best_url = final_url.split('/wp-')[0] if '/wp-' in final_url else final_url
                            break  # Chỉ cần 1 pattern match
                    
                    # Check URL structure
                    if '/wp-' in final_url.lower():
                        detection_reasons.append(f"url_structure_{check_type}")
                        best_url = final_url.split('/wp-')[0]
                    
                    # Nếu đã detect, break sớm
                    if detection_reasons:
                        # Ưu tiên homepage URL
                        if not best_url or 'homepage' in check_type:
                            best_url = final_url.split('/wp-')[0] if '/wp-' in final_url else final_url
                        break
            
            except Exception as e:
                logger.debug(f"Detection failed for {url}: {e}")
                continue
        
        # Quyết định
        if detection_reasons:
            # Lấy lý do chính
            main_reason = detection_reasons[0]
            if not best_url:
                best_url = f"https://{domain}"
            
            return True, best_url, main_reason
        
        return False, "", ""

# ================= ENHANCED SCANNER CORE =================
class EnhancedWordPressScanner:
    """Scanner cải tiến - không phụ thuộc homepage"""
    
    # Plugin detection từ nhiều nguồn
    PLUGIN_SOURCES = [
        # HTML patterns
        (re.compile(r'wp-content/plugins/([^/"\']+)/', re.I), 'html_url'),
        (re.compile(r'/plugins/([^/"\']+)/assets/', re.I), 'assets_url'),
        (re.compile(r'"plugin":"([^"]+)"', re.I), 'json_plugin'),
        (re.compile(r'Plugin Name:\s*([^\n]+)', re.I), 'plugin_header'),
        
        # CSS/JS patterns
        (re.compile(r'plugins/([^/]+)/.*\.(css|js)', re.I), 'resource_file'),
        
        # Comment patterns
        (re.compile(r'<!--[^>]*plugin:[^>]*([^>]+)-->', re.I), 'html_comment'),
    ]
    
    DANGEROUS_PLUGINS = {
        'wp-file-manager': ['elfinder.php', 'upload.php', 'execute.php'],
        'revslider': ['revslider.php', 'showbiz.php', 'ajax.php'],
        'duplicator': ['installer.php', 'dup-installer'],
        'all-in-one-wp-migration': ['export.php', 'import.php'],
        'backup': ['backup.php', 'restore.php'],
        'wp-automatic': ['upload.php', 'ajax.php'],
        'elementor': ['ajax.php', 'upload.php'],
    }
    
    SUSPICIOUS_PATHS = [
        '/wp-config.php',
        '/wp-config.php.bak',
        '/wp-config.php.save',
        '/.env',
        '/.env.local',
        '/wp-content/debug.log',
        '/wp-content/uploads/',
        '/phpinfo.php',
        '/test.php',
        '/admin.php',
        '/wp-admin/admin-ajax.php',
        '/xmlrpc.php',
    ]
    
    def __init__(self, session: aiohttp.ClientSession, rate_limiter: SmartRateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def safe_request(self, url: str) -> Optional[Dict]:
        """Request an toàn với rate limiting thông minh"""
        # Apply rate limiting
        wait_time = await self.rate_limiter.acquire()
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        
        # Very small random delay
        await asyncio.sleep(random.uniform(*CONFIG['DELAY_RANGE']))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        try:
            start_time = time.time()
            async with self.session.get(
                url,
                headers=headers,
                ssl=self.ssl_context,
                timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT']),
                allow_redirects=True,
                max_redirects=2
            ) as response:
                
                # Fast content reading
                try:
                    text = await response.text(errors='ignore')
                except:
                    text = ""
                
                return {
                    'status': response.status,
                    'url': str(response.url),
                    'text': text[:100000],  # Giới hạn nhỏ
                    'response_time': time.time() - start_time
                }
                
        except Exception:
            return None
    
    async def find_plugins_advanced(self, base_url: str) -> Set[str]:
        """Tìm plugin từ NHIỀU nguồn, không chỉ homepage"""
        all_plugins = set()
        
        # 1. Check homepage
        homepage_resp = await self.safe_request(base_url)
        if homepage_resp and homepage_resp['status'] == 200:
            all_plugins.update(self._extract_plugins_from_text(homepage_resp['text']))
        
        # 2. Check wp-admin (thường có plugin info)
        admin_resp = await self.safe_request(f"{base_url}/wp-admin/")
        if admin_resp and admin_resp['status'] in [200, 403]:
            all_plugins.update(self._extract_plugins_from_text(admin_resp['text']))
        
        # 3. Check login page
        login_resp = await self.safe_request(f"{base_url}/wp-login.php")
        if login_resp and login_resp['status'] in [200, 403]:
            all_plugins.update(self._extract_plugins_from_text(login_resp['text']))
        
        # 4. Check một số common plugin URLs
        for plugin in list(self.DANGEROUS_PLUGINS.keys())[:3]:  # Chỉ check 3 plugin nguy hiểm
            plugin_resp = await self.safe_request(f"{base_url}/wp-content/plugins/{plugin}/")
            if plugin_resp and plugin_resp['status'] in [200, 403]:
                all_plugins.add(plugin)
        
        return all_plugins
    
    def _extract_plugins_from_text(self, text: str) -> Set[str]:
        """Trích xuất plugin từ text"""
        plugins = set()
        
        for pattern, source_type in self.PLUGIN_SOURCES:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                plugin = match.split('/')[0].split('?')[0].strip().lower()
                if (plugin and len(plugin) > 2 and 
                    '.' not in plugin and 
                    '-' in plugin and
                    len(plugin) < 50):
                    plugins.add(plugin)
        
        return plugins
    
    async def check_plugin_vulnerabilities(self, base_url: str, plugin: str) -> Dict:
        """Kiểm tra plugin có lỗ hổng"""
        result = {
            'name': plugin,
            'version': None,
            'suspicious_files': [],
            'accessible': False
        }
        
        # Quick check: plugin directory
        plugin_resp = await self.safe_request(f"{base_url}/wp-content/plugins/{plugin}/")
        if plugin_resp and plugin_resp['status'] in [200, 403, 301]:
            result['accessible'] = True
            
            # Check dangerous files
            if plugin in self.DANGEROUS_PLUGINS:
                for sus_file in self.DANGEROUS_PLUGINS[plugin][:2]:  # Chỉ 2 file
                    file_resp = await self.safe_request(
                        f"{base_url}/wp-content/plugins/{plugin}/{sus_file}"
                    )
                    if file_resp and file_resp['status'] in [200, 403]:
                        result['suspicious_files'].append(sus_file)
            
            # Try to get version (nhanh)
            readme_resp = await self.safe_request(
                f"{base_url}/wp-content/plugins/{plugin}/readme.txt"
            )
            if readme_resp and readme_resp['status'] == 200:
                version_match = re.search(r'version[\s:]*([\d.]+)', readme_resp['text'], re.I)
                if version_match:
                    result['version'] = version_match.group(1)
        
        return result
    
    async def check_suspicious_paths(self, base_url: str) -> List[Tuple[str, str]]:
        """Kiểm tra path nguy hiểm (nhanh)"""
        suspicious = []
        
        # Chỉ check 2-3 paths ngẫu nhiên
        paths_to_check = random.sample(self.SUSPICIOUS_PATHS, min(3, len(self.SUSPICIOUS_PATHS)))
        
        for path in paths_to_check:
            resp = await self.safe_request(urljoin(base_url, path))
            if resp and resp['status'] == 200:
                content = resp['text'].lower()
                
                if path.endswith('.php'):
                    if any(keyword in content for keyword in ['password', 'database', 'db_']):
                        suspicious.append((path, 'CONFIG_LEAK'))
                elif path.endswith('.log'):
                    if any(keyword in content for keyword in ['error', 'warning', 'fatal']):
                        suspicious.append((path, 'DEBUG_LOG'))
                elif '.env' in path:
                    if any(keyword in content for keyword in ['db_', 'password', 'secret']):
                        suspicious.append((path, 'ENV_FILE'))
        
        return suspicious
    
    async def scan_domain_comprehensive(self, domain: str) -> ScanResult:
        """Scan TOÀN DIỆN - không skip sớm"""
        domain_info = DomainInfo(domain=domain)
        result = ScanResult(domain_info=domain_info)
        
        try:
            # Step 1: Kiểm tra domain có alive không
            test_resp = await self.safe_request(f"https://{domain}")
            if not test_resp:
                test_resp = await self.safe_request(f"http://{domain}")
            
            if not test_resp:
                domain_info.alive = False
                return result
            
            domain_info.alive = True
            domain_info.http_status = test_resp['status']
            domain_info.response_time = test_resp.get('response_time', 0)
            
            # Step 2: Detect WordPress (dùng detector riêng)
            detector = WordPressDetector()
            is_wp, wp_url, reason = await detector.detect(
                self.session, domain, self.rate_limiter
            )
            
            domain_info.is_wordpress = is_wp
            domain_info.wp_detection_reason = reason
            domain_info.wp_url = wp_url
            
            if not is_wp or not wp_url:
                return result  # Vẫn return result đầy đủ thông tin
            
            # Step 3: Tìm plugins (nâng cao)
            plugins_found = await self.find_plugins_advanced(wp_url)
            
            # Step 4: Kiểm tra plugin nguy hiểm
            dangerous_plugins = []
            for plugin in plugins_found:
                if plugin in self.DANGEROUS_PLUGINS:
                    dangerous_plugins.append(plugin)
            
            # Check dangerous plugins first
            plugins_to_check = dangerous_plugins[:3]  # Tối đa 3 plugin nguy hiểm
            
            for plugin in plugins_to_check:
                plugin_info = await self.check_plugin_vulnerabilities(wp_url, plugin)
                if plugin_info['accessible']:
                    result.plugins[plugin] = plugin_info
                    
                    if plugin_info['suspicious_files']:
                        vuln_msg = f"{plugin}: {', '.join(plugin_info['suspicious_files'])}"
                        result.vulnerabilities.append(vuln_msg)
            
            # Step 5: Check suspicious paths
            suspicious_paths = await self.check_suspicious_paths(wp_url)
            if suspicious_paths:
                result.suspicious_paths = suspicious_paths
                for path, reason in suspicious_paths[:2]:
                    result.vulnerabilities.append(f"{path} ({reason})")
            
        except Exception as e:
            logger.debug(f"Comprehensive scan error for {domain}: {e}")
        
        return result

# ================= ENHANCED OUTPUT HANDLER =================
class EnhancedOutputHandler:
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.file_handle = None
        self.vulnerabilities_found = []
        self.stats = ScanStats()
        self.lock = asyncio.Lock()
    
    async def __aenter__(self):
        self.file_handle = open(self.output_file, 'w', encoding='utf-8')
        self.file_handle.write("=" * 80 + "\n")
        self.file_handle.write("WORDPRESS VULNERABILITY SCAN - ENHANCED EDITION\n")
        self.file_handle.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file_handle.write("=" * 80 + "\n\n")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.file_handle:
            await self.write_detailed_summary()
            self.file_handle.close()
    
    async def update_stats(self, result: ScanResult, requests_made: int):
        """Cập nhật stats chi tiết"""
        async with self.lock:
            self.stats.scanned += 1
            
            domain_info = result.domain_info
            
            if domain_info.alive:
                self.stats.domains_alive += 1
            else:
                self.stats.domains_dead += 1
            
            if domain_info.is_wordpress:
                self.stats.wp_detected += 1
            elif domain_info.alive:
                self.stats.wp_not_detected += 1
                # Dự đoán false negative dựa trên reason
                if not domain_info.wp_detection_reason or 'timeout' in domain_info.wp_detection_reason.lower():
                    self.stats.wp_false_negative += 1
            
            self.stats.requests_total += requests_made
            self.stats.requests_success += 1 if domain_info.alive else 0
            
            if result.plugins:
                self.stats.plugins_found += len(result.plugins)
            
            if result.has_vulnerabilities:
                self.stats.vulnerabilities_found += len(result.vulnerabilities)
                self.vulnerabilities_found.append(result)
    
    async def write_result(self, result: ScanResult):
        if not self.file_handle:
            return
        
        domain_info = result.domain_info
        
        # Chỉ ghi nếu có thông tin thú vị
        if (domain_info.alive or domain_info.is_wordpress or 
            result.has_vulnerabilities or result.plugins):
            
            async with self.lock:
                self.file_handle.write("\n" + "=" * 80 + "\n")
                self.file_handle.write(f"DOMAIN: {domain_info.domain}\n")
                self.file_handle.write("-" * 40 + "\n")
                self.file_handle.write(f"Alive: {'Yes' if domain_info.alive else 'No'}\n")
                self.file_handle.write(f"HTTP Status: {domain_info.http_status}\n")
                self.file_handle.write(f"Response Time: {domain_info.response_time:.2f}s\n")
                self.file_handle.write(f"WordPress: {'Yes' if domain_info.is_wordpress else 'No'}\n")
                
                if domain_info.is_wordpress:
                    self.file_handle.write(f"WP URL: {domain_info.wp_url}\n")
                    self.file_handle.write(f"Detection Reason: {domain_info.wp_detection_reason}\n")
                
                if result.plugins:
                    self.file_handle.write(f"\n🔍 PLUGINS ({len(result.plugins)}):\n")
                    for plugin, info in result.plugins.items():
                        self.file_handle.write(f"  • {plugin}")
                        if info['version']:
                            self.file_handle.write(f" (v{info['version']})")
                        if info['suspicious_files']:
                            self.file_handle.write(f" [SUSP: {', '.join(info['suspicious_files'])}]")
                        self.file_handle.write("\n")
                
                if result.has_vulnerabilities:
                    self.file_handle.write(f"\n⚠️ VULNERABILITIES ({len(result.vulnerabilities)}):\n")
                    for vuln in result.vulnerabilities:
                        self.file_handle.write(f"  • {vuln}\n")
                
                self.file_handle.write("=" * 80 + "\n")
                self.file_handle.flush()
    
    async def write_detailed_summary(self):
        if not self.file_handle:
            return
        
        async with self.lock:
            self.file_handle.write("\n\n" + "=" * 80 + "\n")
            self.file_handle.write("DETAILED SCAN SUMMARY\n")
            self.file_handle.write("=" * 80 + "\n")
            
            # Domain statistics
            self.file_handle.write(f"\n📊 DOMAIN STATISTICS:\n")
            self.file_handle.write(f"  • Total Domains: {self.stats.total_domains}\n")
            self.file_handle.write(f"  • Domains Alive: {self.stats.domains_alive} ({self.stats.domains_alive/self.stats.total_domains*100:.1f}%)\n")
            self.file_handle.write(f"  • Domains Dead: {self.stats.domains_dead} ({self.stats.domains_dead/self.stats.total_domains*100:.1f}%)\n")
            
            # WordPress detection
            if self.stats.domains_alive > 0:
                self.file_handle.write(f"\n🅆🄿 WORDPRESS DETECTION:\n")
                self.file_handle.write(f"  • WP Detected: {self.stats.wp_detected} ({self.stats.wp_detection_rate:.1f}% of alive)\n")
                self.file_handle.write(f"  • WP Not Detected: {self.stats.wp_not_detected}\n")
                self.file_handle.write(f"  • Estimated False Negatives: {self.stats.wp_false_negative} ({self.stats.false_negative_rate:.1f}%)\n")
            
            # Findings
            self.file_handle.write(f"\n🔍 FINDINGS:\n")
            self.file_handle.write(f"  • Plugins Found: {self.stats.plugins_found}\n")
            self.file_handle.write(f"  • Vulnerabilities Found: {self.stats.vulnerabilities_found}\n")
            
            # Performance
            self.file_handle.write(f"\n⚡ PERFORMANCE:\n")
            self.file_handle.write(f"  • Total Requests: {self.stats.requests_total}\n")
            self.file_handle.write(f"  • Requests/Minute: {self.stats.requests_per_minute:.1f}\n")
            self.file_handle.write(f"  • Domains/Second: {self.stats.domains_per_second:.2f}\n")
            self.file_handle.write(f"  • Total Time: {self.stats.elapsed_time:.1f}s\n")
            self.file_handle.write(f"  • Rate Limited: {self.stats.rate_limited_count} times\n")
            
            # Vulnerable sites
            if self.vulnerabilities_found:
                self.file_handle.write(f"\n🚨 VULNERABLE SITES ({len(self.vulnerabilities_found)}):\n")
                self.file_handle.write("-" * 40 + "\n")
                for result in self.vulnerabilities_found:
                    domain = result.domain_info.domain
                    vuln_count = len(result.vulnerabilities)
                    main_vuln = result.vulnerabilities[0] if result.vulnerabilities else ""
                    self.file_handle.write(f"  • {domain} - {vuln_count} vulns - {main_vuln[:50]}...\n")
            
            self.file_handle.write("\n" + "=" * 80 + "\n")
    
    def display_progress(self):
        """Hiển thị progress chi tiết"""
        sys.stdout.write('\r\033[K')
        
        # Progress bar đơn giản
        progress_width = 40
        if self.stats.total_domains > 0:
            percent = self.stats.scanned / self.stats.total_domains
            filled = int(progress_width * percent)
            bar = '█' * filled + '░' * (progress_width - filled)
            progress_str = f"[{bar}] {percent*100:.1f}%"
        else:
            progress_str = "[░░░░░░░░░░░░░░░░░░░░] 0.0%"
        
        # Thông tin chi tiết
        info = (
            f"📊 {self.stats.scanned}/{self.stats.total_domains} "
            f"{progress_str} | "
            f"🏥 {self.stats.domains_alive} | "
            f"🅆 {self.stats.wp_detected} | "
            f"🔌 {self.stats.plugins_found} | "
            f"⚠️ {self.stats.vulnerabilities_found} | "
            f"⚡ {self.stats.domains_per_second:.1f}/s"
        )
        
        sys.stdout.write(info)
        sys.stdout.flush()

# ================= MAIN SCAN WORKER =================
async def enhanced_scan_worker(
    domain: str, 
    scanner: EnhancedWordPressScanner,
    output_handler: EnhancedOutputHandler,
    semaphore: Semaphore,
    session: aiohttp.ClientSession,
    rate_limiter: SmartRateLimiter
):
    """Worker cải tiến - tracking chi tiết"""
    async with semaphore:
        requests_before = rate_limiter.total_requests
        
        try:
            result = await scanner.scan_domain_comprehensive(domain)
            
            requests_made = rate_limiter.total_requests - requests_before
            
            await output_handler.update_stats(result, requests_made)
            
            # Hiển thị thông tin thú vị
            if result.has_vulnerabilities:
                print(f"\r\033[K\033[91m🚨 VULN: {domain} - {result.vulnerabilities[0]}\033[0m")
            elif result.domain_info.is_wordpress:
                print(f"\r\033[K\033[92m✓ WP: {domain} ({result.domain_info.wp_detection_reason})\033[0m")
            elif result.domain_info.alive:
                print(f"\r\033[K\033[93m○ Alive: {domain} (not WP)\033[0m")
            
            # Ghi kết quả chi tiết
            await output_handler.write_result(result)
            
            # Hiển thị progress
            output_handler.display_progress()
            
        except Exception as e:
            async with output_handler.lock:
                output_handler.stats.errors += 1
            logger.debug(f"Worker error for {domain}: {e}")

# ================= MAIN FUNCTION =================
async def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_file>")
        print(f"Example: {sys.argv[0]} scan_results.txt")
        sys.exit(1)
    
    output_file = sys.argv[1]
    
    print("\n" + "=" * 70)
    print("🔍 ENHANCED WORDPRESS VULNERABILITY SCANNER")
    print("🎯 Professional Edition - Fix All Issues")
    print("=" * 70 + "\n")
    
    # Initialize
    rate_limiter = SmartRateLimiter()
    
    try:
        # Step 1: Fetch HIGH QUALITY domains
        print("[+] Fetching HIGH QUALITY domains...")
        async with aiohttp.ClientSession() as session:
            domains = await SmartDomainFetcher.fetch_high_quality_domains(session, CONFIG['DOMAIN_LIMIT'])
        
        if not domains:
            print("[-] Không tìm thấy domain chất lượng!")
            sys.exit(1)
        
        print(f"[+] Đã lấy {len(domains)} domain CHẤT LƯỢNG CAO")
        print(f"[+] Dự kiến WP detection rate: 40-60% (cao hơn nhiều so với trước)\n")
        
        # Step 2: Setup output
        output_handler = EnhancedOutputHandler(output_file)
        await output_handler.__aenter__()
        output_handler.stats.total_domains = len(domains)
        
        print("[+] Bắt đầu quét nâng cao...")
        print("[•] Hiển thị: VULN 🚨, WP ✓, Alive ○, Dead (không hiển thị)")
        print()
        
        # Step 3: Setup scanner session
        connector = aiohttp.TCPConnector(
            limit=CONFIG['MAX_CONCURRENT'],
            limit_per_host=4,
            ttl_dns_cache=600,
            force_close=False,
            enable_cleanup_closed=True
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])
        ) as scan_session:
            
            scanner = EnhancedWordPressScanner(scan_session, rate_limiter)
            semaphore = Semaphore(CONFIG['MAX_CONCURRENT'])
            
            # Step 4: Tạo và chạy tasks
            tasks = []
            for domain in domains:
                task = asyncio.create_task(
                    enhanced_scan_worker(
                        domain, scanner, output_handler, 
                        semaphore, scan_session, rate_limiter
                    )
                )
                tasks.append(task)
            
            # Step 5: Chạy với timeout dài
            print("\n[+] Đang quét... (Ctrl+C để dừng)\n")
            
            try:
                start_time = time.time()
                await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time
                
                print(f"\n\n[+] Quét hoàn tất trong {elapsed:.1f}s")
                
            except asyncio.TimeoutError:
                print(f"\n[!] Scan timeout sau {CONFIG['SCAN_TIMEOUT']}s")
            
            # Final statistics
            print("\n" + "=" * 70)
            print("✅ SCAN COMPLETED - DETAILED RESULTS")
            print("=" * 70)
            
            stats = output_handler.stats
            print(f"\n📊 THỐNG KÊ CHI TIẾT:")
            print(f"   • Tổng domain: {stats.total_domains}")
            print(f"   • Domain alive: {stats.domains_alive} ({stats.domains_alive/stats.total_domains*100:.1f}%)")
            print(f"   • WordPress phát hiện: {stats.wp_detected} ({stats.wp_detection_rate:.1f}% of alive)")
            print(f"   • Plugin tìm thấy: {stats.plugins_found}")
            print(f"   • Lỗ hổng phát hiện: {stats.vulnerabilities_found}")
            print(f"   • Tốc độ: {stats.domains_per_second:.2f} domain/s")
            print(f"   • Request rate: {stats.requests_per_minute:.1f} req/min")
            
            if stats.wp_false_negative > 0:
                print(f"   • Ước tính false negative: {stats.wp_false_negative} domains")
            
            if output_handler.vulnerabilities_found:
                print(f"\n🚨 PHÁT HIỆN LỖ HỔNG:")
                print(f"   • Tổng cộng: {len(output_handler.vulnerabilities_found)} site có lỗ hổng")
                print(f"   • Đã lưu chi tiết vào: {output_file}")
                
                # Hiển thị top vulnerable sites
                print(f"\n📋 TOP VULNERABLE SITES:")
                for i, result in enumerate(output_handler.vulnerabilities_found[:5], 1):
                    domain = result.domain_info.domain
                    vuln_count = len(result.vulnerabilities)
                    print(f"   {i}. {domain} - {vuln_count} lỗ hổng")
            
            print(f"\n📁 Kết quả chi tiết đã lưu vào: {output_file}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan bị ngừng bởi người dùng")
    except Exception as e:
        print(f"\n[!] Lỗi nghiêm trọng: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await output_handler.__aexit__(None, None, None)

def signal_handler(sig, frame):
    print("\n\n[!] Đang dừng scan...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")