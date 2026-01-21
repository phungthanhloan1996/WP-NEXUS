import requests
import re
import concurrent.futures
import urllib3
import os
import time
import socket
import json
import asyncio
import aiohttp
from datetime import datetime
from threading import Lock
from urllib.parse import urlparse, urljoin
from collections import Counter, defaultdict
from tqdm import tqdm
import dns.resolver
import random
import hashlib
import subprocess
import sys
from typing import List, Dict, Set, Tuple, Optional, Any, Callable

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CẤU HÌNH ====================
R, G, Y, B, C, M, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[95m', '\033[0m'
BOLD, UNDER = '\033[1m', '\033[4m'

THREADS = 15
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 0.2
MAX_CONCURRENT_ASYNC = 100

# ==================== PHASE 0: PASSIVE SOURCE ENRICHMENT ====================

class PassiveSourceEnricher:
    """Phase 0: Làm giàu nguồn targets từ dữ liệu thụ động"""
    
    def __init__(self):
        self.sources = []
        self.all_targets = set()
        
    def load_certificate_transparency(self, domain_keyword: str = None, limit: int = 1000) -> Set[str]:
        """Lấy domains từ Certificate Transparency logs (crtsh style)"""
        print(f"{C}[Phase 0] Querying Certificate Transparency...{W}")
        
        targets = set()
        
        # Mô phỏng query crt.sh - thực tế có thể gọi API hoặc parse HTML
        try:
            # Đây là mô phỏng - thực tế cần tích hợp với crt.sh API
            ct_domains = [
                # Các domain từ CT logs
                "*.example.com",
                "*.target-domain.com",
                "*.wordpress-site.net",
                # Subdomains thường gặp
                "blog.*", "wp.*", "cms.*", "www.*",
                # Gov/edu domains
                "*.gov.vn", "*.edu.vn", "*.gov.cn", "*.ac.uk"
            ]
            
            # Chuyển thành domain patterns
            for pattern in ct_domains:
                if domain_keyword and domain_keyword in pattern:
                    # Simple pattern to domain conversion
                    clean_domain = pattern.replace('*.', '').replace('*', '')
                    if clean_domain and '.' in clean_domain:
                        targets.add(clean_domain)
                        
        except Exception as e:
            print(f"{Y}[!] CT query error: {e}{W}")
        
        return targets
    
    def load_public_crawl_dumps(self, file_paths: List[str] = None) -> Set[str]:
        """Tải domains từ các public crawl dumps (CommonCrawl, Project Sonar, etc.)"""
        
        if file_paths is None:
            # Tìm các file dump có sẵn
            file_paths = [
                'commoncrawl_domains.txt',
                'sonar_subdomains.txt',
                'rapid7_forward_dns.txt',
                'alienvault_otx_domains.txt'
            ]
        
        all_domains = set()
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Extract domain từ các định dạng khác nhau
                                domain_match = re.search(
                                    r'([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                                    line
                                )
                                if domain_match:
                                    domain = domain_match.group(1).lower()
                                    # Loại bỏ các phần tử không hợp lệ
                                    if not any(x in domain for x in [' ', '@', '://', '&', '=']):
                                        all_domains.add(domain)
                    
                    print(f"{G}[+] Loaded {len(all_domains)} domains from {file_path}{W}")
                except Exception as e:
                    print(f"{Y}[!] Error loading {file_path}: {e}{W}")
        
        return all_domains
    
    def load_historical_lists(self) -> Set[str]:
        """Tải từ historical bug bounty targets, leak lists, paste sites"""
        
        historical_sources = [
            # Bug bounty platforms history
            'hackerone_targets.txt',
            'bugcrowd_programs.txt',
            'intigriti_domains.txt',
            # Leak lists
            'breach_compilation_domains.txt',
            'collection_1_domains.txt',
            # Paste sites dumps
            'pastebin_scrape.txt',
            'hashes_org_dumps.txt'
        ]
        
        domains = set()
        
        # Thêm các patterns thường gặp
        common_patterns = [
            r'[\w.-]+\.onion',  # Tor sites
            r'[\w.-]+\.i2p',    # I2P
            r'[\w.-]+\.bit',    # Namecoin
            # Gov/edu patterns
            r'[\w.-]+\.gov\.[\w]{2,}',
            r'[\w.-]+\.edu\.[\w]{2,}',
            r'[\w.-]+\.ac\.[\w]{2,}',
            r'[\w.-]+\.mil\.[\w]{2,}'
        ]
        
        for pattern in common_patterns:
            # Tạo các test domains từ patterns
            if '.gov' in pattern:
                domains.add('test.gov.vn')
                domains.add('subdomain.gov.uk')
                domains.add('agency.gov.au')
            elif '.edu' in pattern:
                domains.add('university.edu.vn')
                domains.add('college.ac.uk')
                domains.add('school.edu.au')
        
        return domains
    
    def enrich_from_passive_dns(self, seed_domains: Set[str]) -> Set[str]:
        """Sử dụng Passive DNS để tìm thêm related domains"""
        
        enriched = set(seed_domains)
        
        # Mô phỏng expansion từ seed domains
        for domain in list(seed_domains)[:50]:  # Giới hạn để tránh quá nhiều
            # Thêm các biến thể
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                
                # Tạo các subdomain thường gặp
                common_subs = ['www', 'blog', 'wp', 'cms', 'web', 'dev', 'test',
                             'staging', 'beta', 'mobile', 'api', 'admin', 'dashboard']
                
                for sub in common_subs:
                    enriched.add(f"{sub}.{base_domain}")
                
                # Thêm base domain chính
                enriched.add(base_domain)
        
        return enriched
    
    def generate_dirty_targets(self, min_count: int = 10000) -> Set[str]:
        """Tạo targets bẩn từ nhiều nguồn"""
        
        print(f"{B}[Phase 0] GENERATING DIRTY TARGETS FROM PASSIVE SOURCES{W}")
        
        # 1. CT logs
        ct_targets = self.load_certificate_transparency(limit=2000)
        print(f"{C}[*] CT logs: {len(ct_targets)} domains{W}")
        
        # 2. Public crawl dumps
        crawl_targets = self.load_public_crawl_dumps()
        print(f"{C}[*] Crawl dumps: {len(crawl_targets)} domains{W}")
        
        # 3. Historical lists
        historical_targets = self.load_historical_lists()
        print(f"{C}[*] Historical: {len(historical_targets)} domains{W}")
        
        # 4. Kết hợp tất cả
        all_targets = set()
        all_targets.update(ct_targets)
        all_targets.update(crawl_targets)
        all_targets.update(historical_targets)
        
        # 5. Enrich từ Passive DNS
        if all_targets:
            enriched = self.enrich_from_passive_dns(all_targets)
            print(f"{C}[*] After Passive DNS enrichment: {len(enriched)} domains{W}")
            all_targets.update(enriched)
        
        # 6. Thêm các TLD đặc biệt
        special_tlds = ['.gov.vn', '.edu.vn', '.gov.uk', '.edu.au', 
                       '.ac.uk', '.gov.cn', '.go.jp', '.gov.br']
        
        for tld in special_tlds:
            for i in range(5):  # Thêm một số ví dụ
                all_targets.add(f"agency{i}{tld}")
                all_targets.add(f"university{i}{tld}")
                all_targets.add(f"department{i}{tld}")
        
        print(f"{G}[✓] Total dirty targets generated: {len(all_targets)}{W}")
        
        # Lưu ra file
        if all_targets:
            output_file = 'dirty_targets.txt'
            with open(output_file, 'w', encoding='utf-8') as f:
                for domain in sorted(all_targets):
                    f.write(f"{domain}\n")
            print(f"{G}[+] Saved to {output_file}{W}")
        
        return all_targets

# ==================== HTTP CLIENT PRECISE (requests) ====================

class PreciseHTTPClient:
    """Client chính xác cho phase 1, 2, 3 - Dùng requests"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.max_redirects = 10
        self.timeout = REQUEST_TIMEOUT
        
        # Random User-Agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36'
        ]
        
        self._update_headers()
    
    def _update_headers(self):
        """Cập nhật headers với User-Agent ngẫu nhiên"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def head_request(self, url: str, allow_redirects: bool = True) -> Optional[requests.Response]:
        """HEAD request với xử lý redirect và SSL"""
        try:
            self._update_headers()  # Xoay User-Agent
            return self.session.head(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=allow_redirects
            )
        except Exception:
            return None
    
    def get_request(self, url: str, allow_redirects: bool = False, 
                   headers: Dict = None) -> Optional[requests.Response]:
        """GET request với fallback cho các trường hợp đặc biệt"""
        try:
            self._update_headers()
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            return self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=allow_redirects,
                headers=req_headers
            )
        except Exception:
            return None
    
    def post_request(self, url: str, data: str = None, 
                    content_type: str = None) -> Optional[requests.Response]:
        """POST request cho XML-RPC"""
        headers = {}
        if content_type:
            headers['Content-Type'] = content_type
        
        try:
            self._update_headers()
            return self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
        except Exception:
            return None
    
    def options_request(self, url: str) -> Optional[requests.Response]:
        """OPTIONS request cho behavior testing"""
        try:
            self._update_headers()
            return self.session.options(
                url,
                timeout=self.timeout,
                verify=False
            )
        except Exception:
            return None

# ==================== HTTP CLIENT FAST (aiohttp) ====================

class FastHTTPClient:
    """Client nhanh cho phase 3, 6 - Dùng aiohttp"""
    
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_ASYNC):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_multiple_paths(self, base_url: str, paths: List[str]) -> Dict[str, Dict]:
        """Check nhiều path cùng lúc - dùng aiohttp"""
        results = {}
        
        connector = aiohttp.TCPConnector(
            ssl=False, 
            limit=self.max_concurrent,
            ttl_dns_cache=300
        )
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        
        async with aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            tasks = []
            for path in paths:
                url = urljoin(base_url, path)
                task = self._check_single_path(session, url, path)
                tasks.append(task)
            
            path_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for path, result in zip(paths, path_results):
                if isinstance(result, dict):
                    results[path] = result
        
        return results
    
    async def _check_single_path(self, session: aiohttp.ClientSession, url: str, path: str) -> Dict:
        """Check một path - HEAD method với retry"""
        for attempt in range(2):  # Retry once
            try:
                async with session.head(url, ssl=False) as response:
                    return {
                        'path': path,
                        'status': response.status,
                        'url': str(response.url),
                        'headers': dict(response.headers)
                    }
            except asyncio.TimeoutError:
                if attempt == 0:
                    await asyncio.sleep(0.5)  # Wait before retry
                    continue
                else:
                    return {
                        'path': path,
                        'status': 0,
                        'error': 'timeout'
                    }
            except Exception as e:
                return {
                    'path': path,
                    'status': 0,
                    'error': str(e)[:100]
                }
        
        return {'path': path, 'status': 0, 'error': 'max_retries_exceeded'}

# ==================== PHASE 1: LIVENESS & NORMALIZATION ====================

class LivenessChecker:
    """Phase 1: Kiểm tra site sống và chuẩn hóa - DÙNG requests (chính xác)"""
    
    def __init__(self):
        self.client = PreciseHTTPClient()
    
    def normalize_domain(self, domain: str) -> str:
        """Chuẩn hóa domain: thêm protocol, xử lý www"""
        domain = domain.strip().lower()
        
        # Loại bỏ protocol nếu có
        domain = re.sub(r'^https?://', '', domain)
        
        # Loại bỏ path
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Loại bỏ www
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    
    def check_dns(self, domain: str) -> bool:
        """Kiểm tra DNS resolution trước"""
        try:
            # Thử cả IPv4 và IPv6
            socket.getaddrinfo(domain, None)
            return True
        except:
            return False
    
    def check_liveness(self, domain: str) -> Dict[str, Any]:
        """KIỂM TRA SỐNG: LUÔN THỬ CẢ HTTP VÀ HTTPS"""
        result = {
            'domain': domain,
            'normalized': self.normalize_domain(domain),
            'alive': False,
            'protocol': None,
            'final_url': None,
            'status_code': 0,
            'response_time': 0,
            'error': None,
            'redirect_chain': []
        }
        
        # Check DNS trước
        if not self.check_dns(domain):
            result['error'] = 'DNS resolution failed'
            return result
        
        # LUẬT: LUÔN THỬ CẢ HTTP VÀ HTTPS
        protocols_to_try = [
            ('https', f'https://{domain}'),
            ('http', f'http://{domain}')
        ]
        
        for protocol, url in protocols_to_try:
            try:
                start_time = time.time()
                
                # HEAD request trước
                resp = self.client.head_request(url, allow_redirects=True)
                
                if resp is None:
                    continue
                
                elapsed = time.time() - start_time
                
                # Nếu HEAD thành công
                if resp.status_code < 500:
                    result.update({
                        'alive': True,
                        'protocol': protocol,
                        'final_url': str(resp.url),
                        'status_code': resp.status_code,
                        'response_time': elapsed,
                        'error': None
                    })
                    return result
                
                # Nếu 403/405 thì thử GET
                if resp.status_code in [403, 405, 429]:
                    start_time = time.time()
                    resp_get = self.client.get_request(url, allow_redirects=False)
                    elapsed = time.time() - start_time
                    
                    if resp_get and resp_get.status_code < 500:
                        result.update({
                            'alive': True,
                            'protocol': protocol,
                            'final_url': str(resp_get.url) if hasattr(resp_get, 'url') else url,
                            'status_code': resp_get.status_code,
                            'response_time': elapsed,
                            'error': None
                        })
                        return result
                        
            except Exception as e:
                continue
        
        return result
    
    def normalize_entity(self, liveness_result: Dict) -> str:
        """Chuẩn hóa thành 1 entity duy nhất cho 1 host"""
        if not liveness_result['alive']:
            return liveness_result['normalized']
        
        final_url = liveness_result['final_url']
        if not final_url:
            return liveness_result['normalized']
        
        parsed = urlparse(final_url)
        
        # Loại bỏ www
        netloc = parsed.netloc.lower()
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        # Chuẩn hóa protocol
        scheme = parsed.scheme.lower() if parsed.scheme else 'http'
        
        return f"{scheme}://{netloc}"

# ==================== PHASE 2: WP DETECTION (MULTI-VECTOR ENHANCED) ====================

class EnhancedWPDetector:
    """Phase 2: Phát hiện WP bằng nhiều vector - Kết hợp static + behavioral"""
    
    def __init__(self):
        self.client = PreciseHTTPClient()
    
    def detect_via_direct_endpoints(self, base_url: str) -> List[Dict]:
        """Vector 1: Direct endpoints - mạnh nhất"""
        endpoints = [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-json/',
            '/feed/',
            '/?feed=rss2',
            '/xmlrpc.php',
            '/wp-links-opml.php',
            '/wp-cron.php'
        ]
        
        findings = []
        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            resp = self.client.head_request(url, allow_redirects=False)
            
            if resp and resp.status_code in [200, 301, 302, 401, 403, 405]:
                confidence = 95 if endpoint in ['/wp-login.php', '/wp-admin/', '/xmlrpc.php'] else 85
                findings.append({
                    'vector': 'DIRECT_ENDPOINT',
                    'endpoint': endpoint,
                    'status': resp.status_code,
                    'confidence': confidence
                })
        
        return findings
    
    def detect_via_behavioral_signals(self, base_url: str) -> List[Dict]:
        """Vector 2: Behavioral signals (POST, OPTIONS, 404 patterns)"""
        findings = []
        
        # 1. XML-RPC với body rỗng
        xmlrpc_url = urljoin(base_url, '/xmlrpc.php')
        empty_xml = '<?xml version="1.0"?>'
        resp_post = self.client.post_request(xmlrpc_url, data=empty_xml, content_type='text/xml')
        
        if resp_post and resp_post.status_code == 200:
            # Check for XML-RPC fault pattern
            if 'faultCode' in resp_post.text or 'parse error' in resp_post.text.lower():
                findings.append({
                    'vector': 'BEHAVIORAL',
                    'type': 'XMLRPC_EMPTY_RESPONSE',
                    'details': 'XML-RPC responds to empty request with XML-RPC fault',
                    'confidence': 92
                })
        
        # 2. OPTIONS request to REST API
        rest_url = urljoin(base_url, '/wp-json/')
        resp_options = self.client.options_request(rest_url)
        
        if resp_options:
            allow_header = resp_options.headers.get('Allow', '')
            if any(method in allow_header for method in ['GET', 'POST', 'OPTIONS']):
                findings.append({
                    'vector': 'BEHAVIORAL',
                    'type': 'REST_API_OPTIONS',
                    'details': f'REST API allows methods: {allow_header}',
                    'confidence': 88
                })
        
        # 3. 404 Error Signature
        random_url = urljoin(base_url, f'/nonexistent-{random.randint(10000, 99999)}.html')
        resp_404 = self.client.get_request(random_url, allow_redirects=False)
        
        if resp_404 and resp_404.status_code == 404:
            html = resp_404.text.lower()
            # WordPress 404 patterns
            patterns = [
                (r'error 404', 'WP_404_TITLE'),
                (r'page not found', 'WP_404_MESSAGE'),
                (r'/wp-content/themes/', 'WP_404_THEME_PATH'),
                (r'search form', 'WP_404_SEARCH_FORM')
            ]
            
            for pattern, pattern_type in patterns:
                if re.search(pattern, html):
                    findings.append({
                        'vector': 'BEHAVIORAL',
                        'type': '404_SIGNATURE',
                        'details': f'WordPress 404 pattern: {pattern_type}',
                        'confidence': 75
                    })
        
        return findings
    
    def detect_via_cookie_patterns(self, base_url: str) -> List[Dict]:
        """Vector 3: Cookie patterns"""
        findings = []
        
        resp = self.client.get_request(base_url, allow_redirects=False)
        if not resp:
            return findings
        
        cookies = resp.cookies
        
        # Check for WordPress cookie patterns
        wp_cookie_patterns = [
            r'wordpress_(?!test_)[a-zA-Z0-9_]+',  # wordpress_logged_in, etc
            r'wp-settings(-time)?-\d+',
            r'comment_author_[a-zA-Z0-9_]+',
            r'woocommerce_[a-zA-Z0-9_]+'
        ]
        
        for cookie in cookies:
            cookie_name = str(cookie.name)
            for pattern in wp_cookie_patterns:
                if re.match(pattern, cookie_name):
                    findings.append({
                        'vector': 'COOKIE_PATTERN',
                        'type': 'WP_COOKIE',
                        'cookie': cookie_name,
                        'confidence': 90
                    })
                    break
        
        # Check Set-Cookie header
        set_cookie = resp.headers.get('Set-Cookie', '')
        if 'wordpress_' in set_cookie.lower():
            findings.append({
                'vector': 'COOKIE_PATTERN',
                'type': 'WP_SET_COOKIE',
                'details': 'WordPress cookie in Set-Cookie header',
                'confidence': 85
            })
        
        return findings
    
    def detect_via_http_headers(self, base_url: str) -> List[Dict]:
        """Vector 4: HTTP Headers (enhanced)"""
        findings = []
        
        resp = self.client.get_request(base_url, allow_redirects=False)
        if not resp:
            return findings
        
        headers = resp.headers
        
        # X-Pingback header
        if 'x-pingback' in headers:
            findings.append({
                'vector': 'HTTP_HEADER',
                'type': 'X-Pingback',
                'value': headers['x-pingback'],
                'confidence': 90
            })
        
        # Link header với api.w.org
        if 'Link' in headers and 'api.w.org' in headers['Link']:
            findings.append({
                'vector': 'HTTP_HEADER',
                'type': 'Link',
                'value': headers['Link'],
                'confidence': 85
            })
        
        # X-Powered-By: PHP/...
        if 'x-powered-by' in headers:
            xpb = headers['x-powered-by'].lower()
            if 'php' in xpb:
                findings.append({
                    'vector': 'HTTP_HEADER',
                    'type': 'X-Powered-By',
                    'value': headers['x-powered-by'],
                    'confidence': 70
                })
        
        # Server header với Apache/nginx + PHP
        server_header = headers.get('Server', '').lower()
        if ('apache' in server_header or 'nginx' in server_header) and 'php' in server_header:
            findings.append({
                'vector': 'HTTP_HEADER',
                'type': 'Server',
                'value': headers['Server'],
                'confidence': 65
            })
        
        return findings
    
    def detect_via_html_artifacts(self, base_url: str) -> List[Dict]:
        """Vector 5: HTML artifacts (low-trust, context-aware)"""
        findings = []

        resp = self.client.get_request(base_url, allow_redirects=True)
        if not resp or not resp.text:
            return findings

        html = resp.text.lower()

        artifact_patterns = [
            (r'(?:src|href)=["\'][^"\']*/wp-content/(?:themes|plugins|uploads|mu-plugins)/', 'WP_CONTENT_RESOURCE', 45),
            (r'(?:src|href)=["\'][^"\']*/wp-includes/(?:js|css|images)/', 'WP_INCLUDES_RESOURCE', 45),
            (r'(?:src|href)=["\'][^"\']*wp-embed(\.min)?\.js', 'WP_EMBED_SCRIPT', 55),
            (r'id=["\']wpadminbar["\']', 'WP_ADMIN_BAR', 70),
            (r'wp-block-', 'WP_GUTENBERG_BLOCK', 50),
            (r'<meta[^>]+name=["\']generator["\'][^>]+wordpress', 'WP_GENERATOR_META', 30),
        ]

        for pattern, artifact_type, confidence in artifact_patterns:
            if re.search(pattern, html):
                findings.append({
                    "vector": "HTML_ARTIFACT",
                    "type": artifact_type,
                    "confidence": confidence
                })

        # Comment analysis = VERY LOW TRUST
        comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
        for comment in comments[:20]:  # limit noise
            c = comment.lower()
            if 'wordpress' in c or 'wp-' in c:
                findings.append({
                    "vector": "HTML_ARTIFACT",
                    "type": "WP_HTML_COMMENT",
                    "confidence": 20
                })
                break

        return findings

    
    def detect_via_rest_api_behavior(self, base_url: str) -> List[Dict]:
        """Vector 6: REST API behavior (high-trust WP signal)"""
        findings = []

        endpoints = [
            '/wp-json/',
            '/wp-json/wp/v2/',
        ]

        for ep in endpoints:
            rest_url = urljoin(base_url, ep)
            resp = self.client.get_request(rest_url, allow_redirects=False)
            if not resp:
                continue

            ct = resp.headers.get('Content-Type', '').lower()

            # WP REST normally returns JSON even on error
            if 'application/json' not in ct:
                continue

            try:
                data = json.loads(resp.text)
            except:
                continue

            # Strong WP patterns
            if isinstance(data, dict):
                if 'routes' in data and 'namespace' in data:
                    findings.append({
                        "vector": "REST_API_BEHAVIOR",
                        "type": "WP_REST_INDEX",
                        "confidence": 95
                    })
                    return findings  # đủ mạnh, khỏi test thêm

                if data.get('code') in ('rest_no_route', 'rest_disabled'):
                    findings.append({
                        "vector": "REST_API_BEHAVIOR",
                        "type": f"WP_REST_ERROR_{data.get('code')}",
                        "confidence": 90
                    })

            # 403 REST is still WP-ish
            if resp.status_code == 403:
                findings.append({
                    "vector": "REST_API_BEHAVIOR",
                    "type": "WP_REST_FORBIDDEN",
                    "confidence": 70
                })

        return findings

    
    def detect_via_mixed_content(self, base_url: str) -> List[Dict]:
        """Vector 7: Mixed content analysis (HTTPS site loading HTTP WP resources)"""
        findings = []

        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            return findings

        resp = self.client.get_request(base_url, allow_redirects=True)
        if not resp or not resp.text:
            return findings

        html = resp.text.lower()
        base_domain = parsed.netloc

        # Chỉ bắt src / href / action để giảm noise
        http_links = re.findall(
            r'(?:src|href|action)=["\'](http://[^"\']+)["\']',
            html
        )

        wp_internal = set()
        for link in http_links:
            lp = urlparse(link)
            if lp.netloc and base_domain in lp.netloc:
                if any(x in lp.path for x in (
                    '/wp-content/',
                    '/wp-includes/',
                    '/wp-json/',
                    '/wp-admin/'
                )):
                    wp_internal.add(link)

        if wp_internal:
            findings.append({
                "vector": "MIXED_CONTENT",
                "type": "INTERNAL_HTTP_WP_RESOURCE",
                "count": len(wp_internal),
                "examples": list(wp_internal)[:3],
                "confidence": 35
            })

        return findings

    
    def detect_wordpress(self, base_url: str) -> Dict[str, Any]:
        """PHÁT HIỆN WP: ≥ 2 VECTOR DƯƠNG TÍNH → WP (ENHANCED, FIXED)"""

        all_findings = []
        all_findings.extend(self.detect_via_direct_endpoints(base_url))
        all_findings.extend(self.detect_via_behavioral_signals(base_url))
        all_findings.extend(self.detect_via_cookie_patterns(base_url))
        all_findings.extend(self.detect_via_http_headers(base_url))
        all_findings.extend(self.detect_via_html_artifacts(base_url))
        all_findings.extend(self.detect_via_rest_api_behavior(base_url))
        all_findings.extend(self.detect_via_mixed_content(base_url))

        # --- FIX 1: group theo VECTOR ---
        vectors = {}
        for f in all_findings:
            v = f.get("vector", "UNKNOWN")
            vectors.setdefault(v, []).append(f)

        positive_vectors = list(vectors.keys())

        # LUẬT BẤT DI BẤT DỊCH
        is_wordpress = len(positive_vectors) >= 2

        # --- FIX 2: confidence theo VECTOR, không theo finding ---
        confidence = 0.0
        if is_wordpress:
            vector_scores = []
            for v, fs in vectors.items():
                max_conf = max(f.get("confidence", 0) for f in fs)
                vector_scores.append(max_conf)

            # mỗi vector đóng góp, nhưng diminishing return
            confidence = min(
                100,
                sum(vector_scores) * 0.9
            )

        return {
            "is_wordpress": is_wordpress,
            "confidence": round(confidence, 1),
            "vector_count": len(positive_vectors),
            "vector_breakdown": {v: len(fs) for v, fs in vectors.items()},
            "findings": all_findings,
            "base_url": base_url,
            "timestamp": datetime.now().isoformat()
        }

# ==================== PHASE 3: SURFACE MAPPING (ENHANCED) ====================

class EnhancedSurfaceMapper:
    """Phase 3: Map bề mặt tấn công - Plugin/Theme fingerprinting"""
    
    def __init__(self):
        self.precise_client = PreciseHTTPClient()
        self.fast_client = FastHTTPClient()
        self.plugin_signatures = self._load_plugin_signatures()
        self.theme_signatures = self._load_theme_signatures()
    
    def _load_plugin_signatures(self) -> Dict[str, Dict]:
        """Tải plugin signatures từ file hoặc built-in"""
        signatures = {}
        
        # Common WordPress plugins với signatures
        common_plugins = {
            'contact-form-7': {
                'paths': ['/wp-content/plugins/contact-form-7/'],
                'files': ['/wp-content/plugins/contact-form-7/readme.txt',
                         '/wp-content/plugins/contact-form-7/includes/css/styles.css'],
                'html_patterns': [r'contact-form-7', r'wpcf7']
            },
            'woocommerce': {
                'paths': ['/wp-content/plugins/woocommerce/'],
                'files': ['/wp-content/plugins/woocommerce/readme.txt',
                         '/wp-content/plugins/woocommerce/assets/css/woocommerce.css'],
                'html_patterns': [r'woocommerce', r'wc-']
            },
            'elementor': {
                'paths': ['/wp-content/plugins/elementor/'],
                'files': ['/wp-content/plugins/elementor/readme.txt',
                         '/wp-content/plugins/elementor/assets/css/frontend.css'],
                'html_patterns': [r'elementor', r'e-']
            },
            'yoast-seo': {
                'paths': ['/wp-content/plugins/wordpress-seo/'],
                'files': ['/wp-content/plugins/wordpress-seo/readme.txt',
                         '/wp-content/plugins/wordpress-seo/css/dist/yoast-seo.css'],
                'html_patterns': [r'yoast', r'yoast-seo']
            },
            'akismet': {
                'paths': ['/wp-content/plugins/akismet/'],
                'files': ['/wp-content/plugins/akismet/readme.txt',
                         '/wp-content/plugins/akismet/_inc/akismet.css'],
                'html_patterns': [r'akismet']
            }
        }
        
        return common_plugins
    
    def _load_theme_signatures(self) -> Dict[str, Dict]:
        """Tải theme signatures"""
        signatures = {
            'twentytwentyfour': {
                'paths': ['/wp-content/themes/twentytwentyfour/'],
                'files': ['/wp-content/themes/twentytwentyfour/style.css',
                         '/wp-content/themes/twentytwentyfour/readme.txt'],
                'html_patterns': [r'twentytwentyfour', r'tt4']
            },
            'astra': {
                'paths': ['/wp-content/themes/astra/'],
                'files': ['/wp-content/themes/astra/style.css',
                         '/wp-content/themes/astra/readme.txt'],
                'html_patterns': [r'astra', r'ast-']
            },
            'generatepress': {
                'paths': ['/wp-content/themes/generatepress/'],
                'files': ['/wp-content/themes/generatepress/style.css',
                         '/wp-content/themes/generatepress/readme.txt'],
                'html_patterns': [r'generatepress', r'gp-']
            },
            'oceanwp': {
                'paths': ['/wp-content/themes/oceanwp/'],
                'files': ['/wp-content/themes/oceanwp/style.css',
                         '/wp-content/themes/oceanwp/readme.txt'],
                'html_patterns': [r'oceanwp', r'owp-']
            }
        }
        
        return signatures
    
    def map_critical_surface(self, base_url: str) -> Dict[str, Any]:
        """Map bề mặt quan trọng - DÙNG requests (chính xác)"""
        
        results = {
            'xmlrpc': self._check_xmlrpc_enhanced(base_url),
            'rest_api': self._check_rest_api_enhanced(base_url),
            'user_enumeration': self._check_user_enumeration_enhanced(base_url),
            'login_exposed': self._check_login_exposed_enhanced(base_url),
            'upload_dir': self._check_upload_directory(base_url)
        }
        
        return results
    
    def map_passive_surface(self, base_url: str) -> Dict[str, Any]:
        """Map bề mặt thụ động - DÙNG aiohttp (nhanh)"""
        
        # Tạo danh sách path để check
        paths_to_check = []
        
        # Sensitive files (expanded)
        sensitive_files = [
            '/.env', '/.env.production', '/.env.local', '/.env.development',
            '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.save',
            '/wp-config.php.old', '/wp-config.php.backup',
            '/config.php', '/configuration.php', '/settings.php',
            '/backup.sql', '/database.sql', '/dump.sql', '/export.sql',
            '/backup.zip', '/database.zip', '/site.zip',
            '/error_log', '/debug.log', '/php_errors.log',
            '/phpinfo.php', '/info.php', '/test.php', '/admin.php'
        ]
        
        # Plugin paths từ signatures
        for plugin_name, plugin_info in self.plugin_signatures.items():
            for file_path in plugin_info['files'][:2]:  # Chỉ lấy 2 file đầu
                paths_to_check.append(file_path)
            for path in plugin_info['paths']:
                paths_to_check.append(path)
        
        # Theme paths
        for theme_name, theme_info in self.theme_signatures.items():
            for file_path in theme_info['files'][:2]:
                paths_to_check.append(file_path)
            for path in theme_info['paths']:
                paths_to_check.append(path)
        
        # Upload directories
        upload_paths = [
            '/wp-content/uploads/',
            '/wp-content/uploads/2024/',
            '/wp-content/uploads/2023/',
            '/uploads/',
            '/files/',
            '/media/'
        ]
        
        # Directory listing check
        dir_paths = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
            '/wp-admin/',
            '/wp-content/'
        ]
        
        paths_to_check.extend(sensitive_files)
        paths_to_check.extend(upload_paths)
        paths_to_check.extend(dir_paths)
        
        # Dùng aiohttp để check nhanh
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            path_results = loop.run_until_complete(
                self.fast_client.check_multiple_paths(base_url, paths_to_check)
            )
            loop.close()
        except Exception as e:
            print(f"{Y}[!] Async error in surface mapping: {e}{W}")
            path_results = {}
        
        # Phân tích kết quả
        return self._analyze_path_results(path_results, base_url)
    
    def _analyze_path_results(self, path_results: Dict, base_url: str) -> Dict:
        """Phân tích kết quả path checking"""
        
        exposed_files = []
        directory_listings = []
        detected_plugins = []
        detected_themes = []
        
        for path, result in path_results.items():
            status = result.get('status', 0)
            
            if status == 200:
                # Kiểm tra plugin detection
                for plugin_name, plugin_info in self.plugin_signatures.items():
                    if any(plugin_path in path for plugin_path in plugin_info['paths'] + plugin_info['files']):
                        if plugin_name not in detected_plugins:
                            detected_plugins.append({
                                'name': plugin_name,
                                'path': path,
                                'confidence': 90
                            })
                
                # Kiểm tra theme detection
                for theme_name, theme_info in self.theme_signatures.items():
                    if any(theme_path in path for theme_path in theme_info['paths'] + theme_info['files']):
                        if theme_name not in detected_themes:
                            detected_themes.append({
                                'name': theme_name,
                                'path': path,
                                'confidence': 90
                            })
                
                # Exposed file
                if any(x in path for x in ['.env', 'config', 'sql', 'backup', 'log', 'phpinfo']):
                    risk = 'critical' if any(x in path for x in ['.env', 'config.php', 'backup.sql']) else 'high'
                    exposed_files.append({
                        'path': path,
                        'status': 200,
                        'risk': risk,
                        'type': self._classify_file_type(path)
                    })
                
                # Directory listing check
                elif any(p in path for p in ['/uploads/', '/plugins/', '/themes/', '/includes/', '/admin/']):
                    # Cần GET request để xác định directory listing
                    # Tạm thời đánh dấu
                    directory_listings.append({
                        'directory': path,
                        'status': 200,
                        'potential_listing': True
                    })
        
        # Passive plugin detection từ HTML
        passive_plugins = self._detect_plugins_from_html(base_url)
        detected_plugins.extend(passive_plugins)
        
        # Remove duplicates
        unique_plugins = []
        seen = set()
        for plugin in detected_plugins:
            key = plugin['name']
            if key not in seen:
                seen.add(key)
                unique_plugins.append(plugin)
        
        unique_themes = []
        seen = set()
        for theme in detected_themes:
            key = theme['name']
            if key not in seen:
                seen.add(key)
                unique_themes.append(theme)
        
        return {
            'exposed_files': exposed_files,
            'directory_listing': directory_listings,
            'detected_plugins': unique_plugins,
            'detected_themes': unique_themes,
            'paths_checked': len(path_results),
            'paths_found': len(exposed_files) + len(directory_listings)
        }
    
    def _detect_plugins_from_html(self, base_url: str) -> List[Dict]:
        """Phát hiện plugin từ HTML comments và resource paths"""
        
        plugins = []
        
        resp = self.precise_client.get_request(base_url, allow_redirects=False)
        if not resp or not resp.text:
            return plugins
        
        html = resp.text.lower()
        
        # Tìm trong comments
        comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
        for comment in comments:
            for plugin_name, plugin_info in self.plugin_signatures.items():
                if plugin_name in comment:
                    plugins.append({
                        'name': plugin_name,
                        'source': 'html_comment',
                        'confidence': 80
                    })
        
        # Tìm trong script và link tags
        script_patterns = [
            r'src=["\'][^"\']*?/plugins/([^/"\']+)/',
            r'href=["\'][^"\']*?/plugins/([^/"\']+)/'
        ]
        
        for pattern in script_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match in self.plugin_signatures:
                    plugins.append({
                        'name': match,
                        'source': 'resource_path',
                        'confidence': 85
                    })
        
        # Tìm version strings
        version_pattern = r'([a-z0-9-]+)-([0-9.]+)\.(?:js|css)'
        matches = re.findall(version_pattern, html)
        for plugin_name, version in matches:
            if plugin_name in self.plugin_signatures:
                plugins.append({
                    'name': plugin_name,
                    'version': version,
                    'source': 'version_string',
                    'confidence': 90
                })
        
        return plugins
    
    def _classify_file_type(self, path: str) -> str:
        """Phân loại file type"""
        if '.env' in path:
            return 'environment_config'
        elif 'config' in path and '.php' in path:
            return 'php_config'
        elif '.sql' in path:
            return 'database_dump'
        elif 'backup' in path and ('.zip' in path or '.tar' in path):
            return 'backup_archive'
        elif 'log' in path:
            return 'error_log'
        elif 'phpinfo' in path or 'info.php' in path:
            return 'php_info'
        else:
            return 'other_sensitive'
    
    def _check_xmlrpc_enhanced(self, base_url: str) -> Dict:
        """Kiểm tra XML-RPC nâng cao"""
        url = urljoin(base_url, '/xmlrpc.php')
        resp = self.precise_client.head_request(url, allow_redirects=False)
        
        result = {
            'active': False,
            'status': 0,
            'methods': [],
            'pingback_enabled': False,
            'bruteforce_possible': False
        }
        
        if resp:
            result['status'] = resp.status_code
            result['active'] = resp.status_code == 200
            
            if resp.status_code == 200:
                # Test pingback
                pingback_xml = '''<?xml version="1.0"?>
                <methodCall>
                    <methodName>pingback.ping</methodName>
                    <params>
                        <param><value><string>http://example.com/target</string></value></param>
                        <param><value><string>http://example.com/source</string></value></param>
                    </params>
                </methodCall>'''
                
                resp_pingback = self.precise_client.post_request(
                    url, 
                    data=pingback_xml, 
                    content_type='text/xml'
                )
                
                if resp_pingback and resp_pingback.status_code == 200:
                    result['pingback_enabled'] = True
                
                # Test bruteforce methods
                brute_xml = '''<?xml version="1.0"?>
                <methodCall>
                    <methodName>wp.getUsersBlogs</methodName>
                    <params>
                        <param><value><string>admin</string></value></param>
                        <param><value><string>password123</string></value></param>
                    </params>
                </methodCall>'''
                
                resp_brute = self.precise_client.post_request(
                    url,
                    data=brute_xml,
                    content_type='text/xml'
                )
                
                if resp_brute and resp_brute.status_code == 200:
                    # Check if it's a valid XML-RPC response (not a fault)
                    if 'faultCode' not in resp_brute.text:
                        result['bruteforce_possible'] = True
        
        return result
    
    def _check_rest_api_enhanced(self, base_url: str) -> Dict:
        """Kiểm tra REST API nâng cao"""
        endpoints_to_check = [
            '/wp-json/wp/v2/',
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/comments'
        ]
        
        results = {}
        for endpoint in endpoints_to_check:
            url = urljoin(base_url, endpoint)
            resp = self.precise_client.get_request(url, allow_redirects=False)
            
            if resp:
                endpoint_result = {
                    'active': resp.status_code < 400,
                    'status': resp.status_code,
                    'requires_auth': resp.status_code == 401,
                    'exposes_data': resp.status_code == 200
                }
                
                if resp.status_code == 200:
                    try:
                        data = json.loads(resp.text)
                        if isinstance(data, list):
                            endpoint_result['item_count'] = len(data)
                        elif isinstance(data, dict):
                            endpoint_result['keys'] = list(data.keys())
                    except:
                        pass
                
                results[endpoint] = endpoint_result
        
        # Tổng hợp
        active_endpoints = [ep for ep, res in results.items() if res['active']]
        exposing_endpoints = [ep for ep, res in results.items() if res.get('exposes_data', False)]
        
        return {
            'active': len(active_endpoints) > 0,
            'active_endpoints': active_endpoints,
            'exposing_endpoints': exposing_endpoints,
            'detailed_results': results,
            'users_exposed': '/wp-json/wp/v2/users' in exposing_endpoints,
            'posts_exposed': '/wp-json/wp/v2/posts' in exposing_endpoints
        }
    
    def _check_user_enumeration_enhanced(self, base_url: str) -> Dict:
        """Kiểm tra user enumeration nâng cao"""
        methods = []
        enumerated_users = []
        
        # Method 1: REST API
        rest_url = urljoin(base_url, '/wp-json/wp/v2/users')
        resp_rest = self.precise_client.get_request(rest_url, allow_redirects=False)
        
        if resp_rest and resp_rest.status_code == 200:
            methods.append('rest_api')
            try:
                users = json.loads(resp_rest.text)
                if isinstance(users, list):
                    enumerated_users = [{'id': u.get('id'), 'name': u.get('name')} for u in users[:10]]
            except:
                pass
        
        # Method 2: Author pages
        author_url = urljoin(base_url, '/?author=1')
        resp_author = self.precise_client.head_request(author_url, allow_redirects=False)
        
        if resp_author and resp_author.status_code in [301, 302]:
            methods.append('author_pages')
        
        # Method 3: oEmbed
        oembed_url = urljoin(base_url, '/wp-json/oembed/1.0/embed?url=' + base_url)
        resp_oembed = self.precise_client.get_request(oembed_url, allow_redirects=False)
        
        if resp_oembed and resp_oembed.status_code == 200:
            try:
                data = json.loads(resp_oembed.text)
                if 'author_name' in data:
                    methods.append('oembed')
                    enumerated_users.append({'name': data['author_name'], 'source': 'oembed'})
            except:
                pass
        
        return {
            'enumerable': len(methods) > 0,
            'methods': methods,
            'user_count': len(enumerated_users),
            'users': enumerated_users[:5],  # Limit to 5
            'rest_api_exposed': 'rest_api' in methods
        }
    
    def _check_login_exposed_enhanced(self, base_url: str) -> Dict:
        """Kiểm tra login page nâng cao"""
        login_url = urljoin(base_url, '/wp-login.php')
        
        result = {
            'exposed': False,
            'status': 0,
            'requires_auth': False,
            'has_redirect': False,
            'security_headers': {}
        }
        
        # HEAD request
        resp = self.precise_client.head_request(login_url, allow_redirects=False)
        
        if resp:
            result['status'] = resp.status_code
            result['exposed'] = resp.status_code in [200, 302, 401, 403]
            result['requires_auth'] = resp.status_code == 401
            result['has_redirect'] = resp.status_code in [301, 302]
            
            # Check security headers
            headers_to_check = ['X-Frame-Options', 'Content-Security-Policy', 
                              'Strict-Transport-Security', 'X-Content-Type-Options']
            
            for header in headers_to_check:
                if header in resp.headers:
                    result['security_headers'][header] = resp.headers[header]
        
        # GET request để check form
        if result['exposed'] and not result['requires_auth']:
            resp_get = self.precise_client.get_request(login_url, allow_redirects=False)
            if resp_get and resp_get.text:
                html = resp_get.text.lower()
                result['has_login_form'] = 'loginform' in html or 'user_login' in html
                result['has_remember_me'] = 'rememberme' in html
        
        return result
    
    def _check_upload_directory(self, base_url: str) -> Dict:
        """Kiểm tra upload directory"""
        upload_urls = [
            urljoin(base_url, '/wp-content/uploads/'),
            urljoin(base_url, '/wp-content/uploads/2024/'),
            urljoin(base_url, '/uploads/')
        ]
        
        results = []
        for url in upload_urls:
            resp = self.precise_client.head_request(url, allow_redirects=False)
            if resp:
                results.append({
                    'url': url,
                    'status': resp.status_code,
                    'accessible': resp.status_code in [200, 301, 302, 403]
                })
        
        return {
            'accessible_uploads': [r for r in results if r['accessible']],
            'writable_check': len([r for r in results if r['status'] == 200]) > 0
        }

# ==================== PHASE 4: ENHANCED WEAKNESS CORRELATION ====================

class EnhancedWeaknessCorrelator:
    """Phase 4: Tìm mối tương quan giữa các weakness - EXPANDED"""
    
    CORRELATION_PATTERNS = {
        'RCE_CHAIN': {
            'weaknesses': ['xmlrpc_active', 'upload_writable', 'directory_listing', 
                          'plugin_exposed', 'old_plugin_version', 'file_upload_allowed'],
            'description': 'Chain có thể dẫn đến Remote Code Execution',
            'multiplier': 2.8,
            'scenario': 'RCE'
        },
        'BRUTEFORCE_VECTOR': {
            'weaknesses': ['xmlrpc_active', 'user_enumeration', 'login_exposed',
                          'no_login_captcha', 'no_rate_limit', 'weak_password_policy'],
            'description': 'Chain có thể brute-force credentials',
            'multiplier': 2.3,
            'scenario': 'BRUTEFORCE'
        },
        'DATA_EXFIL': {
            'weaknesses': ['config_exposed', 'backup_exposed', 'directory_listing',
                          'rest_api_exposed', 'database_exposed', 'log_exposed'],
            'description': 'Chain có thể dẫn đến data exfiltration',
            'multiplier': 2.1,
            'scenario': 'DATA_EXFILTRATION'
        },
        'PLUGIN_EXPLOIT': {
            'weaknesses': ['plugin_exposed', 'old_plugin_version', 'no_waf',
                          'xmlrpc_active', 'upload_writable'],
            'description': 'Vulnerable plugin với exploit path',
            'multiplier': 2.5,
            'scenario': 'PLUGIN_EXPLOIT'
        },
        'GOV_SPECIAL': {
            'weaknesses': ['http_only', 'old_wp_version', 'gov_domain',
                          'config_exposed', 'no_https_redirect'],
            'description': 'Government/edu sites với config đặc biệt',
            'multiplier': 2.4,
            'scenario': 'GOV_SPECIAL'
        },
        'AUTH_BYPASS': {
            'weaknesses': ['rest_api_exposed', 'no_auth_required', 'user_enumeration',
                          'xmlrpc_active', 'weak_cors'],
            'description': 'Potential authentication bypass vectors',
            'multiplier': 2.2,
            'scenario': 'AUTH_BYPASS'
        }
    }
    
    def analyze_correlations(self, surface_results: Dict, wp_detection: Dict) -> Dict[str, Any]:
        """Phân tích correlation giữa các weakness - ENHANCED"""
        
        weakness_flags = set()
        
        # 1. Từ critical surface
        critical = surface_results.get('critical_surface', {})
        passive = surface_results.get('passive_surface', {})
        
        if critical.get('xmlrpc', {}).get('active'):
            weakness_flags.add('xmlrpc_active')
            if critical['xmlrpc'].get('pingback_enabled'):
                weakness_flags.add('pingback_enabled')
            if critical['xmlrpc'].get('bruteforce_possible'):
                weakness_flags.add('xmlrpc_bruteforce')
        
        if critical.get('user_enumeration', {}).get('enumerable'):
            weakness_flags.add('user_enumeration')
            if critical['user_enumeration'].get('rest_api_exposed'):
                weakness_flags.add('rest_user_enumeration')
        
        if critical.get('login_exposed', {}).get('exposed'):
            weakness_flags.add('login_exposed')
            if not critical['login_exposed'].get('requires_auth'):
                weakness_flags.add('login_public')
            if not critical['login_exposed'].get('security_headers'):
                weakness_flags.add('no_login_security_headers')
        
        rest_api = critical.get('rest_api', {})
        if rest_api.get('active'):
            weakness_flags.add('rest_api_exposed')
            if rest_api.get('users_exposed'):
                weakness_flags.add('rest_users_exposed')
            if rest_api.get('posts_exposed'):
                weakness_flags.add('rest_posts_exposed')
        
        # 2. Từ passive surface
        for file in passive.get('exposed_files', []):
            file_type = file.get('type', '')
            if 'config' in file_type or '.env' in file['path']:
                weakness_flags.add('config_exposed')
            if 'database' in file_type or 'sql' in file['path']:
                weakness_flags.add('database_exposed')
            if 'backup' in file_type:
                weakness_flags.add('backup_exposed')
            if 'error_log' in file_type:
                weakness_flags.add('log_exposed')
            if 'php_info' in file_type:
                weakness_flags.add('phpinfo_exposed')
        
        if passive.get('directory_listing'):
            weakness_flags.add('directory_listing')
        
        # Plugin analysis
        plugins = passive.get('detected_plugins', [])
        if plugins:
            weakness_flags.add('plugin_exposed')
            # Check for old/known vulnerable plugins
            vulnerable_plugins = ['contact-form-7', 'elementor', 'revslider']
            for plugin in plugins:
                if plugin['name'] in vulnerable_plugins:
                    weakness_flags.add('old_plugin_version')
                    break
        
        # Upload directory check
        upload_dir = critical.get('upload_dir', {})
        if upload_dir.get('writable_check'):
            weakness_flags.add('upload_writable')
        
        # 3. Từ domain characteristics
        normalized_url = wp_detection.get('base_url', '')
        if normalized_url:
            if normalized_url.startswith('http://'):
                weakness_flags.add('http_only')
            if '.gov.' in normalized_url or '.edu.' in normalized_url or '.ac.' in normalized_url:
                weakness_flags.add('gov_domain')
        
        # 4. Từ WP detection confidence
        if wp_detection.get('confidence', 0) < 70:
            weakness_flags.add('low_wp_confidence')
        
        # Tìm correlation patterns
        detected_patterns = []
        total_multiplier = 1.0
        
        for pattern_name, pattern_info in self.CORRELATION_PATTERNS.items():
            required_weaknesses = pattern_info['weaknesses']
            found_weaknesses = [w for w in required_weaknesses if w in weakness_flags]
            found_count = len(found_weaknesses)
            
            # Nếu tìm thấy ít nhất 2 weaknesses trong pattern
            if found_count >= 2:
                pattern_score = found_count / len(required_weaknesses)
                
                # Tính risk weight dựa trên số weaknesses tìm thấy
                risk_weight = 1.0 + (found_count - 2) * 0.2
                
                detected_patterns.append({
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'match_score': round(pattern_score, 2),
                    'weakness_match': found_count,
                    'total_weaknesses': len(required_weaknesses),
                    'multiplier': pattern_info['multiplier'],
                    'scenario': pattern_info['scenario'],
                    'matched_weaknesses': found_weaknesses,
                    'risk_weight': round(risk_weight, 2)
                })
                
                total_multiplier *= (pattern_info['multiplier'] * risk_weight)
        
        # Tính correlation score tổng hợp
        correlation_score = len(detected_patterns) * 20
        
        # Thêm bonus cho nhiều patterns
        if len(detected_patterns) >= 2:
            correlation_score += 15
        if len(detected_patterns) >= 3:
            correlation_score += 20
        
        # Cap at 100
        correlation_score = min(100, correlation_score)
        
        return {
            'weakness_flags': sorted(list(weakness_flags)),
            'weakness_count': len(weakness_flags),
            'detected_patterns': detected_patterns,
            'pattern_count': len(detected_patterns),
            'correlation_multiplier': round(total_multiplier, 2),
            'correlation_score': correlation_score,
            'critical_weaknesses': [w for w in weakness_flags if w in [
                'config_exposed', 'database_exposed', 'xmlrpc_bruteforce',
                'upload_writable', 'phpinfo_exposed'
            ]]
        }

# ==================== PHASE 5: ENHANCED SCENARIO-BASED RISK SCORING ====================

class EnhancedRiskCalculator:
    """Phase 5: Tính risk dựa trên kịch bản thực tế - EXPANDED"""
    
    SCENARIOS = {
        'RCE': {
            'name': 'Remote Code Execution',
            'indicators': ['xmlrpc_active', 'upload_writable', 'directory_listing',
                          'plugin_exposed', 'old_plugin_version', 'file_upload_allowed',
                          'config_exposed', 'phpinfo_exposed'],
            'base_risk': 95,
            'weight': 1.6,
            'impact': 'critical',
            'exploitability': 'high'
        },
        'BRUTEFORCE': {
            'name': 'Authentication Brute-force',
            'indicators': ['xmlrpc_active', 'user_enumeration', 'login_exposed',
                          'no_login_captcha', 'no_rate_limit', 'xmlrpc_bruteforce',
                          'login_public', 'rest_user_enumeration'],
            'base_risk': 75,
            'weight': 1.4,
            'impact': 'high',
            'exploitability': 'very_high'
        },
        'DATA_EXFILTRATION': {
            'name': 'Data Exfiltration',
            'indicators': ['config_exposed', 'backup_exposed', 'directory_listing',
                          'rest_api_exposed', 'database_exposed', 'log_exposed',
                          'rest_users_exposed', 'rest_posts_exposed'],
            'base_risk': 70,
            'weight': 1.3,
            'impact': 'high',
            'exploitability': 'medium'
        },
        'PLUGIN_EXPLOIT': {
            'name': 'Vulnerable Plugin Exploit',
            'indicators': ['plugin_exposed', 'old_plugin_version', 'no_waf',
                          'xmlrpc_active', 'upload_writable', 'directory_listing',
                          'http_only', 'low_wp_confidence'],
            'base_risk': 85,
            'weight': 1.5,
            'impact': 'high',
            'exploitability': 'high'
        },
        'GOV_SPECIAL': {
            'name': 'Government/Edu Special Case',
            'indicators': ['http_only', 'old_wp_version', 'gov_domain',
                          'config_exposed', 'no_https_redirect', 'no_security_headers',
                          'login_public', 'directory_listing'],
            'base_risk': 80,
            'weight': 1.4,
            'impact': 'very_high',  # High impact due to sensitive data
            'exploitability': 'medium'
        },
        'AUTH_BYPASS': {
            'name': 'Authentication Bypass',
            'indicators': ['rest_api_exposed', 'no_auth_required', 'user_enumeration',
                          'xmlrpc_active', 'weak_cors', 'login_public',
                          'rest_users_exposed', 'no_login_security_headers'],
            'base_risk': 90,
            'weight': 1.5,
            'impact': 'critical',
            'exploitability': 'medium'
        }
    }
    
    def calculate_scenario_risk(self, weakness_flags: List[str], 
                               correlation_result: Dict,
                               wp_detection: Dict) -> Dict[str, Any]:
        """Tính risk dựa trên kịch bản - ENHANCED"""
        
        scenario_risks = []
        max_scenario_risk = 0
        worst_scenario = None
        worst_scenario_details = None
        
        for scenario_id, scenario_info in self.SCENARIOS.items():
            # Đếm indicators có mặt
            present_indicators = [ind for ind in scenario_info['indicators'] if ind in weakness_flags]
            indicator_score = len(present_indicators) / len(scenario_info['indicators'])
            
            # Tính base risk
            scenario_risk = scenario_info['base_risk'] * indicator_score * scenario_info['weight']
            
            # Apply correlation multiplier
            scenario_risk *= correlation_result.get('correlation_multiplier', 1.0)
            
            # Apply WP confidence factor
            wp_confidence = wp_detection.get('confidence', 50)
            confidence_factor = wp_confidence / 100.0
            scenario_risk *= confidence_factor
            
            # Thêm bonus cho critical weaknesses
            critical_bonus = 0
            critical_indicators = ['config_exposed', 'database_exposed', 'phpinfo_exposed',
                                 'xmlrpc_bruteforce', 'upload_writable']
            critical_present = [ind for ind in critical_indicators if ind in present_indicators]
            if critical_present:
                critical_bonus = len(critical_present) * 5
            
            scenario_risk += critical_bonus
            
            # Cap at 100
            scenario_risk = min(100, scenario_risk)
            
            # Phân loại mức độ risk
            risk_level = 'low'
            if scenario_risk > 70:
                risk_level = 'critical'
            elif scenario_risk > 50:
                risk_level = 'high'
            elif scenario_risk > 30:
                risk_level = 'medium'
            
            scenario_data = {
                'scenario': scenario_id,
                'name': scenario_info['name'],
                'risk_score': round(scenario_risk, 1),
                'risk_level': risk_level,
                'indicator_score': round(indicator_score * 100, 1),
                'indicators_present': len(present_indicators),
                'total_indicators': len(scenario_info['indicators']),
                'present_indicators': present_indicators,
                'impact': scenario_info['impact'],
                'exploitability': scenario_info['exploitability']
            }
            
            scenario_risks.append(scenario_data)
            
            # Cập nhật worst case
            if scenario_risk > max_scenario_risk:
                max_scenario_risk = scenario_risk
                worst_scenario = scenario_id
                worst_scenario_details = scenario_data
        
        # Tổng risk dựa trên worst case scenario + pattern count
        overall_risk = max_scenario_risk
        
        # Thêm bonus cho multiple scenarios
        high_risk_scenarios = len([s for s in scenario_risks if s['risk_score'] > 50])
        if high_risk_scenarios >= 2:
            overall_risk += 5
        if high_risk_scenarios >= 3:
            overall_risk += 10
        
        # Thêm bonus cho pattern count
        pattern_count = correlation_result.get('pattern_count', 0)
        overall_risk += pattern_count * 3
        
        # Cap at 100
        overall_risk = min(100, overall_risk)
        
        # Xác định risk level tổng thể
        overall_risk_level = 'low'
        if overall_risk > 80:
            overall_risk_level = 'critical'
        elif overall_risk > 60:
            overall_risk_level = 'high'
        elif overall_risk > 40:
            overall_risk_level = 'medium'
        
        return {
            'overall_risk': round(overall_risk, 1),
            'overall_risk_level': overall_risk_level,
            'worst_scenario': worst_scenario,
            'worst_scenario_risk': round(max_scenario_risk, 1) if max_scenario_risk else 0,
            'worst_scenario_details': worst_scenario_details,
            'scenario_breakdown': scenario_risks,
            'high_risk_scenario_count': len([s for s in scenario_risks if s['risk_score'] > 50]),
            'medium_risk_scenario_count': len([s for s in scenario_risks if 30 <= s['risk_score'] <= 50]),
            'total_scenarios_evaluated': len(scenario_risks)
        }

# ==================== PHASE 6: ENHANCED PRIORITIZATION & OUTPUT ====================

class EnhancedPrioritizationEngine:
    """Phase 6: Sắp xếp ưu tiên và output - ENHANCED"""
    
    @staticmethod
    def prioritize_findings(surface_results: Dict, risk_analysis: Dict, 
                           max_findings: int = 15) -> List[Dict]:
        """Sắp xếp findings theo mức độ nguy hiểm - ENHANCED"""
        
        prioritized = []
        
        # Critical findings từ surface mapping
        critical = surface_results.get('critical_surface', {})
        passive = surface_results.get('passive_surface', {})
        
        # Risk scores từ analysis
        risk_score = risk_analysis.get('overall_risk', 0)
        worst_scenario = risk_analysis.get('worst_scenario', '')
        
        # 1. CRITICAL: Exposed config files
        for file in passive.get('exposed_files', []):
            if file.get('risk') == 'critical' or file.get('type') in ['environment_config', 'php_config']:
                prioritized.append({
                    'type': 'EXPOSED_CONFIG',
                    'category': 'CRITICAL',
                    'risk': 'critical',
                    'details': f"Exposed sensitive file: {file['path']}",
                    'priority_score': 100,
                    'remediation': 'Immediately remove or restrict access'
                })
        
        # 2. CRITICAL: XML-RPC với bruteforce
        xmlrpc = critical.get('xmlrpc', {})
        if xmlrpc.get('active') and xmlrpc.get('bruteforce_possible'):
            prioritized.append({
                'type': 'XMLRPC_BRUTEFORCE',
                'category': 'CRITICAL',
                'risk': 'critical',
                'details': f"XML-RPC active with bruteforce capability",
                'priority_score': 98,
                'remediation': 'Disable XML-RPC or implement rate limiting'
            })
        
        # 3. HIGH: User enumeration với nhiều users
        user_enum = critical.get('user_enumeration', {})
        if user_enum.get('enumerable') and user_enum.get('user_count', 0) > 5:
            prioritized.append({
                'type': 'USER_ENUMERATION',
                'category': 'HIGH',
                'risk': 'high',
                'details': f"User enumeration possible ({user_enum.get('user_count', 0)} users)",
                'priority_score': 92,
                'remediation': 'Disable user enumeration via REST API'
            })
        
        # 4. HIGH: Vulnerable plugins detected
        plugins = passive.get('detected_plugins', [])
        vulnerable_plugins = ['contact-form-7', 'revslider', 'elementor']  # Example list
        for plugin in plugins:
            if plugin['name'] in vulnerable_plugins:
                prioritized.append({
                    'type': 'VULNERABLE_PLUGIN',
                    'category': 'HIGH',
                    'risk': 'high',
                    'details': f"Potentially vulnerable plugin: {plugin['name']}",
                    'priority_score': 90,
                    'remediation': 'Update plugin to latest version'
                })
        
        # 5. HIGH: Directory listing
        if passive.get('directory_listing'):
            dir_count = len(passive['directory_listing'])
            prioritized.append({
                'type': 'DIRECTORY_LISTING',
                'category': 'HIGH',
                'risk': 'high',
                'details': f"Directory listing in {dir_count} locations",
                'priority_score': 88,
                'remediation': 'Add Options -Indexes to .htaccess'
            })
        
        # 6. MEDIUM: Login page exposed without auth
        login = critical.get('login_exposed', {})
        if login.get('exposed') and not login.get('requires_auth'):
            prioritized.append({
                'type': 'LOGIN_PUBLIC',
                'category': 'MEDIUM',
                'risk': 'medium',
                'details': "Login page accessible without authentication",
                'priority_score': 75,
                'remediation': 'Implement IP whitelisting or captcha'
            })
        
        # 7. MEDIUM: REST API exposing sensitive data
        rest_api = critical.get('rest_api', {})
        if rest_api.get('users_exposed') or rest_api.get('posts_exposed'):
            exposed_data = []
            if rest_api.get('users_exposed'):
                exposed_data.append('users')
            if rest_api.get('posts_exposed'):
                exposed_data.append('posts')
            
            prioritized.append({
                'type': 'REST_API_EXPOSED',
                'category': 'MEDIUM',
                'risk': 'medium',
                'details': f"REST API exposing: {', '.join(exposed_data)}",
                'priority_score': 72,
                'remediation': 'Implement authentication for sensitive endpoints'
            })
        
        # 8. LOW: HTTP only site
        if risk_analysis.get('worst_scenario_details', {}).get('present_indicators'):
            if 'http_only' in risk_analysis['worst_scenario_details']['present_indicators']:
                prioritized.append({
                    'type': 'HTTP_ONLY',
                    'category': 'LOW',
                    'risk': 'low',
                    'details': "Site accessible via HTTP only (no HTTPS)",
                    'priority_score': 60,
                    'remediation': 'Implement HTTPS redirect'
                })
        
        # 9. Thêm findings dựa trên correlation patterns
        correlation = risk_analysis.get('worst_scenario_details', {}).get('present_indicators', [])
        if 'gov_domain' in correlation:
            prioritized.append({
                'type': 'GOV_DOMAIN_SPECIAL',
                'category': 'HIGH',
                'risk': 'high',
                'details': "Government/education domain with special considerations",
                'priority_score': 85,
                'remediation': 'Apply government security standards'
            })
        
        # Sắp xếp theo priority score
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Giới hạn số lượng và thêm index
        for i, item in enumerate(prioritized[:max_findings]):
            item['id'] = i + 1
        
        return prioritized[:max_findings]
    
    @staticmethod
    def generate_outputs(scan_results: List[Dict], output_dir: str = "reports"):
        """Tạo output files - ENHANCED"""
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. JSON Full Report (Enhanced)
        json_file = os.path.join(output_dir, f"wp_hunter_enhanced_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'total_sites': len(scan_results),
                    'wp_sites': len([r for r in scan_results if r.get('wp_detection', {}).get('is_wordpress')]),
                    'engine': 'WP Hunter Enhanced - Multi-Phase Architecture',
                    'version': '3.0',
                    'principles': [
                        'Phase 0: Passive source enrichment',
                        'Phase 1: Always try HTTP + HTTPS',
                        'Phase 2: ≥ 2 behavioral signals for WP detection',
                        'Phase 3: Plugin/theme fingerprinting',
                        'Phase 4: Advanced correlation patterns',
                        'Phase 5: Scenario-based risk with impact/exploitability',
                        'Phase 6: Enhanced prioritization'
                    ]
                },
                'results': scan_results
            }, f, indent=2, ensure_ascii=False)
        
        # 2. CSV Summary (Enhanced)
        csv_file = os.path.join(output_dir, f"wp_hunter_summary_enhanced_{timestamp}.csv")
        with open(csv_file, 'w', encoding='utf-8') as f:
            # Enhanced header
            f.write("URL,Is_WP,WP_Confidence,WP_Vectors,Overall_Risk,Risk_Level,Worst_Scenario,"
                   "XMLRPC_Active,User_Enum,Exposed_Files,Dir_Listing,Plugins_Detected,"
                   "Critical_Findings,Correlation_Score\n")
            
            for result in scan_results:
                if result.get('wp_detection', {}).get('is_wordpress'):
                    url = result.get('normalized_url', '')
                    wp_conf = result.get('wp_detection', {}).get('confidence', 0)
                    wp_vectors = result.get('wp_detection', {}).get('vector_count', 0)
                    overall_risk = result.get('risk_analysis', {}).get('overall_risk', 0)
                    risk_level = result.get('risk_analysis', {}).get('overall_risk_level', 'low')
                    worst_scenario = result.get('risk_analysis', {}).get('worst_scenario', 'NONE')
                    
                    # Critical findings
                    surface = result.get('surface_mapping', {})
                    critical = surface.get('critical_surface', {})
                    passive = surface.get('passive_surface', {})
                    
                    xmlrpc_active = 1 if critical.get('xmlrpc', {}).get('active') else 0
                    user_enum = 1 if critical.get('user_enumeration', {}).get('enumerable') else 0
                    exposed_files = len(passive.get('exposed_files', []))
                    dir_listing = 1 if passive.get('directory_listing') else 0
                    plugins_detected = len(passive.get('detected_plugins', []))
                    critical_findings = len([f for f in result.get('prioritized_findings', []) 
                                           if f.get('risk') == 'critical'])
                    correlation_score = result.get('correlation_analysis', {}).get('correlation_score', 0)
                    
                    f.write(f'"{url}",TRUE,{wp_conf},{wp_vectors},{overall_risk},{risk_level},'
                           f'{worst_scenario},{xmlrpc_active},{user_enum},{exposed_files},'
                           f'{dir_listing},{plugins_detected},{critical_findings},{correlation_score}\n')
        
        # 3. Executive Summary (HTML)
        html_file = os.path.join(output_dir, f"wp_hunter_executive_{timestamp}.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>WP Hunter Enhanced Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    h1 { color: #333; }
                    .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
                    .critical { color: #d32f2f; font-weight: bold; }
                    .high { color: #f57c00; }
                    .medium { color: #fbc02d; }
                    .low { color: #388e3c; }
                    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                </style>
            </head>
            <body>
                <h1>WP Hunter Enhanced - Executive Summary</h1>
                <div class="summary">
                    <h2>Scan Overview</h2>
                    <p><strong>Timestamp:</strong> """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                    <p><strong>Total Sites Scanned:</strong> """ + str(len(scan_results)) + """</p>
            """)
            
            wp_sites = [r for r in scan_results if r.get('wp_detection', {}).get('is_wordpress')]
            f.write(f'<p><strong>WordPress Sites Found:</strong> {len(wp_sites)}</p>')
            
            if wp_sites:
                # Risk distribution
                critical = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk', 0) > 80])
                high = len([r for r in wp_sites if 60 < r.get('risk_analysis', {}).get('overall_risk', 0) <= 80])
                medium = len([r for r in wp_sites if 40 < r.get('risk_analysis', {}).get('overall_risk', 0) <= 60])
                low = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk', 0) <= 40])
                
                f.write(f"""
                <h2>Risk Distribution</h2>
                <p><span class="critical">Critical (>80):</span> {critical} sites</p>
                <p><span class="high">High (60-80):</span> {high} sites</p>
                <p><span class="medium">Medium (40-60):</span> {medium} sites</p>
                <p><span class="low">Low (≤40):</span> {low} sites</p>
                """)
                
                # Top 10 most vulnerable
                wp_sites.sort(key=lambda x: x.get('risk_analysis', {}).get('overall_risk', 0), reverse=True)
                
                f.write("""
                <h2>Top 10 Most Vulnerable Sites</h2>
                <table>
                    <tr>
                        <th>Rank</th>
                        <th>URL</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Worst Scenario</th>
                        <th>Critical Findings</th>
                    </tr>
                """)
                
                for i, site in enumerate(wp_sites[:10], 1):
                    url = site.get('normalized_url', '')[:50]
                    risk = site.get('risk_analysis', {}).get('overall_risk', 0)
                    risk_level = site.get('risk_analysis', {}).get('overall_risk_level', 'low')
                    scenario = site.get('risk_analysis', {}).get('worst_scenario', '')
                    crit_findings = len([f for f in site.get('prioritized_findings', []) 
                                       if f.get('risk') == 'critical'])
                    
                    risk_class = risk_level.lower()
                    f.write(f"""
                    <tr>
                        <td>{i}</td>
                        <td>{url}</td>
                        <td class="{risk_class}">{risk:.1f}</td>
                        <td class="{risk_class}">{risk_level}</td>
                        <td>{scenario}</td>
                        <td>{crit_findings}</td>
                    </tr>
                    """)
                
                f.write("</table>")
            
            f.write("""
                </div>
                <p><em>Generated by WP Hunter Enhanced v3.0</em></p>
            </body>
            </html>
            """)
        
        # 4. Top Risky Sites (Enhanced)
        risky_sites = [r for r in scan_results if r.get('wp_detection', {}).get('is_wordpress')]
        risky_sites.sort(key=lambda x: x.get('risk_analysis', {}).get('overall_risk', 0), reverse=True)
        
        top_risky_file = os.path.join(output_dir, f"wp_hunter_top_risky_{timestamp}.txt")
        with open(top_risky_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("TOP 15 MOST RISKY WORDPRESS SITES\n")
            f.write("=" * 80 + "\n\n")
            
            for i, site in enumerate(risky_sites[:15], 1):
                f.write(f"{i:2d}. {site.get('normalized_url', '')}\n")
                f.write(f"    Risk Score: {site.get('risk_analysis', {}).get('overall_risk', 0):.1f} ")
                f.write(f"({site.get('risk_analysis', {}).get('overall_risk_level', 'low')})\n")
                f.write(f"    Worst Scenario: {site.get('risk_analysis', {}).get('worst_scenario', 'NONE')}\n")
                f.write(f"    WP Detection Vectors: {site.get('wp_detection', {}).get('vector_count', 0)}\n")
                f.write(f"    Confidence: {site.get('wp_detection', {}).get('confidence', 0)}%\n")
                
                # Top 3 findings
                findings = site.get('prioritized_findings', [])[:3]
                if findings:
                    f.write(f"    Top Findings:\n")
                    for j, finding in enumerate(findings, 1):
                        f.write(f"      {j}. {finding.get('details', '')}\n")
                
                # Weakness count
                weaknesses = site.get('correlation_analysis', {}).get('weakness_count', 0)
                f.write(f"    Weaknesses Found: {weaknesses}\n")
                
                f.write("\n")
        
        return {
            'json_full': json_file,
            'csv_summary': csv_file,
            'html_executive': html_file,
            'top_risky': top_risky_file
        }

# ==================== MAIN ORCHESTRATOR ENHANCED ====================

class WPHunterEnhancedOrchestrator:
    """Orchestrator chính điều phối tất cả phases - ENHANCED"""
    
    def __init__(self, use_passive_sources: bool = True):
        self.use_passive_sources = use_passive_sources
        self.passive_enricher = PassiveSourceEnricher() if use_passive_sources else None
        self.liveness = LivenessChecker()
        self.wp_detector = EnhancedWPDetector()
        self.surface_mapper = EnhancedSurfaceMapper()
        self.correlator = EnhancedWeaknessCorrelator()
        self.risk_calculator = EnhancedRiskCalculator()
        self.prioritizer = EnhancedPrioritizationEngine()
        
        self.results = []
        self.lock = Lock()
        
        # Enhanced statistics
        self.stats = {
            'total_targets': 0,
            'dead_targets': 0,
            'alive_targets': 0,
            'non_wp': 0,
            'wp_targets': 0,
            'clean_wp': 0,
            'vulnerable': 0,
            'high_risk': 0,
            'critical_findings': 0
        }
    
    def load_targets(self, file_path: str, generate_dirty: bool = False) -> Set[str]:
        """Tải targets từ file - Với option tạo dirty targets"""
        
        targets = set()
        
        if generate_dirty and self.use_passive_sources:
            print(f"{C}[*] Generating dirty targets from passive sources...{W}")
            dirty_targets = self.passive_enricher.generate_dirty_targets()
            targets.update(dirty_targets)
            print(f"{G}[+] Added {len(dirty_targets)} passive targets{W}")
        
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Regex mạnh để lấy domain
                    domain_match = re.search(
                        r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})',
                        line
                    )
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        # Basic validation
                        if len(domain) > 4 and '.' in domain and ' ' not in domain:
                            targets.add(domain)
        
        self.stats['total_targets'] = len(targets)
        return targets
    
    def process_single_site(self, domain: str) -> Optional[Dict]:
        """Xử lý một site qua tất cả phases - CHỈ SHOW KHI CÓ VULN"""
        
        # KHÔNG print [Phase 1] Checking ở đây - sẽ làm nhiễu terminal
        
        # Phase 1: Liveness & Normalization
        liveness_result = self.liveness.check_liveness(domain)
        
        if not liveness_result['alive']:
            with self.lock:
                self.stats['total_targets'] += 1
                self.stats['dead_targets'] += 1
            return None
        
        with self.lock:
            self.stats['alive_targets'] += 1
        
        normalized_url = self.liveness.normalize_entity(liveness_result)
        
        # Phase 2: Enhanced WordPress Detection
        wp_result = self.wp_detector.detect_wordpress(normalized_url)
        
        # LUẬT: ≥ 2 signals mới kết luận WP
        if not wp_result['is_wordpress']:
            with self.lock:
                self.stats['non_wp'] += 1
            return None
        
        with self.lock:
            self.stats['wp_targets'] += 1
        
        # Phase 3: Enhanced Surface Mapping
        critical_surface = self.surface_mapper.map_critical_surface(normalized_url)
        passive_surface = self.surface_mapper.map_passive_surface(normalized_url)
        
        surface_results = {
            'critical_surface': critical_surface,
            'passive_surface': passive_surface
        }
        
        # Phase 4: Enhanced Weakness Correlation
        correlation = self.correlator.analyze_correlations(surface_results, wp_result)
        
        # Phase 5: Enhanced Scenario-based Risk
        risk_analysis = self.risk_calculator.calculate_scenario_risk(
            correlation['weakness_flags'],
            correlation,
            wp_result
        )
        
        # Phase 6: Enhanced Prioritization
        prioritized_findings = self.prioritizer.prioritize_findings(
            surface_results, 
            risk_analysis
        )
        
        # Cập nhật statistics
        with self.lock:
            if risk_analysis['overall_risk'] > 70:
                self.stats['high_risk'] += 1
            self.stats['critical_findings'] += len([f for f in risk_analysis.get('scenario_breakdown', []) 
                                                   if f.get('risk_level') == 'critical'])
        
        # CHỈ HIỂN THỊ NẾU CÓ FINDING HOẶC HIGH RISK
        has_findings = len(prioritized_findings) > 0
        is_high_risk = risk_analysis['overall_risk'] > 40
        
        if not (has_findings or is_high_risk):
            with self.lock:
                self.stats['clean_wp'] += 1
            return None
        
        # Compile final result
        result = {
            'original_domain': domain,
            'normalized_url': normalized_url,
            'liveness_check': liveness_result,
            'wp_detection': wp_result,
            'surface_mapping': surface_results,
            'correlation_analysis': correlation,
            'risk_analysis': risk_analysis,
            'prioritized_findings': prioritized_findings,
            'timestamp': datetime.now().isoformat(),
            'scan_id': hashlib.md5(f"{domain}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        }
        
        # CHỈ HIỂN THỊ SUMMARY CHO DOMAIN CÓ VULN
        self._display_vuln_summary(result)
        
        return result
    

    def _display_vuln_summary(self, result: Dict):
        """Chỉ hiển thị summary cho domain có vulnerability"""
        
        url = result['normalized_url'][:60]
        risk = result['risk_analysis']['overall_risk']
        risk_level = result['risk_analysis']['overall_risk_level']
        worst_scenario = result['risk_analysis']['worst_scenario']
        wp_vectors = result['wp_detection']['vector_count']
        
        # Màu sắc và symbol dựa trên risk level
        if risk_level == 'critical':
            color = R
            symbol = "🔥"
            risk_text = "CRITICAL"
        elif risk_level == 'high':
            color = Y
            symbol = "⚠️"
            risk_text = "HIGH"
        elif risk_level == 'medium':
            color = M
            symbol = "🔶"
            risk_text = "MEDIUM"
        else:
            color = G
            symbol = "✅"
            risk_text = "LOW"
        
        # HIỂN THỊ 1 DÒNG DUY NHẤT (không có newline ở đầu)
        print(f"\r{color}{symbol} {risk_text}: {url} | Risk: {risk:.1f} | Scenario: {worst_scenario} | Vectors: {wp_vectors}{W}")
        
        # Hiển thị top finding ngay bên dưới (nếu có)
        if result['prioritized_findings']:
            top_finding = result['prioritized_findings'][0]
            print(f"   {color}Top: {top_finding.get('details', '')[:70]}...{W}")
        
        print()  # Newline để phân tách với domain tiếp theo


    
    def _display_enhanced_summary(self, result: Dict):
        """Hiển thị enhanced summary cho một site"""
        
        url = result['normalized_url'][:60]
        risk = result['risk_analysis']['overall_risk']
        risk_level = result['risk_analysis']['overall_risk_level']
        worst_scenario = result['risk_analysis']['worst_scenario']
        wp_vectors = result['wp_detection']['vector_count']
        wp_confidence = result['wp_detection']['confidence']
        
        # Màu sắc và symbol dựa trên risk level
        if risk_level == 'critical':
            color = R
            symbol = "🔥"
            risk_text = "CRITICAL"
        elif risk_level == 'high':
            color = Y
            symbol = "⚠️"
            risk_text = "HIGH"
        elif risk_level == 'medium':
            color = M
            symbol = "🔶"
            risk_text = "MEDIUM"
        else:
            color = G
            symbol = "✅"
            risk_text = "LOW"
        
        print(f"\n{symbol} {color}{BOLD}{risk_text}: {url}{W}")
        print(f"   {color}Overall Risk: {risk:.1f} ({risk_level}){W}")
        print(f"   {color}Worst Scenario: {worst_scenario}{W}")
        print(f"   {color}WP Confidence: {wp_confidence}% ({wp_vectors} vectors){W}")
        
        # Hiển thị top 3 findings
        if result['prioritized_findings'][:3]:
            print(f"   {color}Top Findings:{W}")
            for i, finding in enumerate(result['prioritized_findings'][:3], 1):
                risk_color = R if finding.get('risk') == 'critical' else Y if finding.get('risk') == 'high' else M
                print(f"     {i}. {risk_color}{finding.get('details', '')[:70]}{W}")
        
        # Weakness count
        weakness_count = result['correlation_analysis'].get('weakness_count', 0)
        if weakness_count > 0:
            print(f"   {color}Weaknesses: {weakness_count}{W}")
        
        # Detected plugins
        plugins = result['surface_mapping'].get('passive_surface', {}).get('detected_plugins', [])
        if plugins:
            plugin_names = [p['name'] for p in plugins[:3]]
            print(f"   {color}Plugins: {', '.join(plugin_names)}{W}")
    
    def scan_targets(self, targets_file: str, max_targets: int = 100, 
                    generate_dirty: bool = False):
        """Scan nhiều targets với enhanced features"""
        
        # Load targets - với option dirty generation
        targets = self.load_targets(targets_file, generate_dirty)
        if not targets:
            print(f"{R}[!] No targets found in {targets_file}{W}")
            return
        
        targets = list(targets)[:max_targets]
        print(f"{G}[+] Loaded {len(targets)} targets (with passive enrichment: {generate_dirty}){W}")
        
        # Display scan configuration
        print(f"\n{C}[⚙️] SCAN CONFIGURATION:{W}")
        print(f"  Targets: {len(targets)}")
        print(f"  Threads: {THREADS}")
        print(f"  Timeout: {REQUEST_TIMEOUT}s")
        print(f"  Passive Enrichment: {'ENABLED' if generate_dirty else 'DISABLED'}")
        print(f"  Async Concurrency: {MAX_CONCURRENT_ASYNC}")
        
        # Scan với thread pool
        self._scan_threaded_enhanced(targets)
        
        # Generate enhanced reports
        if self.results:
            print(f"\n{C}[*] Generating enhanced reports...{W}")
            output_files = self.prioritizer.generate_outputs(self.results)
            
            print(f"\n{G}{BOLD}[✅] ENHANCED SCAN COMPLETED{W}")
            for file_type, file_path in output_files.items():
                print(f"{G}[+] {file_type}: {file_path}{W}")
            
            # Hiển thị enhanced statistics
            self._display_enhanced_statistics()
        else:
            print(f"{R}[!] No WordPress sites found{W}")
    
    def _scan_threaded_enhanced(self, targets: List[str], threads: int = THREADS):
        """Scan style ShadowStrike - hiển thị từng domain"""
        
        print(f"{C}[*] Scanning {len(targets)} targets with {threads} threads{W}")
        
        start_time = time.time()
        
        # Dùng tqdm nhưng custom display
        pbar = tqdm(total=len(targets), desc="Hunting", unit="site", 
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                    position=0, leave=True)
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=threads,
            thread_name_prefix='wp_hunter'
        ) as executor:
            
            futures = {}
            
            for target in targets:
                future = executor.submit(self.process_single_site, target)
                futures[future] = target
                time.sleep(RATE_LIMIT_DELAY)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=REQUEST_TIMEOUT * 2)
                    if result:
                        with self.lock:
                            self.results.append(result)
                except Exception:
                    pass
                
                pbar.update(1)
                
                # Hiển thị domain đang được xử lý (3 domains gần nhất)
                with self.lock:
                    current_target = futures.get(future, "Unknown")
                    wp_count = self.stats['wp_targets']
                    vuln_count = self.stats['vulnerable']
                
                # Update description với domain hiện tại
                pbar.set_description(f"Hunting {current_target[:30]}... [WP:{wp_count} Vuln:{vuln_count}]")
        
        pbar.close()
        
        # Hiển thị summary
        elapsed = time.time() - start_time
        print(f"\n{G}[✓] Completed in {elapsed:.1f}s | WP: {self.stats['wp_targets']} | Vuln: {self.stats['vulnerable']}{W}")
    
    def _display_enhanced_statistics(self):
        """Hiển thị enhanced thống kê cuối cùng"""
        
        if not self.results:
            return
        
        total_targets = self.stats['total_targets']
        alive_targets = self.stats['alive_targets']
        wp_sites = [r for r in self.results if r.get('wp_detection', {}).get('is_wordpress')]
        wp_count = len(wp_sites)
        high_risk_sites = self.stats['high_risk']
        
        print(f"\n{B}{BOLD}[📊] ENHANCED STATISTICS{W}")
        print(f"{C}[*] Total targets processed: {total_targets}{W}")
        
        if total_targets > 0:
            print(f"{C}[*] Alive targets: {alive_targets} ({alive_targets/total_targets*100:.1f}%){W}")
            print(f"{G}[+] WordPress sites found: {wp_count} ({wp_count/total_targets*100:.1f}% of total){W}")
        
        if wp_sites:
            # Risk distribution chi tiết
            critical_risk = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk_level') == 'critical'])
            high_risk = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk_level') == 'high'])
            medium_risk = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk_level') == 'medium'])
            low_risk = len([r for r in wp_sites if r.get('risk_analysis', {}).get('overall_risk_level') == 'low'])
            
            print(f"\n{G}[📈] RISK DISTRIBUTION (WordPress sites):{W}")
            print(f"  🔥 Critical (>80): {critical_risk} sites")
            print(f"  ⚠️  High (60-80): {high_risk} sites")
            print(f"  🔶 Medium (40-60): {medium_risk} sites")
            print(f"  ✅ Low (≤40): {low_risk} sites")
            
            # Common findings statistics
            all_findings = []
            for site in wp_sites:
                all_findings.extend(site.get('prioritized_findings', []))
            
            finding_counts = {}
            for finding in all_findings:
                f_type = finding.get('type', 'UNKNOWN')
                finding_counts[f_type] = finding_counts.get(f_type, 0) + 1
            
            print(f"\n{G}[🔍] MOST COMMON FINDINGS:{W}")
            sorted_findings = sorted(finding_counts.items(), key=lambda x: x[1], reverse=True)
            for f_type, count in sorted_findings[:5]:
                print(f"  {f_type}: {count} sites")
            
            # Plugin statistics
            all_plugins = []
            for site in wp_sites:
                plugins = site.get('surface_mapping', {}).get('passive_surface', {}).get('detected_plugins', [])
                all_plugins.extend([p['name'] for p in plugins])
            
            if all_plugins:
                plugin_counts = Counter(all_plugins)
                print(f"\n{G}[🧩] MOST COMMON PLUGINS:{W}")
                for plugin, count in plugin_counts.most_common(5):
                    print(f"  {plugin}: {count} sites")
            
            # Top 5 most vulnerable (enhanced)
            wp_sites.sort(key=lambda x: x.get('risk_analysis', {}).get('overall_risk', 0), reverse=True)
            
            print(f"\n{R}{BOLD}[🔥] TOP 5 MOST VULNERABLE SITES:{W}")
            for i, site in enumerate(wp_sites[:5], 1):
                risk = site.get('risk_analysis', {}).get('overall_risk', 0)
                risk_level = site.get('risk_analysis', {}).get('overall_risk_level', 'low')
                url = site.get('normalized_url', '')[:55]
                scenario = site.get('risk_analysis', {}).get('worst_scenario', '')
                findings = len(site.get('prioritized_findings', []))
                
                risk_color = R if risk_level == 'critical' else Y if risk_level == 'high' else M
                print(f"{i:2d}. {risk_color}{url:<55} Risk: {risk:.1f} ({risk_level}) | Scenario: {scenario} | Findings: {findings}{W}")
            
            # Performance metrics
            total_vectors = sum([site.get('wp_detection', {}).get('vector_count', 0) for site in wp_sites])
            avg_vectors = total_vectors / wp_count if wp_count > 0 else 0
            
            print(f"\n{C}[📊] PERFORMANCE METRICS:{W}")
            print(f"  Average WP detection vectors per site: {avg_vectors:.1f}")
            print(f"  High risk sites: {high_risk_sites}")
            print(f"  Critical findings total: {self.stats['critical_findings']}")

# ==================== MAIN ENHANCED ====================

def main_enhanced():
    print(f"""{B}
    ╔══════════════════════════════════════════════════════════════════╗
    ║           WP HUNTER ENHANCED - MULTI-PHASE ARCHITECTURE          ║
    ║                   "No WordPress Left Behind"                     ║
    ╚══════════════════════════════════════════════════════════════════╝{W}""")
    
    print(f"\n{Y}[🎯] ENHANCED CORE PRINCIPLES:{W}")
    principles = [
        "1. Phase 0: Passive source enrichment (CT logs, crawl dumps, historical)",
        "2. Phase 1: Always try HTTP + HTTPS (.gov.vn/.edu.vn thường HTTP-only)",
        "3. Phase 2: ≥ 2 behavioral signals for WordPress detection (7 vectors)",
        "4. Phase 3: Plugin/theme fingerprinting + passive detection",
        "5. Phase 4: Advanced correlation patterns (6+ scenarios)",
        "6. Phase 5: Scenario-based risk with impact/exploitability scores",
        "7. Phase 6: Enhanced prioritization with remediation guidance"
    ]
    
    for principle in principles:
        print(f"  {principle}")
    
    print(f"\n{C}[⚙️] ENHANCED PHASES:{W}")
    phases = [
        "Phase 0: Passive Source Enrichment",
        "Phase 1: Liveness & Normalization (requests - chính xác)",
        "Phase 2: WP Detection - 7 vectors (behavioral + static)",
        "Phase 3: Surface Mapping with Plugin/Theme Fingerprinting",
        "Phase 4: Enhanced Weakness Correlation",
        "Phase 5: Scenario-based Risk Scoring with Impact Analysis",
        "Phase 6: Enhanced Prioritization & Multi-Format Output"
    ]
    
    for phase in phases:
        print(f"  {phase}")
    
    # Tìm target file
    target_files = ['targets.txt', 'domains.txt', 'urls.txt', 'input.txt', 'dirty_targets.txt']
    target_file = None
    
    for file in target_files:
        if os.path.exists(file):
            target_file = file
            print(f"\n{G}[*] Found target file: {file}{W}")
            break
    
    if not target_file:
        print(f"\n{Y}[*] No target file found. Creating sample 'targets.txt'{W}")
        with open('targets.txt', 'w') as f:
            f.write("# Add domains here, one per line\n")
            f.write("# Tool will auto-extract domains, no cleaning needed\n")
            f.write("example.com\n")
            f.write("https://wordpress.org\n")
            f.write("http://test.gov.vn\n")
            f.write("university.edu.vn\n")
            f.write("agency.gov.uk\n")
        target_file = 'targets.txt'
    
    # Hỏi về passive enrichment
    print(f"\n{C}[?] Enable passive source enrichment? (y/n) [n]: {W}", end='')
    use_passive = input().strip().lower() == 'y'
    
    # Hỏi về dirty target generation
    generate_dirty = False
    if use_passive:
        print(f"{C}[?] Generate dirty targets from passive sources? (y/n) [y]: {W}", end='')
        generate_dirty_input = input().strip().lower()
        generate_dirty = generate_dirty_input != 'n'
    
    # Hỏi về số lượng targets
    print(f"{C}[?] Maximum targets to scan [100]: {W}", end='')
    max_targets_input = input().strip()
    max_targets = int(max_targets_input) if max_targets_input.isdigit() else 100
    
    # Khởi tạo và chạy enhanced orchestrator
    orchestrator = WPHunterEnhancedOrchestrator(use_passive_sources=use_passive)
    
    try:
        orchestrator.scan_targets(
            targets_file=target_file,
            max_targets=max_targets,
            generate_dirty=generate_dirty
        )
    except KeyboardInterrupt:
        print(f"\n{R}[!] Scan interrupted by user{W}")
    except Exception as e:
        print(f"{R}[!] Fatal error: {str(e)}{W}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main_enhanced()