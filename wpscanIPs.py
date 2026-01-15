#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner - ULTIMATE EDITION
TÍNH NĂNG ĐẦY ĐỦ: Version checking, CVE verification, Content analysis + Behavioral observation
TẤT CẢ dynamic từ external databases + Behavioral patterns từ wp_scan_cve
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
import requests  # THÊM requests cho behavioral observation
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from asyncio import Semaphore
import json
import pickle
import hashlib
import os

# ================= CONFIGURATION =================
CONFIG = {
    'MAX_CONCURRENT': 20,
    'TIMEOUT': 10,
    'DELAY_RANGE': (0.5, 1.5),
    'REQUESTS_PER_MINUTE': 100,
    'CACHE_TTL': 7200,  # 2 giờ cache
    'DOMAIN_LIMIT': 300,
    
    # External sources - KHÔNG hardcode gì
    'EXTERNAL_SOURCES': {
        'domains': [
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames.txt",
            "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
            "https://crt.sh/?q=%25.wordpress%25&output=json",
            "https://crt.sh/?q=%25wp-content%25&output=json",
            "https://crt.sh/?q=%25wp-json%25&output=json",
            "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.wp-content/*&output=json",
            "https://api.wordpress.org/themes/info/1.1/?action=query_themes&request[browse]=popular",
            "https://raw.githubusercontent.com/WordPress/wordpress.org/main/feed-urls.txt",
        ],
        
        'plugins': [
            "https://api.wordpress.org/plugins/info/1.1/?action=query_plugins&request[per_page]=100",
            "https://raw.githubusercontent.com/wpscanteam/vulnerable-plugins-list/main/plugins.json",
        ],
        
        'vulnerabilities': [
            "https://raw.githubusercontent.com/wpscanteam/vulnerable-plugins-list/main/vulnerabilities.json",
            "https://cve.circl.lu/api/last/50",
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50",
        ],
        
        'patterns': [
            "https://raw.githubusercontent.com/wpscanteam/wpscan/master/app/patterns.yml",
        ]
    },
    
    'CACHE_DIR': '.wp_scanner_cache_complete',
}

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ultimate_wp_scanner')

# ================= BEHAVIORAL OBSERVATION MODELS (TỪ wp_scan_cve) =================
class ServerBehaviorObserver:
    """Observe and document server behaviors vs expected patterns"""
    
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.baseline_profile = {}
    
    def observe_rate_handling(self):
        """Observe server response patterns under sequential requests"""
        endpoint = urljoin(self.target, '/wp-login.php')
        observations = []
        
        for i in range(3):  # Giảm từ 5 xuống 3 để nhanh hơn
            try:
                start = time.time()
                r = self.session.post(
                    endpoint, 
                    data={'log': f'obs_test_{i}', 'pwd': 'observation_test'},
                    timeout=8,
                    allow_redirects=True
                )
                elapsed = time.time() - start
                
                observations.append({
                    'request': i+1,
                    'status': r.status_code,
                    'time': round(elapsed, 3),
                    'length': len(r.text),
                    'redirected': len(r.history) > 0,
                    'final_location': r.url if r.history else None
                })
                
                # Baseline comparison
                if i == 0:
                    self.baseline_profile['initial_response_time'] = elapsed
                    self.baseline_profile['initial_status'] = r.status_code
                
                time.sleep(0.5)  # Giảm delay
                
            except Exception as e:
                observations.append({
                    'request': i+1,
                    'error': str(e)[:100],
                    'timeout': isinstance(e, requests.exceptions.Timeout)
                })
        
        # Analyze patterns
        times = [obs.get('time', 0) for obs in observations if 'time' in obs]
        if len(times) >= 2:
            time_increase = all(times[i] <= times[i+1] for i in range(len(times)-1))
            max_time = max(times) if times else 0
        else:
            time_increase = False
            max_time = 0
        
        return {
            'sequential_requests': observations,
            'pattern_analysis': {
                'response_times_consistent': len(set(round(t, 2) for t in times)) <= 2 if times else None,
                'gradual_slowdown_observed': time_increase and max_time > 1.5,
                'all_requests_succeeded': all('status' in obs and obs['status'] < 500 for obs in observations)
            },
            'baseline': self.baseline_profile
        }
    
    def observe_error_response_patterns(self):
        """Observe how server responds to non-standard inputs"""
        test_cases = [
            {
                'path': '/wp-content/plugins/nonexistent-plugin-observation/readme.txt',
                'type': 'non-existent_plugin_path',
                'description': 'Access attempt to non-existent plugin directory'
            },
            {
                'path': f'/?test_param={quote("../../../observation-test")}',
                'type': 'directory_traversal_pattern',
                'description': 'Parameter containing directory traversal pattern'
            },
            {
                'path': '/wp-admin/admin-ajax.php?action=non_existent_action_obs',
                'type': 'invalid_ajax_action',
                'description': 'Invalid AJAX action parameter'
            },
        ]
        
        observations = []
        baseline_response = None
        
        # First get baseline normal response
        try:
            baseline = self.session.get(self.target, timeout=8)
            baseline_response = {
                'status': baseline.status_code,
                'length': len(baseline.text),
                'content_type': baseline.headers.get('Content-Type', ''),
                'has_login_form': 'password' in baseline.text.lower() and 'input' in baseline.text.lower()
            }
        except:
            pass
        
        for test in test_cases:
            url = urljoin(self.target, test['path'])
            try:
                r = self.session.get(url, timeout=10, allow_redirects=False)
                
                # Compare with baseline
                length_deviation = None
                if baseline_response:
                    baseline_len = baseline_response['length']
                    current_len = len(r.text)
                    if baseline_len > 0:
                        length_deviation = round(abs(current_len - baseline_len) / baseline_len * 100, 1)
                
                # Content analysis
                content_analysis = {
                    'contains_technical_errors': any(
                        pattern in r.text.lower() 
                        for pattern in ['stack trace', 'fatal error', 'exception:', 'warning:', 'notice:']
                    ),
                    'contains_path_disclosure': any(
                        pattern in r.text 
                        for pattern in ['/var/www/', '/home/', 'C:\\', 'D:\\', '/etc/']
                    ),
                    'contains_database_references': any(
                        pattern in r.text.lower() 
                        for pattern in ['mysql', 'mysqli', 'pdo', 'database', 'sqlite']
                    ),
                    'is_default_fallback': len(r.text) > 1000 and '</html>' in r.text and '</body>' in r.text
                }
                
                observations.append({
                    'test_type': test['type'],
                    'description': test['description'],
                    'url': url,
                    'status': r.status_code,
                    'response_length': len(r.text),
                    'length_deviation_percent': length_deviation,
                    'content_type': r.headers.get('Content-Type', ''),
                    'differs_from_baseline': length_deviation and abs(length_deviation) > 50,
                    'content_analysis': content_analysis,
                    'observed_behaviors': self._extract_observed_behaviors(r, content_analysis)
                })
                
            except requests.exceptions.Timeout:
                observations.append({
                    'test_type': test['type'],
                    'description': test['description'],
                    'behavior': 'REQUEST_TIMEOUT',
                    'note': 'Server delayed response beyond threshold'
                })
            except Exception as e:
                observations.append({
                    'test_type': test['type'],
                    'description': test['description'],
                    'error': str(e)[:80]
                })
            
            time.sleep(0.8)
        
        return {
            'baseline_response': baseline_response,
            'test_observations': observations,
            'summary': self._summarize_error_behaviors(observations)
        }
    
    def _extract_observed_behaviors(self, response, content_analysis):
        """Extract behavioral observations"""
        behaviors = []
        
        if response.status_code == 200:
            if content_analysis['contains_technical_errors']:
                behaviors.append('TECHNICAL_ERRORS_IN_RESPONSE')
            if content_analysis['contains_path_disclosure']:
                behaviors.append('PATH_INFO_IN_RESPONSE')
            if content_analysis['contains_database_references']:
                behaviors.append('DATABASE_REFERENCES_IN_RESPONSE')
        
        elif response.status_code == 404:
            if len(response.text) > 5000:
                behaviors.append('VERBOSE_404_RESPONSE')
            if 'wp-' in response.text.lower():
                behaviors.append('WORDPRESS_SIGNATURE_IN_404')
        
        elif response.status_code == 403:
            behaviors.append('ACCESS_DENIED')
        
        elif response.status_code >= 500:
            behaviors.append('SERVER_ERROR_RESPONSE')
        
        return behaviors
    
    def _summarize_error_behaviors(self, observations):
        """Create behavioral summary"""
        summary = {
            'tests_completed': len([o for o in observations if 'status' in o or 'behavior' in o]),
            'status_200_responses': len([o for o in observations if o.get('status') == 200]),
            'timeout_occurrences': len([o for o in observations if o.get('behavior') == 'REQUEST_TIMEOUT']),
            'technical_errors_observed': 0,
            'path_disclosures_observed': 0
        }
        
        for obs in observations:
            if 'content_analysis' in obs:
                ca = obs['content_analysis']
                if ca.get('contains_technical_errors'):
                    summary['technical_errors_observed'] += 1
                if ca.get('contains_path_disclosure'):
                    summary['path_disclosures_observed'] += 1
        
        return summary
    
    def observe_authentication_boundaries(self):
        """Observe access patterns to protected areas"""
        paths_to_observe = [
            {'path': '/wp-admin/', 'expected_protection': True, 'description': 'Administration dashboard'},
            {'path': '/wp-admin/users.php', 'expected_protection': True, 'description': 'User management'},
            {'path': '/wp-login.php', 'expected_protection': False, 'description': 'Login page'},
            {'path': '/wp-content/uploads/', 'expected_protection': False, 'description': 'Uploads directory'}
        ]
        
        observations = []
        
        for item in paths_to_observe:
            url = urljoin(self.target, item['path'])
            try:
                r = self.session.get(url, timeout=8, allow_redirects=True)
                
                redirect_chain = []
                if r.history:
                    redirect_chain = [{
                        'status': hist.status_code,
                        'url': hist.url,
                        'location': hist.headers.get('Location', '')
                    } for hist in r.history]
                
                observation = {
                    'path': item['path'],
                    'description': item['description'],
                    'expected_protection': item['expected_protection'],
                    'final_status': r.status_code,
                    'final_url': r.url,
                    'redirects_occurred': len(r.history) > 0,
                    'redirect_chain': redirect_chain if redirect_chain else None,
                    'response_length': len(r.text),
                    'content_type': r.headers.get('Content-Type', ''),
                    'observed_access_level': self._determine_access_level(r, item['expected_protection'])
                }
                
                observations.append(observation)
                
            except Exception as e:
                observations.append({
                    'path': item['path'],
                    'description': item['description'],
                    'error': str(e)[:80],
                    'expected_protection': item['expected_protection']
                })
            
            time.sleep(0.5)
        
        return {
            'path_observations': observations,
            'boundary_analysis': self._analyze_boundaries(observations)
        }
    
    def _determine_access_level(self, response, expected_protection):
        """Determine observed access level without authentication"""
        if response.status_code == 200:
            content = response.text.lower()
            if 'wp-admin' in response.url and 'login' not in response.url:
                if 'password' in content and 'input' in content:
                    return 'LOGIN_FORM_PRESENTED'
                else:
                    return 'POTENTIAL_DIRECT_ACCESS'
            elif 'wp-login' in response.url:
                return 'LOGIN_PAGE'
            else:
                return 'DIRECT_ACCESS'
        
        elif response.status_code in [301, 302, 307, 308]:
            return 'REDIRECTED'
        
        elif response.status_code == 403:
            return 'ACCESS_DENIED'
        
        elif response.status_code == 404:
            return 'NOT_FOUND'
        
        else:
            return f'STATUS_{response.status_code}'
    
    def _analyze_boundaries(self, observations):
        """Analyze boundary patterns"""
        analysis = {
            'admin_paths_without_redirect': 0,
            'login_forms_observed': 0,
            'direct_access_cases': 0
        }
        
        for obs in observations:
            if 'observed_access_level' in obs:
                access = obs['observed_access_level']
                if 'wp-admin' in obs.get('path', '') and access == 'POTENTIAL_DIRECT_ACCESS':
                    analysis['admin_paths_without_redirect'] += 1
                if access == 'LOGIN_FORM_PRESENTED':
                    analysis['login_forms_observed'] += 1
                if access == 'DIRECT_ACCESS':
                    analysis['direct_access_cases'] += 1
        
        return analysis

class BehavioralVulnerabilityScanner:
    """Scanner dựa trên behavioral observation"""
    
    def __init__(self):
        pass
    
    def scan_behavioral_vulnerabilities(self, base_url: str) -> Dict[str, Any]:
        """Scan vulnerabilities dựa trên behavioral patterns"""
        observer = ServerBehaviorObserver(base_url)
        
        result = {
            'endpoint_vulnerabilities': [],
            'behavioral_findings': {
                'rate_handling': None,
                'error_responses': None,
                'auth_boundaries': None
            }
        }
        
        try:
            # 1. Rate handling observation
            rate_data = observer.observe_rate_handling()
            result['behavioral_findings']['rate_handling'] = rate_data
            
            # Extract vulnerabilities từ rate data
            if not rate_data['pattern_analysis'].get('gradual_slowdown_observed'):
                result['endpoint_vulnerabilities'].append({
                    'type': 'NO_RATE_LIMITING',
                    'severity': 'MEDIUM',
                    'description': 'No rate limiting detected on login page',
                    'evidence': f"Response times: {[obs.get('time', 0) for obs in rate_data['sequential_requests'] if 'time' in obs]}",
                    'cvss_score': 4.0,
                    'url': f"{base_url}/wp-login.php"
                })
            
            # 2. Error response observation
            error_data = observer.observe_error_response_patterns()
            result['behavioral_findings']['error_responses'] = error_data
            
            # Check for error disclosure
            if error_data['summary'].get('technical_errors_observed', 0) > 0:
                result['endpoint_vulnerabilities'].append({
                    'type': 'ERROR_DISCLOSURE',
                    'severity': 'MEDIUM',
                    'description': 'Technical error details disclosed in responses',
                    'evidence': f"{error_data['summary']['technical_errors_observed']} cases with technical errors",
                    'cvss_score': 4.3,
                    'url': base_url
                })
            
            # 3. Auth boundary observation
            auth_data = observer.observe_authentication_boundaries()
            result['behavioral_findings']['auth_boundaries'] = auth_data
            
            # Check for direct admin access
            if auth_data['boundary_analysis'].get('admin_paths_without_redirect', 0) > 0:
                result['endpoint_vulnerabilities'].append({
                    'type': 'POTENTIAL_ADMIN_ACCESS',
                    'severity': 'HIGH',
                    'description': 'Admin paths accessible without authentication redirect',
                    'evidence': f"{auth_data['boundary_analysis']['admin_paths_without_redirect']} admin paths",
                    'cvss_score': 6.5,
                    'url': f"{base_url}/wp-admin/"
                })
            
            # 4. Check PHP version disclosure
            try:
                r = observer.session.get(base_url, timeout=5)
                if 'X-Powered-By' in r.headers:
                    php_match = re.search(r'PHP/([\d\.]+)', r.headers['X-Powered-By'])
                    if php_match:
                        version = php_match.group(1)
                        result['endpoint_vulnerabilities'].append({
                            'type': 'PHP_VERSION_DISCLOSURE',
                            'severity': 'LOW',
                            'description': f'PHP version {version} disclosed in headers',
                            'evidence': f"X-Powered-By: {r.headers['X-Powered-By']}",
                            'cvss_score': 2.5,
                            'url': base_url
                        })
            except:
                pass
            
            # 5. Check directory listing
            try:
                uploads_url = f"{base_url}/wp-content/uploads/"
                r = observer.session.get(uploads_url, timeout=5)
                if r.status_code == 200:
                    if 'Index of' in r.text or 'Parent Directory' in r.text:
                        result['endpoint_vulnerabilities'].append({
                            'type': 'DIRECTORY_LISTING',
                            'severity': 'LOW',
                            'description': 'Directory listing enabled on uploads directory',
                            'evidence': uploads_url,
                            'cvss_score': 3.5,
                            'url': uploads_url
                        })
            except:
                pass
            
        except Exception as e:
            logger.debug(f"Behavioral scan error for {base_url}: {e}")
            result['error'] = str(e)
        
        return result

# ================= CACHE MANAGER =================
class CacheManager:
    def __init__(self, cache_dir: str = CONFIG['CACHE_DIR']):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
    
    def _get_cache_key(self, source_type: str, url: str) -> str:
        hash_obj = hashlib.md5(f"{source_type}:{url}".encode())
        return os.path.join(self.cache_dir, f"{hash_obj.hexdigest()}.cache")
    
    def get(self, source_type: str, url: str, ttl: int = CONFIG['CACHE_TTL']) -> Optional[Any]:
        cache_file = self._get_cache_key(source_type, url)
        
        if not os.path.exists(cache_file):
            return None
        
        try:
            with open(cache_file, 'rb') as f:
                cache_data = pickle.load(f)
                
            if time.time() - cache_data['timestamp'] < ttl:
                return cache_data['data']
            
            os.remove(cache_file)
            return None
            
        except Exception:
            return None
    
    def set(self, source_type: str, url: str, data: Any):
        cache_file = self._get_cache_key(source_type, url)
        
        try:
            cache_data = {
                'timestamp': time.time(),
                'url': url,
                'type': source_type,
                'data': data
            }
            
            with open(cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
                
        except Exception as e:
            logger.debug(f"Cache save error: {e}")

# ================= COMPLETE DATA FETCHER =================
class CompleteDataFetcher:
    """Lấy TẤT CẢ data từ external sources"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.cache = CacheManager()
    
    async def fetch_domains_complete(self, limit: int = CONFIG['DOMAIN_LIMIT']) -> List[str]:
        """Lấy domains chất lượng"""
        all_domains = set()
        sources = CONFIG['EXTERNAL_SOURCES']['domains']
        
        print(f"[+] Fetching domains from {len(sources)} external sources...")
        
        for url in sources:
            try:
                cached = self.cache.get('domains', url)
                if cached is not None:
                    all_domains.update(cached)
                    continue
                
                headers = {'User-Agent': 'WP-Scanner/1.0'}
                async with self.session.get(url, headers=headers, timeout=15) as resp:
                    if resp.status != 200:
                        continue
                    
                    content = await resp.text()
                    domains = self._parse_domains(content, url)
                    
                    self.cache.set('domains', url, domains)
                    all_domains.update(domains)
                    
            except Exception as e:
                logger.debug(f"Domain source {url} error: {e}")
                continue
        
        filtered = self._filter_domains(list(all_domains))
        print(f"[+] Complete domains: {len(filtered)}")
        return filtered[:limit]
    
    async def fetch_plugins_complete(self) -> Dict[str, Any]:
        """Lấy plugins từ external sources"""
        plugins_db = {}
        sources = CONFIG['EXTERNAL_SOURCES']['plugins']
        
        print(f"[+] Fetching plugins from {len(sources)} external sources...")
        
        for url in sources:
            try:
                cached = self.cache.get('plugins', url)
                if cached is not None:
                    plugins_db.update(cached)
                    continue
                
                headers = {'User-Agent': 'WP-Scanner/1.0'}
                async with self.session.get(url, headers=headers, timeout=20) as resp:
                    if resp.status != 200:
                        continue
                    
                    data = await resp.json()
                    plugins = self._parse_plugins(data, url)
                    
                    self.cache.set('plugins', url, plugins)
                    plugins_db.update(plugins)
                    
            except Exception as e:
                logger.debug(f"Plugin source {url} error: {e}")
                continue
        
        print(f"[+] Complete plugins: {len(plugins_db)} loaded")
        return plugins_db
    
    async def fetch_vulnerabilities_complete(self) -> Dict[str, List[Dict]]:
        """Lấy vulnerabilities chi tiết từ external sources"""
        vulns_db = {}
        sources = CONFIG['EXTERNAL_SOURCES']['vulnerabilities']
        
        print(f"[+] Fetching vulnerabilities from {len(sources)} external sources...")
        
        for url in sources:
            try:
                cached = self.cache.get('vulnerabilities', url)
                if cached is not None:
                    self._merge_vulnerabilities(vulns_db, cached)
                    continue
                
                headers = {'User-Agent': 'WP-Scanner/1.0'}
                async with self.session.get(url, headers=headers, timeout=25) as resp:
                    if resp.status != 200:
                        continue
                    
                    data = await resp.json()
                    vulns = self._parse_vulnerabilities(data, url)
                    
                    self.cache.set('vulnerabilities', url, vulns)
                    self._merge_vulnerabilities(vulns_db, vulns)
                    
            except Exception as e:
                logger.debug(f"Vulnerability source {url} error: {e}")
                continue
        
        total_vulns = sum(len(v) for v in vulns_db.values())
        print(f"[+] Complete vulnerabilities: {total_vulns} CVEs loaded")
        return vulns_db
    
    def _parse_domains(self, content: str, url: str) -> List[str]:
        """Parse domains từ content"""
        domains = set()
        
        # Tìm tất cả domain patterns
        domain_pattern = r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        for match in re.finditer(domain_pattern, content):
            domain = match.group(0).lower()
            if self._is_valid_domain(domain):
                domains.add(domain)
        
        return list(domains)
    
    def _parse_plugins(self, data: Any, url: str) -> Dict[str, Any]:
        """Parse plugins từ JSON"""
        plugins = {}
        
        if 'wordpress.org' in url:
            # WordPress.org API format
            if 'plugins' in data:
                for plugin in data['plugins']:
                    slug = plugin.get('slug', '')
                    if slug:
                        plugins[slug] = {
                            'name': plugin.get('name', slug),
                            'version': plugin.get('version', ''),
                            'last_updated': plugin.get('last_updated', ''),
                            'active_installs': plugin.get('active_installs', 0),
                            'tested': plugin.get('tested', ''),
                            'requires': plugin.get('requires', '')
                        }
        
        return plugins
    
    def _parse_vulnerabilities(self, data: Any, url: str) -> Dict[str, List[Dict]]:
        """Parse vulnerabilities chi tiết"""
        vulns_by_plugin = {}
        
        if 'wpvulndb' in url or 'wpscanteam' in url:
            # WPVulnDB or wpscan format
            if isinstance(data, dict):
                for plugin_slug, plugin_data in data.items():
                    if not isinstance(plugin_data, dict):
                        continue
                    
                    vulnerabilities = []
                    
                    # Format khác nhau tùy source
                    if 'vulnerabilities' in plugin_data:
                        vuln_list = plugin_data['vulnerabilities']
                    elif 'data' in plugin_data:
                        vuln_list = plugin_data['data']
                    else:
                        vuln_list = []
                    
                    for vuln in vuln_list:
                        if not isinstance(vuln, dict):
                            continue
                        
                        vulnerability = {
                            'id': vuln.get('id', ''),
                            'cve': vuln.get('cve', ''),
                            'title': vuln.get('title', ''),
                            'description': vuln.get('description', ''),
                            'fixed_in': vuln.get('fixed_in', ''),
                            'introduced_in': vuln.get('introduced_in', ''),
                            'cvss': vuln.get('cvss', {}),
                            'severity': vuln.get('severity', ''),
                            'published': vuln.get('published_date', vuln.get('published', '')),
                            'updated': vuln.get('updated_date', vuln.get('updated', '')),
                            'references': vuln.get('references', []),
                            'poc': vuln.get('poc', ''),
                            'exploit_available': vuln.get('exploit_available', False)
                        }
                        
                        # Clean data
                        if vulnerability['cve'] and vulnerability['cve'].upper().startswith('CVE-'):
                            vulnerability['cve'] = vulnerability['cve'].upper()
                        
                        vulnerabilities.append(vulnerability)
                    
                    if vulnerabilities:
                        vulns_by_plugin[plugin_slug] = vulnerabilities
        
        return vulns_by_plugin
    
    def _merge_vulnerabilities(self, target: Dict[str, List[Dict]], source: Dict[str, List[Dict]]):
        """Merge vulnerabilities từ nhiều sources"""
        for plugin_slug, vulns in source.items():
            if plugin_slug not in target:
                target[plugin_slug] = []
            
            # Tránh duplicate vulnerabilities
            existing_ids = {v.get('id') for v in target[plugin_slug] if v.get('id')}
            for vuln in vulns:
                if vuln.get('id') not in existing_ids:
                    target[plugin_slug].append(vuln)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Kiểm tra domain hợp lệ"""
        if not domain or len(domain) > 100 or len(domain) < 4:
            return False
        
        if domain.count('.') < 1:
            return False
        
        # Loại bỏ IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # Loại bỏ local/test domains
        invalid_keywords = ['localhost', 'test', 'example', 'invalid', 'local']
        if any(keyword in domain.lower() for keyword in invalid_keywords):
            return False
        
        return True
    
    def _filter_domains(self, domains: List[str]) -> List[str]:
        """Lọc domains chất lượng"""
        filtered = []
        for domain in domains:
            if self._is_valid_domain(domain):
                # Loại bỏ subdomains quá dài
                if len(domain.split('.')[0]) < 30:
                    filtered.append(domain.lower())
        
        return list(set(filtered))

# ================= COMPLETE VERSION CHECKER =================
class CompleteVersionChecker:
    """Version checking CHI TIẾT từ nhiều nguồn"""
    
    VERSION_PATTERNS = [
        # readme.txt patterns
        (r'Stable tag[\s:]*([\d.]+(?:-[a-z0-9]+)?)', 'readme_stable'),
        (r'Version[\s:]*([\d.]+(?:-[a-z0-9]+)?)', 'readme_version'),
        
        # Plugin header patterns
        (r'\*[\s]*Version[\s:]*([\d.]+(?:-[a-z0-9]+)?)', 'header_version'),
        (r'@version[\s]*([\d.]+(?:-[a-z0-9]+)?)', 'phpdoc_version'),
        (r'define\([\s]*["\']VERSION["\'][\s]*,[\s]*["\']([^"\']+)["\']', 'define_version'),
        
        # Changelog patterns
        (r'==[\s]*Changelog[\s]*==.*?==[\s]*([\d.]+(?:-[a-z0-9]+)?)[\s]*==', 'changelog_latest'),
        
        # File content patterns
        (r'v?([\d]+\.[\d]+\.[\d]+(?:-[a-z0-9]+)?)', 'generic_version'),
    ]
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
    
    async def get_plugin_version_complete(self, base_url: str, plugin_slug: str) -> Dict[str, Any]:
        """Lấy version từ NHIỀU nguồn - ĐẦY ĐỦ"""
        version_sources = [
            # Source 1: readme.txt (chuẩn nhất)
            {
                'url': f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt",
                'patterns': ['readme_stable', 'readme_version'],
                'priority': 1
            },
            # Source 2: Plugin file chính
            {
                'url': f"{base_url}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php",
                'patterns': ['header_version', 'phpdoc_version', 'define_version'],
                'priority': 2
            },
            # Source 3: Alternative plugin file
            {
                'url': f"{base_url}/wp-content/plugins/{plugin_slug}/plugin.php",
                'patterns': ['header_version', 'phpdoc_version'],
                'priority': 3
            },
            # Source 4: Changelog
            {
                'url': f"{base_url}/wp-content/plugins/{plugin_slug}/changelog.txt",
                'patterns': ['changelog_latest'],
                'priority': 4
            },
            # Source 5: index.php trong plugin directory
            {
                'url': f"{base_url}/wp-content/plugins/{plugin_slug}/index.php",
                'patterns': ['header_version', 'generic_version'],
                'priority': 5
            },
        ]
        
        results = []
        
        for source in version_sources:
            version_info = await self._check_version_source(
                source['url'], 
                source['patterns'],
                source['priority']
            )
            
            if version_info['found']:
                results.append(version_info)
        
        # Chọn version tốt nhất
        if results:
            # Ưu tiên priority cao nhất
            results.sort(key=lambda x: x['priority'])
            best_result = results[0]
            
            return {
                'version': best_result['version'],
                'source': best_result['source_url'],
                'method': best_result['method'],
                'confidence': self._calculate_confidence(best_result),
                'all_sources': results  # Giữ tất cả để debug
            }
        
        return {'version': None, 'confidence': 0}
    
    async def _check_version_source(self, url: str, pattern_names: List[str], priority: int) -> Dict[str, Any]:
        """Check version từ một source cụ thể"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with self.session.get(url, headers=headers, timeout=8) as resp:
                if resp.status != 200:
                    return {'found': False}
                
                content = await resp.text(errors='ignore')
                
                # Check content không trống
                if len(content.strip()) < 10:
                    return {'found': False}
                
                # Apply patterns
                for pattern_name in pattern_names:
                    for pattern, method in self.VERSION_PATTERNS:
                        if method == pattern_name:
                            match = re.search(pattern, content, re.I | re.DOTALL)
                            if match:
                                version = match.group(1).strip()
                                if self._is_valid_version(version):
                                    return {
                                        'found': True,
                                        'version': version,
                                        'source_url': url,
                                        'method': method,
                                        'priority': priority,
                                        'content_preview': content[:200]
                                    }
                
                # Fallback: generic version pattern
                generic_pattern = r'v?([\d]+\.[\d]+\.[\d]+(?:-[a-z0-9]+)?)'
                matches = re.findall(generic_pattern, content)
                if matches:
                    # Lấy version đầu tiên trông hợp lý
                    for version in matches:
                        if self._is_valid_version(version):
                            return {
                                'found': True,
                                'version': version,
                                'source_url': url,
                                'method': 'generic_fallback',
                                'priority': priority,
                                'content_preview': content[:200]
                            }
                
                return {'found': False}
                
        except Exception as e:
            logger.debug(f"Version check error for {url}: {e}")
            return {'found': False}
    
    def _is_valid_version(self, version: str) -> bool:
        """Kiểm tra version hợp lệ"""
        if not version:
            return False
        
        # Basic format: x.x.x hoặc x.x.x-suffix
        version_pattern = r'^\d+(?:\.\d+){1,3}(?:-[a-z0-9]+)?$'
        if re.match(version_pattern, version):
            return True
        
        # Check common version formats
        if any(pattern in version.lower() for pattern in ['dev', 'alpha', 'beta', 'rc']):
            return True
        
        return False
    
    def _calculate_confidence(self, version_info: Dict[str, Any]) -> float:
        """Tính độ tin cậy của version"""
        confidence = 0.5  # Base confidence
        
        # Source priority
        if version_info['priority'] == 1:
            confidence += 0.3  # readme.txt = high confidence
        elif version_info['priority'] == 2:
            confidence += 0.2  # plugin.php = medium confidence
        
        # Method confidence
        method = version_info['method']
        if method in ['readme_stable', 'readme_version']:
            confidence += 0.2
        elif method in ['header_version', 'phpdoc_version']:
            confidence += 0.15
        
        # Content length
        preview = version_info.get('content_preview', '')
        if len(preview) > 100:
            confidence += 0.1
        
        return min(confidence, 1.0)  # Max 1.0

# ================= COMPLETE VULNERABILITY CHECKER =================
class CompleteVulnerabilityChecker:
    """Vulnerability checking CHI TIẾT với CVE verification"""
    
    def __init__(self, vulnerabilities_db: Dict[str, List[Dict]]):
        self.vulnerabilities_db = vulnerabilities_db
    
    def check_plugin_vulnerabilities_complete(self, plugin_slug: str, 
                                            plugin_version: str) -> Dict[str, Any]:
        """Check vulnerabilities CHI TIẾT cho plugin"""
        result = {
            'plugin': plugin_slug,
            'version': plugin_version,
            'vulnerabilities': [],
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'exploit_available': 0
            }
        }
        
        if plugin_slug not in self.vulnerabilities_db:
            return result
        
        plugin_vulns = self.vulnerabilities_db[plugin_slug]
        
        for vuln in plugin_vulns:
            # Kiểm tra version affected
            is_affected = self._is_version_affected(plugin_version, vuln)
            
            if is_affected:
                vulnerability = self._format_vulnerability(vuln)
                result['vulnerabilities'].append(vulnerability)
                
                # Update summary
                result['summary']['total'] += 1
                
                # Severity counting
                severity = vulnerability.get('severity', 'medium').lower()
                if 'critical' in severity:
                    result['summary']['critical'] += 1
                elif 'high' in severity:
                    result['summary']['high'] += 1
                elif 'low' in severity:
                    result['summary']['low'] += 1
                else:
                    result['summary']['medium'] += 1
                
                # Exploit available
                if vulnerability.get('exploit_available', False):
                    result['summary']['exploit_available'] += 1
        
        return result
    
    def _is_version_affected(self, current_version: str, vulnerability: Dict) -> bool:
        """Kiểm tra version có bị ảnh hưởng không - CHI TIẾT"""
        if not current_version:
            return True  # Không biết version, coi như có risk
        
        fixed_in = vulnerability.get('fixed_in', '')
        introduced_in = vulnerability.get('introduced_in', '')
        
        # Không có version info -> coi như affected
        if not fixed_in and not introduced_in:
            return True
        
        try:
            current = self._parse_version(current_version)
            
            # Check introduced_in
            if introduced_in:
                introduced = self._parse_version(introduced_in)
                if current < introduced:
                    return False  # Version chưa được introduce
            
            # Check fixed_in
            if fixed_in:
                fixed = self._parse_version(fixed_in)
                if current >= fixed:
                    return False  # Đã được fix
            
            return True
            
        except Exception:
            # Parse lỗi -> coi như affected để an toàn
            return True
    
    def _parse_version(self, version_str: str) -> List[int]:
        """Parse version string thành list of integers"""
        # Lấy phần số đầu tiên
        clean_version = re.search(r'(\d+(?:\.\d+)*)', version_str)
        if not clean_version:
            return [0]
        
        parts = clean_version.group(1).split('.')
        return [int(part) for part in parts]
    
    def _format_vulnerability(self, vuln: Dict) -> Dict[str, Any]:
        """Format vulnerability chi tiết"""
        cvss = vuln.get('cvss', {})
        cvss_score = cvss.get('score', 0) if isinstance(cvss, dict) else 0
        
        return {
            'id': vuln.get('id', ''),
            'cve': vuln.get('cve', 'N/A'),
            'title': vuln.get('title', 'Unknown Vulnerability'),
            'description': vuln.get('description', '')[:200] + '...',
            'fixed_in': vuln.get('fixed_in', 'Unknown'),
            'introduced_in': vuln.get('introduced_in', ''),
            'severity': self._calculate_severity(cvss_score, vuln.get('severity', '')),
            'cvss_score': cvss_score,
            'cvss_vector': cvss.get('vector', '') if isinstance(cvss, dict) else '',
            'published': vuln.get('published', ''),
            'updated': vuln.get('updated', ''),
            'references': vuln.get('references', [])[:3],  # Limit references
            'poc': vuln.get('poc', ''),
            'exploit_available': vuln.get('exploit_available', False),
            'risk_score': self._calculate_risk_score(vuln)
        }
    
    def _calculate_severity(self, cvss_score: float, severity_str: str) -> str:
        """Tính severity từ CVSS score"""
        if severity_str:
            return severity_str
        
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0:
            return 'Low'
        else:
            return 'Unknown'
    
    def _calculate_risk_score(self, vuln: Dict) -> float:
        """Tính risk score tổng hợp"""
        score = 0.0
        
        # CVSS score contribution (0-10 -> 0-0.5)
        cvss = vuln.get('cvss', {})
        cvss_score = cvss.get('score', 0) if isinstance(cvss, dict) else 0
        score += min(cvss_score / 20.0, 0.5)
        
        # Exploit available bonus
        if vuln.get('exploit_available', False):
            score += 0.2
        
        # Recent vulnerability bonus
        published = vuln.get('published', '')
        if published:
            try:
                # Nếu published trong vòng 1 năm
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                one_year_ago = datetime.now() - timedelta(days=365)
                if pub_date > one_year_ago:
                    score += 0.1
            except:
                pass
        
        # Has CVE bonus
        if vuln.get('cve', '').startswith('CVE-'):
            score += 0.1
        
        # Has PoC bonus
        if vuln.get('poc', ''):
            score += 0.1
        
        return min(score, 1.0)

# ================= COMPLETE CONTENT ANALYZER =================
class CompleteContentAnalyzer:
    """Content analysis CHI TIẾT"""
    
    DANGEROUS_PATTERNS = [
        # File upload patterns
        (r'move_uploaded_file\s*\(', 'file_upload'),
        (r'\$_FILES\[', 'file_upload_global'),
        (r'wp_handle_upload\s*\(', 'wordpress_upload'),
        
        # Code execution patterns
        (r'eval\s*\(', 'eval_function'),
        (r'assert\s*\(', 'assert_function'),
        (r'preg_replace\s*\(.*/e', 'preg_replace_eval'),
        (r'create_function\s*\(', 'create_function'),
        (r'system\s*\(', 'system_call'),
        (r'exec\s*\(', 'exec_call'),
        (r'shell_exec\s*\(', 'shell_exec'),
        (r'passthru\s*\(', 'passthru'),
        (r'proc_open\s*\(', 'proc_open'),
        
        # Database patterns (SQLi potential)
        (r'\$wpdb->query\s*\(.*\$', 'wpdb_dynamic_query'),
        (r'\$wpdb->prepare\s*\(', 'wpdb_prepare'),
        
        # Authentication bypass
        (r'wp_set_auth_cookie\s*\(', 'auth_cookie_set'),
        (r'wp_verify_nonce\s*\(', 'nonce_verification'),
        
        # File inclusion
        (r'include\s*\(.*\$', 'dynamic_include'),
        (r'require\s*\(.*\$', 'dynamic_require'),
        (r'include_once\s*\(.*\$', 'dynamic_include_once'),
        
        # Deserialization
        (r'unserialize\s*\(', 'unserialize'),
        
        # Command injection
        (r'escapeshellarg\s*\(', 'escapeshellarg'),
    ]
    
    def __init__(self):
        self.compiled_patterns = [(re.compile(pattern, re.I), reason) 
                                 for pattern, reason in self.DANGEROUS_PATTERNS]
    
    def analyze_file_content(self, content: str, file_url: str) -> Dict[str, Any]:
        """Phân tích content file CHI TIẾT"""
        result = {
            'file': file_url,
            'is_php': False,
            'is_empty': False,
            'dangerous_patterns': [],
            'risk_level': 'low',
            'analysis': {}
        }
        
        # Check empty file
        content_stripped = content.strip()
        if len(content_stripped) == 0:
            result['is_empty'] = True
            result['risk_level'] = 'none'
            return result
        
        # Check if it's PHP
        is_php = '<?php' in content or content.startswith('<?')
        result['is_php'] = is_php
        
        if not is_php:
            result['risk_level'] = 'low'
            return result
        
        # Check dangerous patterns
        patterns_found = []
        for pattern, reason in self.compiled_patterns:
            matches = pattern.findall(content)
            if matches:
                patterns_found.append({
                    'pattern': reason,
                    'count': len(matches),
                    'description': self._get_pattern_description(reason)
                })
        
        result['dangerous_patterns'] = patterns_found
        
        # Calculate risk level
        if patterns_found:
            high_risk_patterns = ['eval_function', 'system_call', 'exec_call', 
                                 'shell_exec', 'unserialize']
            
            high_count = sum(1 for p in patterns_found 
                           if p['pattern'] in high_risk_patterns)
            
            if high_count > 0:
                result['risk_level'] = 'critical'
            elif len(patterns_found) > 3:
                result['risk_level'] = 'high'
            elif len(patterns_found) > 0:
                result['risk_level'] = 'medium'
        
        # Additional analysis
        result['analysis'] = {
            'length': len(content),
            'lines': content.count('\n') + 1,
            'has_functions': 'function ' in content,
            'has_classes': 'class ' in content,
            'has_includes': any(x in content for x in ['include', 'require']),
            'has_database': any(x in content for x in ['$wpdb', 'mysql_', 'mysqli_']),
        }
        
        return result
    
    def _get_pattern_description(self, pattern: str) -> str:
        """Mô tả cho dangerous pattern"""
        descriptions = {
            'file_upload': 'File upload functionality',
            'eval_function': 'eval() function - code execution',
            'system_call': 'system() call - command execution',
            'exec_call': 'exec() call - command execution',
            'shell_exec': 'shell_exec() - command execution',
            'unserialize': 'unserialize() - potential PHP object injection',
            'dynamic_include': 'Dynamic file inclusion - LFI/RFI',
            'wpdb_dynamic_query': 'Dynamic database query - SQL injection risk',
        }
        return descriptions.get(pattern, 'Potentially dangerous code pattern')

# ================= COMPLETE PLUGIN SCANNER =================
class CompletePluginScanner:
    """Plugin scanning CHI TIẾT với tất cả tính năng"""
    
    def __init__(self, session: aiohttp.ClientSession, 
                 version_checker: CompleteVersionChecker,
                 vuln_checker: CompleteVulnerabilityChecker,
                 content_analyzer: CompleteContentAnalyzer):
        self.session = session
        self.version_checker = version_checker
        self.vuln_checker = vuln_checker
        self.content_analyzer = content_analyzer
    
    async def scan_plugin_complete(self, base_url: str, plugin_slug: str) -> Dict[str, Any]:
        """Scan plugin CHI TIẾT với tất cả tính năng"""
        result = {
            'plugin': plugin_slug,
            'accessible': False,
            'version_info': None,
            'vulnerabilities': None,
            'dangerous_files': [],
            'analysis': {},
            'scan_time': 0
        }
        
        start_time = time.time()
        
        try:
            # 1. Check plugin accessibility
            plugin_url = f"{base_url}/wp-content/plugins/{plugin_slug}/"
            accessible = await self._check_accessible(plugin_url)
            result['accessible'] = accessible
            
            if not accessible:
                result['scan_time'] = time.time() - start_time
                return result
            
            # 2. Get version CHI TIẾT
            version_info = await self.version_checker.get_plugin_version_complete(
                base_url, plugin_slug
            )
            result['version_info'] = version_info
            
            # 3. Check vulnerabilities CHI TIẾT
            if version_info.get('version'):
                vulnerabilities = self.vuln_checker.check_plugin_vulnerabilities_complete(
                    plugin_slug, version_info['version']
                )
                result['vulnerabilities'] = vulnerabilities
            
            # 4. Check dangerous files
            dangerous_files = await self._check_dangerous_files(base_url, plugin_slug)
            result['dangerous_files'] = dangerous_files
            
            # 5. Comprehensive analysis
            result['analysis'] = await self._analyze_plugin_comprehensive(
                base_url, plugin_slug, version_info.get('version')
            )
            
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Plugin scan error for {plugin_slug}: {e}")
        
        result['scan_time'] = time.time() - start_time
        return result
    
    async def _check_accessible(self, plugin_url: str) -> bool:
        """Kiểm tra plugin có thể truy cập không"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with self.session.get(plugin_url, headers=headers, timeout=5) as resp:
                return resp.status in [200, 403, 301, 302]
        except Exception:
            return False
    
    async def _check_dangerous_files(self, base_url: str, plugin_slug: str) -> List[Dict]:
        """Check dangerous files CHI TIẾT"""
        dangerous_files = []
        common_files = [
            'ajax.php', 'upload.php', 'execute.php', 'admin-ajax.php',
            'import.php', 'export.php', 'backup.php', 'restore.php',
            'installer.php', 'upgrade.php', 'elfinder.php', 'connector.php'
        ]
        
        for filename in common_files:
            file_url = f"{base_url}/wp-content/plugins/{plugin_slug}/{filename}"
            file_info = await self._analyze_file(file_url)
            
            if file_info and file_info.get('accessible', False):
                dangerous_files.append(file_info)
        
        return dangerous_files
    
    async def _analyze_file(self, file_url: str) -> Optional[Dict]:
        """Phân tích file CHI TIẾT"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with self.session.get(file_url, headers=headers, timeout=8) as resp:
                if resp.status != 200:
                    return None
                
                content = await resp.text(errors='ignore')
                
                # Content analysis
                analysis = self.content_analyzer.analyze_file_content(content, file_url)
                
                # Thêm thông tin cơ bản
                analysis.update({
                    'url': file_url,
                    'accessible': True,
                    'status': resp.status,
                    'size': len(content),
                    'is_blank': len(content.strip()) == 0
                })
                
                return analysis
                
        except Exception as e:
            logger.debug(f"File analysis error for {file_url}: {e}")
            return None
    
    async def _analyze_plugin_comprehensive(self, base_url: str, plugin_slug: str, 
                                          version: Optional[str]) -> Dict[str, Any]:
        """Phân tích plugin toàn diện"""
        analysis = {
            'has_readme': False,
            'has_changelog': False,
            'main_file_exists': False,
            'directory_listing': False,
            'estimated_risk': 'low'
        }
        
        # Check common files
        common_files = [
            f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt",
            f"{base_url}/wp-content/plugins/{plugin_slug}/changelog.txt",
            f"{base_url}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php",
            f"{base_url}/wp-content/plugins/{plugin_slug}/"
        ]
        
        file_checks = await asyncio.gather(*[
            self._check_file_exists(url) for url in common_files
        ])
        
        analysis['has_readme'] = file_checks[0]
        analysis['has_changelog'] = file_checks[1]
        analysis['main_file_exists'] = file_checks[2]
        analysis['directory_listing'] = await self._check_directory_listing(common_files[3])
        
        # Estimate risk
        risk_factors = []
        if not version:
            risk_factors.append('unknown_version')
        if not analysis['has_readme']:
            risk_factors.append('no_readme')
        if analysis['directory_listing']:
            risk_factors.append('directory_listing_enabled')
        
        if risk_factors:
            analysis['risk_factors'] = risk_factors
            analysis['estimated_risk'] = 'medium' if len(risk_factors) > 1 else 'low'
        
        return analysis
    
    async def _check_file_exists(self, url: str) -> bool:
        """Check file exists"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with self.session.get(url, headers=headers, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False
    
    async def _check_directory_listing(self, directory_url: str) -> bool:
        """Check directory listing enabled"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with self.session.get(directory_url, headers=headers, timeout=5) as resp:
                if resp.status != 200:
                    return False
                
                content = await resp.text(errors='ignore')
                # Check common directory listing indicators
                indicators = ['Index of', '<title>Index of', 'Parent Directory', 
                            '[To Parent Directory]', 'Directory listing for']
                return any(indicator in content for indicator in indicators)
        except Exception:
            return False

# ================= ULTIMATE WORDPRESS SCANNER =================
class UltimateWordPressScanner:
    """Scanner ULTIMATE với TẤT CẢ tính năng đầy đủ + Behavioral observation"""
    
    def __init__(self):
        self.data_fetcher = None
        self.version_checker = None
        self.vuln_checker = None
        self.content_analyzer = None
        self.plugin_scanner = None
        self.behavioral_scanner = BehavioralVulnerabilityScanner()
        
        self.plugins_db = {}
        self.vulnerabilities_db = {}
    
    async def initialize(self, session: aiohttp.ClientSession):
        """Khởi tạo tất cả components"""
        print("\n" + "="*70)
        print("🔄 INITIALIZING ULTIMATE SCANNER")
        print("="*70)
        
        # 1. Fetch external data
        self.data_fetcher = CompleteDataFetcher(session)
        
        print("[+] Fetching external databases...")
        self.plugins_db = await self.data_fetcher.fetch_plugins_complete()
        self.vulnerabilities_db = await self.data_fetcher.fetch_vulnerabilities_complete()
        
        # 2. Initialize all checkers
        self.version_checker = CompleteVersionChecker(session)
        self.vuln_checker = CompleteVulnerabilityChecker(self.vulnerabilities_db)
        self.content_analyzer = CompleteContentAnalyzer()
        self.plugin_scanner = CompletePluginScanner(
            session, self.version_checker, self.vuln_checker, self.content_analyzer
        )
        
        print("[✅] Ultimate scanner initialized!")
        print(f"    • Plugins: {len(self.plugins_db)}")
        print(f"    • Vulnerabilities: {sum(len(v) for v in self.vulnerabilities_db.values())}")
        print(f"    • Behavioral scanner: READY")
        print("="*70 + "\n")
    
    async def scan_domain_ultimate(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Scan domain với TẤT CẢ tính năng ULTIMATE"""
        result = {
            'domain': domain,
            'alive': False,
            'wordpress': False,
            'plugins': [],
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'endpoint_vulnerabilities': [],
            'behavioral_findings': {},
            'scan_details': {},
            'scan_time': 0
        }
        
        start_time = time.time()
        
        try:
            # 1. Check alive
            test_url = f"https://{domain}"
            test_resp = await self._safe_request(session, test_url)
            if not test_resp or test_resp['status'] not in [200, 301, 302, 403]:
                test_url = f"http://{domain}"
                test_resp = await self._safe_request(session, test_url)
            
            if not test_resp:
                result['scan_time'] = time.time() - start_time
                return result
            
            result['alive'] = True
            
            # 2. Enhanced WordPress detection
            wp_detected = await self._detect_wordpress_enhanced(session, domain)
            result['wordpress'] = wp_detected
            
            if not wp_detected:
                result['scan_time'] = time.time() - start_time
                return result
            
            wp_url = test_resp['url'].split('/wp-')[0] if '/wp-' in test_resp['url'] else test_url
            
            # 3. BEHAVIORAL VULNERABILITY SCANNING (THÊM MỚI)
            print(f"[B] Scanning behavioral vulnerabilities for {domain}")
            behavioral_result = self.behavioral_scanner.scan_behavioral_vulnerabilities(wp_url)
            result['endpoint_vulnerabilities'] = behavioral_result.get('endpoint_vulnerabilities', [])
            result['behavioral_findings'] = behavioral_result.get('behavioral_findings', {})
            
            # Đếm behavioral vulnerabilities
            behavioral_vuln_count = len(result['endpoint_vulnerabilities'])
            result['vulnerabilities_found'] += behavioral_vuln_count
            
            # Count critical từ behavioral
            for vuln in result['endpoint_vulnerabilities']:
                if vuln.get('severity') == 'HIGH':
                    result['critical_vulnerabilities'] += 1
            
            # 4. Find plugins
            plugins_found = await self._find_plugins_simple(session, wp_url)
            result['plugins_found'] = len(plugins_found)
            
            # 5. Scan plugins COMPLETE
            if plugins_found:
                plugins_scanned = []
                critical_count = 0
                
                # Limit số plugin scan để không quá lâu
                plugins_to_scan = list(plugins_found)[:5]  # Max 5 plugins per site
                
                for plugin_slug in plugins_to_scan:
                    plugin_result = await self.plugin_scanner.scan_plugin_complete(
                        wp_url, plugin_slug
                    )
                    
                    if plugin_result.get('vulnerabilities'):
                        vuln_summary = plugin_result['vulnerabilities']['summary']
                        if vuln_summary['total'] > 0:
                            plugins_scanned.append(plugin_result)
                            
                            # Count vulnerabilities
                            result['vulnerabilities_found'] += vuln_summary['total']
                            result['critical_vulnerabilities'] += vuln_summary['critical']
                            
                            if vuln_summary['critical'] > 0:
                                critical_count += 1
                
                result['plugins'] = plugins_scanned
                result['scan_details']['critical_plugins'] = critical_count
            
            # 6. Tổng kết scan details
            result['scan_details'].update({
                'behavioral_vulnerabilities': behavioral_vuln_count,
                'plugin_vulnerabilities': result['vulnerabilities_found'] - behavioral_vuln_count,
                'total_endpoints_tested': 10,  # Số endpoints behavioral scanner đã test
            })
        
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Ultimate scan error for {domain}: {e}")
        
        result['scan_time'] = time.time() - start_time
        return result
    
    async def _safe_request(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Safe request"""
        try:
            headers = {'User-Agent': 'WP-Scanner/1.0'}
            async with session.get(url, headers=headers, timeout=8, 
                                 allow_redirects=True) as resp:
                text = await resp.text(errors='ignore')
                return {
                    'status': resp.status,
                    'url': str(resp.url),
                    'text': text[:10000]
                }
        except Exception:
            return None
    
    async def _detect_wordpress_enhanced(self, session: aiohttp.ClientSession, domain: str) -> bool:
        """Enhanced WordPress detection với xác minh chặt chẽ"""
        
        # Các URL để check
        check_urls = [
            (f"https://{domain}", "homepage"),
            (f"http://{domain}", "homepage_http"),
            (f"https://{domain}/wp-json/", "wp_json"),
            (f"https://{domain}/wp-admin/", "wp_admin"),
            (f"https://{domain}/wp-login.php", "wp_login"),
            (f"https://{domain}/xmlrpc.php", "xmlrpc"),
            (f"https://{domain}/feed/", "feed"),
            (f"https://{domain}/wp-content/", "wp_content"),  # THÊM
            (f"https://{domain}/?rest_route=/", "rest_route"),  # THÊM
        ]
        wp_indicators = 0
        required_indicators = 2  # Cần ít nhất 2 indicators để confirm WP
        
        for url, check_type in check_urls:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                
                async with session.get(url, headers=headers, timeout=5, 
                                     allow_redirects=True, ssl=False) as response:
                    
                    # Bỏ qua nếu không phải status code hợp lệ
                    if response.status not in [200, 201, 301, 302, 403, 401]:
                        continue
                    
                    text = await response.text(errors='ignore')
                    text_lower = text.lower()
                    
                    # 1. CHECK HEADERS
                    headers_lower = {k.lower(): str(v).lower() for k, v in response.headers.items()}
                    
                    # X-Powered-By có WordPress
                    if 'x-powered-by' in headers_lower and 'wordpress' in headers_lower['x-powered-by']:
                        wp_indicators += 1
                        continue  # Đã tìm thấy indicator, check tiếp URL khác
                    
                    # Link header có wp-json
                    if 'link' in headers_lower and any(x in headers_lower['link'] for x in ['wp-json', 'rest_route']):
                        wp_indicators += 1
                        continue
                    
                    # 2. CHECK CONTENT PATTERNS - CHÍNH XÁC HƠN
                    
                    # Pattern STRONG indicators (chỉ có trong WP)
                    strong_patterns = [
                        r'<meta[^>]*name="generator"[^>]*content="WordPress[^"]*"',  # WordPress generator meta
                        r'/wp-content/(?:themes|plugins|uploads)/[^"\']+\.(?:css|js|png|jpg)',  # WP asset URLs
                        r'wp-includes/js/wp-embed.min.js',  # WP embed script
                        r'wp-json/wp/v2/',  # REST API namespace
                        r'"namespace":"wp/v2"',  # REST API namespace trong JSON
                        r'wp\.i18n',  # WP i18n
                        r'wp\.apiFetch',  # WP API fetch
                        r'admin-bar\.css',  # Admin bar CSS
                        r'dashicons\.css',  # Dashicons
                    ]
                    
                    for pattern in strong_patterns:
                        if re.search(pattern, text_lower, re.I):
                            wp_indicators += 1
                            break  # Chỉ cần 1 strong pattern
                    
                    # Pattern MEDIUM indicators (có thể có ở CMS khác)
                    medium_patterns = [
                        r'/wp-content/',  # WP content path
                        r'/wp-includes/',  # WP includes path
                        r'wp-login\.php',  # WP login
                        r'wp-admin/',  # WP admin
                        r'Lost your password\?',  # WP password reset
                        r'Powered by WordPress',  # WP footer
                    ]
                    
                    # Cần ít nhất 2 medium patterns
                    medium_count = 0
                    for pattern in medium_patterns:
                        if re.search(pattern, text_lower, re.I):
                            medium_count += 1
                    
                    if medium_count >= 2:
                        wp_indicators += 1
                    
                    # 3. CHECK NEGATIVE PATTERNS (LOẠI TRỪ)
                    negative_patterns = [
                        r'Joomla', 'Drupal', 'Magento', 'Shopify', 'Wix', 'Squarespace',
                        r'Blogger', 'Blogspot', 'Tumblr', 'Weebly', 'Ghost',
                    ]
                    
                    # Nếu có negative patterns, giảm điểm
                    for pattern in negative_patterns:
                        if re.search(pattern, text_lower, re.I):
                            wp_indicators = max(0, wp_indicators - 1)
                            break
                    
                    # 4. CHECK URL REDIRECTS
                    final_url = str(response.url).lower()
                    if '/wp-' in final_url:
                        wp_indicators += 1
                    
                    # Kiểm tra nếu đã đủ indicators
                    if wp_indicators >= required_indicators:
                        return True
                    
            except Exception as e:
                logger.debug(f"WordPress detection error for {url}: {e}")
                continue
        
        # Final check: cần đủ indicators
        return wp_indicators >= required_indicators
    
    async def _find_plugins_simple(self, session: aiohttp.ClientSession, base_url: str) -> Set[str]:
        """Simple plugin detection"""
        plugins = set()
        
        # Check homepage
        resp = await self._safe_request(session, base_url)
        if resp and resp['status'] == 200:
            text = resp['text']
            
            # Extract plugin slugs
            pattern = r'wp-content/plugins/([^/"\']+)/'
            matches = re.findall(pattern, text, re.I)
            for match in matches:
                plugin = match.split('/')[0].strip().lower()
                if plugin and 3 <= len(plugin) <= 50:
                    plugins.add(plugin)
        
        return plugins

# ================= ULTIMATE OUTPUT HANDLER =================
class UltimateOutputHandler:
    """Output handler với format ULTIMATE"""
    
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.file_handle = None
        self.stats = {
            'total': 0,
            'alive': 0,
            'wordpress': 0,
            'plugins_found': 0,
            'vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'behavioral_vulnerabilities': 0,
            'plugin_vulnerabilities': 0,
            'start_time': time.time(),
        }
        self.vulnerable_sites = []
    
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
    
    async def write_result(self, result: Dict[str, Any]):
        """Ghi kết quả scan ULTIMATE"""
        if not self.file_handle:
            return
        
        self.stats['total'] += 1
        
        if result['alive']:
            self.stats['alive'] += 1
            
            if result['wordpress']:
                self.stats['wordpress'] += 1
                self.stats['plugins_found'] += result.get('plugins_found', 0)
                self.stats['vulnerabilities'] += result.get('vulnerabilities_found', 0)
                self.stats['critical_vulnerabilities'] += result.get('critical_vulnerabilities', 0)
                self.stats['behavioral_vulnerabilities'] += len(result.get('endpoint_vulnerabilities', []))
                self.stats['plugin_vulnerabilities'] += (result.get('vulnerabilities_found', 0) - len(result.get('endpoint_vulnerabilities', [])))
                
                if result.get('vulnerabilities_found', 0) > 0:
                    self.vulnerable_sites.append(result)
        
        # Chỉ ghi chi tiết nếu có vulnerabilities
        if result.get('vulnerabilities_found', 0) > 0:
            self.file_handle.write("\n" + "=" * 80 + "\n")
            self.file_handle.write(f"🚨 DOMAIN: {result['domain']}\n")
            self.file_handle.write("-" * 40 + "\n")
            self.file_handle.write(f"🌐 Alive: {'Yes' if result['alive'] else 'No'}\n")
            self.file_handle.write(f"🅆 WordPress: {'Yes' if result['wordpress'] else 'No'}\n")
            self.file_handle.write(f"⏱️ Scan Time: {result.get('scan_time', 0):.2f}s\n")
            
            if result['wordpress']:
                self.file_handle.write(f"\n📊 SCAN RESULTS:\n")
                self.file_handle.write(f"  • Plugins Found: {result.get('plugins_found', 0)}\n")
                self.file_handle.write(f"  • Total Vulnerabilities: {result.get('vulnerabilities_found', 0)}\n")
                self.file_handle.write(f"  • Critical Vulnerabilities: {result.get('critical_vulnerabilities', 0)}\n")
                self.file_handle.write(f"  • Behavioral Vulnerabilities: {len(result.get('endpoint_vulnerabilities', []))}\n")
                self.file_handle.write(f"  • Plugin Vulnerabilities: {result.get('vulnerabilities_found', 0) - len(result.get('endpoint_vulnerabilities', []))}\n")
                
                # BEHAVIORAL VULNERABILITIES
                if result.get('endpoint_vulnerabilities'):
                    self.file_handle.write(f"\n🔍 BEHAVIORAL VULNERABILITIES:\n")
                    
                    for vuln in result['endpoint_vulnerabilities']:
                        severity = vuln.get('severity', 'UNKNOWN')
                        severity_icon = '🚨' if severity == 'HIGH' else '⚠️' if severity == 'MEDIUM' else 'ℹ️'
                        
                        self.file_handle.write(f"\n  {severity_icon} {vuln['type']}\n")
                        self.file_handle.write(f"    Severity: {severity}\n")
                        self.file_handle.write(f"    Description: {vuln.get('description', '')}\n")
                        self.file_handle.write(f"    Evidence: {vuln.get('evidence', '')[:100]}...\n")
                        self.file_handle.write(f"    URL: {vuln.get('url', '')}\n")
                
                # PLUGIN VULNERABILITIES
                if result.get('plugins'):
                    self.file_handle.write(f"\n🔌 PLUGIN VULNERABILITIES:\n")
                    
                    for plugin_result in result['plugins']:
                        plugin_name = plugin_result.get('plugin', 'Unknown')
                        vuln_info = plugin_result.get('vulnerabilities', {})
                        summary = vuln_info.get('summary', {})
                        
                        if summary.get('total', 0) > 0:
                            self.file_handle.write(f"\n  • {plugin_name}\n")
                            
                            # Version info
                            version_info = plugin_result.get('version_info', {})
                            if version_info.get('version'):
                                self.file_handle.write(f"    Version: {version_info['version']} ")
                                self.file_handle.write(f"(Confidence: {version_info.get('confidence', 0):.1%})\n")
                            
                            # Vulnerability summary
                            self.file_handle.write(f"    Vulnerabilities: {summary.get('total', 0)} total\n")
                            
                            if summary.get('critical', 0) > 0:
                                self.file_handle.write(f"    🚨 Critical: {summary.get('critical', 0)}\n")
                            if summary.get('high', 0) > 0:
                                self.file_handle.write(f"    ⚠️ High: {summary.get('high', 0)}\n")
                            
                            if summary.get('exploit_available', 0) > 0:
                                self.file_handle.write(f"    💥 Exploits Available: {summary.get('exploit_available', 0)}\n")
                
                # Scan details
                if result.get('scan_details'):
                    details = result['scan_details']
                    self.file_handle.write(f"\n📈 SCAN DETAILS:\n")
                    for key, value in details.items():
                        self.file_handle.write(f"  • {key.replace('_', ' ').title()}: {value}\n")
            
            self.file_handle.write("=" * 80 + "\n")
            self.file_handle.flush()
    
    async def write_summary(self):
        """Ghi summary ULTIMATE"""
        elapsed = time.time() - self.stats['start_time']
        
        self.file_handle.write("\n\n" + "=" * 80 + "\n")
        self.file_handle.write("ULTIMATE SCAN SUMMARY\n")
        self.file_handle.write("=" * 80 + "\n")
        
        self.file_handle.write(f"\n📊 STATISTICS:\n")
        self.file_handle.write(f"  • Total Domains: {self.stats['total']}\n")
        
        if self.stats['total'] > 0:
            alive_percent = (self.stats['alive'] / self.stats['total']) * 100
            self.file_handle.write(f"  • Alive: {self.stats['alive']} ({alive_percent:.1f}%)\n")
        
        if self.stats['alive'] > 0:
            wp_percent = (self.stats['wordpress'] / self.stats['alive']) * 100
            self.file_handle.write(f"\n🅆🄿 WORDPRESS:\n")
            self.file_handle.write(f"  • Total: {self.stats['wordpress']} ({wp_percent:.1f}%)\n")
            self.file_handle.write(f"  • Plugins Found: {self.stats['plugins_found']}\n")
        
        self.file_handle.write(f"\n🔍 VULNERABILITY BREAKDOWN:\n")
        self.file_handle.write(f"  • Total Vulnerabilities: {self.stats['vulnerabilities']}\n")
        self.file_handle.write(f"  • Critical Vulnerabilities: {self.stats['critical_vulnerabilities']}\n")
        self.file_handle.write(f"  • Behavioral Vulnerabilities: {self.stats['behavioral_vulnerabilities']}\n")
        self.file_handle.write(f"  • Plugin Vulnerabilities: {self.stats['plugin_vulnerabilities']}\n")
        
        self.file_handle.write(f"\n⚡ PERFORMANCE:\n")
        self.file_handle.write(f"  • Total Time: {elapsed:.1f}s\n")
        if self.stats['total'] > 0 and elapsed > 0:
            domains_per_second = self.stats['total'] / elapsed
            self.file_handle.write(f"  • Domains/Second: {domains_per_second:.2f}\n")
        
        if self.vulnerable_sites:
            self.file_handle.write(f"\n🚨 TOP VULNERABLE SITES ({len(self.vulnerable_sites)}):\n")
            self.file_handle.write("-" * 40 + "\n")
            
            # Sort by total vulnerabilities
            self.vulnerable_sites.sort(key=lambda x: x.get('vulnerabilities_found', 0), reverse=True)
            
            for site in self.vulnerable_sites[:20]:  # Top 20
                domain = site['domain']
                total_vulns = site.get('vulnerabilities_found', 0)
                critical_vulns = site.get('critical_vulnerabilities', 0)
                behavioral_vulns = len(site.get('endpoint_vulnerabilities', []))
                plugin_vulns = total_vulns - behavioral_vulns
                
                critical_str = f"🚨{critical_vulns}" if critical_vulns > 0 else ""
                behavioral_str = f"👁️{behavioral_vulns}" if behavioral_vulns > 0 else ""
                plugin_str = f"🔌{plugin_vulns}" if plugin_vulns > 0 else ""
                
                self.file_handle.write(f"  • {domain} - {total_vulns} vulns {critical_str} {behavioral_str} {plugin_str}\n")
        
        self.file_handle.write("\n" + "=" * 80 + "\n")
        self.file_handle.write("✅ ULTIMATE FEATURES ENABLED:\n")
        self.file_handle.write("  • Version Checking (from multiple sources)\n")
        self.file_handle.write("  • CVE Verification (with CVSS scores)\n")
        self.file_handle.write("  • Content Analysis (dangerous patterns)\n")
        self.file_handle.write("  • Behavioral Observation (endpoint scanning)\n")
        self.file_handle.write("  • Rate Handling Analysis\n")
        self.file_handle.write("  • Authentication Boundary Testing\n")
        self.file_handle.write("  • Error Response Pattern Analysis\n")
        self.file_handle.write("=" * 80 + "\n")

# ================= MAIN FUNCTION =================
async def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_file>")
        print(f"Example: {sys.argv[0]} ultimate_scan_results.txt")
        sys.exit(1)
    
    output_file = sys.argv[1]
    
    print("\n" + "=" * 70)
    print("🔍 WORDPRESS VULNERABILITY SCANNER - ULTIMATE EDITION")
    print("✅ TÍNH NĂNG ĐẦY ĐỦ: CVE + Behavioral + Content analysis")
    print("=" * 70 + "\n")
    
    # Setup output
    output_handler = UltimateOutputHandler(output_file)
    await output_handler.__aenter__()
    
    # Initialize scanner
    scanner = UltimateWordPressScanner()
    
    try:
        # Create session
        connector = aiohttp.TCPConnector(
            limit=CONFIG['MAX_CONCURRENT'],
            limit_per_host=3,
            ttl_dns_cache=300,
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])
        ) as session:
            
            # 1. Initialize scanner với external data
            await scanner.initialize(session)
            
            # 2. Fetch domains
            print("[+] Fetching domains from external sources...")
            data_fetcher = CompleteDataFetcher(session)
            domains = await data_fetcher.fetch_domains_complete(CONFIG['DOMAIN_LIMIT'])
            
            if not domains:
                print("[-] No domains found!")
                return
            
            print(f"[+] Starting ULTIMATE scan for {len(domains)} domains...\n")
            print("[•] This will take time due to ULTIMATE feature checking")
            print("[•] Displaying only vulnerable sites\n")
            
            # 3. Scan từng domain với semaphore
            semaphore = Semaphore(CONFIG['MAX_CONCURRENT'])
            scanned = 0
            
            async def scan_domain_with_semaphore(domain: str):
                async with semaphore:
                    try:
                        result = await scanner.scan_domain_ultimate(domain, session)
                        await output_handler.write_result(result)
                        
                        nonlocal scanned
                        scanned += 1
                        
                        # Hiển thị progress
                        percent = (scanned / len(domains)) * 100
                        bar = '█' * int(percent/2) + '░' * (50 - int(percent/2))
                        
                        # Thông tin chi tiết
                        info = (
                            f"[{bar}] {percent:.1f}% | "
                            f"Scanned: {scanned}/{len(domains)} | "
                            f"WP: {output_handler.stats['wordpress']} | "
                            f"Vulns: {output_handler.stats['vulnerabilities']} | "
                            f"B: {output_handler.stats['behavioral_vulnerabilities']} | "
                            f"P: {output_handler.stats['plugin_vulnerabilities']}"
                        )
                        
                        sys.stdout.write(f"\r{info}")
                        sys.stdout.flush()
                        
                        # Hiển thị thông báo cho site có vuln
                        if result.get('vulnerabilities_found', 0) > 0:
                            critical_str = f" (🚨{result.get('critical_vulnerabilities', 0)} critical)" \
                                         if result.get('critical_vulnerabilities', 0) > 0 else ""
                            behavioral_str = f" (👁️{len(result.get('endpoint_vulnerabilities', []))} behavioral)" \
                                          if result.get('endpoint_vulnerabilities') else ""
                            print(f"\n\033[91m🚨 VULN: {domain} - {result['vulnerabilities_found']} vulnerabilities{critical_str}{behavioral_str}\033[0m")
                            
                    except Exception as e:
                        logger.debug(f"Error scanning {domain}: {e}")
            
            # Tạo tasks
            tasks = []
            for domain in domains:
                task = asyncio.create_task(scan_domain_with_semaphore(domain))
                tasks.append(task)
            
            # Chạy đồng thời
            await asyncio.gather(*tasks, return_exceptions=True)
            
            print(f"\n\n[✅] ULTIMATE scan finished!")
            print(f"[📊] Statistics: {output_handler.stats}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan stopped by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await output_handler.__aexit__(None, None, None)
        print(f"\n[📁] Ultimate results saved to: {output_file}")

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