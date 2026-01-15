#!/usr/bin/env python3
"""
WordPress/PHP Security Audit - Behavioral Observation Edition (2026)
Static Posture Assessment + Dynamic Server Response Observation
Language tuned for professional pentest reports
"""

import requests
import sys
import re
import json
import time
from urllib.parse import urljoin, quote, urlparse
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# ===============================
# BEHAVIORAL OBSERVATION MODELS
# ===============================
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
        
        for i in range(5):
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
                
                time.sleep(0.8)  # Conservative delay
                
            except Exception as e:
                observations.append({
                    'request': i+1,
                    'error': str(e)[:100],
                    'timeout': isinstance(e, requests.exceptions.Timeout)
                })
        
        # Analyze patterns (not conclusions)
        times = [obs.get('time', 0) for obs in observations if 'time' in obs]
        if len(times) >= 3:
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
            {
                'path': '/?s=' + 'a' * 200,
                'type': 'extended_search_query',
                'description': 'Extended length search parameter'
            }
        ]
        
        observations = []
        baseline_response = None
        
        # First get baseline normal response
        try:
            baseline = self.session.get(self.target, timeout=10)
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
                r = self.session.get(url, timeout=12, allow_redirects=False)
                
                # Compare with baseline
                length_deviation = None
                if baseline_response:
                    baseline_len = baseline_response['length']
                    current_len = len(r.text)
                    if baseline_len > 0:
                        length_deviation = round(abs(current_len - baseline_len) / baseline_len * 100, 1)
                
                # Content analysis (not exploitation)
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
                    'note': 'Server delayed response beyond 12-second threshold'
                })
            except Exception as e:
                observations.append({
                    'test_type': test['type'],
                    'description': test['description'],
                    'error': str(e)[:80]
                })
            
            time.sleep(1.2)  # Respectful delay
        
        return {
            'baseline_response': baseline_response,
            'test_observations': observations,
            'summary': self._summarize_error_behaviors(observations)
        }
    
    def _extract_observed_behaviors(self, response, content_analysis):
        """Extract behavioral observations without making vulnerability claims"""
        behaviors = []
        
        if response.status_code == 200:
            if content_analysis['contains_technical_errors']:
                behaviors.append('TECHNICAL_ERRORS_IN_RESPONSE')
            if content_analysis['contains_path_disclosure']:
                behaviors.append('PATH_INFO_IN_RESPONSE')
            if content_analysis['contains_database_references']:
                behaviors.append('DATABASE_REFERENCES_IN_RESPONSE')
            if content_analysis['is_default_fallback']:
                behaviors.append('DEFAULT_FALLBACK_RENDERING')
            if len(response.text) < 500:
                behaviors.append('MINIMAL_RESPONSE')
        
        elif response.status_code == 404:
            if len(response.text) > 5000:
                behaviors.append('VERBOSE_404_RESPONSE')
            if 'wp-' in response.text.lower():
                behaviors.append('WORDPRESS_SIGNATURE_IN_404')
        
        elif response.status_code == 403:
            behaviors.append('ACCESS_DENIED')
            if 'forbidden' in response.text.lower():
                behaviors.append('EXPLICIT_FORBIDDEN_MESSAGE')
        
        elif response.status_code >= 500:
            behaviors.append('SERVER_ERROR_RESPONSE')
            if 'error' in response.text.lower()[:200]:
                behaviors.append('ERROR_MESSAGE_PRESENT')
        
        return behaviors
    
    def _summarize_error_behaviors(self, observations):
        """Create behavioral summary without conclusions"""
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
            {'path': '/wp-admin/options-general.php', 'expected_protection': True, 'description': 'Settings'},
            {'path': '/wp-login.php', 'expected_protection': False, 'description': 'Login page'},
            {'path': '/wp-content/uploads/', 'expected_protection': False, 'description': 'Uploads directory'}
        ]
        
        observations = []
        
        for item in paths_to_observe:
            url = urljoin(self.target, item['path'])
            try:
                r = self.session.get(url, timeout=10, allow_redirects=True)
                
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
            
            time.sleep(1.0)
        
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




    def fingerprint_plugins_themes(self):
        """Passive + enhanced semi-active fingerprinting for plugins & themes
        - Passive: parse HTML for resource paths and generator meta
        - Semi-active: check readme.txt/style.css for detected slugs + brute top common plugins
        """
        observations = {
            'detected_cms': False,
            'wp_version': None,
            'plugins': [],
            'themes': [],
            'plugin_detection_sources': []  # Để theo dõi nguồn phát hiện (debug/report)
        }

        try:
            # Lấy trang chủ một lần
            r = self.session.get(self.target, timeout=10)
            if r.status_code != 200:
                return observations

            html = r.text
            html_lower = html.lower()

            # 1. Passive: Xác nhận là WordPress + version từ meta generator
            if any(x in html_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress']):
                observations['detected_cms'] = True

            generator_match = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)"', html, re.IGNORECASE)
            if generator_match:
                observations['wp_version'] = generator_match.group(1)

            # 2. Passive: Tìm slug plugin/theme từ các đường dẫn tài nguyên trong HTML
            plugin_paths = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
            theme_paths = set(re.findall(r'/wp-content/themes/([^/]+)/', html))

            # 3. Semi-active: Check chi tiết cho các slug đã phát hiện (passive)
            for slug in list(plugin_paths)[:12]:  # tăng nhẹ giới hạn
                self._check_plugin_readme(slug, observations, source="passive_resource_path")
            
            # 4. Semi-active: Check theme đã phát hiện
            for slug in list(theme_paths)[:6]:
                self._check_theme_style_css(slug, observations, source="passive_resource_path")

            # 5. ENHANCED: Brute-force nhẹ top common plugins (rất hiệu quả với site che giấu tốt)
            common_plugin_slugs = [
                'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo', 'akismet',
                'wpforms-lite', 'all-in-one-seo-pack', 'jetpack', 'wordfence', 
                'litespeed-cache', 'rank-math', 'wp-rocket', 'classic-editor',
                'wp-mail-smtp', 'updraftplus', 'monsterinsights-lite', 'smush',
                'autoptimize', 'redirection', 'wp-optimize', 'complianz-gdpr',
                'mailchimp-for-wp', 'ninja-forms', 'tablepress', 'better-search-replace',
                'duplicate-post', 'google-site-kit', 'really-simple-ssl'
            ]

            detected_slugs = {p['slug'] for p in observations['plugins']}  # Tránh check lại

            for slug in common_plugin_slugs:
                if slug in detected_slugs:
                    continue

                self._check_plugin_readme(slug, observations, source="common_list_brute")

                # Giới hạn tốc độ + tránh bị WAF chặn
                time.sleep(0.9 + (len(observations['plugins']) * 0.1))  # tăng dần delay nhẹ

            # 6. Optional: Check thêm một số file signature phổ biến khác (nếu cần)
            # self._check_extra_signatures(observations)

            return observations

        except Exception as e:
            return {'error': str(e)[:120]}


    def _check_plugin_readme(self, slug, observations, source="unknown"):
        """Helper: Check readme.txt của plugin và thêm vào observations nếu tồn tại"""
        url = urljoin(self.target, f'/wp-content/plugins/{slug}/readme.txt')
        try:
            # HEAD trước để tiết kiệm băng thông
            head_resp = self.session.head(url, timeout=5, allow_redirects=False)
            if head_resp.status_code != 200:
                return

            # GET để lấy nội dung version + name
            resp = self.session.get(url, timeout=7)
            if resp.status_code == 200:
                version_match = re.search(r'Stable tag:\s*([\d\.]+)', resp.text, re.IGNORECASE)
                name_match = re.search(r'Plugin Name:\s*(.+)', resp.text, re.IGNORECASE)

                plugin_info = {
                    'slug': slug,
                    'name': name_match.group(1).strip() if name_match else 'Unknown',
                    'version': version_match.group(1) if version_match else 'Unknown',
                    'evidence': 'readme.txt accessible',
                    'detection_source': source
                }
                observations['plugins'].append(plugin_info)
                observations['plugin_detection_sources'].append(f"{slug} ({source})")
                print(f"[+] Detected plugin: {slug} ({source})")  # debug console
        except:
            pass


    def _check_theme_style_css(self, slug, observations, source="unknown"):
        """Helper: Check style.css của theme"""
        url = urljoin(self.target, f'/wp-content/themes/{slug}/style.css')
        try:
            head_resp = self.session.head(url, timeout=5)
            if head_resp.status_code != 200:
                return

            resp = self.session.get(url, timeout=7)
            if resp.status_code == 200:
                version_match = re.search(r'Version:\s*([\d\.]+)', resp.text, re.IGNORECASE)
                name_match = re.search(r'Theme Name:\s*(.+)', resp.text, re.IGNORECASE)

                theme_info = {
                    'slug': slug,
                    'name': name_match.group(1).strip() if name_match else 'Unknown',
                    'version': version_match.group(1) if version_match else 'Unknown',
                    'evidence': 'style.css accessible',
                    'detection_source': source
                }
                observations['themes'].append(theme_info)
        except:
            pass


# ===============================
# PROFESSIONAL AUDIT ENGINE
# ===============================
class ProfessionalWPAudit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Professional Security Assessment)'
        })
        self.observer = ServerBehaviorObserver(target_url)
        
        self.observations = {
            'posture_indicators': [],
            'behavioral_patterns': [],
            'configuration_observations': []
        }
        self.static_indicators = {}
        self.behavioral_data = {}
        self.reality_context = []  # Context between static indicators and observed behavior
    
    def log(self, level, message, context=""):
        color_map = {
            'OBSERVATION': Fore.MAGENTA,
            'INDICATOR': Fore.YELLOW,
            'CONTEXT': Fore.CYAN,
            'BEHAVIOR': Fore.BLUE,
            'SUMMARY': Fore.GREEN,
            'NOTE': Fore.WHITE
        }
        print(f"{color_map.get(level, Fore.WHITE)}[{level}] {message}")
        if context:
            print(f"   {context}")
    
    # ================= STATIC INDICATORS =================
    def assess_static_indicators(self):
        """Collect static posture indicators"""
        self.log('INDICATOR', 'Collecting static posture indicators')
        
        # PHP version indicator
        try:
            r = self.session.get(self.target, timeout=12)
            if r and 'X-Powered-By' in r.headers:
                php_match = re.search(r'PHP/([\d\.]+)', r.headers['X-Powered-By'])
                if php_match:
                    version = php_match.group(1)
                    self.static_indicators['php_version'] = version
                    self.static_indicators['php_version_in_header'] = True
                    
                    indicator = {
                        'type': 'SERVER_SOFTWARE_DISCLOSURE',
                        'severity': 'MEDIUM',
                        'evidence': f'X-Powered-By: {r.headers["X-Powered-By"]}',
                        'context': 'PHP version disclosed in response headers',
                        'recommendation': 'Consider removing or customizing the X-Powered-By header'
                    }
                    
                    # Add version context
                    if version.startswith(('7.', '5.', '8.0', '8.1')):
                        indicator['additional_context'] = f'PHP {version} is EOL or approaching EOL'
                        indicator['severity'] = 'HIGH'
                    
                    self.observations['posture_indicators'].append(indicator)
        except:
            pass
        
        # Directory listing indicator
        try:
            uploads_url = urljoin(self.target, '/wp-content/uploads/')
            r = self.session.get(uploads_url, timeout=10)
            if r and r.status_code == 200:
                is_listing = 'Index of' in r.text or 'Parent Directory' in r.text
                if is_listing:
                    self.static_indicators['directory_listing_enabled'] = True
                    
                    self.observations['posture_indicators'].append({
                        'type': 'DIRECTORY_LISTING_ENABLED',
                        'severity': 'LOW_TO_MEDIUM',
                        'evidence': uploads_url,
                        'context': 'Directory listing enabled on /wp-content/uploads/',
                        'recommendation': 'Disable directory listing via server configuration'
                    })
        except:
            pass
        
        self.log('INDICATOR', f'Collected {len(self.observations["posture_indicators"])} static indicators')
    
    # ================= BEHAVIORAL OBSERVATION =================
    def observe_server_behaviors(self):
        """Observe dynamic server behaviors"""
        self.log('BEHAVIOR', 'Beginning behavioral observation phase')
        fp_data = self.observer.fingerprint_plugins_themes()
        self.behavioral_data['fingerprint'] = fp_data
        # 1. Rate handling observation
        self.log('OBSERVATION', 'Observing request rate handling patterns...')
        rate_data = self.observer.observe_rate_handling()
        self.behavioral_data['rate_handling'] = rate_data
        
        # Add behavioral observations
        pattern = rate_data['pattern_analysis']
        if not pattern['gradual_slowdown_observed']:
            self.observations['behavioral_patterns'].append({
                'type': 'CONSISTENT_RESPONSE_TIMES',
                'observation': 'Server maintained consistent response times under sequential requests',
                'data': f"Response times: {[round(t, 2) for t in [obs.get('time', 0) for obs in rate_data['sequential_requests'] if 'time' in obs]]}",
                'context': 'No rate-limiting behavior observed during light sequential probing'
            })
        
        # 2. Error response observation
        self.log('OBSERVATION', 'Observing error response patterns...')
        error_data = self.observer.observe_error_response_patterns()
        self.behavioral_data['error_responses'] = error_data
        
        # Analyze observations
        summary = error_data['summary']
        if summary['technical_errors_observed'] > 0:
            self.observations['behavioral_patterns'].append({
                'type': 'TECHNICAL_ERRORS_IN_RESPONSES',
                'observation': f"Server returned technical error details in {summary['technical_errors_observed']} test case(s)",
                'context': 'Error messages may contain debugging information',
                'severity_note': 'Information disclosure potential'
            })
        
        # 3. Authentication boundary observation
        self.log('OBSERVATION', 'Observing authentication boundary behaviors...')
        auth_data = self.observer.observe_authentication_boundaries()
        self.behavioral_data['auth_boundaries'] = auth_data
        
        # Analyze boundary observations
        analysis = auth_data['boundary_analysis']
        if analysis['admin_paths_without_redirect'] > 0:
            self.observations['behavioral_patterns'].append({
                'type': 'ADMIN_PATH_ACCESS_PATTERN',
                'observation': f"{analysis['admin_paths_without_redirect']} admin path(s) returned content without authentication redirect",
                'context': 'Direct access patterns observed - requires authentication verification',
                'note': 'May indicate misconfiguration or require session testing'
            })
        
        self.log('BEHAVIOR', f'Recorded {len(self.observations["behavioral_patterns"])} behavioral patterns')
    
    # ================= CONTEXTUAL ANALYSIS =================
    def analyze_observational_context(self):
        """Provide context between static indicators and observed behaviors"""
        self.log('CONTEXT', 'Analyzing observational context')
        
        # Example: PHP version + error handling context
        php_version = self.static_indicators.get('php_version')
        error_summary = self.behavioral_data.get('error_responses', {}).get('summary', {})
        
        if php_version and error_summary:
            context = {
                'static_indicator': f'PHP {php_version} disclosed in headers',
                'behavioral_observation': f"Technical errors observed: {error_summary.get('technical_errors_observed', 0)} cases",
                'contextual_interpretation': 'Version disclosure combined with error details may increase information available to attackers',
                'practical_consideration': 'While PHP version alone is a posture indicator, combined with error leakage it represents a clearer attack surface'
            }
            self.reality_context.append(context)
        
        # Directory listing + actual access context
        if self.static_indicators.get('directory_listing_enabled'):
            # Check if sensitive content is actually exposed
            sensitive_paths = ['/wp-config.php', '/.env', '/.htaccess']
            exposed = []
            
            for path in sensitive_paths:
                url = urljoin(self.target, path)
                try:
                    r = self.session.head(url, timeout=6)
                    if r.status_code == 200:
                        exposed.append(path)
                except:
                    pass
            
            context = {
                'static_indicator': 'Directory listing enabled',
                'behavioral_observation': f"Sensitive files directly accessible: {len(exposed)} of {len(sensitive_paths)} tested",
                'contextual_interpretation': 'Directory listing is a posture issue; actual exposure depends on file permissions and location',
                'practical_consideration': 'Risk level depends on what content is actually listable/accessible'
            }
            self.reality_context.append(context)
    
    # ================= PROFESSIONAL REPORT =================
    def generate_professional_report(self):
        """Generate professional assessment report"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print("   PROFESSIONAL WORDPRESS SECURITY ASSESSMENT")
        print(f"   Target: {self.target}")
        print(f"   Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        # Executive Summary
        print(f"{Fore.YELLOW}📋 EXECUTIVE SUMMARY")
        print(f"{'-'*40}")
        
        posture_count = len(self.observations['posture_indicators'])
        behavior_count = len(self.observations['behavioral_patterns'])
        
        print(f"Posture Indicators Collected: {posture_count}")
        print(f"Behavioral Patterns Observed: {behavior_count}")
        print(f"Contextual Analyses: {len(self.reality_context)}")
        print()
        
        # Posture Indicators (Static)
        if self.observations['posture_indicators']:
            print(f"{Fore.CYAN}🔍 POSTURE INDICATORS")
            print(f"{'-'*40}")
            
            for indicator in self.observations['posture_indicators']:
                sev = indicator.get('severity', 'UNKNOWN')
                color = Fore.RED if sev == 'HIGH' else Fore.YELLOW if sev == 'MEDIUM' else Fore.CYAN
                print(f"{color}• [{sev}] {indicator['type']}")
                print(f"  {Fore.WHITE}{indicator.get('context', '')}")
                if 'additional_context' in indicator:
                    print(f"  {Fore.CYAN}  Note: {indicator['additional_context']}")
                print()
        
        # Behavioral Observations
        if self.observations['behavioral_patterns']:
            print(f"{Fore.BLUE}🧪 BEHAVIORAL OBSERVATIONS")
            print(f"{'-'*40}")
            
            for pattern in self.observations['behavioral_patterns']:
                print(f"{Fore.BLUE}• {pattern['type']}")
                print(f"  {Fore.WHITE}Observation: {pattern['observation']}")
                print(f"  {Fore.CYAN}Context: {pattern.get('context', 'N/A')}")
                if 'note' in pattern:
                    print(f"  {Fore.YELLOW}Note: {pattern['note']}")
                print()
        
        # Contextual Analysis
        if self.reality_context:
            print(f"{Fore.MAGENTA}🎯 CONTEXTUAL ANALYSIS")
            print(f"{'-'*40}")
            
            for context in self.reality_context:
                print(f"{Fore.WHITE}• {context['static_indicator']}")
                print(f"  {Fore.CYAN}  Observed: {context['behavioral_observation']}")
                print(f"  {Fore.GREEN}  Interpretation: {context['contextual_interpretation']}")
                print(f"  {Fore.YELLOW}  Consideration: {context['practical_consideration']}")
                print()
        
        # Assessment Notes
        print(f"{Fore.GREEN}📝 ASSESSMENT NOTES")
        print(f"{'-'*40}")
        
        notes = [
            "• Assessment focused on observational patterns, not exploitation",
            "• Behavioral observations based on server responses to non-malicious inputs",
            "• Posture indicators represent configuration observations",
            "• Contextual analysis connects static indicators with observed behaviors",
            "• No authentication or session testing performed in this phase",
            "• No destructive or denial-of-service testing conducted"
        ]
        
        for note in notes:
            print(f"{Fore.WHITE}{note}")
        
        # Save comprehensive report
        report_data = {
            'target': self.target,
            'timestamp': datetime.utcnow().isoformat(),
            'assessment_scope': 'Observational security assessment - static indicators and behavioral patterns',
            'methodology': {
                'static_assessment': 'Collection of observable configuration and posture indicators',
                'behavioral_observation': 'Observation of server responses to non-malicious test inputs',
                'contextual_analysis': 'Correlation between static indicators and observed behaviors'
            },
            'static_indicators': self.static_indicators,
            'behavioral_data': self.behavioral_data,
            'observations': self.observations,
            'reality_context': self.reality_context,
            'summary': {
                'posture_indicators_count': posture_count,
                'behavioral_patterns_count': behavior_count,
                'contextual_analyses_count': len(self.reality_context)
            }
        }
        
        filename = f"wp_professional_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN}✅ Professional report saved to: {filename}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    def run_assessment(self):
        """Execute professional assessment"""
        try:
            self.log('SUMMARY', 'Starting Professional WordPress Security Assessment')
            self.assess_static_indicators()
            time.sleep(1.5)
            self.observe_server_behaviors()
            time.sleep(1.0)
            self.analyze_observational_context()
            self.generate_professional_report()
            self.log('SUMMARY', 'Assessment completed successfully')
        except Exception as e:
            self.log('NOTE', f'Assessment encountered issue: {str(e)[:100]}')
            import traceback
            traceback.print_exc()

# ===============================
# MAIN EXECUTION
# ===============================
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} https://example.com")
        print(f"\nNote: This tool performs observational assessment only.")
        print(f"      No exploitation, authentication testing, or DoS testing.")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = f'http://{target}'
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print("   PROFESSIONAL WORDPRESS OBSERVATIONAL ASSESSMENT")
    print("   Method: Static Indicators + Behavioral Patterns")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}Target: {target}")
    print(f"Start Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"Scope: Observational patterns and server behavior analysis")
    print(f"Note: This assessment does not attempt exploitation\n")
    
    audit = ProfessionalWPAudit(target)
    audit.run_assessment()

if __name__ == '__main__':
    main()