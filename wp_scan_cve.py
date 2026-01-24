#!/usr/bin/env python3
"""
WordPress/PHP Security Audit - Professional Edition (2026)
Advanced WordPress Version Detection + PHP Version Checking + WP API Analysis
Behavioral Observation + Static Posture Assessment
Multi-target support with comprehensive reporting
"""

import requests
import sys
import re
import json
import time
from urllib.parse import urljoin, quote, urlparse
from datetime import datetime
from colorama import init, Fore, Style
from pathlib import Path

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

    # ================= ENHANCED WORDPRESS VERSION DETECTION =================
    def detect_wordpress_version_advanced(self):
        """
        Advanced WordPress version detection using multiple methods
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
            # Method 1: Generator meta tag (most reliable)
            r = self.session.get(self.target, timeout=10)
            html = r.text
            
            # Check if it's WordPress
            if not any(x in html.lower() for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress']):
                return version_info
            
            version_info['detected'] = True
            
            all_versions = []  # Lưu tất cả version phát hiện được
            
            # Method 1A: Meta generator tag
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
            
            # Method 1B: RDF feed (older WP versions)
            rdf_match = re.search(
                r'<rdf:RDF.*xmlns:admin="http://webns.net/mvcb/".*<admin:generatorAgent.*rdf:resource="http://wordpress.org/\?v=([\d\.]+)"',
                html,
                re.IGNORECASE | re.DOTALL
            )
            if rdf_match:
                version = rdf_match.group(1)
                version_info['methods'].append('rdf_feed')
                version_info['evidence'].append(f'RDF feed: WordPress {version}')
                version_info['sources'].append('html_rdf')
                all_versions.append(('medium', version))
            
            # Method 2: Readme.html file
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
                        version_info['sources'].append('readme_html')
                        all_versions.append(('high', version))
                        
                        # Ưu tiên readme.html hơn nếu chưa có version
                        if not version_info['version']:
                            version_info['version'] = version
                            version_info['confidence'] = 'high'
            except:
                pass
            
            # Method 3: CSS/JS file versions
            version_patterns = [
                r'/wp-includes/js/jquery/jquery-migrate\.js\?ver=([\d\.]+)',
                r'/wp-includes/js/wp-embed\.min\.js\?ver=([\d\.]+)',
                r'/wp-includes/css/dist/block-library/style\.min\.css\?ver=([\d\.]+)',
                r'/wp-includes/js/jquery/jquery\.js\?ver=([\d\.]+)',
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, html)
                for match in matches[:2]:
                    if match and match.count('.') >= 1:
                        # Filter out jQuery versions
                        if not (match.startswith('1.') or match.startswith('2.') or match.startswith('3.')):
                            version_info['methods'].append('asset_version')
                            version_info['evidence'].append(f'Asset version: {match}')
                            version_info['sources'].append('html_assets')
                            all_versions.append(('medium', match))
                            
                            # Chỉ set nếu chưa có version
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
                        version_info['sources'].append('xml_feed')
                        all_versions.append(('medium', version))
                        
                        if not version_info['version']:
                            version_info['version'] = version
                            version_info['confidence'] = 'medium'
            except:
                pass
            
            # Method 5: wp-links-opml.php (CHỈ thêm evidence, KHÔNG set version)
            opml_url = urljoin(self.target, '/wp-links-opml.php')
            try:
                opml_resp = self.session.get(opml_url, timeout=5)
                if opml_resp.status_code == 200 and 'opml' in opml_resp.text.lower():
                    version_info['methods'].append('deprecated_file')
                    version_info['evidence'].append('wp-links-opml.php present (WordPress < 3.5)')
                    version_info['sources'].append('deprecated_file')
                    # KHÔNG set version ở đây, chỉ thêm evidence
            except:
                pass
            
            # Method 6: Login page version
            login_url = urljoin(self.target, '/wp-login.php')
            try:
                login_resp = self.session.get(login_url, timeout=5)
                login_match = re.search(
                    r'WordPress\s+([\d\.]+)',
                    login_resp.text,
                    re.IGNORECASE
                )
                if login_match:
                    version = login_match.group(1)
                    version_info['methods'].append('login_page')
                    version_info['evidence'].append(f'Login page: WordPress {version}')
                    version_info['sources'].append('login_page')
                    all_versions.append(('low', version))
                    
                    if not version_info['version']:
                        version_info['version'] = version
                        version_info['confidence'] = 'low'
            except:
                pass
            
            # Chọn version có độ tin cậy cao nhất từ all_versions
            if all_versions and not version_info['version']:
                # Ưu tiên: high > medium > low
                high_versions = [v for conf, v in all_versions if conf == 'high']
                if high_versions:
                    version_info['version'] = high_versions[0]
                    version_info['confidence'] = 'high'
                else:
                    medium_versions = [v for conf, v in all_versions if conf == 'medium']
                    if medium_versions:
                        version_info['version'] = medium_versions[0]
                        version_info['confidence'] = 'medium'
                    else:
                        low_versions = [v for conf, v in all_versions if conf == 'low']
                        if low_versions:
                            version_info['version'] = low_versions[0]
                            version_info['confidence'] = 'low'
            
            # Clean up version string
            if version_info['version']:
                version_info['version'] = re.sub(r'[^\d\.]', '', version_info['version'])
                if not re.match(r'^\d+(\.\d+)+$', version_info['version']):
                    version_info['version'] = None
                    version_info['confidence'] = 'unknown'
            
            return version_info
            
        except Exception as e:
            return version_info

    # ================= 1. CHECK ALL RESPONSES FOR PHP VERSION =================
    def check_all_responses_for_php_version(self):
        """Check X-Powered-By in all response headers"""
        php_versions = set()
        headers_data = []

        test_endpoints = [
            {'path': '/', 'name': 'Homepage'},
            {'path': '/wp-login.php', 'name': 'Login Page'},
            {'path': '/wp-admin/', 'name': 'Admin Dashboard'},
            {'path': '/wp-json/wp/v2/', 'name': 'REST API v2'},
            {'path': '/wp-content/uploads/', 'name': 'Uploads Directory'},
            {'path': '/index.php', 'name': 'Index PHP'}
        ]

        for endpoint in test_endpoints:
            try:
                url = urljoin(self.target, endpoint['path'])
                r = self.session.get(url, timeout=8, allow_redirects=True)
                
                php_version = None
                
                # Check X-Powered-By header
                if 'X-Powered-By' in r.headers:
                    php_match = re.search(r'PHP/([\d\.]+)', r.headers['X-Powered-By'], re.IGNORECASE)
                    if php_match:
                        php_version = php_match.group(1)
                        php_versions.add(php_version)
                
                # Also check Server header for PHP info
                if 'Server' in r.headers and php_version is None:
                    php_match = re.search(r'PHP/([\d\.]+)', r.headers['Server'], re.IGNORECASE)
                    if php_match:
                        php_version = php_match.group(1)
                        php_versions.add(php_version)
                
                headers_data.append({
                    'endpoint': endpoint['name'],
                    'url': url,
                    'status_code': r.status_code,
                    'headers': {
                        'X-Powered-By': r.headers.get('X-Powered-By'),
                        'Server': r.headers.get('Server')
                    },
                    'php_version': php_version
                })
                
                time.sleep(0.5)
            except Exception as e:
                continue

        php_versions_list = list(php_versions)
        consistency = 'HIGH' if len(php_versions_list) == 1 else 'LOW' if len(php_versions_list) > 1 else 'NONE'
        
        return {
            'php_versions_found': php_versions_list,
            'headers_data': headers_data,
            'consistent_across_endpoints': consistency,
            'primary_php_version': php_versions_list[0] if php_versions_list else None
        }

    # ================= 2. CHECK WP JSON API =================
    def check_wp_json_api(self):
        """Check WordPress REST API for version and info"""
        api_info = {
            'wp_api_available': False,
            'wp_version_via_api': None,
            'api_endpoints': [],
            'users_endpoint_status': None,
            'user_enumeration_possible': False,
            'api_details': {}
        }

        try:
            wp_json_url = urljoin(self.target, '/wp-json/')
            r = self.session.get(wp_json_url, timeout=10)
            if r.status_code == 200:
                api_info['wp_api_available'] = True
                try:
                    data = r.json()
                    if 'namespace' in data:
                        api_info['api_endpoints'] = list(data.get('namespaces', []))
                except:
                    pass
        except:
            pass

        try:
            wp_v2_url = urljoin(self.target, '/wp-json/wp/v2/')
            r = self.session.get(wp_v2_url, timeout=8)
            if r.status_code == 200:
                api_info['wp_version_via_api'] = 'v2_available'
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if 'version' in key.lower() and isinstance(value, str):
                                api_info['wp_version_via_api'] = value
                                break
                except:
                    pass
                
                users_url = urljoin(self.target, '/wp-json/wp/v2/users')
                r_users = self.session.get(users_url, timeout=6)
                api_info['users_endpoint_status'] = r_users.status_code
                if r_users.status_code == 200:
                    try:
                        users_data = r_users.json()
                        api_info['users_count'] = len(users_data) if isinstance(users_data, list) else 'unknown'
                        if isinstance(users_data, list) and len(users_data) > 0:
                            api_info['user_enumeration_possible'] = True
                            # Check what user data is exposed
                            sample_user = users_data[0]
                            exposed_fields = []
                            for field in ['id', 'name', 'slug', 'url', 'description']:
                                if field in sample_user and sample_user[field]:
                                    exposed_fields.append(field)
                            api_info['exposed_fields'] = exposed_fields
                    except:
                        pass
        except:
            pass

        return api_info

    # ================= 3. CHECK SPECIFIC PLUGIN VERSIONS =================
    def check_specific_plugin_versions(self):
        """Check specific plugins for detailed version info"""
        plugins_to_check = [
            {
                'slug': 'contact-form-7',
                'files': ['readme.txt', 'contact-form-7.php', 'style.css'],
                'description': 'Contact Form 7 - Popular form plugin'
            },
            {
                'slug': 'elementor',
                'files': ['readme.txt', 'elementor.php', 'elementor-pro.php'],
                'description': 'Elementor - Page builder'
            },
            {
                'slug': 'woocommerce',
                'files': ['readme.txt', 'woocommerce.php'],
                'description': 'WooCommerce - E-commerce'
            },
            {
                'slug': 'wp-file-manager',
                'files': ['readme.txt', 'file_manager.php'],
                'description': 'WP File Manager - File management'
            }
        ]

        plugin_details = []

        for plugin in plugins_to_check:
            plugin_data = {
                'slug': plugin['slug'],
                'description': plugin['description'],
                'detected': False,
                'found_files': [],
                'versions_detected': [],
                'detection_methods': []
            }
            
            for file in plugin['files']:
                file_url = urljoin(self.target, f'/wp-content/plugins/{plugin["slug"]}/{file}')
                try:
                    r = self.session.head(file_url, timeout=5, allow_redirects=False)
                    if r.status_code == 200:
                        plugin_data['found_files'].append(file)
                        if file.endswith(('.php', '.txt', '.css')):
                            r_content = self.session.get(file_url, timeout=7)
                            if r_content.status_code == 200:
                                version_patterns = [
                                    r'Version:\s*([\d\.]+)',
                                    r'Stable tag:\s*([\d\.]+)',
                                    r'v([\d\.]+)'
                                ]
                                for pattern in version_patterns:
                                    match = re.search(pattern, r_content.text, re.IGNORECASE)
                                    if match:
                                        version = match.group(1)
                                        if version not in plugin_data['versions_detected']:
                                            plugin_data['versions_detected'].append(version)
                                            plugin_data['detection_methods'].append(f'file:{file}')
                                        break
                                plugin_data['detected'] = True
                except:
                    continue
            
            # Check if directory exists
            if not plugin_data['detected']:
                plugin_dir_url = urljoin(self.target, f'/wp-content/plugins/{plugin["slug"]}/')
                try:
                    resp = self.session.head(plugin_dir_url, timeout=5, allow_redirects=False)
                    if resp.status_code in (200, 301, 302, 403):
                        plugin_data['detected'] = True
                        plugin_data['detection_methods'].append('directory_exists')
                except:
                    pass
            
            if plugin_data['detected']:
                plugin_details.append(plugin_data)

            time.sleep(0.7)
        
        # Add summary
        summary = {
            'plugins_searched': len(plugins_to_check),
            'plugins_found': len([p for p in plugin_details if p['detected']]),
            'versions_detected': len([p for p in plugin_details if p['versions_detected']]),
            'detection_rate': f"{(len([p for p in plugin_details if p['detected']]) / len(plugins_to_check) * 100):.1f}%" if plugins_to_check else '0%'
        }
        
        return {
            'plugins_checked': plugin_details,
            'summary': summary
        }

    # ================= ORIGINAL BEHAVIORAL METHODS =================
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
                    'request': i + 1,
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

                time.sleep(0.8)
            except Exception as e:
                observations.append({
                    'request': i + 1,
                    'error': str(e)[:100],
                    'timeout': isinstance(e, requests.exceptions.Timeout)
                })

        # Analyze patterns
        times = [obs.get('time', 0) for obs in observations if 'time' in obs]
        if len(times) >= 3:
            time_increase = all(times[i] <= times[i + 1] for i in range(len(times) - 1))
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
                    'note': 'Server delayed response beyond 12-second threshold'
                })
            except Exception as e:
                observations.append({
                    'test_type': test['type'],
                    'description': test['description'],
                    'error': str(e)[:80]
                })

            time.sleep(1.2)

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
        """Passive + enhanced semi-active fingerprinting for plugins & themes"""
        observations = {
            'detected_cms': False,
            'wp_version': None,
            'wp_version_info': {},  # NEW: Detailed version info
            'plugins': [],
            'themes': [],
            'plugin_detection_sources': []
        }

        try:
            r = self.session.get(self.target, timeout=10)
            if r.status_code != 200:
                return observations

            html = r.text
            html_lower = html.lower()

            # 1. Detect WordPress + version
            if any(x in html_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress']):
                observations['detected_cms'] = True

            # NEW: Advanced version detection
            version_info = self.detect_wordpress_version_advanced()
            observations['wp_version'] = version_info.get('version')
            observations['wp_version_info'] = version_info

            # 2. Passive resource paths
            plugin_paths = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
            theme_paths = set(re.findall(r'/wp-content/themes/([^/]+)/', html))

            # 3. Themes
            for slug in list(theme_paths)[:6]:
                self._check_theme_style_css(slug, observations, source="passive_resource_path")

            # 4. Plugins from HTML
            for slug in list(plugin_paths)[:12]:
                self._check_plugin_readme(slug, observations, source="passive_resource_path")
                self._check_plugin_main_file(slug, observations, source="passive_resource_path")
                self._infer_plugin_version_from_assets(slug, html, observations, source="passive_resource_path")

            existing = {p['slug'] for p in observations['plugins']}

            for slug in plugin_paths:
                if slug not in existing:
                    observations['plugins'].append({
                        'slug': slug,
                        'name': 'Unknown',
                        'version': None,
                        'evidence': 'resource path observed',
                        'detection_source': 'passive_resource_path',
                        'version_confidence': 'none'
                    })

            # 5. Brute common plugins
            common_plugin_slugs = [
                'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo', 'akismet',
                'wpforms-lite', 'all-in-one-seo-pack', 'jetpack', 'wordfence',
                'litespeed-cache', 'rank-math', 'wp-rocket', 'classic-editor',
                'wp-mail-smtp', 'updraftplus', 'monsterinsights-lite', 'smush',
                'autoptimize', 'redirection', 'wp-optimize', 'complianz-gdpr',
                'mailchimp-for-wp', 'ninja-forms', 'tablepress', 'better-search-replace',
                'duplicate-post', 'google-site-kit', 'really-simple-ssl'
            ]

            detected_slugs = {p['slug'] for p in observations['plugins']}

            for slug in common_plugin_slugs:
                if slug in detected_slugs:
                    continue

                self._check_plugin_readme(slug, observations, source="common_list_brute")
                self._check_plugin_main_file(slug, observations, source="common_list_brute")
                self._infer_plugin_version_from_assets(slug, html, observations, source="common_list_brute")

                # Check if plugin directory exists
                if slug not in {p['slug'] for p in observations['plugins']}:
                    plugin_dir = urljoin(self.target, f'/wp-content/plugins/{slug}/')
                    resp = self.session.head(
                        plugin_dir, timeout=5, allow_redirects=False
                    )
                    if resp.status_code in (200, 403):
                        self._upsert_plugin(
                            observations,
                            {
                                'slug': slug,
                                'name': 'Unknown',
                                'version': 'Unknown',
                                'evidence': 'plugin directory exists',
                                'detection_source': 'directory_existence'
                            }
                        )

                time.sleep(0.9 + (len(observations['plugins']) * 0.1))
            return observations
        except Exception as e:
            return {'error': str(e)[:120]}

    def _check_plugin_readme(self, slug, observations, source="unknown"):
        """Helper: Check readme.txt of plugin and add to observations if exists"""
        url = urljoin(self.target, f'/wp-content/plugins/{slug}/readme.txt')
        try:
            head_resp = self.session.head(url, timeout=5, allow_redirects=False)
            if head_resp.status_code != 200:
                return
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
                self._upsert_plugin(observations, plugin_info)
                observations['plugin_detection_sources'].append(f"{slug} ({source})")
        except:
            pass

    def _upsert_plugin(self, observations, plugin_info):
        """Update plugin if slug exists and version is Unknown, else append"""
        for p in observations['plugins']:
            if p['slug'] == plugin_info['slug']:
                if p.get('version') in [None, 'Unknown']:
                    p.update(plugin_info)
                return
        observations['plugins'].append(plugin_info)

    def _infer_plugin_version_from_assets(self, slug, html, observations, source="asset_query_string"):
        """Infer plugin version from ?ver= in JS/CSS assets"""
        pattern = rf'/wp-content/plugins/{slug}/[^"\']+\?ver=([\d\.]+)'
        matches = re.findall(pattern, html)
        if matches:
            version = max(matches, key=len)
            plugin_info = {
                'slug': slug,
                'name': 'Unknown',
                'version': version,
                'version_confidence': 'low',
                'evidence': '?ver query string in assets',
                'detection_source': source
            }
            self._upsert_plugin(observations, plugin_info)
            observations['plugin_detection_sources'].append(f"{slug} ({source})")

    def _check_plugin_main_file(self, slug, observations, source="plugin_main_file"):
        """Heuristic plugin version detection via main plugin PHP file"""
        url = urljoin(self.target, f'/wp-content/plugins/{slug}/{slug}.php')
        try:
            r = self.session.get(url, timeout=6)
            if r.status_code != 200 or len(r.text) > 120000:
                return
            version_match = re.search(r'Version:\s*([\d\.]+)', r.text, re.IGNORECASE)
            name_match = re.search(r'Plugin Name:\s*(.+)', r.text, re.IGNORECASE)
            if version_match:
                plugin_info = {
                    'slug': slug,
                    'name': name_match.group(1).strip() if name_match else 'Unknown',
                    'version': version_match.group(1),
                    'version_confidence': 'medium',
                    'evidence': f'{slug}.php header',
                    'detection_source': source
                }
                self._upsert_plugin(observations, plugin_info)
                observations['plugin_detection_sources'].append(f"{slug} ({source})")
        except:
            pass

    def _check_theme_style_css(self, slug, observations, source="unknown"):
        """Helper: Check style.css of theme"""
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
        self.reality_context = []

    def log(self, level, message, context=""):
        color_map = {
            'OBSERVATION': Fore.MAGENTA,
            'INDICATOR': Fore.YELLOW,
            'CONTEXT': Fore.CYAN,
            'BEHAVIOR': Fore.BLUE,
            'SUMMARY': Fore.GREEN,
            'NOTE': Fore.WHITE,
            'VERSION': Fore.CYAN,
            'PHP': Fore.MAGENTA,
            'API': Fore.BLUE,
            'PLUGIN': Fore.CYAN
        }
        print(f"{color_map.get(level, Fore.WHITE)}[{level}] {message}")
        if context:
            print(f"   {context}")

    # ================= WORDPRESS VERSION ANALYSIS =================
    def analyze_wordpress_version(self):
        """Analyze WordPress version for security implications"""
        self.log('VERSION', 'Analyzing WordPress version security implications...')
        
        version_info = self.behavioral_data.get('fingerprint', {}).get('wp_version_info', {})
        wp_version = version_info.get('version')
        
        if not wp_version:
            self.log('VERSION', 'WordPress version not detected or could not be determined')
            return
        
        # Add version as static indicator
        self.static_indicators['wordpress_version'] = wp_version
        self.static_indicators['version_confidence'] = version_info.get('confidence', 'unknown')
        self.static_indicators['version_detection_methods'] = version_info.get('methods', [])
        
        # Security implications analysis
        security_notes = []
        severity = 'LOW'
        
        try:
            # Parse version
            parts = wp_version.split('.')
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            
            # EOL versions check (as of 2026)
            eol_versions = [
                ('3.', 'CRITICAL'),  # WordPress 3.x series
                ('4.0', 'CRITICAL'), ('4.1', 'CRITICAL'), ('4.2', 'CRITICAL'),
                ('4.3', 'CRITICAL'), ('4.4', 'CRITICAL'), ('4.5', 'CRITICAL'),
                ('4.6', 'CRITICAL'), ('4.7', 'CRITICAL'), ('4.8', 'CRITICAL'),
                ('4.9', 'CRITICAL'), ('5.0', 'HIGH'), ('5.1', 'HIGH'),
                ('5.2', 'HIGH'), ('5.3', 'HIGH'), ('5.4', 'HIGH'),
                ('5.5', 'HIGH'), ('5.6', 'HIGH'), ('5.7', 'HIGH'),
                ('5.8', 'MEDIUM'), ('5.9', 'MEDIUM'), ('6.0', 'MEDIUM'),
                ('6.1', 'MEDIUM'), ('6.2', 'MEDIUM'), ('6.3', 'MEDIUM')
            ]
            
            for eol_ver, eol_severity in eol_versions:
                if wp_version.startswith(eol_ver):
                    security_notes.append({
                        'severity': eol_severity,
                        'note': f'WordPress {wp_version} is outdated and may have known vulnerabilities',
                        'recommendation': f'Upgrade to latest WordPress version immediately'
                    })
                    severity = eol_severity
                    break
            
            # Check if it's the latest major version
            if major < 6:
                if not security_notes:  # Only add if not already flagged
                    security_notes.append({
                        'severity': 'MEDIUM',
                        'note': f'WordPress {wp_version} is not the latest major version (6.x+)',
                        'recommendation': 'Consider upgrading to WordPress 6.x or later'
                    })
                    severity = 'MEDIUM'
            
            # Check for very old versions
            if major < 4:
                security_notes.append({
                    'severity': 'CRITICAL',
                    'note': f'WordPress {wp_version} is extremely outdated and unsupported',
                    'recommendation': 'Immediate upgrade required - significant security risks'
                })
                severity = 'CRITICAL'
                
        except Exception as e:
            self.log('NOTE', f'Version analysis error: {e}')
        
        # Add to observations
        version_indicator = {
            'type': 'WORDPRESS_VERSION_DISCLOSED',
            'severity': severity,
            'evidence': f'WordPress {wp_version} detected',
            'context': f'Confidence: {version_info.get("confidence", "unknown")}. Methods: {", ".join(version_info.get("methods", []))}',
            'version_details': version_info,
            'security_notes': security_notes,
            'recommendation': 'Keep WordPress updated to latest version for security patches'
        }
        
        self.observations['posture_indicators'].append(version_indicator)
        
        # Log findings
        if version_info.get('evidence'):
            for evidence in version_info['evidence'][:3]:  # Show top 3 evidences
                self.log('VERSION', f'  {evidence}')
        
        for note in security_notes:
            color = Fore.RED if note['severity'] == 'CRITICAL' else Fore.YELLOW if note['severity'] == 'HIGH' else Fore.WHITE
            self.log('VERSION', f'{color}  {note["severity"]}: {note["note"]}')

    # ================= STATIC INDICATORS =================
    def assess_static_indicators(self):
        """Collect static posture indicators"""
        self.log('INDICATOR', 'Collecting static posture indicators')

        # 1. Check PHP version in all responses (NEW ENHANCEMENT)
        self.log('PHP', 'Checking X-Powered-By headers across multiple endpoints...')
        php_check_data = self.observer.check_all_responses_for_php_version()
        self.behavioral_data['php_headers_scan'] = php_check_data

        php_versions = php_check_data.get('php_versions_found', [])
        if php_versions:
            version_str = ', '.join(php_versions)
            self.static_indicators['php_version'] = php_check_data.get('primary_php_version')
            self.static_indicators['php_versions_found'] = php_versions
            self.static_indicators['php_headers_consistent'] = php_check_data.get('consistent_across_endpoints')

            # Add observation
            indicator = {
                'type': 'PHP_VERSION_DISCLOSURE',
                'severity': 'MEDIUM',
                'evidence': f'PHP version(s) found in headers: {version_str}',
                'context': f'PHP version disclosure across {len(php_check_data.get("headers_data", []))} endpoint(s). Consistency: {php_check_data.get("consistent_across_endpoints")}',
                'recommendation': 'Consider removing or customizing the X-Powered-By header',
                'data': php_check_data['headers_data']
            }
            # Check for outdated PHP versions
            for version in php_versions:
                if version.startswith(('5.', '7.', '8.0', '8.1')):
                    indicator['severity'] = 'HIGH'
                    indicator['additional_context'] = f'PHP {version} is EOL or approaching EOL'
                    break
            self.observations['posture_indicators'].append(indicator)

        # 2. Check WordPress REST API (NEW ENHANCEMENT)
        self.log('API', 'Checking WordPress REST API endpoints...')
        wp_api_data = self.observer.check_wp_json_api()
        self.behavioral_data['wp_api_scan'] = wp_api_data

        if wp_api_data.get('wp_api_available'):
            self.static_indicators['wp_rest_api_enabled'] = True
            self.static_indicators['wp_api_version'] = wp_api_data.get('wp_version_via_api', 'unknown')
            self.static_indicators['user_enumeration_possible'] = wp_api_data.get('user_enumeration_possible', False)
            
            if wp_api_data.get('users_endpoint_status') == 200:
                indicator = {
                    'type': 'WORDPRESS_API_USER_ENUMERATION',
                    'severity': 'LOW',
                    'evidence': '/wp-json/wp/v2/users endpoint accessible',
                    'context': 'WordPress REST API users endpoint may allow user enumeration',
                    'recommendation': 'Consider restricting API access or disabling user enumeration',
                    'data': {
                        'users_count': wp_api_data.get('users_count', 'unknown'),
                        'status_code': wp_api_data.get('users_endpoint_status'),
                        'exposed_fields': wp_api_data.get('exposed_fields', [])
                    }
                }
                
                if wp_api_data.get('user_enumeration_possible'):
                    indicator['severity'] = 'MEDIUM'
                    indicator['additional_context'] = 'User enumeration via REST API is possible'
                
                self.observations['posture_indicators'].append(indicator)

        # 3. Check specific plugin versions (NEW ENHANCEMENT)
        self.log('PLUGIN', 'Checking specific plugin versions...')
        plugin_details = self.observer.check_specific_plugin_versions()
        self.behavioral_data['plugin_version_scan'] = plugin_details

        for plugin_data in plugin_details.get('plugins_checked', []):
            if plugin_data.get('detected'):
                versions = plugin_data.get('versions_detected', [])
                if versions:
                    indicator = {
                        'type': 'PLUGIN_VERSION_DETECTION',
                        'severity': 'INFO',
                        'evidence': f"Plugin {plugin_data['slug']} version(s): {', '.join(versions)}",
                        'context': plugin_data.get('description', ''),
                        'data': {
                            'slug': plugin_data['slug'],
                            'versions': versions,
                            'files_found': plugin_data.get('found_files', []),
                            'detection_methods': plugin_data.get('detection_methods', [])
                        }
                    }
                    
                    # Critical plugins check
                    if plugin_data['slug'] == 'wp-file-manager':
                        indicator['severity'] = 'HIGH'
                        indicator['additional_context'] = 'WP File Manager has known vulnerabilities - ensure updated'
                    
                    self.observations['posture_indicators'].append(indicator)
        
        # Add summary for plugin checking
        if plugin_details.get('summary'):
            summary = plugin_details['summary']
            self.log('PLUGIN', f"Plugins searched: {summary.get('plugins_searched', 0)}")
            self.log('PLUGIN', f"Plugins found: {summary.get('plugins_found', 0)}")
            self.log('PLUGIN', f"Detection rate: {summary.get('detection_rate', '0%')}")

        # 4. Directory listing indicator (ORIGINAL)
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

        # 0. Plugin and theme fingerprinting
        fp_data = self.observer.fingerprint_plugins_themes()
        self.behavioral_data['fingerprint'] = fp_data

        # NEW: WordPress version analysis
        self.analyze_wordpress_version()

        # Log detected plugins and themes
        if fp_data.get('plugins'):
            self.log('OBSERVATION', f"Detected {len(fp_data['plugins'])} plugins")
            for plugin in fp_data['plugins'][:10]:
                if plugin.get('version') and plugin.get('version') != 'Unknown':
                    self.log('CONTEXT', f"  {plugin['slug']} v{plugin['version']}")

        if fp_data.get('themes'):
            self.log('OBSERVATION', f"Detected {len(fp_data['themes'])} themes")
            for theme in fp_data['themes'][:5]:
                if theme.get('version') and theme.get('version') != 'Unknown':
                    self.log('CONTEXT', f"  {theme['slug']} v{theme['version']}")

        # 1. Rate handling observation
        self.log('OBSERVATION', 'Observing request rate handling patterns...')
        rate_data = self.observer.observe_rate_handling()
        self.behavioral_data['rate_handling'] = rate_data

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

        # Example 1: PHP version + error handling context
        php_version = self.static_indicators.get('php_version')
        error_summary = self.behavioral_data.get('error_responses', {}).get('summary', {})

        if php_version and error_summary:
            context = {
                'static_indicator': f'PHP {php_version} disclosed in headers',
                'behavioral_observation': f"Technical errors observed: {error_summary.get('technical_errors_observed', 0)} cases",
                'contextual_interpretation': 'Version disclosure combined with error leakage may increase information available to attackers',
                'practical_consideration': 'While PHP version alone is a posture indicator, combined with error leakage it represents a clearer attack surface'
            }
            self.reality_context.append(context)

        # Example 2: WordPress version + PHP version context
        wp_version = self.static_indicators.get('wordpress_version')
        if php_version and wp_version:
            context = {
                'static_indicator': f'PHP {php_version} + WordPress {wp_version}',
                'behavioral_observation': 'Software stack version disclosure',
                'contextual_interpretation': 'Attackers can target known vulnerabilities in specific version combinations',
                'practical_consideration': 'Consider version obscuration and regular updates'
            }
            self.reality_context.append(context)

        # Example 3: WordPress API + user enumeration context
        wp_api_data = self.behavioral_data.get('wp_api_scan', {})
        if wp_api_data.get('user_enumeration_possible'):
            context = {
                'static_indicator': 'WordPress REST API enabled',
                'behavioral_observation': f"Users endpoint accessible with status {wp_api_data.get('users_endpoint_status')}",
                'contextual_interpretation': 'API accessibility may facilitate reconnaissance',
                'practical_consideration': 'Consider if user enumeration via API aligns with security requirements'
            }
            self.reality_context.append(context)

        # Example 4: Plugin versions + directory listing context
        plugin_scan = self.behavioral_data.get('plugin_version_scan', {})
        if plugin_scan.get('plugins_checked') and self.static_indicators.get('directory_listing_enabled'):
            vulnerable_plugins = []
            for plugin in plugin_scan.get('plugins_checked', []):
                if plugin.get('detected') and plugin.get('slug') in ['wp-file-manager']:
                    versions = plugin.get('versions_detected', [])
                    if versions:
                        vulnerable_plugins.append(f"{plugin['slug']} ({versions[0]})")
            if vulnerable_plugins:
                context = {
                    'static_indicator': 'Directory listing enabled on uploads',
                    'behavioral_observation': f"Plugin versions detected: {', '.join(vulnerable_plugins)}",
                    'contextual_interpretation': 'Directory access combined with known plugin versions may increase risk',
                    'practical_consideration': 'Attackers can correlate plugin versions with known vulnerabilities'
                }
                self.reality_context.append(context)

        # Example 5: PHP version consistency across endpoints
        php_scan = self.behavioral_data.get('php_headers_scan', {})
        if php_scan.get('consistent_across_endpoints') is False:
            context = {
                'static_indicator': 'PHP version disclosure',
                'behavioral_observation': 'PHP version headers inconsistent across endpoints',
                'contextual_interpretation': 'Inconsistent headers may indicate load balancers or different server configurations',
                'practical_consideration': 'Inconsistent infrastructure may have varied security postures'
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

        # WordPress Version Summary
        wp_version = self.static_indicators.get('wordpress_version')
        if wp_version:
            version_info = self.behavioral_data.get('fingerprint', {}).get('wp_version_info', {})
            confidence = version_info.get('confidence', 'unknown').upper()
            methods = version_info.get('methods', [])
            
            print(f"{Fore.YELLOW}🔄 WORDPRESS VERSION DETECTION")
            print(f"{'-'*40}")
            print(f"{Fore.WHITE}Version: {Fore.CYAN}{wp_version}")
            print(f"{Fore.WHITE}Confidence: {Fore.CYAN}{confidence}")
            
            if methods:
                print(f"{Fore.WHITE}Detection Methods: {Fore.CYAN}{', '.join(methods)}")
            
            # Show security implications
            for indicator in self.observations['posture_indicators']:
                if indicator.get('type') == 'WORDPRESS_VERSION_DISCLOSED' and indicator.get('security_notes'):
                    print(f"\n{Fore.WHITE}Security Implications:")
                    for note in indicator['security_notes']:
                        color = Fore.RED if note['severity'] == 'CRITICAL' else Fore.YELLOW if note['severity'] == 'HIGH' else Fore.WHITE
                        print(f"{color}  ⚠ {note['severity']}: {note['note']}")
                    break
            
            print()

        # PHP Version Summary
        php_version = self.static_indicators.get('php_version')
        if php_version:
            php_versions = self.static_indicators.get('php_versions_found', [])
            consistency = self.static_indicators.get('php_headers_consistent', 'N/A')
            
            print(f"{Fore.MAGENTA}🐘 PHP VERSION DETECTION")
            print(f"{'-'*40}")
            print(f"{Fore.WHITE}Primary Version: {Fore.CYAN}{php_version}")
            if len(php_versions) > 1:
                print(f"{Fore.WHITE}All Versions Found: {Fore.CYAN}{', '.join(php_versions)}")
            print(f"{Fore.WHITE}Consistency: {Fore.CYAN}{consistency}")
            
            # Check for old PHP versions
            if php_version.startswith(('5.', '7.0', '7.1', '7.2', '7.3')):
                print(f"{Fore.RED}  ⚠ WARNING: PHP {php_version} is EOL or approaching EOL - security risk")
            
            print()

        # WordPress API Summary
        if self.static_indicators.get('wp_rest_api_enabled'):
            api_version = self.static_indicators.get('wp_api_version')
            user_enum = self.static_indicators.get('user_enumeration_possible', False)
            
            print(f"{Fore.BLUE}🔌 WORDPRESS REST API")
            print(f"{'-'*40}")
            print(f"{Fore.WHITE}Status: {Fore.GREEN}Detected")
            if api_version and api_version != 'unknown':
                print(f"{Fore.WHITE}API Version: {Fore.CYAN}{api_version}")
            print(f"{Fore.WHITE}User Enumeration: {Fore.YELLOW if user_enum else Fore.GREEN}{'Possible' if user_enum else 'Not detected'}")
            if user_enum:
                print(f"{Fore.YELLOW}  ⚠ NOTE: User information may be exposed via API")
            print()

        # Specific Plugin Versions Summary
        plugin_scan = self.behavioral_data.get('plugin_version_scan', {})
        if plugin_scan.get('plugins_checked'):
            detected_plugins = [p for p in plugin_scan['plugins_checked'] if p.get('detected')]
            
            if detected_plugins:
                print(f"{Fore.CYAN}🧩 SPECIFIC PLUGIN VERSIONS")
                print(f"{'-'*40}")
                
                for plugin in detected_plugins:
                    plugin_name = plugin.get('description', plugin.get('slug'))
                    versions = plugin.get('versions_detected', [])
                    
                    if versions:
                        version_display = f"v{versions[0]}" if versions[0] != 'unknown' else "version unknown"
                    else:
                        version_display = "detected (version unknown)"
                    
                    print(f"{Fore.WHITE}• {plugin_name}: {Fore.CYAN}{version_display}")
                    
                    # Highlight critical plugins
                    if plugin.get('slug') == 'wp-file-manager':
                        print(f"{Fore.RED}    ⚠ CRITICAL: WP File Manager has known vulnerabilities")
                
                print()

        # Executive Summary
        print(f"{Fore.YELLOW}📋 EXECUTIVE SUMMARY")
        print(f"{'-'*40}")

        posture_count = len(self.observations['posture_indicators'])
        behavior_count = len(self.observations['behavioral_patterns'])

        print(f"WordPress Version: {wp_version or 'Not detected'}")
        print(f"PHP Version: {php_version or 'Not detected'}")
        print(f"WordPress API: {'Detected' if self.static_indicators.get('wp_rest_api_enabled') else 'Not detected'}")
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
                color = Fore.RED if sev == 'HIGH' or sev == 'CRITICAL' else Fore.YELLOW if sev == 'MEDIUM' else Fore.CYAN
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

        # Plugin & Theme Details
        fp_data = self.behavioral_data.get('fingerprint', {})
        if fp_data.get('plugins') or fp_data.get('themes'):
            print(f"{Fore.GREEN}🔧 DETECTED COMPONENTS")
            print(f"{'-'*40}")
            if fp_data.get('plugins'):
                print(f"{Fore.CYAN}Plugins ({len(fp_data['plugins'])}):")
                for plugin in fp_data['plugins'][:15]:
                    version_display = f"v{plugin.get('version')}" if plugin.get('version') and plugin.get('version') != 'Unknown' else "version unknown"
                    print(f"  {Fore.WHITE}• {plugin['slug']} - {version_display}")
                if len(fp_data['plugins']) > 15:
                    print(f"  {Fore.CYAN}... and {len(fp_data['plugins']) - 15} more")
                print()

            if fp_data.get('themes'):
                print(f"{Fore.CYAN}Themes ({len(fp_data['themes'])}):")
                for theme in fp_data['themes'][:10]:
                    version_display = f"v{theme.get('version')}" if theme.get('version') and theme.get('version') != 'Unknown' else "version unknown"
                    print(f"  {Fore.WHITE}• {theme['slug']} - {version_display}")
                print()

        # Assessment Notes
        print(f"{Fore.GREEN}📝 ASSESSMENT NOTES")
        print(f"{'-'*40}")
        notes = [
            "• Assessment focused on observational patterns, not exploitation",
            "• Behavioral observations based on server responses to non-malicious inputs",
            "• Posture indicators represent configuration observations",
            "• Contextual analysis connects static indicators with observed behaviors",
            "• WordPress version detection uses 7 different methods",
            "• PHP version checked across 6 different endpoints",
            "• Specific plugin versions checked: contact-form-7, elementor, woocommerce, wp-file-manager",
            "• WordPress REST API analyzed for user enumeration possibilities",
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
                'contextual_analysis': 'Correlation between static indicators and observed behaviors',
                'enhanced_checks': [
                    'Advanced WordPress version detection (7 methods)',
                    'X-Powered-By header analysis across multiple endpoints',
                    'WordPress REST API verification and user enumeration check',
                    'Specific plugin version detection (4 plugins)'
                ]
            },
            'static_indicators': self.static_indicators,
            'behavioral_data': self.behavioral_data,
            'observations': self.observations,
            'reality_context': self.reality_context,
            'summary': {
                'wordpress_version': wp_version,
                'php_version': php_version,
                'wp_api_detected': self.static_indicators.get('wp_rest_api_enabled'),
                'posture_indicators_count': posture_count,
                'behavioral_patterns_count': behavior_count,
                'contextual_analyses_count': len(self.reality_context),
                'plugins_detected': len(fp_data.get('plugins', [])),
                'themes_detected': len(fp_data.get('themes', []))
            }
        }
        
        # Create output directory
        output_dir = Path("wp_assessment_results")
        output_dir.mkdir(exist_ok=True)
        
        # Create target-specific directory (clean target name)
        target_name = self.target.replace("://", "_").replace("/", "_").replace(":", "_").replace(".", "_")
        if target_name.endswith("_"):
            target_name = target_name[:-1]
        
        target_dir = output_dir / target_name
        target_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_filename = target_dir / "assessment.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Also save a text summary
        txt_filename = target_dir / "summary.txt"
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(f"WordPress Security Assessment - {self.target}\n")
            f.write(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            f.write(f"WordPress Version: {wp_version or 'Not detected'}\n")
            f.write(f"PHP Version: {php_version or 'Not detected'}\n")
            f.write(f"WordPress API: {'Detected' if self.static_indicators.get('wp_rest_api_enabled') else 'Not detected'}\n")
            f.write(f"Posture Indicators: {posture_count}\n")
            f.write(f"Behavioral Patterns: {behavior_count}\n")
            f.write(f"Contextual Analyses: {len(self.reality_context)}\n\n")
            
            if wp_version and 'security_notes' in report_data.get('observations', {}):
                for indicator in report_data['observations']['posture_indicators']:
                    if indicator.get('type') == 'WORDPRESS_VERSION_DISCLOSED' and indicator.get('security_notes'):
                        f.write("Security Implications:\n")
                        for note in indicator['security_notes']:
                            f.write(f"  {note['severity']}: {note['note']}\n")
                        break
            
            if php_version and php_version.startswith(('5.', '7.0', '7.1', '7.2', '7.3')):
                f.write(f"\nPHP Security Note:\n")
                f.write(f"  WARNING: PHP {php_version} is EOL or approaching EOL - security risk\n")
        
        print(f"\n{Fore.GREEN}✅ Professional reports saved to:")
        print(f"   JSON: {json_filename}")
        print(f"   Text: {txt_filename}")
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


# ================================
# MAIN EXECUTION
# ================================

def main():
    # Check for targets.txt file or command line argument
    import os
    
    if len(sys.argv) == 2:
        # Single target from command line
        target = sys.argv[1]
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print("   PROFESSIONAL WORDPRESS OBSERVATIONAL ASSESSMENT")
        print("   Method: Static Indicators + Behavioral Patterns")
        print("   Enhanced with Advanced WordPress Version Detection")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Target: {target}")
        print(f"Start Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Scope: Observational patterns and server behavior analysis")
        print(f"Enhanced Checks: PHP headers, WordPress API, plugin versions")
        print(f"Note: This assessment does not attempt exploitation\n")
        
        audit = ProfessionalWPAudit(target)
        audit.run_assessment()
        
    else:
        # Multi-target from targets.txt
        targets_file = "targets.txt"
        
        if not os.path.exists(targets_file):
            print(f"{Fore.RED}Error: File '{targets_file}' not found.")
            print(f"Please create {targets_file} with one target URL per line.")
            print(f"Or use: {sys.argv[0]} <single_target_url>")
            sys.exit(1)
        
        try:
            with open(targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Fore.RED}Error reading targets.txt: {e}")
            sys.exit(1)
        
        if not targets:
            print(f"{Fore.RED}Error: No targets found in '{targets_file}'")
            sys.exit(1)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print("   PROFESSIONAL WORDPRESS OBSERVATIONAL ASSESSMENT")
        print("   Enhanced with Advanced WordPress Version Detection")
        print("   PHP Version Checking + WP API Analysis + Plugin Version Detection")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Targets file: {targets_file}")
        print(f"Number of targets: {len(targets)}")
        print(f"Start Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Scope: WordPress version detection + observational analysis")
        print(f"Version Detection Methods: 7 different techniques")
        print(f"PHP Checking: Across 6 endpoints")
        print(f"Plugin Checking: 4 specific plugins")
        print(f"Note: This assessment does not attempt exploitation\n")
        
        # Process each target
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.YELLOW}🔍 Processing target {i}/{len(targets)}: {target}")
            print(f"{'-'*60}")
            
            # Add scheme if missing
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            try:
                audit = ProfessionalWPAudit(target)
                audit.run_assessment()
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}⚠ Assessment interrupted by user.")
                sys.exit(1)
            except Exception as e:
                print(f"{Fore.RED}❌ Error processing {target}: {str(e)[:100]}")
                import traceback
                traceback.print_exc()
                print()
                continue
            
            # Add delay between targets (except last one)
            if i < len(targets):
                print(f"{Fore.CYAN}⏳ Waiting 2 seconds before next target...")
                time.sleep(2)
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"✅ All {len(targets)} targets processed successfully!")
        print(f"{'='*60}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()