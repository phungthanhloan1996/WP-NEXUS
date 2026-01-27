#!/usr/bin/env python3
"""
WORDPRESS ATTACK SURFACE ENGINE (WASE) v2.0 - Complete 9-Phase Pipeline
Phase 0-9 theo đúng kiến trúc streaming đã thiết kế
"""

import asyncio
import aiohttp
import aiodns
import json
import re
import time
import random
import sys
import os
import ipaddress
import hashlib
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, AsyncGenerator, Tuple
from enum import Enum
import argparse
import warnings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import signal

warnings.filterwarnings('ignore')

# =================== CONFIGURATION ===================
class Config:
    # General
    MAX_CONCURRENT_TASKS = 50
    EVENT_BUS_SIZE = 1000
    REQUEST_TIMEOUT = 10
    DNS_TIMEOUT = 2
    
    # Phase 0: Discovery
    DISCOVERY_SOURCES = [
        "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
        "https://raw.githubusercontent.com/wordpress/wordpress.org-seo/master/data/top-1m.csv",
    ]
    
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
    ]
    
    # Phase 3-4: Plugin & Technology Database
    POPULAR_PLUGINS = {
        'yoast-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
        'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
        'all-in-one-seo-pack': {'name': 'All in One SEO', 'category': 'SEO', 'installs': '3M+'},
        'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
        'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
        'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
        'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
        'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
        'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    }
    
    # Non-WP CMS patterns
    CMS_PATTERNS = {
        'joomla': [
            (r'/media/system/js/', 80),
            (r'/media/system/css/', 80),
            (r'joomla', 70),
            (r'content="Joomla', 90),
        ],
        'drupal': [
            (r'/sites/default/files/', 80),
            (r'content="Drupal', 90),
            (r'Drupal.settings', 85),
        ],
        'magento': [
            (r'/static/version', 80),
            (r'Magento_', 75),
            (r'content="Magento', 90),
        ],
        'opencart': [
            (r'/catalog/view/theme/', 80),
            (r'Powered By OpenCart', 85),
        ],
    }
    
    # Phase 7: Risk Scoring Weights
    RISK_WEIGHTS = {
        'wp_config_exposed': 40,
        'debug_log_exposed': 30,
        'uploads_listing': 25,
        'backup_files': 20,
        'xmlrpc_enabled': 15,
        'rest_api_exposed': 10,
        'user_enumeration': 15,
        'old_php_version': 30,
        'old_wp_version': 25,
        'vulnerable_plugin': 35,
    }
    
    # Phase 8: Triage Rules
    TRIAGE_RULES = {
        'CRITICAL': {'min_score': 80, 'action': 'FOCUS', 'color': '\033[91m'},
        'HIGH': {'min_score': 60, 'action': 'REVIEW', 'color': '\033[93m'},
        'MEDIUM': {'min_score': 40, 'action': 'MONITOR', 'color': '\033[33m'},
        'LOW': {'min_score': 20, 'action': 'ARCHIVE', 'color': '\033[92m'},
        'INFO': {'min_score': 0, 'action': 'LOG', 'color': '\033[94m'},
    }

# =================== DATA STRUCTURES ===================
class EventType(Enum):
    # Phase 0
    RAW_TARGET = "raw_target"
    
    # Phase 1
    CLEAN_TARGET = "clean_target"
    
    # Phase 2
    LIVE_PROFILE = "live_profile"
    
    # Phase 3
    TECH_PROFILE = "tech_profile"
    
    # Phase 4 & 5
    TECH_ENUM_RESULT = "tech_enum_result"
    WP_CORE_PROFILE = "wp_core_profile"
    
    # Phase 6
    SURFACE_MAP = "surface_map"
    
    # Phase 7
    RISK_PROFILE = "risk_profile"
    
    # Phase 8
    TRIAGED_TARGET = "triaged_target"
    
    # Phase 9
    FINAL_OUTPUT = "final_output"

@dataclass
class Event:
    type: EventType
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    
    def __str__(self):
        return f"[{self.type.value}] {self.data.get('domain', 'N/A')}"

# =================== ASYNC EVENT BUS ===================
class AsyncEventBus:
    """Event bus trung tâm cho 9-phase pipeline"""
    
    def __init__(self, max_size=1000):
        self.queue = asyncio.Queue(maxsize=max_size)
        self.subscribers = defaultdict(list)
        self.stats = {'processed': 0, 'dropped': 0}
        self.is_running = False
    
    async def publish(self, event: Event):
        """Publish event vào bus"""
        try:
            await self.queue.put(event)
            self.stats['processed'] += 1
            return True
        except asyncio.QueueFull:
            self.stats['dropped'] += 1
            return False
    
    async def subscribe(self, event_type: EventType, callback):
        """Subscribe đến loại event cụ thể"""
        self.subscribers[event_type].append(callback)
    
    async def run(self):
        """Chạy event bus loop"""
        print(f"[EventBus] Started with {len(self.subscribers)} subscribers")
        self.is_running = True
        
        while self.is_running:
            try:
                event = await self.queue.get()
                
                if event.type in self.subscribers:
                    # Fire and forget cho subscribers
                    for callback in self.subscribers[event.type]:
                        asyncio.create_task(callback(event))
                
                self.queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[EventBus] Error: {e}")
        
        print("[EventBus] Stopped")
    
    async def stop(self):
        """Dừng event bus"""
        self.is_running = False
        # Đợi queue trống
        await self.queue.join()

# =================== PHASE 0: TARGET PRODUCER ===================
class TargetProducer:
    """Phase 0: Tạo targets từ nhiều nguồn"""
    
    def __init__(self, event_bus: AsyncEventBus, targets_file: Optional[str] = None):
        self.event_bus = event_bus
        self.targets_file = targets_file
        self.is_running = False
        
        # Static fallback domains (nếu không có nguồn nào)
        self.static_fallback = [
            "example.com",
            "test.wordpress.org",
        ]
    
    async def start(self):
        """Bắt đầu producer"""
        self.is_running = True
        asyncio.create_task(self._produce_targets())
    
    async def stop(self):
        """Dừng producer"""
        self.is_running = False
    
    async def _produce_targets(self):
        """Tạo targets từ tất cả nguồn"""
        print("[Phase 0] 🎯 Target Producer started")
        
        # 1. Từ file targets.txt
        if self.targets_file and os.path.exists(self.targets_file):
            await self._read_from_file()
        
        # 2. Từ dorks (DDGS)
        await self._collect_from_dorks()
        
        # 3. Static fallback
        await self._use_fallback()
        
        print("[Phase 0] ✅ Target production completed")
    
    async def _read_from_file(self):
        """Đọc targets từ file"""
        try:
            with open(self.targets_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not self.is_running:
                        break
                    
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        event = Event(
                            type=EventType.RAW_TARGET,
                            data={'domain': domain, 'source': 'file'},
                            source="TargetProducer"
                        )
                        await self.event_bus.publish(event)
                        await asyncio.sleep(0.01)
            
            print(f"[Phase 0] 📁 Read targets from {self.targets_file}")
            
        except Exception as e:
            print(f"[Phase 0] File error: {e}")
    
    async def _collect_from_dorks(self):
        """Thu thập từ dorks"""
        try:
            from ddgs import DDGS
            ddgs = DDGS()
            
            for dork in Config.DORKS[:3]:  # Giới hạn 3 dorks cho nhanh
                if not self.is_running:
                    break
                
                print(f"[Phase 0] 🔍 Processing dork: {dork[:50]}...")
                
                try:
                    results = ddgs.text(
                        query=dork,
                        region="vn-vn",
                        safesearch="off",
                        max_results=20,
                        timeout=10
                    )
                    
                    for result in results:
                        url = result.get('href', '')
                        if url:
                            try:
                                parsed = urlparse(url)
                                domain = parsed.netloc.lower()
                                if domain.startswith('www.'):
                                    domain = domain[4:]
                                
                                event = Event(
                                    type=EventType.RAW_TARGET,
                                    data={'domain': domain, 'source': 'dork', 'dork': dork},
                                    source="TargetProducer"
                                )
                                await self.event_bus.publish(event)
                                
                            except:
                                pass
                        
                        await asyncio.sleep(0.1)
                    
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    print(f"[Phase 0] Dork error: {e}")
                    await asyncio.sleep(5)
        
        except ImportError:
            print("[Phase 0] ⚠️ DDGS not available, skipping dorks")
        except Exception as e:
            print(f"[Phase 0] Dork collection error: {e}")
    
    async def _use_fallback(self):
        """Dùng static fallback"""
        print("[Phase 0] ⚡ Using static fallback targets")
        for domain in self.static_fallback:
            event = Event(
                type=EventType.RAW_TARGET,
                data={'domain': domain, 'source': 'fallback'},
                source="TargetProducer"
            )
            await self.event_bus.publish(event)
            await asyncio.sleep(0.1)

# =================== PHASE 1: SOFT PRE-FILTER ===================
class SoftPreFilter:
    """Phase 1: Lọc nhẹ, chỉ gắn tag, không drop"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.seen_domains = set()
        self.dns_resolver = aiodns.DNSResolver()
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RAW_TARGET,
            self.process_raw_target
        ))
    
    async def process_raw_target(self, event: Event):
        """Xử lý raw target - Phase 1"""
        raw_domain = event.data.get('domain', '')
        tags = []
        
        # 1. Normalize domain
        normalized = self._normalize_domain(raw_domain)
        if not normalized:
            tags.append('invalid_format')
            return  # Drop thật sự nếu format sai
        
        # 2. Duplicate check (tag only)
        if normalized in self.seen_domains:
            tags.append('duplicate')
            return  # Drop duplicate
        
        self.seen_domains.add(normalized)
        
        # 3. DNS check (tag only)
        dns_ok = await self._check_dns(normalized)
        if not dns_ok:
            tags.append('dns_fail')
        else:
            tags.append('dns_ok')
        
        # 4. HTTP ping (tag only)
        http_ok = await self._http_ping(normalized)
        if not http_ok:
            tags.append('http_fail')
        else:
            tags.append('http_ok')
        
        # 5. Format/IP/CDN hint
        if self._looks_like_ip(normalized):
            tags.append('is_ip')
        
        if self._looks_like_cdn(normalized):
            tags.append('cdn_hint')
        
        # Tạo clean target event
        clean_event = Event(
            type=EventType.CLEAN_TARGET,
            data={
                'domain': normalized,
                'original': raw_domain,
                'source': event.data.get('source', 'unknown'),
                'tags': tags,
                'timestamp': time.time()
            },
            source="SoftPreFilter"
        )
        
        await self.event_bus.publish(clean_event)
        
        # Log
        tag_str = ",".join(tags) if tags else "no-tags"
        print(f"[Phase 1] 🏷️  {normalized[:40]:<40} tags: {tag_str}")
    
    def _normalize_domain(self, domain: str) -> Optional[str]:
        """Normalize domain, trả None nếu invalid"""
        try:
            if '://' in domain:
                parsed = urlparse(domain)
                domain = parsed.netloc
            
            domain = domain.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Validate cơ bản
            if not re.match(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$', domain):
                return None
            
            return domain
            
        except:
            return None
    
    async def _check_dns(self, domain: str) -> bool:
        """Check DNS resolution"""
        try:
            await asyncio.wait_for(
                self.dns_resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return True
        except:
            return False
    
    async def _http_ping(self, domain: str) -> bool:
        """HTTP ping nhanh"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                for scheme in ['https://', 'http://']:
                    try:
                        async with session.head(f"{scheme}{domain}", ssl=False) as resp:
                            return resp.status < 500
                    except:
                        continue
        except:
            pass
        return False
    
    def _looks_like_ip(self, domain: str) -> bool:
        """Check if domain looks like IP"""
        try:
            ipaddress.ip_address(domain)
            return True
        except:
            return False
    
    def _looks_like_cdn(self, domain: str) -> bool:
        """Check if domain looks like CDN"""
        cdn_keywords = ['cdn.', 'cloudfront.', 'akamaiedge.', 'fastly.', 'cloudflare.']
        return any(domain.startswith(kw) for kw in cdn_keywords)

# =================== PHASE 2: LIVE DETECTOR ===================
class LiveDetector:
    """Phase 2: Phát hiện live site với profiling"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.CLEAN_TARGET,
            self.process_clean_target
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def process_clean_target(self, event: Event):
        """Xử lý clean target - Phase 2"""
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Test cả HTTP và HTTPS
        http_result = await self._test_protocol(domain, 'http')
        https_result = await self._test_protocol(domain, 'https')
        
        # Tính alive_score
        alive_score = 0
        redirects = []
        headers = {}
        
        if https_result and https_result['alive']:
            alive_score = 100
            redirects = https_result['redirects']
            headers = https_result['headers']
        elif http_result and http_result['alive']:
            alive_score = 80
            redirects = http_result['redirects']
            headers = http_result['headers']
        
        # Tạo live profile
        live_event = Event(
            type=EventType.LIVE_PROFILE,
            data={
                'domain': domain,
                'alive_score': alive_score,
                'https_alive': https_result['alive'] if https_result else False,
                'http_alive': http_result['alive'] if http_result else False,
                'redirects': redirects,
                'headers': headers,
                'response_time': https_result.get('response_time', 0) if https_result else 
                               http_result.get('response_time', 0) if http_result else 0,
                'final_url': https_result.get('final_url', '') if https_result else 
                           http_result.get('final_url', '') if http_result else '',
                'tags': event.data.get('tags', []),
                'timestamp': time.time()
            },
            source="LiveDetector"
        )
        
        await self.event_bus.publish(live_event)
        
        # Log
        status = "🟢" if alive_score >= 50 else "🟡" if alive_score > 0 else "🔴"
        print(f"[Phase 2] {status} {domain[:40]:<40} score: {alive_score}, "
              f"HTTPS: {'✓' if https_result and https_result['alive'] else '✗'}, "
              f"HTTP: {'✓' if http_result and http_result['alive'] else '✗'}")
    
    async def _test_protocol(self, domain: str, protocol: str) -> Optional[Dict]:
        """Test một protocol"""
        url = f"{protocol}://{domain}"
        
        try:
            start_time = time.time()
            
            async with self.session.get(
                url,
                allow_redirects=True,
                ssl=False,
                timeout=8
            ) as resp:
                response_time = time.time() - start_time
                
                # Lấy redirect chain
                redirects = []
                if resp.history:
                    for r in resp.history:
                        redirects.append(str(r.url))
                
                # Lấy headers
                headers = dict(resp.headers)
                
                return {
                    'alive': resp.status < 400,
                    'status': resp.status,
                    'response_time': response_time,
                    'redirects': redirects,
                    'final_url': str(resp.url),
                    'headers': headers
                }
                
        except Exception as e:
            return {
                'alive': False,
                'error': str(e),
                'response_time': 0,
                'redirects': [],
                'headers': {}
            }

# =================== PHASE 3: WORDPRESS GATE ===================
class WordPressGate:
    """Phase 3: Phát hiện WordPress với confidence score"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.LIVE_PROFILE,
            self.process_live_profile
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def process_live_profile(self, event: Event):
        """Xử lý live profile - Phase 3"""
        if event.data['alive_score'] < 10:
            return  # Bỏ qua site không alive
        
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Chạy probes song song
        probes = [
            self._probe_homepage(domain),
            self._probe_wp_login(domain),
            self._probe_wp_content(domain),
            self._probe_wp_json(domain),
            self._probe_rss_feed(domain),
        ]
        
        results = await asyncio.gather(*probes, return_exceptions=True)
        
        # Tính confidence score
        confidence = 0
        signals = []
        evidence = {}
        
        probe_names = ['homepage', 'wp_login', 'wp_content', 'wp_json', 'rss']
        for i, (name, result) in enumerate(zip(probe_names, results)):
            if isinstance(result, dict) and result.get('detected'):
                confidence += result.get('weight', 20)
                signals.append(name)
                evidence[name] = result
        
        # Normalize confidence
        confidence = min(confidence, 100)
        is_wp_probable = confidence >= 25
        
        # Phát hiện CMS khác
        other_cms = await self._detect_other_cms(domain)
        
        # Tạo tech profile
        tech_event = Event(
            type=EventType.TECH_PROFILE,
            data={
                'domain': domain,
                'wp_confidence': confidence,
                'is_wp_probable': is_wp_probable,
                'signals': signals,
                'evidence': evidence,
                'other_cms': other_cms,
                'alive_score': event.data['alive_score'],
                'timestamp': time.time()
            },
            source="WordPressGate"
        )
        
        await self.event_bus.publish(tech_event)
        
        # Log
        if confidence >= 50:
            print(f"[Phase 3] 🟢 WP {domain[:40]:<40} confidence: {confidence}%, signals: {', '.join(signals)}")
        elif confidence >= 25:
            print(f"[Phase 3] 🟡 WP? {domain[:40]:<40} confidence: {confidence}%")
        elif other_cms:
            print(f"[Phase 3] 🔵 {other_cms[0].upper()} {domain[:40]:<40} detected")
        else:
            print(f"[Phase 3] ⚫ NON-WP {domain[:40]:<40}")
    
    async def _probe_homepage(self, domain: str) -> Dict:
        """Probe homepage"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False, timeout=5) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            
                            # Check các dấu hiệu WordPress
                            weight = 0
                            detected = False
                            details = []
                            
                            if '/wp-content/' in html:
                                weight += 15
                                detected = True
                                details.append('wp_content_path')
                            
                            if '/wp-includes/' in html:
                                weight += 15
                                detected = True
                                details.append('wp_includes_path')
                            
                            if 'wordpress' in html.lower() and 'generator' in html.lower():
                                weight += 25
                                detected = True
                                details.append('meta_generator')
                            
                            # Check common WP JS
                            wp_js_patterns = ['wp-embed.min.js', 'wp-emoji-release.min.js']
                            if any(pattern in html for pattern in wp_js_patterns):
                                weight += 20
                                detected = True
                                details.append('wp_js')
                            
                            return {
                                'detected': detected,
                                'weight': weight,
                                'details': details,
                                'status': resp.status
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False, 'weight': 0}
    
    async def _probe_wp_login(self, domain: str) -> Dict:
        """Probe wp-login.php"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-login.php"
                try:
                    async with self.session.head(url, allow_redirects=False, ssl=False, timeout=3) as resp:
                        if resp.status < 400:
                            return {
                                'detected': True,
                                'weight': 30,
                                'status': resp.status,
                                'redirect': resp.headers.get('Location', '')
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False, 'weight': 0}
    
    async def _probe_wp_content(self, domain: str) -> Dict:
        """Probe wp-content directory"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/"
                try:
                    async with self.session.head(url, allow_redirects=False, ssl=False, timeout=3) as resp:
                        if resp.status < 400:
                            return {
                                'detected': True,
                                'weight': 25,
                                'status': resp.status
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False, 'weight': 0}
    
    async def _probe_wp_json(self, domain: str) -> Dict:
        """Probe REST API"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get('Content-Type', '')
                            if 'application/json' in content_type:
                                try:
                                    data = await resp.json()
                                    if 'namespace' in str(data):
                                        return {
                                            'detected': True,
                                            'weight': 35,
                                            'status': resp.status,
                                            'is_wp_json': True
                                        }
                                except:
                                    pass
                except:
                    continue
        except:
            pass
        
        return {'detected': False, 'weight': 0}
    
    async def _probe_rss_feed(self, domain: str) -> Dict:
        """Probe RSS feed"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/feed/"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if 'generator="https://wordpress.org/' in text:
                                return {
                                    'detected': True,
                                    'weight': 20,
                                    'status': resp.status
                                }
                except:
                    continue
        except:
            pass
        
        return {'detected': False, 'weight': 0}
    
    async def _detect_other_cms(self, domain: str) -> List[str]:
        """Phát hiện CMS khác"""
        detected = []
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False, timeout=5) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            
                            for cms, patterns in Config.CMS_PATTERNS.items():
                                for pattern, weight in patterns:
                                    if re.search(pattern, html, re.IGNORECASE):
                                        detected.append(cms)
                                        break
                            
                            if detected:
                                break
                except:
                    continue
        except:
            pass
        
        return list(set(detected))

# =================== PHASE 4: TECH ENUM (CHO TẤT CẢ) ===================
class TechEnumerator:
    """Phase 4: Enumerate công nghệ cho tất cả targets"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.TECH_PROFILE,
            self.process_tech_profile
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def process_tech_profile(self, event: Event):
        """Xử lý tech profile - Phase 4 (cho tất cả)"""
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Chạy enumeration song song
        tasks = [
            self._detect_server_info(domain),
            self._detect_php_version(domain),
            self._detect_js_frameworks(domain),
            self._detect_waf(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Tạo tech enum result
        enum_event = Event(
            type=EventType.TECH_ENUM_RESULT,
            data={
                'domain': domain,
                'server': results[0] if not isinstance(results[0], Exception) else {},
                'php': results[1] if not isinstance(results[1], Exception) else {},
                'js_frameworks': results[2] if not isinstance(results[2], Exception) else [],
                'waf': results[3] if not isinstance(results[3], Exception) else None,
                'wp_confidence': event.data['wp_confidence'],
                'other_cms': event.data.get('other_cms', []),
                'timestamp': time.time()
            },
            source="TechEnumerator"
        )

        
        await self.event_bus.publish(enum_event)
        
        # Log
        server_info = results[0] if not isinstance(results[0], Exception) else {}
        server_str = server_info.get('server', 'unknown')[:20]
        print(f"[Phase 4] 🔧 {domain[:40]:<40} Server: {server_str}, "
              f"PHP: {results[1].get('version', 'unknown') if not isinstance(results[1], Exception) else 'unknown'}")
    
    async def _detect_server_info(self, domain: str) -> Dict:
        """Phát hiện server information"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        server_info = {
                            'server': resp.headers.get('Server', ''),
                            'x_powered_by': resp.headers.get('X-Powered-By', ''),
                            'x_frame_options': resp.headers.get('X-Frame-Options', ''),
                            'content_security_policy': resp.headers.get('Content-Security-Policy', ''),
                        }
                        
                        # Detect CDN
                        cdn_headers = ['CF-RAY', 'X-Cache', 'X-Amz-Cf-Id', 'X-Served-By']
                        cdn_detected = []
                        for header in cdn_headers:
                            if header in resp.headers:
                                cdn_detected.append(header)
                        
                        if cdn_detected:
                            server_info['cdn'] = cdn_detected
                        
                        return server_info
                except:
                    continue
        except:
            pass
        
        return {}
    
    async def _detect_php_version(self, domain: str) -> Dict:
        """Phát hiện PHP version"""
        php_info = {'version': None, 'method': 'unknown'}
        
        # Method 1: X-Powered-By header
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        powered_by = resp.headers.get('X-Powered-By', '')
                        if 'PHP' in powered_by:
                            match = re.search(r'PHP/([\d\.]+)', powered_by)
                            if match:
                                php_info['version'] = match.group(1)
                                php_info['method'] = 'header'
                                return php_info
                except:
                    continue
        except:
            pass
        
        # Method 2: Error pages
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-admin/install.php"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 500:
                            text = await resp.text()
                            match = re.search(r'PHP/([\d\.]+)', text)
                            if match:
                                php_info['version'] = match.group(1)
                                php_info['method'] = 'error_page'
                                return php_info
                except:
                    continue
        except:
            pass
        
        return php_info
    
    async def _detect_js_frameworks(self, domain: str) -> List[str]:
        """Phát hiện JS frameworks"""
        frameworks = []
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False, timeout=5) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            
                            # Common JS frameworks
                            js_patterns = {
                                'jquery': [r'jquery(?:\.min)?\.js', r'jQuery\.fn'],
                                'react': [r'react(?:\.min)?\.js', r'React\.'],
                                'vue': [r'vue(?:\.min)?\.js', r'Vue\.'],
                                'angular': [r'angular(?:\.min)?\.js', r'angular\.module'],
                            }
                            
                            for framework, patterns in js_patterns.items():
                                for pattern in patterns:
                                    if re.search(pattern, html, re.IGNORECASE):
                                        frameworks.append(framework)
                                        break
                except:
                    continue
        except:
            pass
        
        return list(set(frameworks))
    
    async def _detect_waf(self, domain: str) -> Optional[str]:
        """Phát hiện WAF"""
        wafs = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'Wordfence': ['x-wf-', 'wfwaf-'],
            'Comodo': ['Protected-By-Comodo'],
        }
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        
                        for waf_name, waf_headers in wafs.items():
                            for header in waf_headers:
                                if header in headers:
                                    return waf_name
                except:
                    continue
        except:
            pass
        
        return None

# =================== PHASE 5: WP CORE FINGERPRINT ===================
class WPCoreFingerprinter:
    """Phase 5: Lấy thông tin WordPress core (chỉ khi wp_confidence >= 10)"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.TECH_ENUM_RESULT,
            self.process_tech_enum
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def process_tech_enum(self, event: Event):
        """Xử lý tech enum - Phase 5 (chỉ cho WP)"""
        if event.data['wp_confidence'] < 10:
            return  # Bỏ qua non-WP
        
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Chạy fingerprinting song song
        tasks = [
            self._get_wp_version(domain),
            self._get_theme_slug(domain),
            self._check_xmlrpc(domain),
            self._check_rest_api(domain),
            self._get_server_headers(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Tạo WP core profile
        wp_event = Event(
            type=EventType.WP_CORE_PROFILE,
            data={
                'domain': domain,
                'wp_version': results[0] if not isinstance(results[0], Exception) else None,
                'theme_slug': results[1] if not isinstance(results[1], Exception) else None,
                'xmlrpc_enabled': results[2] if not isinstance(results[2], Exception) else False,
                'rest_api_enabled': results[3] if not isinstance(results[3], Exception) else False,
                'server_headers': results[4] if not isinstance(results[4], Exception) else {},
                'wp_confidence': event.data['wp_confidence'],
                'tech_info': event.data,
                'timestamp': time.time()
            },
            source="WPCoreFingerprinter"
        )
        
        await self.event_bus.publish(wp_event)
        
        # Log
        wp_ver = results[0] if not isinstance(results[0], Exception) else 'unknown'
        theme = results[1] if not isinstance(results[1], Exception) else 'unknown'
        print(f"[Phase 5] 🎯 WP-CORE {domain[:40]:<40} Version: {wp_ver}, Theme: {theme}, "
              f"XML-RPC: {'✓' if results[2] and not isinstance(results[2], Exception) else '✗'}")
    
    async def _get_wp_version(self, domain: str) -> Optional[str]:
        """Lấy WordPress version"""
        version_patterns = [
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)["\']',
            r'content=["\']WordPress\s+([\d.]+)["\'][^>]+name=["\']generator["\']',
            r'wp-embed\.js\?ver=([\d.]+)',
            r'<!--[^>]*WordPress\s+([\d.]+)[^>]*-->',
            r'generator="WordPress/([\d.]+)"',
        ]
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False, timeout=5) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, html, re.IGNORECASE)
                                if match:
                                    version = match.group(1)
                                    if self._is_valid_version(version):
                                        return version
                except:
                    continue
        except:
            pass
        
        return None
    
    async def _get_theme_slug(self, domain: str) -> Optional[str]:
        """Lấy theme slug"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False, timeout=5) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            match = re.search(r'/wp-content/themes/([^/]+)/', html)
                            if match:
                                return match.group(1).lower()
                except:
                    continue
        except:
            pass
        
        return None
    
    async def _check_xmlrpc(self, domain: str) -> bool:
        """Kiểm tra XML-RPC"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/xmlrpc.php"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False
    
    async def _check_rest_api(self, domain: str) -> bool:
        """Kiểm tra REST API"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/wp/v2/"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False
    
    async def _get_server_headers(self, domain: str) -> Dict:
        """Lấy server headers chi tiết"""
        headers = {}
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False, timeout=3) as resp:
                        headers = dict(resp.headers)
                except:
                    continue
        except:
            pass
        
        return headers
    
    def _is_valid_version(self, version: str) -> bool:
        """Validate version string"""
        if not version or len(version) > 10:
            return False
        
        pattern = r'^\d+(?:\.\d+){1,2}$'
        if not re.match(pattern, version):
            return False
        
        parts = version.split('.')
        if len(parts) > 3:
            return False
        
        try:
            for part in parts:
                int(part)
        except:
            return False
        
        return True

# =================== PHASE 6: ATTACK SURFACE ENUMERATOR ===================
class AttackSurfaceEnumerator:
    """Phase 6: Enumerate attack surface"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Subscribe (chỉ cho WP sites)
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_CORE_PROFILE,
            self.process_wp_core
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def process_wp_core(self, event: Event):
        """Xử lý WP core - Phase 6"""
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Chạy tất cả enumeration song song
        tasks = [
            self._enumerate_plugins(domain),
            self._get_theme_details(domain, event.data.get('theme_slug')),
            self._enumerate_users(domain),
            self._enumerate_endpoints(domain),
            self._check_uploads_listing(domain),
            self._check_debug_log(domain),
            self._check_backup_files(domain),
            self._check_wp_config(domain),
            self._get_php_version_detail(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Tính initial risk score
        initial_risk = self._calculate_initial_risk(results)
        
        # Tạo surface map
        surface_event = Event(
            type=EventType.SURFACE_MAP,
            data={
                'domain': domain,
                'plugins': results[0] if not isinstance(results[0], Exception) else [],
                'theme': results[1] if not isinstance(results[1], Exception) else {},
                'users': results[2] if not isinstance(results[2], Exception) else [],
                'endpoints': results[3] if not isinstance(results[3], Exception) else {},
                'uploads_listing': results[4] if not isinstance(results[4], Exception) else False,
                'debug_log_exposed': results[5] if not isinstance(results[5], Exception) else False,
                'backup_files': results[6] if not isinstance(results[6], Exception) else [],
                'wp_config_exposed': results[7] if not isinstance(results[7], Exception) else False,
                'php_version': results[8] if not isinstance(results[8], Exception) else {},
                'initial_risk_score': initial_risk,
                'wp_core_info': event.data,
                'timestamp': time.time()
            },
            source="AttackSurfaceEnumerator"
        )
        
        await self.event_bus.publish(surface_event)
        
        # Log
        plugin_count = len(results[0]) if not isinstance(results[0], Exception) else 0
        user_count = len(results[2]) if not isinstance(results[2], Exception) else 0
        print(f"[Phase 6] 🎯 SURFACE {domain[:40]:<40} Plugins: {plugin_count}, "
              f"Users: {user_count}, Risk: {initial_risk}/50")
    
    async def _enumerate_plugins(self, domain: str) -> List[Dict]:
        """Enumerate popular plugins"""
        plugins = []
        
        for plugin_slug in list(Config.POPULAR_PLUGINS.keys())[:15]:  # Giới hạn 15 plugins
            try:
                for scheme in ['https://', 'http://']:
                    url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/"
                    try:
                        async with self.session.head(url, ssl=False, timeout=2) as resp:
                            if resp.status < 400:
                                plugin_info = Config.POPULAR_PLUGINS[plugin_slug].copy()
                                plugin_info['slug'] = plugin_slug
                                plugin_info['detected'] = True
                                
                                # Thử lấy version
                                version = await self._get_plugin_version(domain, plugin_slug)
                                if version:
                                    plugin_info['version'] = version
                                
                                plugins.append(plugin_info)
                                break
                    except:
                        continue
            except:
                continue
            
            await asyncio.sleep(0.05)  # Rate limiting
        
        return plugins
    
    async def _get_plugin_version(self, domain: str, plugin_slug: str) -> Optional[str]:
        """Lấy plugin version"""
        try:
            for scheme in ['https://', 'http://']:
                # Thử readme.txt
                url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/readme.txt"
                try:
                    async with self.session.get(url, ssl=False, timeout=2) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            match = re.search(r'Stable tag:\s*([\d\.]+)', text, re.IGNORECASE)
                            if match:
                                return match.group(1).strip()
                except:
                    continue
        except:
            pass
        
        return None
    
    async def _get_theme_details(self, domain: str, theme_slug: Optional[str]) -> Dict:
        """Lấy theme details"""
        if not theme_slug:
            return {}
        
        theme_info = {'slug': theme_slug, 'name': theme_slug}
        
        # Thử lấy version từ style.css
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/themes/{theme_slug}/style.css"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            match = re.search(r'Version:\s*([\d\.]+)', text, re.IGNORECASE)
                            if match:
                                theme_info['version'] = match.group(1).strip()
                except:
                    continue
        except:
            pass
        
        return theme_info
    
    async def _enumerate_users(self, domain: str) -> List[Dict]:
        """Enumerate users"""
        users = []
        
        # Method 1: REST API
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/wp/v2/users?per_page=10"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if isinstance(data, list):
                                for user in data:
                                    users.append({
                                        'id': user.get('id'),
                                        'slug': user.get('slug'),
                                        'name': user.get('name'),
                                        'source': 'rest_api'
                                    })
                except:
                    continue
        except:
            pass
        
        # Method 2: Author enumeration (limited)
        if len(users) == 0:
            for i in range(1, 4):  # Chỉ thử 3 IDs
                try:
                    for scheme in ['https://', 'http://']:
                        url = f"{scheme}{domain}/?author={i}"
                        try:
                            async with self.session.get(url, allow_redirects=True, 
                                                       ssl=False, timeout=3) as resp:
                                final_url = str(resp.url)
                                match = re.search(r'/author/([a-zA-Z0-9_-]+)/?', final_url)
                                if match:
                                    users.append({
                                        'id': i,
                                        'slug': match.group(1),
                                        'source': 'author_redirect'
                                    })
                                    break
                        except:
                            continue
                except:
                    continue
        
        return users
    
    async def _enumerate_endpoints(self, domain: str) -> Dict:
        """Enumerate endpoints"""
        endpoints = {
            'xmlrpc': False,
            'rest_api': False,
            'ajax': False,
            'admin_ajax': False,
        }
        
        # Check XML-RPC
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/xmlrpc.php"
                try:
                    async with self.session.head(url, ssl=False, timeout=2) as resp:
                        endpoints['xmlrpc'] = resp.status < 400
                        break
                except:
                    continue
        except:
            pass
        
        # Check REST API
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/"
                try:
                    async with self.session.head(url, ssl=False, timeout=2) as resp:
                        endpoints['rest_api'] = resp.status < 400
                        break
                except:
                    continue
        except:
            pass
        
        # Check admin-ajax.php
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-admin/admin-ajax.php"
                try:
                    async with self.session.head(url, ssl=False, timeout=2) as resp:
                        endpoints['admin_ajax'] = resp.status < 400
                        break
                except:
                    continue
        except:
            pass
        
        return endpoints
    
    async def _check_uploads_listing(self, domain: str) -> bool:
        """Check uploads directory listing"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/uploads/"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            return 'index of' in text.lower()
                except:
                    continue
        except:
            pass
        
        return False
    
    async def _check_debug_log(self, domain: str) -> bool:
        """Check debug.log"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/debug.log"
                try:
                    async with self.session.head(url, ssl=False, timeout=2) as resp:
                        return resp.status == 200
                except:
                    continue
        except:
            pass
        
        return False
    
    async def _check_backup_files(self, domain: str) -> List[str]:
        """Check backup files"""
        backup_patterns = [
            'wp-config.php.bak',
            'wp-config.php.backup',
            'wp-config.php.old',
            '.sql',
            '.tar.gz',
            'backup-',
        ]
        
        found = []
        
        for pattern in backup_patterns[:3]:  # Giới hạn 3 patterns
            try:
                for scheme in ['https://', 'http://']:
                    url = f"{scheme}{domain}/{pattern}"
                    try:
                        async with self.session.head(url, ssl=False, timeout=2) as resp:
                            if resp.status == 200:
                                found.append(pattern)
                                break
                    except:
                        continue
            except:
                continue
        
        return found
    
    async def _check_wp_config(self, domain: str) -> bool:
        """Check wp-config.php exposure"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-config.php"
                try:
                    async with self.session.get(url, ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            return 'DB_NAME' in text or 'define(' in text
                except:
                    continue
        except:
            pass
        
        return False
    
    async def _get_php_version_detail(self, domain: str) -> Dict:
        """Lấy chi tiết PHP version"""
        php_info = {'version': None, 'method': 'unknown'}
        
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False, timeout=2) as resp:
                        powered_by = resp.headers.get('X-Powered-By', '')
                        if 'PHP' in powered_by:
                            match = re.search(r'PHP/([\d\.]+)', powered_by)
                            if match:
                                php_info['version'] = match.group(1)
                                php_info['method'] = 'header'
                except:
                    continue
        except:
            pass
        
        return php_info
    
    def _calculate_initial_risk(self, results: List) -> int:
        """Tính initial risk score (0-50)"""
        risk = 0
        
        # Plugins
        plugins = results[0] if not isinstance(results[0], Exception) else []
        risk += min(len(plugins) * 2, 10)
        
        # Users
        users = results[2] if not isinstance(results[2], Exception) else []
        risk += min(len(users) * 3, 15)
        
        # Security issues
        if results[4] and not isinstance(results[4], Exception):  # uploads_listing
            risk += 8
        
        if results[5] and not isinstance(results[5], Exception):  # debug_log
            risk += 10
        
        if results[7] and not isinstance(results[7], Exception):  # wp_config_exposed
            risk += 15
        
        if results[6] and not isinstance(results[6], Exception):  # backup_files
            risk += len(results[6]) * 5
        
        return min(risk, 50)

# =================== PHASE 7: RISK SCORER ===================
class RiskScorer:
    """Phase 7: Tính risk score với layered model"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.SURFACE_MAP,
            self.process_surface_map
        ))
    
    async def process_surface_map(self, event: Event):
        """Xử lý surface map - Phase 7"""
        surface = event.data
        domain = surface['domain']
        
        # Tính layered risk score
        layered_score = self._calculate_layered_risk(surface)
        
        # Xác định risk level
        risk_level = self._determine_risk_level(layered_score)
        
        # Tạo risk profile
        risk_event = Event(
            type=EventType.RISK_PROFILE,
            data={
                'domain': domain,
                'weighted_score': layered_score,
                'level': risk_level,
                'layer_scores': self._get_layer_scores(surface),
                'findings': self._extract_findings(surface),
                'surface_data': surface,
                'timestamp': time.time()
            },
            source="RiskScorer"
        )
        
        await self.event_bus.publish(risk_event)
        
        # Log
        color = Config.TRIAGE_RULES[risk_level]['color']
        reset = '\033[0m'
        print(f"[Phase 7] {color}⚠️  RISK {domain[:40]:<40} Score: {layered_score}/100 "
              f"[{risk_level}]{reset}")
    
    def _calculate_layered_risk(self, surface: Dict) -> int:
        """Tính risk với layered model"""
        score = surface.get('initial_risk_score', 0) * 2  # Base score
        
        # Layer 1: Input Surface
        score += len(surface.get('plugins', [])) * 3
        score += len(surface.get('users', [])) * 5
        
        # Layer 2: Storage
        if surface.get('uploads_listing'):
            score += 15
        
        if surface.get('debug_log_exposed'):
            score += 20
        
        # Layer 3: Output
        endpoints = surface.get('endpoints', {})
        if endpoints.get('xmlrpc'):
            score += 10
        
        if endpoints.get('rest_api'):
            score += 5
        
        # Layer 4: Context
        wp_version = surface.get('wp_core_info', {}).get('wp_version')
        if wp_version:
            # Giả sử version cũ hơn 5.0 là risk
            if self._is_old_version(wp_version, '5.0'):
                score += 25
        
        php_version = surface.get('php_version', {}).get('version')
        if php_version:
            # Giả sử PHP < 7.4 là risk
            if self._is_old_php_version(php_version):
                score += 30
        
        # Layer 5: Guards
        if surface.get('wp_config_exposed'):
            score += 40
        
        if surface.get('backup_files'):
            score += len(surface['backup_files']) * 15
        
        # Layer 6: Headers
        headers = surface.get('wp_core_info', {}).get('server_headers', {})
        
        # Check security headers
        security_headers = ['X-Frame-Options', 'Content-Security-Policy', 
                           'X-Content-Type-Options', 'Strict-Transport-Security']
        
        missing_headers = 0
        for header in security_headers:
            if header not in headers:
                missing_headers += 1
        
        score += missing_headers * 5
        
        return min(score, 100)
    
    def _get_layer_scores(self, surface: Dict) -> Dict:
        """Lấy scores từng layer"""
        return {
            'input_surface': len(surface.get('plugins', [])) * 3 + len(surface.get('users', [])) * 5,
            'storage': 15 if surface.get('uploads_listing') else 0 + 20 if surface.get('debug_log_exposed') else 0,
            'output': 10 if surface.get('endpoints', {}).get('xmlrpc') else 0 + 5 if surface.get('endpoints', {}).get('rest_api') else 0,
            'context': self._calculate_context_score(surface),
            'guards': 40 if surface.get('wp_config_exposed') else 0 + len(surface.get('backup_files', [])) * 15,
            'headers': self._calculate_header_score(surface),
        }
    
    def _calculate_context_score(self, surface: Dict) -> int:
        """Tính context score"""
        score = 0
        
        wp_version = surface.get('wp_core_info', {}).get('wp_version')
        if wp_version and self._is_old_version(wp_version, '5.0'):
            score += 25
        
        php_version = surface.get('php_version', {}).get('version')
        if php_version and self._is_old_php_version(php_version):
            score += 30
        
        return score
    
    def _calculate_header_score(self, surface: Dict) -> int:
        """Tính header security score"""
        headers = surface.get('wp_core_info', {}).get('server_headers', {})
        
        security_headers = ['X-Frame-Options', 'Content-Security-Policy', 
                           'X-Content-Type-Options', 'Strict-Transport-Security']
        
        missing = 0
        for header in security_headers:
            if header not in headers:
                missing += 1
        
        return missing * 5
    
    def _extract_findings(self, surface: Dict) -> List[str]:
        """Trích xuất findings từ surface"""
        findings = []
        
        # Plugin findings
        plugins = surface.get('plugins', [])
        if plugins:
            findings.append(f"Found {len(plugins)} plugins")
        
        # User findings
        users = surface.get('users', [])
        if users:
            findings.append(f"Enumerated {len(users)} users")
        
        # Security findings
        if surface.get('wp_config_exposed'):
            findings.append("wp-config.php exposed")
        
        if surface.get('uploads_listing'):
            findings.append("Uploads directory listing enabled")
        
        if surface.get('debug_log_exposed'):
            findings.append("debug.log accessible")
        
        if surface.get('backup_files'):
            findings.append(f"Found {len(surface['backup_files'])} backup files")
        
        # Version findings
        wp_version = surface.get('wp_core_info', {}).get('wp_version')
        if wp_version and self._is_old_version(wp_version, '5.0'):
            findings.append(f"Old WordPress version: {wp_version}")
        
        php_version = surface.get('php_version', {}).get('version')
        if php_version and self._is_old_php_version(php_version):
            findings.append(f"Old PHP version: {php_version}")
        
        return findings[:8]  # Giới hạn 8 findings
    
    def _is_old_version(self, version: str, threshold: str) -> bool:
        """Check nếu version cũ"""
        try:
            v_parts = list(map(int, version.split('.')[:2]))
            t_parts = list(map(int, threshold.split('.')[:2]))
            
            for v, t in zip(v_parts, t_parts):
                if v < t:
                    return True
                elif v > t:
                    return False
            
            return False
        except:
            return False
    
    def _is_old_php_version(self, version: str) -> bool:
        """Check nếu PHP version cũ (< 7.4)"""
        try:
            match = re.match(r'(\d+)\.(\d+)', version)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                
                if major < 7:
                    return True
                elif major == 7 and minor < 4:
                    return True
                elif major == 8 and minor == 0:
                    return True  # PHP 8.0 cũng có thể có vấn đề
            
            return False
        except:
            return False
    
    def _determine_risk_level(self, score: int) -> str:
        """Xác định risk level"""
        for level, config in Config.TRIAGE_RULES.items():
            if score >= config['min_score']:
                return level
        return 'INFO'

# =================== PHASE 8: TRIAGE ENGINE ===================
class TriageEngine:
    """Phase 8: Phân loại và đề xuất action"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RISK_PROFILE,
            self.process_risk_profile
        ))
    
    async def process_risk_profile(self, event: Event):
        """Xử lý risk profile - Phase 8"""
        risk = event.data
        domain = risk['domain']
        
        # Xác định priority và action
        triage_result = self._perform_triage(risk)
        
        # Tạo triaged target
        triage_event = Event(
            type=EventType.TRIAGED_TARGET,
            data={
                'domain': domain,
                'priority': triage_result['priority'],
                'action': triage_result['action'],
                'reason': triage_result['reason'],
                'risk_profile': risk,
                'recommendations': triage_result['recommendations'],
                'timestamp': time.time()
            },
            source="TriageEngine"
        )
        
        await self.event_bus.publish(triage_event)
        
        # Log với màu sắc
        config = Config.TRIAGE_RULES[triage_result['priority']]
        color = config['color']
        reset = '\033[0m'
        
        print(f"[Phase 8] {color}🎯 TRIAGE {domain[:40]:<40} "
              f"Priority: {triage_result['priority']}, "
              f"Action: {triage_result['action']}{reset}")
        print(f"         Reason: {triage_result['reason'][:60]}...")
    
    def _perform_triage(self, risk: Dict) -> Dict:
        """Thực hiện triage"""
        level = risk['level']
        score = risk['weighted_score']
        findings = risk.get('findings', [])
        
        # Base từ config
        config = Config.TRIAGE_RULES[level]
        priority = level
        action = config['action']
        
        # Điều chỉnh dựa trên findings
        reason = ""
        recommendations = []
        
        if level == 'CRITICAL':
            reason = "Critical risk score with multiple severe findings"
            recommendations = [
                "Immediate manual review required",
                "Check for data exposure",
                "Verify backup files",
                "Test for authentication bypass",
            ]
        
        elif level == 'HIGH':
            reason = "High risk with security misconfigurations"
            recommendations = [
                "Review within 24 hours",
                "Check exposed configuration files",
                "Verify user enumeration",
                "Test directory listings",
            ]
        
        elif level == 'MEDIUM':
            reason = "Medium risk with some concerning findings"
            recommendations = [
                "Review within 1 week",
                "Update outdated components",
                "Check plugin security",
                "Monitor for changes",
            ]
        
        elif level == 'LOW':
            reason = "Low risk with minimal findings"
            recommendations = [
                "Archive for future reference",
                "Consider basic security hardening",
                "Monitor for new vulnerabilities",
            ]
        
        else:  # INFO
            reason = "Informational only, no significant risk"
            recommendations = [
                "Log for compliance",
                "No immediate action required",
            ]
        
        # Thêm reason cụ thể từ findings
        if findings:
            critical_findings = [f for f in findings if any(word in f.lower() for word in 
                                                          ['exposed', 'accessible', 'old', 'backup'])]
            if critical_findings:
                reason += f". Key findings: {', '.join(critical_findings[:2])}"
        
        return {
            'priority': priority,
            'action': action,
            'reason': reason,
            'recommendations': recommendations
        }

# =================== PHASE 9: OUTPUT MANAGER ===================
class OutputManager:
    """Phase 9: Quản lý output đa định dạng"""
    
    def __init__(self, event_bus: AsyncEventBus, 
                 json_file: Optional[str] = None,
                 csv_file: Optional[str] = None):
        self.event_bus = event_bus
        self.json_file = json_file
        self.csv_file = csv_file
        self.results = []
        self.stats = {
            'total_processed': 0,
            'wp_sites': 0,
            'risk_distribution': defaultdict(int),
            'start_time': time.time(),
        }
        
        # Subscribe
        asyncio.create_task(self.event_bus.subscribe(
            EventType.TRIAGED_TARGET,
            self.process_triaged_target
        ))
        
        # Also subscribe để hiển thị progress
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RAW_TARGET,
            self.log_progress
        ))
    
    async def process_triaged_target(self, event: Event):
        """Xử lý triaged target - Phase 9"""
        triage = event.data
        domain = triage['domain']
        
        # Update stats
        self.stats['total_processed'] += 1
        
        risk_level = triage['priority']
        self.stats['risk_distribution'][risk_level] += 1
        
        if triage['risk_profile'].get('surface_data', {}).get('wp_core_info'):
            self.stats['wp_sites'] += 1
        
        # Lưu vào memory
        self.results.append(triage)
        
        # Hiển thị terminal output
        await self._display_terminal(triage)
        
        # Lưu vào files
        if self.json_file:
            await self._save_to_json(triage)
        
        if self.csv_file:
            await self._save_to_csv(triage)
    
    async def _display_terminal(self, triage: Dict):
        """Hiển thị human-readable trên terminal"""
        domain = triage['domain']
        priority = triage['priority']
        action = triage['action']
        score = triage['risk_profile']['weighted_score']
        
        config = Config.TRIAGE_RULES[priority]
        color = config['color']
        reset = '\033[0m'
        
        print(f"\n{color}{'='*80}{reset}")
        print(f"{color}🎯 FINAL RESULT: {domain}{reset}")
        print(f"{color}{'='*80}{reset}")
        
        # Basic info
        print(f"\n📊 BASIC INFORMATION")
        print(f"  • Domain: {domain}")
        print(f"  • Risk Score: {score}/100 [{priority}]")
        print(f"  • Action: {action}")
        print(f"  • Priority: {priority}")
        
        # Key findings
        findings = triage['risk_profile'].get('findings', [])
        if findings:
            print(f"\n🔍 KEY FINDINGS:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding}")
        
        # Recommendations
        recommendations = triage.get('recommendations', [])
        if recommendations:
            print(f"\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"  {i}. {rec}")
        
        # Stats
        elapsed = time.time() - self.stats['start_time']
        print(f"\n📈 STATISTICS")
        print(f"  • Processed: {self.stats['total_processed']} targets")
        print(f"  • WP Sites: {self.stats['wp_sites']}")
        print(f"  • Elapsed: {elapsed:.1f}s")
        print(f"  • Risk Distribution:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = self.stats['risk_distribution'][level]
            if count > 0:
                level_color = Config.TRIAGE_RULES[level]['color']
                print(f"    - {level_color}{level}: {count}{reset}")
        
        print(f"{color}{'='*80}{reset}\n")
    
    async def _save_to_json(self, triage: Dict):
        """Lưu vào JSON file"""
        try:
            # Đọc file hiện tại nếu có
            data = []
            if os.path.exists(self.json_file):
                try:
                    with open(self.json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if not isinstance(data, list):
                            data = [data]
                except:
                    data = []
            
            # Thêm result mới
            data.append(triage)
            
            # Ghi lại file
            with open(self.json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"[OutputManager] JSON save error: {e}")
    
    async def _save_to_csv(self, triage: Dict):
        """Lưu vào CSV file"""
        try:
            import csv
            
            domain = triage['domain']
            priority = triage['priority']
            action = triage['action']
            score = triage['risk_profile']['weighted_score']
            wp_version = triage['risk_profile'].get('surface_data', {}).get('wp_core_info', {}).get('wp_version', '')
            plugin_count = len(triage['risk_profile'].get('surface_data', {}).get('plugins', []))
            user_count = len(triage['risk_profile'].get('surface_data', {}).get('users', []))
            
            row = [
                domain,
                priority,
                action,
                str(score),
                wp_version,
                str(plugin_count),
                str(user_count),
                datetime.now().isoformat(),
            ]
            
            file_exists = os.path.exists(self.csv_file)
            
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                if not file_exists:
                    # Write header
                    header = ['Domain', 'Priority', 'Action', 'Risk_Score', 
                             'WP_Version', 'Plugin_Count', 'User_Count', 'Timestamp']
                    writer.writerow(header)
                
                writer.writerow(row)
                
        except Exception as e:
            print(f"[OutputManager] CSV save error: {e}")
    
    async def log_progress(self, event: Event):
        """Log progress"""
        self.stats['total_targets'] = self.stats.get('total_targets', 0) + 1
        
        # Hiển thị progress mỗi 10 targets
        if self.stats['total_targets'] % 10 == 0:
            elapsed = time.time() - self.stats['start_time']
            print(f"[Progress] Targets: {self.stats['total_targets']}, "
                  f"Processed: {self.stats['total_processed']}, "
                  f"Elapsed: {elapsed:.1f}s")

# =================== COMPLETE 9-PHASE PIPELINE ===================
class CompleteWASEPipeline:
    """Complete 9-phase pipeline"""
    
    def __init__(self, targets_file: Optional[str] = None, 
                 output_json: str = "wase_results.json",
                 output_csv: str = "wase_results.csv",
                 workers: int = 8):
        
        self.targets_file = targets_file
        self.output_json = output_json
        self.output_csv = output_csv
        self.workers = workers
        
        # Khởi tạo event bus
        self.event_bus = AsyncEventBus(max_size=Config.EVENT_BUS_SIZE)
        
        # Khởi tạo tất cả 9 phases
        self.phases = [
            # Phase 0
            TargetProducer(self.event_bus, targets_file),
            
            # Phase 1
            SoftPreFilter(self.event_bus),
            
            # Phase 2
            LiveDetector(self.event_bus),
            
            # Phase 3
            WordPressGate(self.event_bus),
            
            # Phase 4
            TechEnumerator(self.event_bus),
            
            # Phase 5
            WPCoreFingerprinter(self.event_bus),
            
            # Phase 6
            AttackSurfaceEnumerator(self.event_bus),
            
            # Phase 7
            RiskScorer(self.event_bus),
            
            # Phase 8
            TriageEngine(self.event_bus),
            
            # Phase 9
            OutputManager(self.event_bus, output_json, output_csv),
        ]
        
        # Track để cleanup
        self.sessions_to_close = []
    
    async def run(self):
        """Chạy complete 9-phase pipeline"""
        print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║         WORDPRESS ATTACK SURFACE ENGINE (WASE) v2.0                   ║
║                     Complete 9-Phase Pipeline                          ║
╚════════════════════════════════════════════════════════════════════════╝
        """)
        
        print(f"[Pipeline] Starting 9-phase pipeline...")
        print(f"[Pipeline] Output: JSON={self.output_json}, CSV={self.output_csv}")
        print(f"[Pipeline] Workers: {self.workers}")
        
        if self.targets_file:
            print(f"[Pipeline] Mode: Targeted scan from {self.targets_file}")
        else:
            print(f"[Pipeline] Mode: Discovery + Static fallback")
        
        print(f"\n{'═' * 80}")
        print("🚀 9-PHASE PIPELINE STARTING...")
        print(f"{'═' * 80}\n")
        
        try:
            # Start event bus
            bus_task = asyncio.create_task(self.event_bus.run())
            
            # Start Phase 0 (Target Producer)
            await self.phases[0].start()
            
            # Chờ producer hoàn thành
            print("[Pipeline] Waiting for target production to complete...")
            await asyncio.sleep(2)  # Cho producer chạy một lúc
            
            # Chờ tất cả events được xử lý
            print("[Pipeline] Waiting for pipeline to process all targets...")
            
            # Đợi một khoảng thời gian hoặc cho đến khi không còn activity
            max_wait = 300  # 5 phút max
            check_interval = 5
            last_count = 0
            same_count_cycles = 0
            
            for _ in range(max_wait // check_interval):
                processed = self.event_bus.stats['processed']
                
                if processed == last_count:
                    same_count_cycles += 1
                else:
                    same_count_cycles = 0
                    last_count = processed
                
                # Nếu không có activity trong 3 cycles, dừng
                if same_count_cycles >= 3:
                    print("[Pipeline] No activity detected, stopping...")
                    break
                
                # Hiển thị progress
                dropped = self.event_bus.stats['dropped']
                print(f"[Pipeline] Progress: Processed={processed}, Dropped={dropped}, "
                      f"Queue={self.event_bus.queue.qsize()}")
                
                await asyncio.sleep(check_interval)
            
            print("[Pipeline] Pipeline processing completed")
            
        except KeyboardInterrupt:
            print("\n\n🛑 Pipeline interrupted by user")
        except Exception as e:
            print(f"[Pipeline] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            await self._cleanup()
            
            # Final statistics
            output_mgr = self.phases[9]  # Phase 9
            stats = output_mgr.stats
            
            print(f"\n{'═' * 80}")
            print("📊 FINAL PIPELINE STATISTICS")
            print(f"{'═' * 80}")
            print(f"Total targets processed: {stats['total_processed']}")
            print(f"WordPress sites detected: {stats['wp_sites']}")
            print(f"Total processing time: {time.time() - stats['start_time']:.1f}s")
            
            print(f"\nRisk Distribution:")
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = stats['risk_distribution'][level]
                if count > 0:
                    color = Config.TRIAGE_RULES[level]['color']
                    reset = '\033[0m'
                    print(f"  {color}{level}: {count} targets{reset}")
            
            print(f"\n📁 Results saved to:")
            if self.output_json:
                print(f"  • JSON: {self.output_json}")
            if self.output_csv:
                print(f"  • CSV: {self.output_csv}")
            
            print(f"\n✅ 9-phase pipeline completed successfully!")
    
    async def _cleanup(self):
        """Cleanup tất cả resources"""
        print("\n[Pipeline] Cleaning up resources...")
        
        # Stop event bus
        if hasattr(self.event_bus, 'stop'):
            await self.event_bus.stop()
        
        # Close tất cả sessions
        for phase in self.phases:
            if hasattr(phase, 'session') and phase.session:
                try:
                    if not phase.session.closed:
                        await phase.session.close()
                        print(f"[Cleanup] Closed session for {phase.__class__.__name__}")
                except Exception as e:
                    print(f"[Cleanup] Error closing session: {e}")
        
        # Cancel remaining tasks
        tasks = [t for t in asyncio.all_tasks() 
                if t is not asyncio.current_task() and not t.done()]
        
        if tasks:
            print(f"[Cleanup] Cancelling {len(tasks)} remaining tasks...")
            for task in tasks:
                task.cancel()
            
            try:
                await asyncio.wait(tasks, timeout=2.0)
            except:
                pass

# =================== MAIN ===================
async def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='WordPress Attack Surface Engine (WASE) - Complete 9-Phase Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline với discovery
  python wase_complete.py
  
  # Targeted scan từ file
  python wase_complete.py --targets targets.txt
  
  # Custom output files
  python wase_complete.py --json results.json --csv overview.csv
  
  # Limited workers
  python wase_complete.py --workers 4
        """
    )
    
    parser.add_argument('--targets', '-t', type=str,
                       help='File chứa targets (mỗi dòng 1 domain)')
    
    parser.add_argument('--json', '-j', type=str, default='wase_results.json',
                       help='JSON output file (default: wase_results.json)')
    
    parser.add_argument('--csv', '-c', type=str, default='wase_results.csv',
                       help='CSV output file (default: wase_results.csv)')
    
    parser.add_argument('--workers', '-w', type=int, default=8,
                       help='Số concurrent workers (default: 8)')
    
    args = parser.parse_args()
    
    # Kiểm tra targets file
    if args.targets and not os.path.exists(args.targets):
        print(f"❌ Không tìm thấy targets file: {args.targets}")
        return
    
    # Tạo và chạy pipeline
    pipeline = CompleteWASEPipeline(
        targets_file=args.targets,
        output_json=args.json,
        output_csv=args.csv,
        workers=args.workers
    )
    
    try:
        await pipeline.run()
    except KeyboardInterrupt:
        print("\n\n👋 Pipeline stopped by user")
    except Exception as e:
        print(f"\n❌ Pipeline error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Thiết lập event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n🛑 Program interrupted")
    finally:
        # Cleanup
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
    
    print("\n🏁 Program exited")