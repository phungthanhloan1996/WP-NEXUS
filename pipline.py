#!/usr/bin/env python3
"""
WORDPRESS ATTACK SURFACE ENGINE (WASE) v2.0 - ENHANCED VERSION
Integrated WPScan + Enhanced Enumeration + Attack Simulation
Chạy: python wase.py [--targets targets.txt] [--workers N] [--output results.json]
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
from urllib.parse import urlparse, urljoin, parse_qs, quote
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, AsyncGenerator, Tuple
from enum import Enum
import argparse
import warnings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import signal
import html
import base64

warnings.filterwarnings('ignore')

# =================== CONFIGURATION ===================
class Config:
    # General
    MAX_CONCURRENT_TASKS = 50
    EVENT_BUS_SIZE = 1000
    REQUEST_TIMEOUT = 10
    DNS_TIMEOUT = 2
    
    # Discovery
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
        'inurl:/wp-content/plugins/elementor/ site:.vn',
        'inurl:/wp-content/plugins/woocommerce/ site:.vn',
        'inurl:/wp-content/plugins/contact-form-7/ site:.vn',
        'inurl:/wp-content/plugins/revslider/ site:.vn',
        'site:.com.vn "WordPress"',
        'site:.vn inurl:wp-json',
        'site:.vn "xmlrpc.php"',
    ]
    
    # Enhanced Plugin Database với CVE và PoC
    POPULAR_PLUGINS = {
        # 🔥 SEO & CONTENT
        'yoast-seo': {
            'name': 'Yoast SEO', 
            'category': 'SEO', 
            'installs': '10M+',
            'vulnerabilities': [
                {'cve': 'CVE-2022-27230', 'severity': 'HIGH', 'fixed_version': '18.7'},
                {'cve': 'CVE-2021-25645', 'severity': 'MEDIUM', 'fixed_version': '16.5'}
            ]
        },
        'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
        'all-in-one-seo-pack': {'name': 'All in One SEO', 'category': 'SEO', 'installs': '3M+'},
        'seo-by-rank-math': {'name': 'Rank Math SEO', 'category': 'SEO', 'installs': '2M+'},
        
        # 🎨 PAGE BUILDERS
        'elementor': {
            'name': 'Elementor', 
            'category': 'Page Builder', 
            'installs': '10M+',
            'vulnerabilities': [
                {'cve': 'CVE-2022-3191', 'severity': 'CRITICAL', 'fixed_version': '3.7.2'},
                {'cve': 'CVE-2021-25070', 'severity': 'HIGH', 'fixed_version': '3.5.4'}
            ]
        },
        'beaver-builder-lite-version': {'name': 'Beaver Builder', 'category': 'Page Builder', 'installs': '1M+'},
        'siteorigin-panels': {'name': 'SiteOrigin Page Builder', 'category': 'Page Builder', 'installs': '1M+'},
        
        # 📝 FORMS
        'contact-form-7': {
            'name': 'Contact Form 7', 
            'category': 'Forms', 
            'installs': '10M+',
            'vulnerabilities': [
                {'cve': 'CVE-2020-35489', 'severity': 'MEDIUM', 'fixed_version': '5.3.2'}
            ]
        },
        'wpforms-lite': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
        
        # ⚡ CACHE & PERFORMANCE
        'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
        'wp-rocket': {'name': 'WP Rocket', 'category': 'Performance', 'installs': '2M+'},
        
        # 🛒 E-COMMERCE
        'woocommerce': {
            'name': 'WooCommerce', 
            'category': 'E-commerce', 
            'installs': '7M+',
            'vulnerabilities': [
                {'cve': 'CVE-2022-29599', 'severity': 'HIGH', 'fixed_version': '6.6.0'},
                {'cve': 'CVE-2022-2401', 'severity': 'MEDIUM', 'fixed_version': '6.7.0'}
            ]
        },
        
        # 🔐 SECURITY
        'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
        'better-wp-security': {'name': 'iThemes Security', 'category': 'Security', 'installs': '1M+'},
        
        # 📧 EMAIL
        'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
        
        # 🚨 VULNERABLE PLUGINS (KNOWN)
        'revslider': {
            'name': 'Revolution Slider',
            'category': 'Slider',
            'installs': '5M+',
            'vulnerabilities': [
                {'cve': 'CVE-2022-25640', 'severity': 'CRITICAL', 'fixed_version': '6.5.11'},
                {'cve': 'CVE-2018-11792', 'severity': 'CRITICAL', 'fixed_version': '5.4.8'}
            ]
        },
        'duplicator': {
            'name': 'Duplicator',
            'category': 'Migration',
            'installs': '1M+',
            'vulnerabilities': [
                {'cve': 'CVE-2020-11738', 'severity': 'HIGH', 'fixed_version': '1.3.28'}
            ]
        }
    }
    
    # PHP Version Vulnerabilities
    PHP_VULNERABILITIES = {
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
        },
        '8.2': {
            '<8.2.0': ['CVE-2023-0567', 'CVE-2023-0662'],
        }
    }
    
    # WordPress Core CVEs
    WORDPRESS_CVES = {
        '6.4': {'<6.4.1': ['CVE-2023-5360', 'CVE-2023-5361']},
        '6.3': {'<6.3.2': ['CVE-2023-4514', 'CVE-2023-4515']},
        '6.2': {'<6.2.3': ['CVE-2023-2795', 'CVE-2023-2796']},
        '6.1': {'<6.1.1': ['CVE-2023-28121', 'CVE-2023-28122']},
        '6.0': {'<6.0.5': ['CVE-2023-0031', 'CVE-2022-35945']},
        '5.9': {'<5.9.5': ['CVE-2022-35944', 'CVE-2022-35943']},
        '5.8': {'<5.8.5': ['CVE-2022-21662', 'CVE-2022-21661']},
    }
    
    # WPScan Database Integration
    WPVULNDB_API_KEY = ""  # Add your API key here
    WPSIGNATURES = {
        'wp_admin': '/wp-admin/',
        'wp_login': '/wp-login.php',
        'wp_content': '/wp-content/',
        'wp_includes': '/wp-includes/',
        'wp_json': '/wp-json/',
        'xmlrpc': '/xmlrpc.php',
        'readme': '/readme.html',
    }
    
    # Attack Simulation Patterns - CHỈ DÙNG ĐỂ PHÂN TÍCH, KHÔNG BẮN THẬT
    ATTACK_PATTERNS = {
        'sqli': ["'", "\"", "1' OR '1'='1", "1' OR '1'='1'--", "1' OR '1'='1'#"],
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"],
        'lfi': ["../../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"],
        'rce': [";id", "|id", "`id`", "$(id)"],
        'xxe': ["<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"],
    }

# =================== DATA STRUCTURES ===================
class EventType(Enum):
    RAW_DOMAIN = "raw_domain"
    CLEAN_DOMAIN = "clean_domain"
    WP_DETECTED = "wp_detected"
    TECH_PROFILE = "tech_profile"  # NEW: Tech profile separate from WP detection
    WP_PROFILE = "wp_profile"
    WP_VULN_PROFILE = "wp_vuln_profile"  # NEW: Separate vulnerability profile
    SURFACE_RESULT = "surface_result"
    RISK_SCORE = "risk_score"
    ATTACK_ANALYSIS = "attack_analysis"  # RENAMED: Analysis only, not simulation
    TRIAGE_RESULT = "triage_result"
    FINAL_RESULT = "final_result"

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
    """Event bus trung tâm cho streaming architecture"""
    
    def __init__(self, max_size=1000):
        self.queue = asyncio.Queue(maxsize=max_size)
        self.subscribers = defaultdict(list)
        self.stats = {'processed': 0, 'dropped': 0}
        self.is_running = False
        self.shutdown_event = asyncio.Event()
    
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
        print(f"[EventBus] Started")
        self.is_running = True
        
        while self.is_running and not self.shutdown_event.is_set():
            try:
                try:
                    event = await asyncio.wait_for(
                        self.queue.get(),
                        timeout=0.5
                    )
                except asyncio.TimeoutError:
                    continue
                
                if event.type in self.subscribers:
                    for callback in self.subscribers[event.type]:
                        asyncio.create_task(callback(event))
                
                self.queue.task_done()
                
            except asyncio.CancelledError:
                print("[EventBus] Cancelled!")
                break
            except Exception as e:
                print(f"[EventBus] Error: {e}")
        
        print("[EventBus] Stopped")
    
    async def stop(self):
        """Dừng event bus ngay lập tức"""
        print("[EventBus] Force stopping...")
        self.is_running = False
        self.shutdown_event.set()
        
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except:
                pass

# =================== GLOBAL SESSION MANAGER ===================
class SessionManager:
    """Global session management để tránh FD leak và optimize connections"""
    _sessions = {}
    _connector_pool = None
    
    @classmethod
    async def get_session(cls, name: str = "default") -> aiohttp.ClientSession:
        """Get or create a session with pooling"""
        if name not in cls._sessions or cls._sessions[name].closed:
            if cls._connector_pool is None:
                # Shared connector với limits
                cls._connector_pool = aiohttp.TCPConnector(
                    limit=100,  # Tổng connection limit
                    limit_per_host=20,  # Limit per domain
                    ssl=False,
                    force_close=False,
                    enable_cleanup_closed=True
                )
            
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            cls._sessions[name] = aiohttp.ClientSession(
                timeout=timeout,
                connector=cls._connector_pool,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
        
        return cls._sessions[name]
    
    @classmethod
    async def close_all(cls):
        """Close all sessions"""
        print("[SessionManager] Closing all sessions...")
        for name, session in list(cls._sessions.items()):
            if not session.closed:
                try:
                    await session.close()
                    print(f"[SessionManager] ✓ Closed session: {name}")
                except Exception as e:
                    print(f"[SessionManager] Error closing {name}: {e}")
        
        if cls._connector_pool is not None:
            try:
                await cls._connector_pool.close()
                print("[SessionManager] ✓ Closed connector pool")
            except Exception as e:
                print(f"[SessionManager] Error closing connector: {e}")

# =================== PHASE 0: SOURCE PRODUCERS ===================
class BaseProducer:
    """Base class cho tất cả producers"""
    
    def __init__(self, name: str, event_bus: AsyncEventBus):
        self.name = name
        self.event_bus = event_bus
        self.is_running = False
    
    async def start(self):
        """Bắt đầu producer"""
        self.is_running = True
        asyncio.create_task(self._produce_loop())
    
    async def stop(self):
        """Dừng producer"""
        self.is_running = False
    
    async def _produce_loop(self):
        """Override trong subclass"""
        pass

class TargetFileProducer(BaseProducer):
    """Producer từ file targets.txt"""
    
    def __init__(self, event_bus: AsyncEventBus, targets_file: str):
        super().__init__("TargetFileProducer", event_bus)
        self.targets_file = targets_file
    
    async def _produce_loop(self):
        """Thu thập domain từ targets file"""
        print(f"[{self.name}] Reading targets from {self.targets_file}")
        
        try:
            with open(self.targets_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not self.is_running:
                        break
                    
                    domain = line.strip()
                    if not domain or domain.startswith('#'):
                        continue
                    
                    event = Event(
                        type=EventType.RAW_DOMAIN,
                        data={'domain': domain, 'source': 'file', 'raw': domain},
                        source=self.name
                    )
                    await self.event_bus.publish(event)
                    
                    await asyncio.sleep(0.01)
        
        except Exception as e:
            print(f"[{self.name}] Error reading file: {e}")
        
        print(f"[{self.name}] Finished processing targets file")

class DorkProducer(BaseProducer):
    """Producer từ DuckDuckGo dorks"""
    
    def __init__(self, event_bus: AsyncEventBus):
        super().__init__("DorkProducer", event_bus)
    
    async def _produce_loop(self):
        """Thu thập domain từ dorks - GIỚI HẠN SỐ LƯỢNG"""
        print(f"[{self.name}] Starting dork-based discovery")
        
        try:
            from ddgs import DDGS
            self.ddgs = DDGS()
            
            max_domains_per_dork = 20  # 🆕 GIỚI HẠN
            processed_count = 0
            
            for dork in Config.DORKS:
                if not self.is_running or processed_count > 100:  # 🆕 TỔNG GIỚI HẠN
                    break
                
                print(f"[{self.name}] Processing dork: {dork[:50]}...")
                
                try:
                    results = self.ddgs.text(
                        query=dork,
                        region="vn-vn",
                        safesearch="off",
                        max_results=max_domains_per_dork,  # 🆕 GIỚI HẠN
                        timeout=8
                    )
                    
                    for result in results:
                        if not self.is_running:
                            break
                        
                        url = result.get('href', '') or result.get('url', '')
                        if url:
                            try:
                                parsed = urlparse(url)
                                domain = parsed.netloc.lower()
                                if domain.startswith('www.'):
                                    domain = domain[4:]
                                
                                event = Event(
                                    type=EventType.RAW_DOMAIN,
                                    data={'domain': domain, 'raw': url, 'dork': dork},
                                    source=self.name
                                )
                                await self.event_bus.publish(event)
                                
                                processed_count += 1
                                if processed_count % 10 == 0:
                                    print(f"[{self.name}] Processed {processed_count} domains...")
                                
                            except:
                                pass
                        
                        await asyncio.sleep(0.05)  # 🆕 GIẢM delay
                    
                    await asyncio.sleep(random.uniform(1, 2))  # 🆕 GIẢM delay
                    
                except Exception as e:
                    print(f"[{self.name}] Dork error: {e}")
                    await asyncio.sleep(2)
        
        except ImportError:
            print(f"[{self.name}] DDGS not available, skipping dork discovery")
        except Exception as e:
            print(f"[{self.name}] Error: {e}")

# =================== PHASE 1: PRE-FILTER ===================
class PreFilter:
    """Phase 1: Lọc nhanh, rẻ"""
    
    def __init__(self, event_bus: AsyncEventBus, history_file: str = "scanned_history.txt"):
        self.event_bus = event_bus
        self.seen_domains = set()
        self.dns_resolver = aiodns.DNSResolver()
        self.history_file = history_file
        self._load_history()
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RAW_DOMAIN, 
            self.process_raw_domain
        ))
    
    def _load_history(self):
        """Load domains đã scan từ file"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain:
                            self.seen_domains.add(domain)
                print(f"[PreFilter] ⏮️  Loaded {len(self.seen_domains)} scanned domains from history")
            except Exception as e:
                print(f"[PreFilter] Warning: {e}")
    
    def _save_to_history(self, domain: str):
        """Lưu domain vào file"""
        try:
            with open(self.history_file, 'a', encoding='utf-8') as f:
                f.write(f"{domain}\n")
        except:
            pass
    
    async def process_raw_domain(self, event: Event):
        """Xử lý raw domain event"""
        domain = event.data.get('domain', '')
        
        # 1. Dedup toàn cục
        if domain in self.seen_domains:
            return
        self.seen_domains.add(domain)
        
        # 2. Normalize và validate
        normalized = self.normalize_domain(domain)
        if not normalized:
            return
        
        # 3. DNS resolve nhanh
        is_resolvable = await self.quick_dns_check(normalized)
        if not is_resolvable:
            return
        
        self._save_to_history(normalized)
        
        # 4. Tạo clean domain event
        clean_event = Event(
            type=EventType.CLEAN_DOMAIN,
            data={
                'domain': normalized,
                'original': domain,
                'source': event.source,
                'timestamp': time.time()
            },
            source="PreFilter"
        )
        
        await self.event_bus.publish(clean_event)
    
    def normalize_domain(self, domain: str) -> Optional[str]:
        """Normalize domain"""
        try:
            # 🆕 BLACKLIST NGAY TỪ ĐẦU
            common_non_wp = [
                'medium.com', 'github.com', 'twitter.com', 
                'facebook.com', 'youtube.com', 'linkedin.com',
                'wordpress.com', 'blogger.com', 'tumblr.com',
                'wixsite.com', 'weebly.com', 'shopify.com',
                'squarespace.com', 'blogspot.com', 'reddit.com',
                'stackoverflow.com', 'amazon.com', 'google.com',
                'microsoft.com', 'apple.com'
            ]
            
            domain_lower = domain.lower()
            for non_wp in common_non_wp:
                if non_wp in domain_lower:
                    return None
            
            if '://' in domain:
                parsed = urlparse(domain)
                domain = parsed.netloc
            
            domain = domain.lower().replace("www.", "")
            
            if ':' in domain:
                domain = domain.split(':')[0]
            
            if not re.match(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$', domain):
                return None
            
            cdn_keywords = ['cdn', 'cloudfront', 'akamai', 'fastly', 'cloudflare']
            if any(kw in domain for kw in cdn_keywords):
                return None
            
            if domain.count('.') > 4:
                return None
            
            return domain
            
        except:
            return None
    
    async def quick_dns_check(self, domain: str) -> bool:
        try:
            # Thử A record
            try:
                await asyncio.wait_for(
                    self.dns_resolver.query(domain, 'A'),
                    timeout=Config.DNS_TIMEOUT
                )
                return True
            except:
                pass

            # Thử AAAA
            try:
                await asyncio.wait_for(
                    self.dns_resolver.query(domain, 'AAAA'),
                    timeout=Config.DNS_TIMEOUT
                )
                return True
            except:
                pass

            # ❗ Cho qua DNS fail → để HTTP quyết định
            return True
        except:
            return True

# =================== PHASE 2: WP GATE DETECTOR ===================
class WPGateDetector:
    """Phase 2: Phát hiện WordPress sớm"""
    
    def __init__(self, event_bus: AsyncEventBus, workers: int = 8):
        self.event_bus = event_bus
        self.session = None
        self.semaphore = asyncio.Semaphore(workers)
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.CLEAN_DOMAIN,
            self.process_clean_domain
        ))
    
    async def get_session(self):
        return await SessionManager.get_session("wp_detector")
    
    async def process_clean_domain(self, event: Event):
        async with self.semaphore:
            domain = event.data['domain']
            
            session = await self.get_session()
            
            probes = [
                self.probe_homepage(session, domain),
                self.probe_wp_login(session, domain),
                self.probe_wp_content(session, domain),
                self.probe_wp_json(session, domain),
            ]
            
            results = await asyncio.gather(*probes, return_exceptions=True)
            http_alive = not isinstance(results[0], Exception)

            confidence = 0
            signals = []

            for i, result in enumerate(results):
                if isinstance(result, dict) and result.get('detected'):
                    confidence += 25
                    signals.append(result.get('signal', f'probe_{i}'))

            if confidence == 0 and http_alive:
                confidence = 10
                signals.append("http_alive_stealth")

            is_wp = confidence >= 25

            if confidence == 0:
                print(f"[NON-WP] {domain}")
            elif 0 < confidence < 50:
                print(f"[WP?][LOW] {domain} confidence={confidence} signals={signals}")
            else:
                print(f"[WP][DETECTED] {domain} confidence={confidence} signals={signals}")

            wp_event = Event(
                type=EventType.WP_DETECTED,
                data={
                    'domain': domain,
                    'is_wp': is_wp,
                    'confidence': min(confidence, 100),
                    'signals': signals,
                    'timestamp': time.time()
                },
                source="WPGateDetector"
            )
            
            await self.event_bus.publish(wp_event)
    
    async def probe_homepage(self, session, domain: str) -> Dict:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        if resp.status < 400:
                            html = await resp.text()
                            
                            signals = []
                            if '/wp-content/' in html:
                                signals.append('wp_content_structure')
                            if '/wp-includes/' in html:
                                signals.append('wp_includes')
                            if 'wordpress' in html.lower() and 'generator' in html.lower():
                                signals.append('meta_generator')
                            
                            return {
                                'detected': len(signals) > 0,
                                'signal': 'homepage',
                                'signals': signals
                            }
                except:
                    continue
        except Exception as e:
            pass
        
        return {'detected': False}
    
    async def probe_wp_login(self, session, domain: str) -> Dict:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-login.php"
                try:
                    async with session.head(url, allow_redirects=False, ssl=False) as resp:
                        if resp.status < 400:
                            return {
                                'detected': True,
                                'signal': 'wp_login',
                                'status': resp.status
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False}
    
    async def probe_wp_content(self, session, domain: str) -> Dict:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/"
                try:
                    async with session.head(url, allow_redirects=False, ssl=False) as resp:
                        if resp.status < 400:
                            return {
                                'detected': True,
                                'signal': 'wp_content',
                                'status': resp.status
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False}
    
    async def probe_wp_json(self, session, domain: str) -> Dict:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/"
                try:
                    async with session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            return {
                                'detected': True,
                                'signal': 'wp_json',
                                'status': resp.status
                            }
                except:
                    continue
        except:
            pass
        
        return {'detected': False}

# =================== PHASE 3: TECH STACK PROFILING (CHẠY SAU WP DETECT) ===================
class TechStackProfiler:
    """Phase 3: Profiling công nghệ sử dụng - CHỈ CHẠY KHI CÓ WP"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_DETECTED,
            self.process_wp_domain
        ))
    
    async def get_session(self):
        return await SessionManager.get_session("tech_profiler")
    
    async def process_wp_domain(self, event: Event):
        """Chỉ profile tech stack nếu là WP với confidence đủ cao"""
        if not event.data['is_wp'] or event.data['confidence'] < 50:
            return
        
        domain = event.data['domain']
        
        session = await self.get_session()
        
        tasks = [
            self.detect_server(session, domain),
            self.detect_php(session, domain),
            self.detect_js_frameworks(session, domain),
            self.detect_waf_cdn(session, domain),
            self.detect_cloud_hosting(session, domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        tech_profile = {
            'domain': domain,
            'server': results[0] if not isinstance(results[0], Exception) else {},
            'php': results[1] if not isinstance(results[1], Exception) else {},
            'js_frameworks': results[2] if not isinstance(results[2], Exception) else [],
            'waf': results[3] if not isinstance(results[3], Exception) else None,
            'cdn': results[4] if not isinstance(results[4], Exception) else None,
            'timestamp': time.time()
        }
        
        # Publish TECH_PROFILE thay vì WP_DETECTED
        await self.event_bus.publish(Event(
            type=EventType.TECH_PROFILE,
            data={
                'domain': domain,
                'tech_profile': tech_profile,
                'wp_confidence': event.data['confidence']
            },
            source="TechStackProfiler"
        ))
    
    async def detect_server(self, session, domain: str) -> Dict:
        """Detect web server"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.head(url, ssl=False) as resp:
                    server_header = resp.headers.get('Server', '').lower()
                    
                    server_info = {'name': 'unknown', 'version': None}
                    
                    if 'apache' in server_header:
                        server_info['name'] = 'Apache'
                        match = re.search(r'apache/([\d\.]+)', server_header)
                        if match:
                            server_info['version'] = match.group(1)
                    elif 'nginx' in server_header:
                        server_info['name'] = 'Nginx'
                        match = re.search(r'nginx/([\d\.]+)', server_header)
                        if match:
                            server_info['version'] = match.group(1)
                    elif 'iis' in server_header or 'microsoft-iis' in server_header:
                        server_info['name'] = 'IIS'
                        match = re.search(r'iis/([\d\.]+)', server_header)
                        if match:
                            server_info['version'] = match.group(1)
                    elif 'litespeed' in server_header:
                        server_info['name'] = 'LiteSpeed'
                    
                    return server_info
            except:
                continue
        return {}
    
    async def detect_php(self, session, domain: str) -> Dict:
        """Detect PHP version"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.head(url, ssl=False) as resp:
                    powered_by = resp.headers.get('X-Powered-By', '').lower()
                    
                    if 'php' in powered_by:
                        match = re.search(r'php/([\d\.]+)', powered_by)
                        if match:
                            return {'version': match.group(1), 'method': 'header'}
                    
                    # Try PHP info
                    phpinfo_url = f"{scheme}{domain}/phpinfo.php"
                    try:
                        async with session.get(phpinfo_url, timeout=3, ssl=False) as php_resp:
                            if php_resp.status == 200:
                                text = await php_resp.text()
                                if 'php version' in text.lower():
                                    match = re.search(r'php version\s*<[^>]+>([\d\.]+)', text, re.IGNORECASE)
                                    if match:
                                        return {'version': match.group(1), 'method': 'phpinfo'}
                    except:
                        pass
            except:
                continue
        return {}
    
    async def detect_js_frameworks(self, session, domain: str) -> List[str]:
        """Detect JavaScript frameworks"""
        frameworks = []
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        
                        if 'react' in html.lower() or 'react-dom' in html:
                            frameworks.append('React')
                        if 'vue' in html.lower() or 'vue.js' in html:
                            frameworks.append('Vue.js')
                        if 'angular' in html.lower():
                            frameworks.append('Angular')
                        if 'jquery' in html.lower():
                            frameworks.append('jQuery')
                        if 'webpack' in html.lower():
                            frameworks.append('Webpack')
                        if 'vite' in html.lower():
                            frameworks.append('Vite')
                        
                        break
            except:
                continue
        
        return list(set(frameworks))
    
    async def detect_waf_cdn(self, session, domain: str) -> Optional[str]:
        """Detect WAF/CDN"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.head(url, ssl=False) as resp:
                    headers = resp.headers
                    
                    # Check common WAF/CDN headers
                    if 'server' in headers:
                        server = headers['server'].lower()
                        if 'cloudflare' in server:
                            return 'Cloudflare'
                        elif 'akamai' in server:
                            return 'Akamai'
                        elif 'sucuri' in server:
                            return 'Sucuri'
                        elif 'imperva' in server:
                            return 'Imperva'
                    
                    if 'x-sucuri-id' in headers:
                        return 'Sucuri'
                    if 'x-waf-event' in headers:
                        return 'Wordfence'
                    if 'cf-ray' in headers:
                        return 'Cloudflare'
                    
            except:
                continue
        
        return None
    
    async def detect_cloud_hosting(self, session, domain: str) -> Optional[str]:
        """Detect cloud hosting"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.head(url, ssl=False) as resp:
                    headers = resp.headers
                    
                    # Check headers for cloud providers
                    if 'x-amz-cf-id' in headers:
                        return 'AWS CloudFront'
                    if 'x-azure-ref' in headers:
                        return 'Azure'
                    if 'x-guploader-uploadid' in headers:
                        return 'Google Cloud'
                    if 'cf-cache-status' in headers:
                        return 'Cloudflare'
                    
                    # Check server header
                    server = headers.get('server', '').lower()
                    if 'ecs' in server:
                        return 'AWS'
                    if 'gws' in server:
                        return 'Google'
                    if 'edge' in server:
                        return 'Cloudflare'
                    
            except:
                continue
        
        return None

# =================== PHASE 4: WP CORE FINGERPRINT ===================
class WPCoreFingerprint:
    """Phase 4: Lấy thông tin core WordPress"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.TECH_PROFILE,  # Changed: Subscribe to TECH_PROFILE instead of WP_DETECTED
            self.process_wp_domain
        ))
    
    async def get_session(self):
        return await SessionManager.get_session("wp_fingerprint")
    
    async def process_wp_domain(self, event: Event):
        domain = event.data['domain']
        
        session = await self.get_session()
        
        tasks = [
            self.get_wp_version(session, domain),
            self.get_theme_info(session, domain),
            self.get_server_info(session, domain),
            self.check_xmlrpc(session, domain),
            self.check_rest_api(session, domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        wp_profile = {
            'domain': domain,
            'confidence': event.data.get('wp_confidence', 50),
            'wp_version': results[0] if not isinstance(results[0], Exception) else None,
            'theme': results[1] if not isinstance(results[1], Exception) else None,
            'server': results[2] if not isinstance(results[2], Exception) else None,
            'xmlrpc': results[3] if not isinstance(results[3], Exception) else False,
            'rest_api': results[4] if not isinstance(results[4], Exception) else False,
            'tech_profile': event.data.get('tech_profile', {}),
            'timestamp': time.time()
        }
        
        surfaces = []
        if wp_profile['wp_version']:
            surfaces.append("version")
        if wp_profile['theme']:
            surfaces.append("theme")
        if wp_profile['xmlrpc']:
            surfaces.append("xmlrpc")
        if wp_profile['rest_api']:
            surfaces.append("rest")

        surface_str = ",".join(surfaces) if surfaces else "no-surface"
        print(f"[WP][OK] {domain} | {surface_str}")

        try:
            with open("scanned_wp_targets.txt", "a") as f:
                f.write(domain + "\n")
        except Exception:
            pass

        profile_event = Event(
            type=EventType.WP_PROFILE,
            data=wp_profile,
            source="WPCoreFingerprint"
        )
        
        await self.event_bus.publish(profile_event)
    
    async def get_wp_version(self, session, domain: str) -> Optional[str]:
        version_candidates = []
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.get(url, ssl=False, timeout=8) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        
                        patterns = [
                            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)["\']',
                            r'content=["\']WordPress\s+([\d.]+)["\'][^>]+name=["\']generator["\']',
                            r'generator=["\']WordPress\s+([\d.]+)["\']',
                            r'(?:wp-embed|wp-emoji|wp-api)\.js\?ver=([\d.]+)',
                            r'src="[^"]+ver=([\d.]+)"[^>]*wp-embed',
                            r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
                            r'generator="WordPress/([\d.]+)"',
                            r'<!--[^>]*WordPress\s+([\d.]+)[^>]*-->',
                            r'WordPress\s+([\d.]+)',
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            version_candidates.extend(matches)
                        
                        break
            except:
                continue
        
        if version_candidates:
            valid_versions = []
            for v in version_candidates:
                if self._is_valid_version(v):
                    valid_versions.append(v)
            
            if valid_versions:
                counter = Counter(valid_versions)
                most_common = counter.most_common(1)[0]
                return most_common[0]
        
        return None
    
    def _is_valid_version(self, version: str) -> bool:
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
        
        if int(parts[0]) > 10:
            return False
        
        return True
    
    async def get_theme_info(self, session, domain: str) -> Optional[Dict]:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            
                            match = re.search(r'/wp-content/themes/([^/]+)/', html)
                            if match:
                                theme_slug = match.group(1)
                                return {'slug': theme_slug, 'name': theme_slug}
                except:
                    continue
        except:
            pass
        
        return None
    
    async def get_server_info(self, session, domain: str) -> Optional[Dict]:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with session.head(url, ssl=False) as resp:
                        server_info = {
                            'server': resp.headers.get('Server', ''),
                            'php': resp.headers.get('X-Powered-By', ''),
                        }
                        return server_info
                except:
                    continue
        except:
            pass
        
        return None
    
    async def check_xmlrpc(self, session, domain: str) -> bool:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/xmlrpc.php"
                try:
                    async with session.head(url, ssl=False) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False
    
    async def check_rest_api(self, session, domain: str) -> bool:
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/wp/v2/"
                try:
                    async with session.head(url, ssl=False) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False

# =================== WPScan INTEGRATION ===================
class WPScanIntegration:
    """WPScan-like vulnerability scanning"""
    
    def __init__(self, event_bus: AsyncEventBus, api_key: str = ""):
        self.event_bus = event_bus
        self.api_key = api_key or Config.WPVULNDB_API_KEY
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_PROFILE,
            self.scan_vulnerabilities
        ))
    
    async def get_session(self):
        return await SessionManager.get_session("wpscan")
    
    async def scan_vulnerabilities(self, event: Event):
        """Scan vulnerabilities WPScan style"""
        profile = event.data
        domain = profile['domain']
        
        session = await self.get_session()
        
        # Collect data for vulnerability checking
        wp_version = profile.get('wp_version')
        theme_slug = profile.get('theme', {}).get('slug') if isinstance(profile.get('theme'), dict) else None
        
        # Check vulnerabilities
        tasks = [
            self.check_wp_core_vulns(session, wp_version),
            self.check_theme_vulns(session, theme_slug),
            self.enumerate_plugins_vulns(session, domain),
            self.check_user_enumeration(session, domain),
            self.check_file_exposure(session, domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        vuln_report = {
            'domain': domain,
            'core_vulnerabilities': results[0] if not isinstance(results[0], Exception) else [],
            'theme_vulnerabilities': results[1] if not isinstance(results[1], Exception) else [],
            'plugin_vulnerabilities': results[2] if not isinstance(results[2], Exception) else {},
            'user_enumeration': results[3] if not isinstance(results[3], Exception) else {},
            'file_exposure': results[4] if not isinstance(results[4], Exception) else {},
            'timestamp': time.time()
        }
        
        # Publish WP_VULN_PROFILE thay vì WP_PROFILE
        await self.event_bus.publish(Event(
            type=EventType.WP_VULN_PROFILE,
            data={
                'domain': domain,
                'wp_profile': profile,
                'vulnerability_report': vuln_report
            },
            source="WPScanIntegration"
        ))
    
    async def check_wp_core_vulns(self, session, wp_version: Optional[str]) -> List[Dict]:
        """Check WordPress core vulnerabilities"""
        if not wp_version:
            return []
        
        vulns = []
        
        # Check against known CVEs
        for version_range, cve_list in Config.WORDPRESS_CVES.items():
            if self._is_version_in_range(wp_version, version_range):
                if isinstance(cve_list, dict):
                    for sub_range, sub_cves in cve_list.items():
                        if self._is_version_in_range(wp_version, sub_range):
                            for cve in sub_cves:
                                vulns.append({
                                    'cve': cve,
                                    'type': 'core',
                                    'severity': self._estimate_severity(cve),
                                    'affected_version': wp_version,
                                    'fixed_version': sub_range[1:] if sub_range.startswith('<') else 'latest'
                                })
        
        # Try WPVulnDB API if key available
        if self.api_key:
            try:
                url = f"https://wpscan.com/api/v3/wordpresses/{wp_version}"
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if wp_version in data:
                            for vuln in data[wp_version].get('vulnerabilities', []):
                                vulns.append({
                                    'cve': vuln.get('cve', ''),
                                    'type': 'core',
                                    'severity': vuln.get('severity', 'medium'),
                                    'title': vuln.get('title', ''),
                                    'fixed_in': vuln.get('fixed_in', '')
                                })
            except:
                pass
        
        return vulns
    
    async def check_theme_vulns(self, session, theme_slug: Optional[str]) -> List[Dict]:
        """Check theme vulnerabilities"""
        if not theme_slug:
            return []
        
        vulns = []
        
        # Check against known vulnerable themes
        vulnerable_themes = {
            'twentyseventeen': [],
            'twentysixteen': [],
            'twentytwenty': [],
        }
        
        if theme_slug in vulnerable_themes:
            vulns.append({
                'theme': theme_slug,
                'type': 'theme',
                'severity': 'medium',
                'description': f'Known vulnerable theme: {theme_slug}'
            })
        
        # WPVulnDB API check
        if self.api_key:
            try:
                url = f"https://wpscan.com/api/v3/themes/{theme_slug}"
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if theme_slug in data:
                            for vuln in data[theme_slug].get('vulnerabilities', []):
                                vulns.append({
                                    'cve': vuln.get('cve', ''),
                                    'type': 'theme',
                                    'severity': vuln.get('severity', 'medium'),
                                    'title': vuln.get('title', ''),
                                    'fixed_in': vuln.get('fixed_in', '')
                                })
            except:
                pass
        
        return vulns
    
    async def enumerate_plugins_vulns(self, session, domain: str) -> Dict:
        """Enumerate plugins and check vulnerabilities"""
        plugins = {}
        
        # Quick plugin enumeration
        for plugin_slug in list(Config.POPULAR_PLUGINS.keys())[:20]:  # Limit for speed
            exists = await self._check_plugin_exists(session, domain, plugin_slug)
            if exists:
                plugin_info = Config.POPULAR_PLUGINS.get(plugin_slug, {})
                plugins[plugin_slug] = {
                    'name': plugin_info.get('name', plugin_slug),
                    'vulnerabilities': plugin_info.get('vulnerabilities', []),
                    'category': plugin_info.get('category', 'unknown')
                }
        
        return plugins
    
    async def _check_plugin_exists(self, session, domain: str, plugin_slug: str) -> bool:
        """Check if plugin exists"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/"
            try:
                async with session.head(url, timeout=2, ssl=False) as resp:
                    if resp.status < 400:
                        return True
            except:
                continue
        
        return False
    
    async def check_user_enumeration(self, session, domain: str) -> Dict:
        """Check user enumeration vulnerabilities"""
        results = {
            'rest_api': False,
            'author_archives': False,
            'oembed': False,
            'users': []
        }
        
        # Check REST API users endpoint
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-json/wp/v2/users"
            try:
                async with session.get(url, timeout=3, ssl=False) as resp:
                    if resp.status == 200:
                        results['rest_api'] = True
                        try:
                            users = await resp.json()
                            if isinstance(users, list):
                                results['users'].extend([u.get('slug', '') for u in users[:5]])
                        except:
                            pass
            except:
                pass
        
        # Check author archives
        for i in range(1, 4):
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/?author={i}"
                try:
                    async with session.get(url, allow_redirects=True, timeout=3, ssl=False) as resp:
                        final_url = str(resp.url)
                        if '/author/' in final_url:
                            results['author_archives'] = True
                            match = re.search(r'/author/([^/]+)/?', final_url)
                            if match and match.group(1) not in results['users']:
                                results['users'].append(match.group(1))
                            break
                except:
                    continue
        
        return results
    
    async def check_file_exposure(self, session, domain: str) -> Dict:
        """Check file exposure vulnerabilities"""
        exposed_files = []
        
        files_to_check = [
            'wp-config.php',
            'wp-config.php.bak',
            'wp-config.php.backup',
            'debug.log',
            'readme.html',
            'license.txt',
            'xmlrpc.php',
            'wp-admin/install.php',
        ]
        
        for file_path in files_to_check:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/{file_path}"
                try:
                    async with session.head(url, timeout=2, ssl=False) as resp:
                        if resp.status == 200:
                            exposed_files.append(file_path)
                            break
                except:
                    continue
        
        return {'exposed_files': exposed_files}
    
    def _is_version_in_range(self, version: str, version_range: str) -> bool:
        """Check if version is in range"""
        try:
            if version_range.startswith('<'):
                max_ver = version_range[1:]
                return self._compare_versions(version, max_ver) < 0
            else:
                return version.startswith(version_range)
        except:
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare version strings"""
        try:
            v1_parts = list(map(int, v1.split('.')[:3]))
            v2_parts = list(map(int, v2.split('.')[:3]))
            
            while len(v1_parts) < 3:
                v1_parts.append(0)
            while len(v2_parts) < 3:
                v2_parts.append(0)
            
            for i in range(3):
                if v1_parts[i] != v2_parts[i]:
                    return v1_parts[i] - v2_parts[i]
            return 0
        except:
            return 0
    
    def _estimate_severity(self, cve: str) -> str:
        """Estimate severity from CVE"""
        if not cve:
            return 'medium'
        
        cve_year = cve.split('-')[1] if '-' in cve else ''
        if cve_year:
            try:
                year = int(cve_year)
                # More recent CVEs might be more severe
                if year >= 2022:
                    return 'high'
            except:
                pass
        
        return 'medium'

# =================== PHASE 5: ENHANCED ATTACK SURFACE ===================
class EnhancedAttackSurfaceEnumerator:
    """Phase 5: Deep attack surface enumeration"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.active_resolvers = []
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_VULN_PROFILE,  # Changed: Subscribe to WP_VULN_PROFILE
            self.deep_enumeration
        ))
    
    async def get_session(self):
        return await SessionManager.get_session("surface_enumerator")
    
    async def deep_enumeration(self, event: Event):
        profile_data = event.data
        wp_profile = profile_data['wp_profile']
        vuln_report = profile_data['vulnerability_report']
        
        domain = wp_profile['domain']
        
        session = await self.get_session()
        
        # Initialize resolvers
        plugin_resolver = PluginVersionResolver(session, domain)
        theme_resolver = ThemeVersionResolver(session, domain)
        php_detector = PHPVersionDetector(session, domain)
        
        self.active_resolvers.extend([plugin_resolver, theme_resolver, php_detector])
        
        # Run all enumerations
        tasks = [
            self.deep_plugin_enumeration(session, domain, plugin_resolver),
            self.deep_theme_enumeration(session, domain, theme_resolver),
            self.enumerate_users(session, domain),
            self.check_uploads(session, domain),
            self.check_debug_log(session, domain),
            self.enumerate_rest_routes(session, domain),
            php_detector.detect(),
            self.check_wp_config(session, domain),
            self.check_backup_files(session, domain),
            self.check_xmlrpc_methods(session, domain),
            self.check_admin_paths(session, domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        surfaces = {
            'domain': domain,
            'plugins': results[0] if not isinstance(results[0], Exception) else [],
            'themes': results[1] if not isinstance(results[1], Exception) else [],
            'users': results[2] if not isinstance(results[2], Exception) else [],
            'uploads_listing': results[3] if not isinstance(results[3], Exception) else False,
            'debug_log': results[4] if not isinstance(results[4], Exception) else False,
            'rest_routes': results[5] if not isinstance(results[5], Exception) else [],
            'php_info': results[6] if not isinstance(results[6], Exception) else {},
            'wp_config_exposed': results[7] if not isinstance(results[7], Exception) else False,
            'backup_files': results[8] if not isinstance(results[8], Exception) else [],
            'xmlrpc_methods': results[9] if not isinstance(results[9], Exception) else [],
            'admin_paths': results[10] if not isinstance(results[10], Exception) else [],
            'wp_version': wp_profile.get('wp_version'),
            'xmlrpc': wp_profile.get('xmlrpc', False),
            'rest_api': wp_profile.get('rest_api', False),
            'server_info': wp_profile.get('server', {}),
            'wpscan_report': vuln_report,
            'timestamp': time.time()
        }
        
        surfaces['initial_risk_score'] = self._calculate_initial_risk(surfaces)
        
        surface_event = Event(
            type=EventType.SURFACE_RESULT,
            data=surfaces,
            source="EnhancedAttackSurfaceEnumerator"
        )
        
        await self.event_bus.publish(surface_event)
    
    async def deep_plugin_enumeration(self, session, domain: str, resolver) -> List[Dict]:
        plugins = []
        
        detected_slugs = await self._detect_plugin_presence(session, domain)
        
        for plugin_slug in detected_slugs[:15]:
            try:
                version_result = await resolver.resolve(plugin_slug)
                
                plugin_info = Config.POPULAR_PLUGINS.get(plugin_slug, {})
                
                plugin_data = {
                    'slug': plugin_slug,
                    'name': plugin_info.get('name', plugin_slug),
                    'category': plugin_info.get('category', 'unknown'),
                    'installs': plugin_info.get('installs', 'unknown'),
                    'version': version_result.version,
                    'version_confidence': version_result.confidence,
                    'version_method': version_result.method,
                    'vulnerabilities': plugin_info.get('vulnerabilities', []),
                    'vulnerability_count': len(plugin_info.get('vulnerabilities', [])),
                    'risk_level': 'HIGH' if plugin_info.get('vulnerabilities') else 'LOW',
                    'detected': True,
                    'evidence': version_result.evidence[:100] if version_result.evidence else None,
                }
                
                plugins.append(plugin_data)
                
                if version_result.version:
                    print(f"\r\033[K\033[92m✓ Plugin\033[0m {plugin_slug:<25} v{version_result.version} "
                          f"(confidence: {version_result.confidence}%)")
                else:
                    print(f"\r\033[K\033[93m? Plugin\033[0m {plugin_slug:<25} (no version)")
                    
            except Exception as e:
                print(f"\r\033[K\033[91m✗ Plugin error\033[0m {plugin_slug}: {str(e)[:30]}")
                continue
        
        return plugins
    
    async def _detect_plugin_presence(self, session, domain: str) -> List[str]:
        """Detect which plugins are present với timeout ngắn hơn"""
        detected = []
        popular_plugins = list(Config.POPULAR_PLUGINS.keys())
        
        # 🆕 GIẢM: Chỉ check 10 plugins phổ biến nhất
        popular_plugins = popular_plugins[:10]
        
        batch_size = 3  # 🆕 GIẢM batch size
        max_total_time = 30  # 🆕 GIẢM thời gian tổng
        
        start_time = time.time()
        
        for i in range(0, len(popular_plugins), batch_size):
            elapsed = time.time() - start_time
            if elapsed > max_total_time:
                break
            
            batch = popular_plugins[i:i+batch_size]
            
            try:
                # 🆕 Timeout ngắn hơn
                tasks = [self._check_single_plugin(session, domain, slug) for slug in batch]
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=3.0  # 🆕 GIẢM timeout
                )
                
                for j, result in enumerate(results):
                    if isinstance(result, bool) and result:
                        detected.append(batch[j])
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
            
            await asyncio.sleep(0.05)  # 🆕 GIẢM delay
        
        return detected
    
    async def _check_single_plugin(self, session, domain: str, plugin_slug: str) -> bool:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/"
            try:
                async with session.head(url, timeout=3, ssl=False) as resp:
                    if resp.status < 400:
                        return True
            except:
                continue
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/readme.txt"
            try:
                async with session.head(url, timeout=3, ssl=False) as resp:
                    if resp.status < 400:
                        return True
            except:
                continue
        
        return False
    
    async def deep_theme_enumeration(self, session, domain: str, resolver) -> List[Dict]:
        themes = []
        
        active_theme = await self._detect_active_theme(session, domain)
        if active_theme:
            version_result = await resolver.resolve(active_theme)
            
            theme_data = {
                'slug': active_theme,
                'name': active_theme.replace('-', ' ').title(),
                'version': version_result.version,
                'version_confidence': version_result.confidence,
                'version_method': version_result.method,
                'is_active': True,
                'evidence': version_result.evidence,
            }
            themes.append(theme_data)
        
        return themes
    
    async def _detect_active_theme(self, session, domain: str) -> Optional[str]:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text(encoding='utf-8', errors='ignore')
                        
                        patterns = [
                            r'/wp-content/themes/([^/]+)/',
                            r'theme_name["\']\s*:\s*["\']([^"\']+)["\']',
                            r'theme["\']\s*:\s*["\']([^"\']+)["\']',
                        ]
                        
                        for pattern in patterns:
                            match = re.search(pattern, html, re.IGNORECASE)
                            if match:
                                return match.group(1).lower()
            except:
                continue
        return None
    
    async def enumerate_users(self, session, domain):
        users = []
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-json/wp/v2/users?per_page=20"
            try:
                async with session.get(url, ssl=False, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, list):
                            for u in data:
                                if isinstance(u, dict) and 'slug' in u and u['slug']:
                                    users.append({
                                        "id": u.get("id"),
                                        "slug": u.get("slug"),
                                        "name": u.get("name"),
                                        "source": "wp-json"
                                    })
                            if users:
                                return users
            except Exception as e:
                pass
        
        seen_slugs = set()
        for i in range(1, 11):
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/?author={i}"
                try:
                    async with session.get(url, allow_redirects=True, 
                                           ssl=False, timeout=5) as resp:
                        final_url = str(resp.url)
                        
                        m = re.search(r'/author/([a-zA-Z0-9_-]+)/?', final_url)
                        if m:
                            slug = m.group(1).lower()
                            
                            blacklist = ['page', 'author', 'user', 'admin', 
                                       'login', 'wp-admin', 'feed', 'rss',
                                       'comments', 'index', 'home']
                            
                            if (slug not in blacklist and 
                                slug not in seen_slugs and 
                                len(slug) >= 3 and
                                not slug.isdigit()):
                                
                                seen_slugs.add(slug)
                                users.append({
                                    "id": i,
                                    "slug": slug,
                                    "source": "author_redirect"
                                })
                                break
                except:
                    continue
        
        return users
    
    async def check_uploads(self, session, domain: str) -> bool:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/uploads/"
            try:
                async with session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text(encoding='utf-8', errors='ignore')
                        if 'index of' in text.lower() or '<title>Index of' in text:
                            return True
            except:
                continue
        return False
    
    async def check_debug_log(self, session, domain: str) -> bool:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/debug.log"
            try:
                async with session.head(url, timeout=3, ssl=False) as resp:
                    return resp.status == 200
            except:
                continue
        return False
    
    async def enumerate_rest_routes(self, session, domain: str) -> List[str]:
        routes = []
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-json/"
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'routes' in data:
                            routes = list(data['routes'].keys())[:10]
            except:
                continue
        return routes
    
    async def check_wp_config(self, session, domain: str) -> bool:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-config.php"
            try:
                async with session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        if 'DB_NAME' in content or 'define(' in content:
                            return True
            except:
                continue
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-config-sample.php"
            try:
                async with session.get(url, timeout=4, ssl=False) as resp:
                    return resp.status == 200
            except:
                continue
        
        return False
    
    async def check_backup_files(self, session, domain: str) -> List[str]:
        """Check for backup files"""
        backup_patterns = [
            'wp-config.php.bak',
            'wp-config.php.backup',
            '.sql',
            '.tar.gz',
            '.zip',
            'backup-',
        ]
        
        found_backups = []
        
        for pattern in backup_patterns[:5]:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/{pattern}"
                try:
                    async with session.head(url, timeout=3, ssl=False) as resp:
                        if resp.status == 200:
                            found_backups.append(pattern)
                            break
                except:
                    continue
        
        return found_backups
    
    async def check_xmlrpc_methods(self, session, domain: str) -> List[str]:
        methods = []
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/xmlrpc.php"
            try:
                xml_request = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>"""
                
                headers = {'Content-Type': 'text/xml'}
                async with session.post(url, data=xml_request, headers=headers, 
                                       timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if 'methodName' in content:
                            method_pattern = r'<value><string>([^<]+)</string></value>'
                            found = re.findall(method_pattern, content)
                            methods.extend(found)
            except:
                continue
        
        return methods
    
    async def check_admin_paths(self, session, domain: str) -> List[str]:
        admin_paths = [
            'wp-admin/',
            'wp-admin/admin.php',
            'wp-admin/admin-ajax.php',
            'wp-admin/install.php',
            'wp-admin/upgrade.php',
            'admin/',
            'administrator/',
            'backend/',
            'cp/',
        ]
        
        accessible_paths = []
        
        for path in admin_paths:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/{path}"
                try:
                    async with session.head(url, timeout=2, ssl=False) as resp:
                        if resp.status < 400:
                            accessible_paths.append(path)
                            break
                except:
                    continue
        
        return accessible_paths
    
    def _calculate_initial_risk(self, surfaces: Dict) -> int:
        score = 0
        
        for plugin in surfaces.get('plugins', []):
            vuln_count = plugin.get('vulnerability_count', 0)
            score += vuln_count * 25
        
        if surfaces.get('wp_config_exposed'):
            score += 40
        
        if surfaces.get('uploads_listing'):
            score += 30
        
        if surfaces.get('debug_log'):
            score += 25
        
        if surfaces['php_info'].get('vulnerabilities'):
            score += len(surfaces['php_info']['vulnerabilities']) * 20
        
        if surfaces.get('xmlrpc') and surfaces.get('xmlrpc_methods'):
            score += 20
        
        if len(surfaces.get('rest_routes', [])) > 10:
            score += 15
        
        if surfaces.get('backup_files'):
            score += len(surfaces['backup_files']) * 10
        
        return min(score, 100)

# =================== VERSION RESOLVERS MODULE ===================
class VersionDetection:
    def __init__(self, version: Optional[str] = None, confidence: int = 0, 
                 method: str = "unknown", evidence: str = ""):
        self.version = version
        self.confidence = confidence
        self.method = method
        self.evidence = evidence
    
    def __str__(self):
        if self.version:
            return f"{self.version} (confidence: {self.confidence}%, method: {self.method})"
        return "Not detected"

class PluginVersionResolver:
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
        self.cache = {}
        self.html_cache = None
        
        self.VERSION_PATTERNS = [
            r'\*\s*Version:\s*([\d\.]+)',
            r'@version\s+([\d\.]+)',
            r"define\('.*VERSION',\s*['\"]([\d\.]+)['\"]",
            r'define\(".*VERSION",\s*["\']([\d\.]+)["\']',
            r'"version"\s*:\s*"([\d\.]+)"',
            r"'version'\s*=>\s*'([\d\.]+)'",
            r'\$version\s*=\s*[\'"]([\d\.]+)[\'"]',
            r'Version\s*=\s*[\'"]([\d\.]+)[\'"]',
            r'const\s+VERSION\s*=\s*[\'"]([\d\.]+)[\'"]',
            r'v([\d\.]+)',
            r'version\s+([\d\.]+)',
            r'Version\s+([\d\.]+)',
        ]
    
    async def resolve(self, plugin_slug: str) -> VersionDetection:
        if plugin_slug in self.cache:
            return self.cache[plugin_slug]
        
        methods = [
            (self._detect_via_readme, 85),
            (self._detect_via_plugin_header, 95),
            (self._detect_via_assets, 75),
            (self._detect_via_changelog, 70),
        ]
        
        best_result = VersionDetection()
        
        for method_func, base_confidence in methods:
            try:
                result = await method_func(plugin_slug)
                if result.confidence > best_result.confidence:
                    best_result = result
                    
                    if best_result.confidence >= 90:
                        break
            except:
                continue
        
        self.cache[plugin_slug] = best_result
        return best_result
    
    async def _detect_via_readme(self, plugin_slug: str) -> VersionDetection:
        readme_patterns = [
            r'Stable tag:\s*([\d\.]+)',
            r'Version:\s*([\d\.]+)',
            r'Tested up to:\s*([\d\.]+)',
            r'Requires at least:\s*([\d\.]+)',
        ]
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}/wp-content/plugins/{plugin_slug}/readme.txt"
            try:
                async with self.session.get(url, timeout=3, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        
                        for pattern in readme_patterns:
                            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                            if match:
                                version = match.group(1).strip()
                                if self._is_valid_version(version):
                                    return VersionDetection(
                                        version=version,
                                        confidence=85,
                                        method="readme_txt",
                                        evidence=f"Found in readme.txt"
                                    )
            except:
                continue
        
        return VersionDetection()
    
    async def _detect_via_plugin_header(self, plugin_slug: str) -> VersionDetection:
        slug_variants = [
            plugin_slug,
            plugin_slug.replace('-', '_'),
            plugin_slug.replace('-', ''),
            f"wp-{plugin_slug}",
        ]
        
        candidate_files = set()
        for variant in slug_variants:
            candidate_files.update([
                f"{variant}.php",
                f"index.php",
                f"plugin.php",
                f"main.php",
                f"init.php",
                f"class-{variant}.php",
                f"{variant}-main.php",
                f"core.php",
            ])
        
        for scheme in ['https://', 'http://']:
            for main_file in candidate_files:
                url = f"{scheme}{self.domain}/wp-content/plugins/{plugin_slug}/{main_file}"
                try:
                    async with self.session.get(url, timeout=4, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.text(encoding='utf-8', errors='ignore')
                            
                            lines = content.split('\n')[:100]
                            header_text = '\n'.join(lines)
                            
                            version = self._extract_version_from_text(header_text)
                            if version:
                                return VersionDetection(
                                    version=version,
                                    confidence=95,
                                    method="plugin_header",
                                    evidence=f"Found in {main_file} header"
                                )
                            
                            version = self._extract_version_from_text(content)
                            if version:
                                return VersionDetection(
                                    version=version,
                                    confidence=85,
                                    method="plugin_content",
                                    evidence=f"Found in {main_file} content"
                                )
                except:
                    continue
        
        return VersionDetection()
    
    async def _detect_via_assets(self, plugin_slug: str) -> VersionDetection:
        html = await self._get_homepage_html()
        if not html:
            return VersionDetection()
        
        asset_pattern = rf'/wp-content/plugins/{re.escape(plugin_slug)}/[^\s"\'>]+\.(?:js|css)\?ver=([\d\.]+)'
        matches = re.findall(asset_pattern, html, re.IGNORECASE)
        
        if matches:
            version_counts = Counter(matches)
            most_common_version, count = version_counts.most_common(1)[0]
            
            if self._is_valid_version(most_common_version):
                confidence = min(75 + (count * 5), 90)
                return VersionDetection(
                    version=most_common_version,
                    confidence=confidence,
                    method="asset_version",
                    evidence=f"Found in {count} asset(s)"
                )
        
        return VersionDetection()
    
    async def _detect_via_changelog(self, plugin_slug: str) -> VersionDetection:
        changelog_files = [
            'changelog.txt', 'changelog.md', 'CHANGELOG.md',
            'changes.txt', 'CHANGES.txt', 'CHANGELOG'
        ]
        
        for scheme in ['https://', 'http://']:
            for filename in changelog_files:
                url = f"{scheme}{self.domain}/wp-content/plugins/{plugin_slug}/{filename}"
                try:
                    async with self.session.get(url, timeout=3, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.text(encoding='utf-8', errors='ignore')
                            
                            patterns = [
                                r'^(\d+\.\d+(?:\.\d+)?)\s',
                                r'Version\s+(\d+\.\d+(?:\.\d+)?)',
                                r'v(\d+\.\d+(?:\.\d+?))\s',
                                r'(\d+\.\d+(?:\.\d+?))\s+\(\d{4}-\d{2}-\d{2}\)',
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                                if match:
                                    version = match.group(1).strip()
                                    if self._is_valid_version(version):
                                        return VersionDetection(
                                            version=version,
                                            confidence=70,
                                            method="changelog",
                                            evidence=f"Found in {filename}"
                                        )
                except:
                    continue
        
        return VersionDetection()
    
    def _extract_version_from_text(self, text: str) -> Optional[str]:
        for pattern in self.VERSION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if self._is_valid_version(match):
                    return match
        return None
    
    async def _get_homepage_html(self) -> Optional[str]:
        if self.html_cache is not None:
            return self.html_cache
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}"
            try:
                async with self.session.get(url, timeout=8, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text(encoding='utf-8', errors='ignore')
                        self.html_cache = html
                        return html
            except:
                continue
        
        self.html_cache = None
        return None
    
    def _is_valid_version(self, version: str) -> bool:
        if not version or len(version) > 15:
            return False
        
        pattern = r'^\d+(?:\.\d+)*$'
        if not re.match(pattern, version):
            return False
        
        parts = version.split('.')
        if len(parts) > 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num > 999:
                    return False
        except:
            return False
        
        if int(parts[0]) > 100:
            return False
        
        if len(parts) == 1 and len(parts[0]) > 4:
            return False
        
        if len(parts) == 1 and 1900 <= int(parts[0]) <= 2100:
            return False
        
        return True

class ThemeVersionResolver:
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
    
    async def resolve(self, theme_slug: str) -> VersionDetection:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}/wp-content/themes/{theme_slug}/style.css"
            try:
                async with self.session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        
                        patterns = [
                            r'Version:\s*([\d\.]+)',
                            r'Theme Version:\s*([\d\.]+)',
                            r'Version\s*:\s*([\d\.]+)',
                        ]
                        
                        for pattern in patterns:
                            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                            if match:
                                version = match.group(1).strip()
                                if self._is_valid_version(version):
                                    return VersionDetection(
                                        version=version,
                                        confidence=95,
                                        method="style.css",
                                        evidence="Found in theme style.css"
                                    )
            except:
                continue
        
        return VersionDetection()
    
    def _is_valid_version(self, version: str) -> bool:
        if not version or len(version) > 15:
            return False
        
        pattern = r'^\d+(?:\.\d+)*$'
        return bool(re.match(pattern, version))

class PHPVersionDetector:
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
    
    async def detect(self) -> Dict:
        detection_methods = [
            (self._detect_from_phpinfo, 95, "phpinfo_leak"),
            (self._detect_from_headers, 80, "x-powered-by-header"),
            (self._detect_from_errors, 70, "error_messages"),
            (self._detect_from_fingerprints, 60, "fingerprinting"),
        ]
        
        best_result = {
            'version': None,
            'confidence': 0,
            'method': 'unknown',
            'methods_tried': []
        }
        
        for method_func, confidence, method_name in detection_methods:
            try:
                version = await method_func()
                if version:
                    best_result['methods_tried'].append(method_name)
                    
                    if confidence > best_result['confidence']:
                        best_result['version'] = version
                        best_result['confidence'] = confidence
                        best_result['method'] = method_name
                    
                    if confidence >= 90:
                        break
            except:
                continue
        
        if best_result['version'] and best_result['confidence'] > 50:
            best_result['vulnerabilities'] = self._check_php_vulnerabilities(best_result['version'])
        else:
            best_result['vulnerabilities'] = []
        
        return best_result
    
    async def _detect_from_phpinfo(self) -> Optional[str]:
        common_paths = [
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/admin/phpinfo.php',
            '/wp-content/phpinfo.php',
        ]
        
        for scheme in ['https://', 'http://']:
            for path in common_paths:
                url = f"{scheme}{self.domain}{path}"
                try:
                    async with self.session.get(url, timeout=5, ssl=False) as resp:
                        if resp.status == 200:
                            text = await resp.text(encoding='utf-8', errors='ignore')
                            if 'phpinfo' in text.lower() or 'PHP Version' in text:
                                match = re.search(r'PHP Version\s*<[^>]+>([\d\.]+)', text)
                                if match:
                                    return match.group(1)
                except:
                    continue
        return None
    
    async def _detect_from_headers(self) -> Optional[str]:
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}"
            try:
                async with self.session.head(url, timeout=5, ssl=False) as resp:
                    powered_by = resp.headers.get('X-Powered-By', '')
                    if 'PHP' in powered_by:
                        match = re.search(r'PHP/([\d\.]+)', powered_by)
                        if match:
                            return match.group(1)
            except:
                continue
        return None
    
    async def _detect_from_errors(self) -> Optional[str]:
        test_paths = [
            '/wp-admin/install.php',
            '/wp-login.php?action=invalid',
            '/index.php?non_existing_function=1',
        ]
        
        for scheme in ['https://', 'http://']:
            for path in test_paths:
                url = f"{scheme}{self.domain}{path}"
                try:
                    async with self.session.get(url, timeout=5, ssl=False) as resp:
                        if resp.status == 500:
                            text = await resp.text(encoding='utf-8', errors='ignore')
                            
                            patterns = [
                                r'PHP/([\d\.]+)',
                                r'PHP\s+([\d\.]+)',
                                r'version\s+([\d\.]+)',
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, text)
                                if match:
                                    return match.group(1)
                except:
                    continue
        return None
    
    async def _detect_from_fingerprints(self) -> Optional[str]:
        common_versions = ['7.4', '8.0', '8.1', '8.2', '8.3']
        
        for version in common_versions:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{self.domain}/index.php"
                try:
                    headers = {'X-Forwarded-For': f'127.0.0.{random.randint(1, 255)}'}
                    async with self.session.get(url, headers=headers, timeout=3, ssl=False) as resp:
                        if 'PHP' in resp.headers.get('X-Powered-By', ''):
                            match = re.search(r'PHP/([\d\.]+)', resp.headers.get('X-Powered-By', ''))
                            if match:
                                return match.group(1)
                except:
                    continue
        return None
    
    def _check_php_vulnerabilities(self, version: str) -> List[str]:
        vulnerabilities = []
        
        match = re.match(r'(\d+\.\d+)', version)
        if not match:
            return vulnerabilities
        
        major_minor = match.group(1)
        
        if major_minor in Config.PHP_VULNERABILITIES:
            for version_range, cves in Config.PHP_VULNERABILITIES[major_minor].items():
                if self._is_version_in_range(version, version_range):
                    vulnerabilities.extend(cves)
        
        return vulnerabilities
    
    def _is_version_in_range(self, version: str, version_range: str) -> bool:
        try:
            if version_range.startswith('<'):
                max_ver = version_range[1:]
                return self._compare_versions(version, max_ver) < 0
        except:
            pass
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        try:
            v1_parts = list(map(int, v1.split('.')[:3]))
            v2_parts = list(map(int, v2.split('.')[:3]))
            
            while len(v1_parts) < 3:
                v1_parts.append(0)
            while len(v2_parts) < 3:
                v2_parts.append(0)
            
            for i in range(3):
                if v1_parts[i] != v2_parts[i]:
                    return v1_parts[i] - v2_parts[i]
            return 0
        except:
            return 0

# =================== PHASE 6: RISK ASSESSMENT ENGINE ===================
class EnhancedRiskScorer:
    """Phase 6: Risk assessment engine"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.SURFACE_RESULT,
            self.score_risk
        ))
    
    async def score_risk(self, event: Event):
        surfaces = event.data
        domain = surfaces['domain']
        
        findings = []
        cve_matches = []
        risk_score = surfaces.get('initial_risk_score', 0)
        
        wp_version = surfaces.get('wp_version')
        if wp_version:
            wp_cves = self._check_wordpress_cves(wp_version)
            if wp_cves:
                risk_score += len(wp_cves) * 30
                cve_matches.extend(wp_cves)
                findings.append(f"WordPress {wp_version}: {len(wp_cves)} CVEs")
        
        for plugin in surfaces.get('plugins', []):
            vulns = plugin.get('vulnerabilities', [])
            if vulns:
                plugin_name = plugin.get('name', plugin['slug'])
                plugin_version = plugin.get('version', 'unknown')
                findings.append(f"{plugin_name} {plugin_version}: {len(vulns)} vulns")
                cve_matches.extend([v.get('cve', '') for v in vulns if v.get('cve')])
        
        php_info = surfaces.get('php_info', {})
        if php_info.get('vulnerabilities'):
            php_version = php_info.get('version', 'unknown')
            vulns = php_info['vulnerabilities']
            risk_score += len(vulns) * 25
            cve_matches.extend(vulns)
            findings.append(f"PHP {php_version}: {len(vulns)} CVEs")
        
        if surfaces.get('wp_config_exposed'):
            findings.append("wp-config.php exposed")
            risk_score += 40
        
        if surfaces.get('uploads_listing'):
            findings.append("Uploads directory listing enabled")
            risk_score += 30
        
        if surfaces.get('debug_log'):
            findings.append("debug.log accessible")
            risk_score += 25
        
        users = surfaces.get('users', [])
        real_users = [u for u in users if u.get("slug")]
        if len(real_users) > 0:
            findings.append(
                f"User enumeration confirmed ({len(real_users)} real users)"
            )
            risk_score += min(len(real_users) * 5, 20)
        
        if surfaces.get('xmlrpc') and surfaces.get('xmlrpc_methods'):
            method_count = len(surfaces['xmlrpc_methods'])
            findings.append(f"XML-RPC enabled with {method_count} methods")
            risk_score += 20
        
        rest_routes = surfaces.get('rest_routes', [])
        if len(rest_routes) > 10:
            findings.append(f"Many REST API routes exposed ({len(rest_routes)})")
            risk_score += 15
        
        backup_files = surfaces.get('backup_files', [])
        if backup_files:
            findings.append(f"Backup files found: {len(backup_files)}")
            risk_score += len(backup_files) * 10
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 80:
            risk_level = "CRITICAL"
            color_code = "\033[91m"
        elif risk_score >= 60:
            risk_level = "HIGH"
            color_code = "\033[93m"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            color_code = "\033[33m"
        elif risk_score >= 20:
            risk_level = "LOW"
            color_code = "\033[92m"
        else:
            risk_level = "INFO"
            color_code = "\033[94m"
        
        unique_findings = []
        seen = set()
        for finding in findings:
            if finding not in seen:
                unique_findings.append(finding)
                seen.add(finding)
        
        risk_event = Event(
            type=EventType.RISK_SCORE,
            data={
                'domain': domain,
                'score': risk_score,
                'level': risk_level,
                'color_code': color_code,
                'findings': unique_findings[:8],
                'cves': list(set([c for c in cve_matches if c])),
                'wp_version': wp_version,
                'plugin_count': len(surfaces.get('plugins', [])),
                'vulnerable_plugins': len([p for p in surfaces.get('plugins', []) 
                                          if p.get('vulnerability_count', 0) > 0]),
                'php_version': php_info.get('version'),
                'timestamp': time.time()
            },
            source="EnhancedRiskScorer"
        )
        
        await self.event_bus.publish(risk_event)
    
    def _check_wordpress_cves(self, version: str) -> List[str]:
        cves = []
        
        try:
            for version_range, cve_list in Config.WORDPRESS_CVES.items():
                if self._is_version_in_range(version, version_range):
                    if isinstance(cve_list, list):
                        cves.extend(cve_list)
                    elif isinstance(cve_list, dict):
                        for sub_range, sub_cves in cve_list.items():
                            if self._is_version_in_range(version, sub_range):
                                cves.extend(sub_cves)
        except:
            pass
        
        return list(set(cves))
    
    def _is_version_in_range(self, version: str, version_range: str) -> bool:
        try:
            if version_range.startswith('<'):
                max_ver = version_range[1:]
                return self._compare_versions(version, max_ver) < 0
            else:
                return version.startswith(version_range)
        except:
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        try:
            v1_parts = list(map(int, v1.split('.')[:3]))
            v2_parts = list(map(int, v2.split('.')[:3]))
            
            while len(v1_parts) < 3:
                v1_parts.append(0)
            while len(v2_parts) < 3:
                v2_parts.append(0)
            
            for i in range(3):
                if v1_parts[i] != v2_parts[i]:
                    return v1_parts[i] - v2_parts[i]
            return 0
        except:
            return 0

# =================== PHASE 7: ATTACK ANALYSIS (NOT SIMULATION) ===================
class AttackAnalyzer:
    """Phase 7: Attack analysis only (no active payloads)"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RISK_SCORE,
            self.analyze_attack
        ))
    
    async def analyze_attack(self, event: Event):
        risk_data = event.data
        domain = risk_data['domain']
        
        possible_chains = []
        requirements = {}
        complexity = "LOW"
        
        if risk_data['score'] >= 60:
            possible_chains.append("Authentication bypass via XML-RPC")
            requirements['xmlrpc'] = True
            complexity = "MEDIUM"
        
        if risk_data.get('vulnerable_plugins', 0) > 0:
            possible_chains.append("Plugin vulnerability exploitation")
            requirements['vulnerable_plugins'] = True
            complexity = "MEDIUM"
        
        if risk_data.get('wp_config_exposed', False):
            possible_chains.append("Direct database access via exposed config")
            requirements['wp_config_exposed'] = True
            complexity = "HIGH"
        
        if risk_data.get('uploads_listing', False):
            possible_chains.append("File upload to exposed uploads directory")
            requirements['uploads_listing'] = True
            complexity = "MEDIUM"
        
        attack_event = Event(
            type=EventType.ATTACK_ANALYSIS,  # Changed to ATTACK_ANALYSIS
            data={
                'domain': domain,
                'possible_chains': possible_chains,
                'requirements': requirements,
                'complexity': complexity,
                'timestamp': time.time()
            },
            source="AttackAnalyzer"
        )
        
        await self.event_bus.publish(attack_event)

# =================== PHASE 8: TRIAGE ENGINE ===================
class TriageEngine:
    """Phase 8: Triage và prioritization"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.ATTACK_ANALYSIS,  # Changed to ATTACK_ANALYSIS
            self.triage_target
        ))
    
    async def triage_target(self, event: Event):
        attack_data = event.data
        domain = attack_data['domain']
        
        risk_score = 0
        waf_detected = False
        
        priority = "LOW"
        action = "ARCHIVE"
        reasoning = "Low risk target"
        confidence = 70
        
        if attack_data['complexity'] == "HIGH":
            priority = "CRITICAL"
            action = "FOCUS"
            reasoning = "High complexity attack chain possible"
            confidence = 85
        elif attack_data['complexity'] == "MEDIUM" and not waf_detected:
            priority = "HIGH"
            action = "REVIEW"
            reasoning = "Medium complexity attack possible, no WAF detected"
            confidence = 75
        elif attack_data['complexity'] == "MEDIUM" and waf_detected:
            priority = "MEDIUM"
            action = "MONITOR"
            reasoning = "Medium complexity but WAF protection detected"
            confidence = 65
        
        triage_event = Event(
            type=EventType.TRIAGE_RESULT,
            data={
                'domain': domain,
                'priority': priority,
                'action': action,
                'reasoning': reasoning,
                'confidence': confidence,
                'attack_chains': attack_data['possible_chains'],
                'timestamp': time.time()
            },
            source="TriageEngine"
        )
        
        await self.event_bus.publish(triage_event)

# =================== PHASE 9: ENHANCED OUTPUT MANAGER ===================
class EnhancedOutputManager:
    """Phase 9: Output và knowledge base"""
    
    def __init__(self, event_bus: AsyncEventBus, output_file: Optional[str] = None):
        self.event_bus = event_bus
        self.output_file = output_file
        self.results = []
        self.processed_domains = set()
        self.displayed_domains = set()
        self.lock = asyncio.Lock()
        self.stats = {
            'total': 0,
            'wp': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'plugins_found': 0,
            'vulnerabilities_found': 0,
        }
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.TRIAGE_RESULT,
            self.handle_final_result
        ))
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_DETECTED,
            self.log_wp_detection
        ))
    
    async def handle_final_result(self, event: Event):
        result = event.data
        domain = result['domain']
        
        self.stats['total'] += 1
        self.stats['wp'] += 1
        
        level = result.get('priority', 'LOW')
        if level == "CRITICAL":
            self.stats['critical'] += 1
        elif level == "HIGH":
            self.stats['high'] += 1
        elif level == "MEDIUM":
            self.stats['medium'] += 1
        elif level == "LOW":
            self.stats['low'] += 1
        else:
            self.stats['info'] += 1
        
        color = "\033[91m" if level == "CRITICAL" else "\033[93m" if level == "HIGH" else "\033[33m" if level == "MEDIUM" else "\033[92m"
        reset = "\033[0m"
        
        print(f"\n{color}{'═' * 80}{reset}")
        print(f"{color}🔍 WORDPRESS ATTACK SURFACE: {domain}{reset}")
        print(f"{color}{'═' * 80}{reset}")
        
        print(f"\n📊 TRIAGE RESULT")
        print(f"  • Priority: {color}{level}{reset}")
        print(f"  • Action: {result.get('action', 'UNKNOWN')}")
        print(f"  • Reasoning: {result.get('reasoning', '')}")
        print(f"  • Confidence: {result.get('confidence', 0)}%")
        
        if result.get('attack_chains'):
            print(f"\n⚔️  POSSIBLE ATTACK CHAINS:")
            for i, chain in enumerate(result['attack_chains'][:3], 1):
                print(f"  {i}. {chain}")
        
        print(f"{color}{'═' * 80}{reset}\n")
        
        self.results.append(result)
        
        if self.output_file:
            await self.save_to_file(result)
    
    async def log_wp_detection(self, event: Event):
        data = event.data
        if data['is_wp']:
            confidence = data['confidence']
            if confidence >= 80:
                color = "\033[92m✓"
            elif confidence >= 50:
                color = "\033[93m?"
            else:
                color = "\033[90m~"
            
            print(f"\r\033[K{color} WP\033[0m {data['domain'][:40]:<40} "
                  f"Confidence: {confidence}%")
        else:
            print(f"\r\033[K\033[90m✗ Non-WP\033[0m {data['domain'][:40]:<40}")
    
    async def save_to_file(self, result: Dict):
        try:
            file_exists = os.path.exists(self.output_file)
            
            if file_exists:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        if not isinstance(data, list):
                            data = [data]
                    except:
                        data = []
            else:
                data = []
            
            data.append(result)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"[OutputManager] Save error: {e}")

# =================== ENHANCED PIPELINE ===================
class EnhancedWASEPipeline:
    """Enhanced pipeline với tất cả phases"""
    
    def __init__(self, targets_file: Optional[str] = None, output_file: Optional[str] = None, 
                 workers: int = 12, discovery: bool = True, history_file: str = "scanned_history.txt",
                 wpscan_api: str = ""):
        self.targets_file = targets_file
        self.output_file = output_file
        self.workers = workers
        self.discovery = discovery
        self.wpscan_api = wpscan_api
        self.is_running = False
        
        self.event_bus = AsyncEventBus(max_size=Config.EVENT_BUS_SIZE)
        
        self.producers = []
        
        # Initialize all phases với flow đã sửa
        self.pre_filter = PreFilter(self.event_bus, history_file)
        self.wp_detector = WPGateDetector(self.event_bus, workers=workers)
        self.tech_profiler = TechStackProfiler(self.event_bus)  # Chỉ chạy sau khi WP detect
        self.wp_fingerprint = WPCoreFingerprint(self.event_bus)
        self.wpscan = WPScanIntegration(self.event_bus, wpscan_api)
        self.surface_enumerator = EnhancedAttackSurfaceEnumerator(self.event_bus)
        self.risk_scorer = EnhancedRiskScorer(self.event_bus)
        self.attack_analyzer = AttackAnalyzer(self.event_bus)  # Đổi tên thành analyzer
        self.triage_engine = TriageEngine(self.event_bus)
        self.output_manager = EnhancedOutputManager(self.event_bus, output_file)
    
    async def setup_producers(self):
        if self.targets_file:
            print(f"[Pipeline] Mode: Targeted scan từ {self.targets_file}")
            producer = TargetFileProducer(self.event_bus, self.targets_file)
            self.producers.append(producer)
        elif self.discovery:
            print(f"[Pipeline] Mode: Full discovery + deep scan")
            producer = DorkProducer(self.event_bus)
            self.producers.append(producer)
        else:
            print("[Pipeline] Không có producers nào được cấu hình!")
            return False
        return True
    
    async def run(self):
        print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║         WORDPRESS ATTACK SURFACE ENGINE (WASE) v2.0 - ENHANCED        ║
║         Fixed Architecture + Attack Analysis Only                     ║
╚════════════════════════════════════════════════════════════════════════╝
        """)
        
        self.is_running = True
        
        try:
            if not await self.setup_producers():
                return
            
            bus_task = asyncio.create_task(self.event_bus.run())
            
            for producer in self.producers:
                await producer.start()
                print(f"[Pipeline] Đã khởi động producer: {producer.name}")
            
            print(f"\n{'═' * 80}")
            print("🚀 ENHANCED PIPELINE ĐÃ BẮT ĐẦU - All phases enabled")
            print(f"{'═' * 80}\n")
            print("📢 NHẤN CTRL+C ĐỂ DỪNG NGAY\n")
            
            try:
                producer_tasks = [asyncio.create_task(self._wait_for_producer(p)) 
                                 for p in self.producers]
                
                done, pending = await asyncio.wait(
                    producer_tasks,
                    timeout=None,
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                for task in pending:
                    task.cancel()
                
            except KeyboardInterrupt:
                print("\n\n🛑 NHẬN CTRL+C - DỪNG PIPELINE!")
            
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt trong pipeline")
        except Exception as e:
            print(f"[Pipeline] Lỗi: {e}")
            import traceback
            traceback.print_exc()
        finally:
            await self._force_shutdown()
            
            stats = self.output_manager.stats
            print(f"\n{'═' * 80}")
            print("📊 THỐNG KÊ CUỐI CÙNG")
            print(f"{'═' * 80}")
            print(f"Tổng domains đã xử lý: {stats['total']}")
            print(f"Sites WordPress tìm thấy: {stats['wp']}")
            print(f"Lỗ hổng đã xác định: {stats['vulnerabilities_found']}")
            print(f"\nPhân bố rủi ro:")
            print(f"  • CRITICAL: {stats['critical']}")
            print(f"  • HIGH: {stats['high']}")
            print(f"  • MEDIUM: {stats['medium']}")
            print(f"  • LOW: {stats['low']}")
            print(f"  • INFO: {stats['info']}")
            
            if self.output_file:
                print(f"\n📁 Kết quả đã lưu vào: {self.output_file}")
            
            print(f"\n✅ Enhanced pipeline hoàn thành thành công!")
            
            import sys
            sys.exit(0)
    
    async def _wait_for_producer(self, producer):
        while producer.is_running:
            await asyncio.sleep(0.5)
        return True
    
    async def _force_shutdown(self):
        print("\n" + "!" * 80)
        print("🛑 FORCE SHUTDOWN - ĐANG DỪNG TẤT CẢ!")
        print("!" * 80)

        self.is_running = False

        await asyncio.sleep(0.1)

        print("[Shutdown] Stopping producers...")
        for producer in self.producers:
            try:
                await producer.stop()
            except Exception as e:
                print(f"[Producer stop error] {producer.name}: {e}")

        # Stop event bus
        if hasattr(self.event_bus, 'stop'):
            try:
                await self.event_bus.stop()
            except Exception as e:
                print(f"[EventBus stop error] {e}")

        # Close all sessions via SessionManager
        await SessionManager.close_all()
        
        # Đóng DNS resolver
        if hasattr(self, 'pre_filter') and hasattr(self.pre_filter, 'dns_resolver'):
            try:
                self.pre_filter.dns_resolver.cancel()
                print("[Cleanup] ✓ Closed DNS resolver")
            except:
                pass
        
        print("[Shutdown] Waiting for final cleanup...")
        await asyncio.sleep(0.5)
        
        print("✅ SHUTDOWN HOÀN TẤT")

# =================== MAIN ===================
async def main():
    args = parse_args()
    
    if args.targets and not os.path.exists(args.targets):
        print(f"❌ Không tìm thấy file targets: {args.targets}")
        return
    
    pipeline = EnhancedWASEPipeline(
        targets_file=args.targets,
        output_file=args.output,
        workers=args.workers,
        discovery=not args.no_discovery,
        history_file=args.history,
        wpscan_api=args.wpscan_api
    )
    
    try:
        await pipeline.run()
    except KeyboardInterrupt:
        print("\n\n👋 Dừng theo yêu cầu người dùng")
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🏁 Kết thúc chương trình")

def parse_args():
    parser = argparse.ArgumentParser(
        description='WordPress Attack Surface Engine (WASE) v2.0 - Enhanced Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full discovery mode
  python wase.py --workers 12 --output results.json
  
  # Targeted scan from file
  python wase.py --targets targets.txt --output scan_results.json
  
  # With WPScan API key
  python wase.py --targets urls.txt --wpscan-api YOUR_API_KEY --output wpscan_results.json
  
  # Quick scan
  python wase.py --targets urls.txt --workers 4 --no-discovery --output quick.json
        """
    )
    
    parser.add_argument('--targets', '-t', type=str,
                       help='File chứa targets (mỗi dòng 1 domain/URL)')
    
    parser.add_argument('--output', '-o', type=str, default='wase_results.json',
                       help='File output JSON (default: wase_results.json)')
    
    parser.add_argument('--workers', '-w', type=int, default=8,
                       help='Số concurrent workers (default: 8)')
    
    parser.add_argument('--no-discovery', action='store_true',
                       help='Tắt discovery mode (chỉ dùng nếu có --targets)')
    
    parser.add_argument('--history', type=str, default='scanned_history.txt',
                       help='File lưu domains đã scan (default: scanned_history.txt)')
    
    parser.add_argument('--wpscan-api', type=str, default='',
                       help='WPScan API key cho vulnerability checking')
    
    return parser.parse_args()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Dừng theo yêu cầu người dùng")
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
    
    print("\n🏁 Kết thúc chương trình")
    sys.exit(0)