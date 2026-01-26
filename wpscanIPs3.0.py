#!/usr/bin/env python3
"""
WORDPRESS ATTACK SURFACE ENGINE (WASE) v1.0
Complete Integrated Version with Deep Enumeration
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
    
    # Discovery (giữ nguyên vì cần thiết)
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
    
    # Enhanced Plugin Database with CVE info (giữ nguyên vì cần thiết)
    POPULAR_PLUGINS = {
        # 🔥 SEO & CONTENT
        'yoast-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
        'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
        'all-in-one-seo-pack': {'name': 'All in One SEO', 'category': 'SEO', 'installs': '3M+'},
        'seo-by-rank-math': {'name': 'Rank Math SEO', 'category': 'SEO', 'installs': '2M+'},
        
        # 🎨 PAGE BUILDERS
        'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
        'beaver-builder-lite-version': {'name': 'Beaver Builder', 'category': 'Page Builder', 'installs': '1M+'},
        'siteorigin-panels': {'name': 'SiteOrigin Page Builder', 'category': 'Page Builder', 'installs': '1M+'},
        
        # 📝 FORMS
        'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
        'wpforms-lite': {'name': 'WPForms', 'category': 'Forms', 'installs': '6M+'},
        
        # ⚡ CACHE & PERFORMANCE
        'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
        'wp-rocket': {'name': 'WP Rocket', 'category': 'Performance', 'installs': '2M+'},
        
        # 🛒 E-COMMERCE
        'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
        
        # 🔐 SECURITY
        'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
        'better-wp-security': {'name': 'iThemes Security', 'category': 'Security', 'installs': '1M+'},
        
        # 📧 EMAIL
        'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    }
    
    # PHP Version Vulnerabilities (giữ nguyên)
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
        }
    }
    
    # WordPress Core CVEs (giữ nguyên)
    WORDPRESS_CVES = {
        '6.1': {'<6.1.1': ['CVE-2023-28121', 'CVE-2023-28122']},
        '6.0': {'<6.0.5': ['CVE-2023-0031', 'CVE-2022-35945']},
        '5.9': {'<5.9.5': ['CVE-2022-35944', 'CVE-2022-35943']},
        '5.8': {'<5.8.5': ['CVE-2022-21662', 'CVE-2022-21661']},
    }


# =================== DATA STRUCTURES ===================
class EventType(Enum):
    RAW_DOMAIN = "raw_domain"
    CLEAN_DOMAIN = "clean_domain"
    WP_DETECTED = "wp_detected"
    WP_PROFILE = "wp_profile"
    SURFACE_RESULT = "surface_result"
    RISK_SCORE = "risk_score"
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
        self.shutdown_event = asyncio.Event()  # Thêm shutdown event
    
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
                # Sử dụng asyncio.wait để có thể bị interrupt
                try:
                    event = await asyncio.wait_for(
                        self.queue.get(),
                        timeout=0.5  # Timeout ngắn
                    )
                except asyncio.TimeoutError:
                    continue  # Kiểm tra lại điều kiện dừng
                
                # Gọi tất cả subscribers cho event type này
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
        
        # Xóa tất cả items trong queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except:
                pass

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
        """Đọc targets từ file và publish"""
        print(f"[{self.name}] Reading targets from {self.targets_file}")
        
        try:
            with open(self.targets_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                if not self.is_running:
                    break
                
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    # Tạo raw domain event
                    event = Event(
                        type=EventType.RAW_DOMAIN,
                        data={'domain': domain, 'raw': domain},
                        source=self.name
                    )
                    await self.event_bus.publish(event)
                
                # Small delay để không block event bus
                await asyncio.sleep(0.01)
            
            print(f"[{self.name}] Finished reading {len(lines)} targets")
            
        except Exception as e:
            print(f"[{self.name}] Error: {e}")

class DorkProducer(BaseProducer):
    """Producer từ DuckDuckGo dorks"""
    
    def __init__(self, event_bus: AsyncEventBus):
        super().__init__("DorkProducer", event_bus)
        self.session = None
    
    async def _produce_loop(self):
        """Thu thập domain từ dorks"""
        print(f"[{self.name}] Starting dork-based discovery")
        
        try:
            from ddgs import DDGS
            self.ddgs = DDGS()
            
            for dork in Config.DORKS:
                if not self.is_running:
                    break
                
                print(f"[{self.name}] Processing dork: {dork[:50]}...")
                
                try:
                    results = self.ddgs.text(
                        query=dork,
                        region="vn-vn",
                        safesearch="off",
                        max_results=50,
                        timeout=10
                    )
                    
                    for result in results:
                        if not self.is_running:
                            break
                        
                        url = result.get('href', '') or result.get('url', '')
                        if url:
                            # Extract domain
                            try:
                                parsed = urlparse(url)
                                domain = parsed.netloc.lower()
                                if domain.startswith('www.'):
                                    domain = domain[4:]
                                
                                # Publish raw domain
                                event = Event(
                                    type=EventType.RAW_DOMAIN,
                                    data={'domain': domain, 'raw': url, 'dork': dork},
                                    source=self.name
                                )
                                await self.event_bus.publish(event)
                                
                            except:
                                pass
                        
                        await asyncio.sleep(0.1)  # Rate limiting
                    
                    # Delay giữa các dorks
                    await asyncio.sleep(random.uniform(2, 4))
                    
                except Exception as e:
                    print(f"[{self.name}] Dork error: {e}")
                    await asyncio.sleep(5)
        
        except ImportError:
            print(f"[{self.name}] DDGS not available, skipping dork discovery")
        except Exception as e:
            print(f"[{self.name}] Error: {e}")

class PassiveDNSProducer(BaseProducer):
    """Producer từ passive DNS sources"""
    
    def __init__(self, event_bus: AsyncEventBus):
        super().__init__("PassiveDNSProducer", event_bus)
        self.session = None
    
    async def _produce_loop(self):
        """Thu thập từ passive DNS sources"""
        print(f"[{self.name}] Starting passive DNS discovery")
        
        async with aiohttp.ClientSession() as session:
            for source in Config.DISCOVERY_SOURCES:
                if not self.is_running:
                    break
                
                try:
                    async with session.get(source, timeout=10) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            # Extract domains .vn
                            domains = re.findall(
                                r'([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))',
                                text,
                                re.IGNORECASE
                            )
                            
                            for domain_raw in set(domains):
                                domain = domain_raw.lower().replace("www.", "")
                                
                                event = Event(
                                    type=EventType.RAW_DOMAIN,
                                    data={'domain': domain, 'raw': domain_raw, 'source': source},
                                    source=self.name
                                )
                                await self.event_bus.publish(event)
                                
                                await asyncio.sleep(0.01)  # Small delay
                    
                    print(f"[{self.name}] Processed source: {source}")
                    
                except Exception as e:
                    print(f"[{self.name}] Source error {source}: {e}")
                
                await asyncio.sleep(1)

# =================== PHASE 1: PRE-FILTER ===================
class PreFilter:
    """Phase 1: Lọc nhanh, rẻ"""
    
    def __init__(self, event_bus: AsyncEventBus, history_file: str = "scanned_history.txt"):
        self.event_bus = event_bus
        self.seen_domains = set()
        self.dns_resolver = aiodns.DNSResolver()
        self.history_file = history_file  # 🆕 THÊM 1 DÒNG
        self._load_history()  # 🆕 THÊM 1 DÒNG
        # Đăng ký subscriber
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
            pass  # Silent fail
    



    async def process_raw_domain(self, event: Event):
        """Xử lý raw domain event"""
        domain = event.data.get('domain', '')
        
        # 1. Dedup toàn cục
        if domain in self.seen_domains:
            print(f"[PreFilter] ⏭️  Skip (scanned): {domain}")
            return
        self.seen_domains.add(domain)
        # 2. Normalize và validate
        normalized = self.normalize_domain(domain)
        if not normalized:
            print(f"[DROP][FORMAT] {domain}")
            return

        
        # 3. DNS resolve nhanh
        is_resolvable = await self.quick_dns_check(normalized)
        if not is_resolvable:
            print(f"[DROP][DNS] {normalized}")
            return

        
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
            # Loại bỏ protocol nếu có
            if '://' in domain:
                parsed = urlparse(domain)
                domain = parsed.netloc
            
            # Loại bỏ www.
            domain = domain.lower().replace("www.", "")
            
            # Loại bỏ port
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Validate format
            if not re.match(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$', domain):
                return None
            
            # Filter CDN/API
            cdn_keywords = ['cdn', 'cloudfront', 'akamai', 'fastly', 'cloudflare']
            if any(kw in domain for kw in cdn_keywords):
                return None
            
            # Too many subdomains
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
        
        # Đăng ký subscriber
        asyncio.create_task(self.event_bus.subscribe(
            EventType.CLEAN_DOMAIN,
            self.process_clean_domain
        ))
    
    async def init_session(self):
        """Khởi tạo aiohttp session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
    
    async def process_clean_domain(self, event: Event):
        """Xử lý clean domain để detect WordPress"""
        async with self.semaphore:
            domain = event.data['domain']
            
            if not self.session:
                await self.init_session()
            
            # Adaptive probing - thử các probe song song
            probes = [
                self.probe_homepage(domain),
                self.probe_wp_login(domain),
                self.probe_wp_content(domain),
                self.probe_wp_json(domain),
            ]
            
            results = await asyncio.gather(*probes, return_exceptions=True)
            
            # Tính confidence score
            confidence = 0
            signals = []
            
            for i, result in enumerate(results):
                if isinstance(result, dict) and result.get('detected'):
                    confidence += 25  # Mỗi probe thành công +25%
                    signals.append(result.get('signal', f'probe_{i}'))
            
            is_wp = confidence >= 25  # Ngưỡng 50%
            

            # ===== TERMINAL RENDER: WP DETECTION RESULT =====
            if confidence == 0:
                print(f"[NON-WP] {domain}")
            elif 0 < confidence < 50:
                print(f"[WP?][LOW] {domain} confidence={confidence} signals={signals}")
            else:
                print(f"[WP][DETECTED] {domain} confidence={confidence} signals={signals}")



            # Tạo event kết quả
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
    
    async def probe_homepage(self, domain: str) -> Dict:
        """Probe homepage cho WordPress signs"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, allow_redirects=True, ssl=False) as resp:
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
    
    async def probe_wp_login(self, domain: str) -> Dict:
        """Probe wp-login.php"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-login.php"
                try:
                    async with self.session.head(url, allow_redirects=False, ssl=False) as resp:
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
    
    async def probe_wp_content(self, domain: str) -> Dict:
        """Probe wp-content directory"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-content/"
                try:
                    async with self.session.head(url, allow_redirects=False, ssl=False) as resp:
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
    
    async def probe_wp_json(self, domain: str) -> Dict:
        """Probe WordPress REST API"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/"
                try:
                    async with self.session.get(url, ssl=False) as resp:
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




    async def cleanup(self):
        """Cleanup session"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                print("[WPGateDetector] Session closed")
            except Exception as e:
                print(f"[WPGateDetector] Session close error: {e}")









# =================== PHASE 3: WP CORE FINGERPRINT ===================
class WPCoreFingerprint:
    """Phase 3: Lấy thông tin core WordPress"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        
        # Chỉ subscribe đến WP sites
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_DETECTED,
            self.process_wp_domain
        ))
    
    async def init_session(self):
        """Khởi tạo session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
    
    async def process_wp_domain(self, event: Event):
        """Xử lý domain đã xác nhận là WordPress"""
        if not event.data['is_wp']:
            return  # Bỏ qua non-WP
        
        domain = event.data['domain']
        
        if not self.session:
            await self.init_session()
        
        # Thu thập thông tin song song
        tasks = [
            self.get_wp_version(domain),
            self.get_theme_info(domain),
            self.get_server_info(domain),
            self.check_xmlrpc(domain),
            self.check_rest_api(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge kết quả
        wp_profile = {
            'domain': domain,
            'confidence': event.data['confidence'],
            'wp_version': results[0] if not isinstance(results[0], Exception) else None,
            'theme': results[1] if not isinstance(results[1], Exception) else None,
            'server': results[2] if not isinstance(results[2], Exception) else None,
            'xmlrpc': results[3] if not isinstance(results[3], Exception) else False,
            'rest_api': results[4] if not isinstance(results[4], Exception) else False,
            'timestamp': time.time()
        }
            

        # ===== TERMINAL RENDER: CONFIRMED WP =====
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


                # ✅ SAVE CONFIRMED WP TARGET ONLY
        try:
            with open("scanned_wp_targets.txt", "a") as f:
                f.write(domain + "\n")
        except Exception:
            pass

        # Publish profile event
        profile_event = Event(
            type=EventType.WP_PROFILE,
            data=wp_profile,
            source="WPCoreFingerprint"
        )
        
        await self.event_bus.publish(profile_event)
    
    async def get_wp_version(self, domain: str) -> Optional[str]:
        """Lấy WordPress version với multiple strategies"""
        version_candidates = []
        
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with self.session.get(url, ssl=False, timeout=8) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        
                        # Tổng hợp tất cả các patterns để tìm version
                        patterns = [
                            # Meta generator tags
                            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)["\']',
                            r'content=["\']WordPress\s+([\d.]+)["\'][^>]+name=["\']generator["\']',
                            r'generator=["\']WordPress\s+([\d.]+)["\']',
                            
                            # Script versions
                            r'(?:wp-embed|wp-emoji|wp-api)\.js\?ver=([\d.]+)',
                            r'src="[^"]+ver=([\d.]+)"[^>]*wp-embed',
                            
                            # RSS/Atom feeds trong HTML
                            r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
                            r'generator="WordPress/([\d.]+)"',
                            
                            # Comments trong HTML
                            r'<!--[^>]*WordPress\s+([\d.]+)[^>]*-->',
                            
                            # Đơn giản hơn
                            r'WordPress\s+([\d.]+)',
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            version_candidates.extend(matches)
                        
                        break  # Break sau khi lấy được HTML
            except:
                continue
        
        # Xử lý các candidate versions
        if version_candidates:
            # Lọc các version hợp lệ
            valid_versions = []
            for v in version_candidates:
                if self._is_valid_version(v):
                    valid_versions.append(v)
            
            if valid_versions:
                # Chọn version xuất hiện nhiều nhất
                counter = Counter(valid_versions)
                most_common = counter.most_common(1)[0]
                return most_common[0]
        
        return None
    
    def _is_valid_version(self, version: str) -> bool:
        """Validate version string"""
        if not version or len(version) > 10:
            return False
        
        # Pattern: x.y.z hoặc x.y
        pattern = r'^\d+(?:\.\d+){1,2}$'
        if not re.match(pattern, version):
            return False
        
        # Check số phần
        parts = version.split('.')
        if len(parts) > 3:
            return False
        
        # Check mỗi phần là số
        try:
            for part in parts:
                int(part)
        except:
            return False
        
        # Phiên bản hợp lý (không quá lớn)
        if int(parts[0]) > 10:  # WordPress chưa tới version 10
            return False
        
        return True
    
    async def get_theme_info(self, domain: str) -> Optional[Dict]:
        """Lấy thông tin theme"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            
                            # Tìm theme slug
                            match = re.search(r'/wp-content/themes/([^/]+)/', html)
                            if match:
                                theme_slug = match.group(1)
                                return {'slug': theme_slug, 'name': theme_slug}
                except:
                    continue
        except:
            pass
        
        return None
    
    async def get_server_info(self, domain: str) -> Optional[Dict]:
        """Lấy thông tin server"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}"
                try:
                    async with self.session.head(url, ssl=False) as resp:
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
    
    async def check_xmlrpc(self, domain: str) -> bool:
        """Kiểm tra XML-RPC"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/xmlrpc.php"
                try:
                    async with self.session.head(url, ssl=False) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False
    
    async def check_rest_api(self, domain: str) -> bool:
        """Kiểm tra REST API"""
        try:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/wp/v2/"
                try:
                    async with self.session.head(url, ssl=False) as resp:
                        return resp.status < 400
                except:
                    continue
        except:
            pass
        
        return False



    async def cleanup(self):
        """Cleanup session"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                print("[WPCoreFingerprint] Session closed")
            except Exception as e:
                print(f"[WPCoreFingerprint] Session close error: {e}")






# =================== PLUGIN VERSION RESOLVER ===================
class VersionDetection:
    def __init__(self, version: Optional[str] = None, confidence: int = 0, 
                 method: str = "unknown", evidence: str = ""):
        self.version = version
        self.confidence = confidence  # 0-100
        self.method = method
        self.evidence = evidence
    
    def __str__(self):
        if self.version:
            return f"{self.version} (confidence: {self.confidence}%, method: {self.method})"
        return "Not detected"

class PluginVersionResolver:
    """Multi-stage plugin version resolver với heuristic algorithms"""
    
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
        self.cache = {}
        self.html_cache = None
        
        # Common file patterns for version detection
        self.VERSION_PATTERNS = [
            # WordPress standard patterns
            r'\*\s*Version:\s*([\d\.]+)',
            r'@version\s+([\d\.]+)',
            # PHP defines
            r"define\('.*VERSION',\s*['\"]([\d\.]+)['\"]",
            r'define\(".*VERSION",\s*["\']([\d\.]+)["\']',
            # JSON/array
            r'"version"\s*:\s*"([\d\.]+)"',
            r"'version'\s*=>\s*'([\d\.]+)'",
            # Variable assignment
            r'\$version\s*=\s*[\'"]([\d\.]+)[\'"]',
            r'Version\s*=\s*[\'"]([\d\.]+)[\'"]',
            # Class constants
            r'const\s+VERSION\s*=\s*[\'"]([\d\.]+)[\'"]',
            # Simple patterns
            r'v([\d\.]+)',
            r'version\s+([\d\.]+)',
            r'Version\s+([\d\.]+)',
        ]
    
    async def resolve(self, plugin_slug: str) -> VersionDetection:
        """Resolve plugin version using multi-stage approach"""
        
        if plugin_slug in self.cache:
            return self.cache[plugin_slug]
        
        # Run detection methods với priority
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
                    
                    # Nếu confidence cao, có thể dừng sớm
                    if best_result.confidence >= 90:
                        break
            except:
                continue
        
        # Cache result
        self.cache[plugin_slug] = best_result
        return best_result
    
    async def _detect_via_readme(self, plugin_slug: str) -> VersionDetection:
        """Detect version via readme.txt"""
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
        """Detect version via plugin main file header"""
        
        # Tạo danh sách các file có thể là main file
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
                            
                            # Tìm trong 100 dòng đầu (header area)
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
                            
                            # Nếu không tìm thấy trong header, tìm trong toàn bộ content
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
        """Detect version via asset query strings"""
        html = await self._get_homepage_html()
        if not html:
            return VersionDetection()
        
        # Tìm tất cả assets từ plugin này
        asset_pattern = rf'/wp-content/plugins/{re.escape(plugin_slug)}/[^\s"\'>]+\.(?:js|css)\?ver=([\d\.]+)'
        matches = re.findall(asset_pattern, html, re.IGNORECASE)
        
        if matches:
            # Sử dụng version phổ biến nhất
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
        """Detect version via changelog files"""
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
                            
                            # Tìm version mới nhất
                            patterns = [
                                r'^(\d+\.\d+(?:\.\d+)?)\s',
                                r'Version\s+(\d+\.\d+(?:\.\d+)?)',
                                r'v(\d+\.\d+(?:\.\d+?))\s',
                                r'(\d+\.\d+(?:\.\d+)?)\s+\(\d{4}-\d{2}-\d{2}\)',
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
        """Extract version từ text với multiple patterns"""
        for pattern in self.VERSION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if self._is_valid_version(match):
                    return match
        return None
    
    async def _get_homepage_html(self) -> Optional[str]:
        """Get homepage HTML once (cached)"""
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
        """Enhanced version validation"""
        if not version or len(version) > 15:
            return False
        
        # Pattern: x.y.z hoặc x.y
        pattern = r'^\d+(?:\.\d+)*$'
        if not re.match(pattern, version):
            return False
        
        # Check số phần hợp lý
        parts = version.split('.')
        if len(parts) > 4:  # Tối đa 4 phần
            return False
        
        # Check mỗi phần là số và hợp lý
        try:
            for part in parts:
                num = int(part)
                # 🆕 Mỗi phần không quá lớn
                if num > 999:  # Version part không vượt 999
                    return False
        except:
            return False
        
        # 🆕 Phiên bản hợp lý (không quá lớn)
        if int(parts[0]) > 100:  # Major version unlikely > 100
            return False
        
        # 🆕 Check version không phải là timestamp hoặc build number
        # VD: 20231225 là invalid
        if len(parts) == 1 and len(parts[0]) > 4:
            return False
        
        # 🆕 Check version không phải là năm đơn thuần
        if len(parts) == 1 and 1900 <= int(parts[0]) <= 2100:
            return False
        
        return True

# =================== THEME VERSION RESOLVER ===================
class ThemeVersionResolver:
    """Theme version detection"""
    
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
    
    async def resolve(self, theme_slug: str) -> VersionDetection:
        """Resolve theme version"""
        
        # Thử style.css trước (WordPress standard)
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}/wp-content/themes/{theme_slug}/style.css"
            try:
                async with self.session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        
                        # Parse WordPress theme header
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
        """Validate version string"""
        if not version or len(version) > 15:
            return False
        
        pattern = r'^\d+(?:\.\d+)*$'
        return bool(re.match(pattern, version))

# =================== PHP VERSION DETECTOR ===================
class PHPVersionDetector:
    """PHP version detection from headers and errors"""
    
    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session = session
        self.domain = domain
    
    async def detect(self) -> Dict:
        """Detect PHP version using priority-based methods"""
        
        # Thử các methods theo priority
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
                    
                    # Nếu confidence cao, có thể dừng sớm
                    if confidence >= 90:
                        break
            except:
                continue
        
        # Check vulnerabilities nếu tìm thấy version
        if best_result['version'] and best_result['confidence'] > 50:
            best_result['vulnerabilities'] = self._check_php_vulnerabilities(best_result['version'])
        else:
            best_result['vulnerabilities'] = []
        
        return best_result
    
    async def _detect_from_phpinfo(self) -> Optional[str]:
        """Try to find phpinfo leaks"""
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
                                # Extract PHP version
                                match = re.search(r'PHP Version\s*<[^>]+>([\d\.]+)', text)
                                if match:
                                    return match.group(1)
                except:
                    continue
        return None
    
    async def _detect_from_headers(self) -> Optional[str]:
        """Detect PHP version from X-Powered-By header"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{self.domain}"
            try:
                async with self.session.head(url, timeout=5, ssl=False) as resp:
                    powered_by = resp.headers.get('X-Powered-By', '')
                    if 'PHP' in powered_by:
                        # Extract version: PHP/7.4.33 → 7.4.33
                        match = re.search(r'PHP/([\d\.]+)', powered_by)
                        if match:
                            return match.group(1)
            except:
                continue
        return None
    
    async def _detect_from_errors(self) -> Optional[str]:
        """Detect PHP version from error messages"""
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
                            
                            # Look for PHP version in error
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
        """Detect PHP version via fingerprinting"""
        # Kiểm tra các phiên bản PHP phổ biến
        common_versions = ['7.4', '8.0', '8.1', '8.2', '8.3']
        
        for version in common_versions:
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{self.domain}/index.php"
                try:
                    # Gửi request với header đặc biệt
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
        """Check for known PHP vulnerabilities"""
        vulnerabilities = []
        
        # Extract major.minor
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
        """Check if version is in range"""
        try:
            if version_range.startswith('<'):
                max_ver = version_range[1:]
                return self._compare_versions(version, max_ver) < 0
        except:
            pass
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

# =================== ENHANCED ATTACK SURFACE ENUMERATOR ===================
class EnhancedAttackSurfaceEnumerator:
    """Enhanced enumerator with deep plugin/theme detection"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        self.session = None
        self.active_resolvers = []
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_PROFILE,
            self.deep_enumeration
        ))
    
    async def init_session(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                connector=aiohttp.TCPConnector(ssl=False)
            )
    
    async def deep_enumeration(self, event: Event):
        """Deep enumeration with version detection"""
        profile = event.data
        domain = profile['domain']
        
        if not self.session:
            await self.init_session()
        
        # Initialize detectors
        plugin_resolver = PluginVersionResolver(self.session, domain)
        theme_resolver = ThemeVersionResolver(self.session, domain)
        php_detector = PHPVersionDetector(self.session, domain)
        
        # 🆕 Track để cleanup sau
        self.active_resolvers.extend([plugin_resolver, theme_resolver, php_detector])
        
        # Run all enumerations in parallel
        tasks = [
            self.deep_plugin_enumeration(domain, plugin_resolver),
            self.deep_theme_enumeration(domain, theme_resolver),
            self.enumerate_users(domain),
            self.check_uploads(domain),
            self.check_debug_log(domain),
            self.enumerate_rest_routes(domain),
            php_detector.detect(),
            self.check_wp_config(domain),
            self.check_backup_files(domain),
            self.check_xmlrpc_methods(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compile results
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
            'wp_version': profile.get('wp_version'),
            'xmlrpc': profile.get('xmlrpc', False),
            'rest_api': profile.get('rest_api', False),
            'server_info': profile.get('server', {}),
            'timestamp': time.time()
        }
        
        # Calculate initial risk based on findings
        surfaces['initial_risk_score'] = self._calculate_initial_risk(surfaces)
        
        # Publish surface result
        surface_event = Event(
            type=EventType.SURFACE_RESULT,
            data=surfaces,
            source="EnhancedAttackSurfaceEnumerator"
        )
        
        await self.event_bus.publish(surface_event)
    
    async def deep_plugin_enumeration(self, domain: str, resolver: PluginVersionResolver) -> List[Dict]:
        """Deep plugin enumeration with version detection"""
        plugins = []
        
        # Detect plugin presence
        detected_slugs = await self._detect_plugin_presence(domain)
        
        # Resolve version for each plugin
        for plugin_slug in detected_slugs[:30]:  # Limit to 15 for performance
            try:
                version_result = await resolver.resolve(plugin_slug)
                
                # Get plugin info từ database
                plugin_info = Config.POPULAR_PLUGINS.get(plugin_slug, {})
                
                # Build plugin data
                plugin_data = {
                    'slug': plugin_slug,
                    'name': plugin_info.get('name', plugin_slug),
                    'category': plugin_info.get('category', 'unknown'),
                    'installs': plugin_info.get('installs', 'unknown'),
                    'version': version_result.version,
                    'version_confidence': version_result.confidence,
                    'version_method': version_result.method,
                    'vulnerabilities': [],  # Có thể thêm sau
                    'vulnerability_count': 0,
                    'risk_level': 'LOW',
                    'detected': True,
                    'evidence': version_result.evidence[:100] if version_result.evidence else None,
                }
                
                plugins.append(plugin_data)
                
                # Log detection
                if version_result.version:
                    print(f"\r\033[K\033[92m✓ Plugin\033[0m {plugin_slug:<25} v{version_result.version} "
                          f"(confidence: {version_result.confidence}%)")
                else:
                    print(f"\r\033[K\033[93m? Plugin\033[0m {plugin_slug:<25} (no version)")
                    
            except Exception as e:
                print(f"\r\033[K\033[91m✗ Plugin error\033[0m {plugin_slug}: {str(e)[:30]}")
                continue
        
        return plugins
    
    async def _detect_plugin_presence(self, domain: str) -> List[str]:
        """Detect which plugins are present with timeout protection"""
        detected = []
        popular_plugins = list(Config.POPULAR_PLUGINS.keys())
        
        batch_size = 10
        max_total_time = 90  # 🆕 Max 90 giây cho toàn bộ plugin detection
        start_time = time.time()
        
        for i in range(0, len(popular_plugins), batch_size):
            # 🆕 Check overall timeout
            elapsed = time.time() - start_time
            if elapsed > max_total_time:
                print(f"[PluginDetection] Overall timeout after {i} plugins ({elapsed:.1f}s)")
                break
            
            batch = popular_plugins[i:i+batch_size]
            
            try:
                # 🆕 Timeout cho từng batch (10s)
                tasks = [self._check_single_plugin(domain, slug) for slug in batch]
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=10.0
                )
                
                for j, result in enumerate(results):
                    if isinstance(result, bool) and result:
                        detected.append(batch[j])
                        
            except asyncio.TimeoutError:
                print(f"[PluginDetection] Batch {i//batch_size + 1} timeout, skipping...")
                continue
            except Exception as e:
                print(f"[PluginDetection] Batch {i//batch_size + 1} error: {e}")
                continue
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)
        
        return detected

    
    async def _check_single_plugin(self, domain: str, plugin_slug: str) -> bool:
        """Check if a specific plugin exists"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/"
            try:
                async with self.session.head(url, timeout=3, ssl=False) as resp:
                    if resp.status < 400:
                        return True
            except:
                continue
        
        # Also check for readme.txt
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/plugins/{plugin_slug}/readme.txt"
            try:
                async with self.session.head(url, timeout=3, ssl=False) as resp:
                    if resp.status < 400:
                        return True
            except:
                continue
        
        return False
    
    async def deep_theme_enumeration(self, domain: str, resolver: ThemeVersionResolver) -> List[Dict]:
        """Deep theme enumeration"""
        themes = []
        
        # Detect active theme
        active_theme = await self._detect_active_theme(domain)
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
    
    async def _detect_active_theme(self, domain: str) -> Optional[str]:
        """Detect active theme"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}"
            try:
                async with self.session.get(url, timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text(encoding='utf-8', errors='ignore')
                        
                        # Look for theme in HTML
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
    
    async def check_wp_config(self, domain: str) -> bool:
        """Check if wp-config.php is exposed"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-config.php"
            try:
                async with self.session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        if 'DB_NAME' in content or 'define(' in content:
                            return True
            except:
                continue
        
        # Also check wp-config-sample.php
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-config-sample.php"
            try:
                async with self.session.get(url, timeout=4, ssl=False) as resp:
                    return resp.status == 200
            except:
                continue
        
        return False
    
    async def check_backup_files(self, domain: str) -> List[str]:
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
                    async with self.session.head(url, timeout=3, ssl=False) as resp:
                        if resp.status == 200:
                            found_backups.append(pattern)
                            break
                except:
                    continue
        
        return found_backups
    
    async def check_xmlrpc_methods(self, domain: str) -> List[str]:
        """Check available XML-RPC methods"""
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
                async with self.session.post(url, data=xml_request, headers=headers, 
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
    
    async def enumerate_users(self, domain):
        """Enhanced user enumeration with better validation"""
        users = []
        
        # 1️⃣ REST API (ưu tiên cao nhất)
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-json/wp/v2/users?per_page=20"
            try:
                async with self.session.get(url, ssl=False, timeout=5) as resp:
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
                            if users:  # Nếu có users thật, return ngay
                                return users
            except Exception as e:
                pass
        
        # 2️⃣ Author enumeration (fallback với validation chặt)
        seen_slugs = set()
        for i in range(1, 11):  # Tăng lên 10 users
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/?author={i}"
                try:
                    async with self.session.get(url, allow_redirects=True, 
                                               ssl=False, timeout=5) as resp:
                        final_url = str(resp.url)
                        
                        # Validate redirect URL
                        m = re.search(r'/author/([a-zA-Z0-9_-]+)/?', final_url)
                        if m:
                            slug = m.group(1).lower()
                            
                            # Blacklist false positives
                            blacklist = ['page', 'author', 'user', 'admin', 
                                       'login', 'wp-admin', 'feed', 'rss',
                                       'comments', 'index', 'home']
                            
                            # Validate slug
                            if (slug not in blacklist and 
                                slug not in seen_slugs and 
                                len(slug) >= 3 and  # Tối thiểu 3 ký tự
                                not slug.isdigit()):  # Không phải toàn số
                                
                                seen_slugs.add(slug)
                                users.append({
                                    "id": i,
                                    "slug": slug,
                                    "source": "author_redirect"
                                })
                                break  # Next user ID
                except:
                    continue
        
        return users

    
    async def check_uploads(self, domain: str) -> bool:
        """Check uploads directory listing"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/uploads/"
            try:
                async with self.session.get(url, timeout=4, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text(encoding='utf-8', errors='ignore')
                        if 'index of' in text.lower() or '<title>Index of' in text:
                            return True
            except:
                continue
        return False
    
    async def check_debug_log(self, domain: str) -> bool:
        """Check debug.log file"""
        for scheme in ['https://', 'http://']:
            url = f"{scheme}{domain}/wp-content/debug.log"
            try:
                async with self.session.head(url, timeout=3, ssl=False) as resp:
                    return resp.status == 200
            except:
                continue
        return False
    
    async def enumerate_rest_routes(self, domain: str) -> List[str]:
            """Enumerate REST API routes"""
            routes = []
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{domain}/wp-json/"
                try:
                    async with self.session.get(url, timeout=5, ssl=False) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if 'routes' in data:
                                routes = list(data['routes'].keys())[:10]
                except:
                    continue
            return routes
    
    async def cleanup(self):
        """Cleanup tất cả resolvers và sessions"""
        print("[EnhancedAttackSurfaceEnumerator] Cleaning up resolvers...")
        
        for resolver in self.active_resolvers:
            # Resolvers không có session riêng, chúng dùng shared session
            # Nên không cần close session ở đây
            pass
        
        self.active_resolvers.clear()
        
        # Close main session
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                print("[EnhancedAttackSurfaceEnumerator] Session closed")
            except Exception as e:
                print(f"[EnhancedAttackSurfaceEnumerator] Session close error: {e}")
    
    def _calculate_initial_risk(self, surfaces: Dict) -> int:
        """Calculate initial risk score based on surfaces"""
        score = 0
        
        # Plugins with vulnerabilities
        for plugin in surfaces.get('plugins', []):
            vuln_count = plugin.get('vulnerability_count', 0)
            score += vuln_count * 25
        
        # Exposed config files
        if surfaces.get('wp_config_exposed'):
            score += 40
        
        # Directory listings
        if surfaces.get('uploads_listing'):
            score += 30
        
        # Debug log exposed
        if surfaces.get('debug_log'):
            score += 25
        
        # PHP vulnerabilities
        if surfaces['php_info'].get('vulnerabilities'):
            score += len(surfaces['php_info']['vulnerabilities']) * 20
        
        # XML-RPC enabled with methods
        if surfaces.get('xmlrpc') and surfaces.get('xmlrpc_methods'):
            score += 20
        
        # Many REST routes
        if len(surfaces.get('rest_routes', [])) > 10:
            score += 15
        
        # Backup files found
        if surfaces.get('backup_files'):
            score += len(surfaces['backup_files']) * 10
        
        return min(score, 100)

# =================== ENHANCED RISK SCORER ===================
class EnhancedRiskScorer:
    """Enhanced risk scoring với CVE matching"""
    
    def __init__(self, event_bus: AsyncEventBus):
        self.event_bus = event_bus
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.SURFACE_RESULT,
            self.score_risk
        ))
    
    async def score_risk(self, event: Event):
        """Enhanced risk scoring with deep analysis"""
        surfaces = event.data
        domain = surfaces['domain']
        
        # Collect all findings
        findings = []
        cve_matches = []
        risk_score = surfaces.get('initial_risk_score', 0)
        
        # 1. WordPress Core CVEs
        wp_version = surfaces.get('wp_version')
        if wp_version:
            wp_cves = self._check_wordpress_cves(wp_version)
            if wp_cves:
                risk_score += len(wp_cves) * 30
                cve_matches.extend(wp_cves)
                findings.append(f"WordPress {wp_version}: {len(wp_cves)} CVEs")
        
        # 2. Plugin vulnerabilities
        for plugin in surfaces.get('plugins', []):
            vulns = plugin.get('vulnerabilities', [])
            if vulns:
                plugin_name = plugin.get('name', plugin['slug'])
                plugin_version = plugin.get('version', 'unknown')
                findings.append(f"{plugin_name} {plugin_version}: {len(vulns)} vulns")
                cve_matches.extend(vulns)
        
        # 3. PHP vulnerabilities
        php_info = surfaces.get('php_info', {})
        if php_info.get('vulnerabilities'):
            php_version = php_info.get('version', 'unknown')
            vulns = php_info['vulnerabilities']
            risk_score += len(vulns) * 25
            cve_matches.extend(vulns)
            findings.append(f"PHP {php_version}: {len(vulns)} CVEs")
        
        # 4. Security misconfigurations
        if surfaces.get('wp_config_exposed'):
            findings.append("wp-config.php exposed")
            risk_score += 40
        
        if surfaces.get('uploads_listing'):
            findings.append("Uploads directory listing enabled")
            risk_score += 30
        
        if surfaces.get('debug_log'):
            findings.append("debug.log accessible")
            risk_score += 25
        
        # 5. User enumeration
        users = surfaces.get('users', [])

        # chỉ tính nếu user có slug thật
        real_users = [u for u in users if u.get("slug")]

        if len(real_users) > 0:
            findings.append(
                f"User enumeration confirmed ({len(real_users)} real users)"
            )
            risk_score += min(len(real_users) * 5, 20)

        
        # 6. XML-RPC attack surface
        if surfaces.get('xmlrpc') and surfaces.get('xmlrpc_methods'):
            method_count = len(surfaces['xmlrpc_methods'])
            findings.append(f"XML-RPC enabled with {method_count} methods")
            risk_score += 20
        
        # 7. REST API exposure
        rest_routes = surfaces.get('rest_routes', [])
        if len(rest_routes) > 10:
            findings.append(f"Many REST API routes exposed ({len(rest_routes)})")
            risk_score += 15
        
        # 8. Backup files
        backup_files = surfaces.get('backup_files', [])
        if backup_files:
            findings.append(f"Backup files found: {len(backup_files)}")
            risk_score += len(backup_files) * 10
        
        # Cap score
        risk_score = min(risk_score, 100)
        
        # Determine risk level
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
        
        # Remove duplicates
        unique_findings = []
        seen = set()
        for finding in findings:
            if finding not in seen:
                unique_findings.append(finding)
                seen.add(finding)
        
        # Create risk event
        risk_event = Event(
            type=EventType.RISK_SCORE,
            data={
                'domain': domain,
                'score': risk_score,
                'level': risk_level,
                'color_code': color_code,
                'findings': unique_findings[:8],
                'cves': list(set(cve_matches)),
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
        """Check WordPress version against CVE database"""
        cves = []
        
        try:
            # Check each version range
            for version_range, cve_list in Config.WORDPRESS_CVES.items():
                if self._is_version_in_range(version, version_range):
                    if isinstance(cve_list, list):
                        cves.extend(cve_list)
                    elif isinstance(cve_list, dict):
                        # Check sub-ranges
                        for sub_range, sub_cves in cve_list.items():
                            if self._is_version_in_range(version, sub_range):
                                cves.extend(sub_cves)
        except:
            pass
        
        return list(set(cves))
    
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

# =================== ENHANCED OUTPUT MANAGER ===================
class EnhancedOutputManager:
    """Enhanced output with detailed plugin/theme info"""
    
    def __init__(self, event_bus: AsyncEventBus, output_file: Optional[str] = None):
        self.event_bus = event_bus
        self.output_file = output_file
        self.results = []
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
        
        # Subscribe to events
        asyncio.create_task(self.event_bus.subscribe(
            EventType.RISK_SCORE,
            self.handle_final_result
        ))
        
        asyncio.create_task(self.event_bus.subscribe(
            EventType.WP_DETECTED,
            self.log_wp_detection
        ))
    
    async def handle_final_result(self, event: Event):
        """Handle final result with enhanced display"""
        result = event.data
        domain = result['domain']
        
        # Update stats
        self.stats['total'] += 1
        self.stats['wp'] += 1
        
        level = result['level']
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
        
        self.stats['vulnerabilities_found'] += len(result.get('cves', []))
        
        # Display results
        color = result['color_code']
        reset = "\033[0m"
        
        print(f"\n{color}{'═' * 80}{reset}")
        print(f"{color}🔍 WORDPRESS ATTACK SURFACE: {domain}{reset}")
        print(f"{color}{'═' * 80}{reset}")
        
        # Basic info
        print(f"\n📊 BASIC INFORMATION")
        print(f"  • WordPress Version: {result.get('wp_version', 'Unknown')}")
        print(f"  • PHP Version: {result.get('php_version', 'Unknown')}")
        print(f"  • Vulnerable Plugins: {result.get('vulnerable_plugins', 0)}")
        print(f"  • Total Plugins: {result.get('plugin_count', 0)}")
        # Risk assessment
        print(f"\n⚠️  RISK ASSESSMENT")
        print(f"  • Score: {color}{result['score']}/100 [{result['level']}]{reset}")
        print(f"  • CVEs Found: {len(result.get('cves', []))}")
        
        # Top findings
        if result.get('findings'):
            print(f"\n🔎 TOP FINDINGS:")
            for i, finding in enumerate(result['findings'][:6], 1):
                print(f"  {i}. {finding}")
        
        # CVEs if any
        if result.get('cves'):
            print(f"\n🚨 VULNERABILITIES (CVEs):")
            for cve in result['cves'][:3]:
                print(f"  • {cve}")
            if len(result['cves']) > 3:
                print(f"  • ... and {len(result['cves']) - 3} more")
        
        print(f"{color}{'═' * 80}{reset}\n")
        
        # Save to memory
        self.results.append(result)
        
        # Save to file
        if self.output_file:
            await self.save_to_file(result)
    
    async def log_wp_detection(self, event: Event):
        """Log WP detection"""
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
        """Save result to JSON file"""
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
            
            # Add new result
            data.append(result)
            
            # Write back
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"[OutputManager] Save error: {e}")

# =================== UPDATED PIPELINE ===================
class EnhancedWASEPipeline:
    """Enhanced pipeline với tất cả cải tiến"""
    
    def __init__(self, targets_file: Optional[str] = None, output_file: Optional[str] = None, 
                     workers: int = 12, discovery: bool = True, history_file: str = "scanned_history.txt"):  
        self.targets_file = targets_file
        self.output_file = output_file
        self.workers = workers
        self.discovery = discovery
        self.is_running = False
        
        # Initialize components
        self.event_bus = AsyncEventBus(max_size=Config.EVENT_BUS_SIZE)
        
        # Producers
        self.producers = []
        


        self.pre_filter = PreFilter(self.event_bus, history_file)
        self.wp_detector = WPGateDetector(self.event_bus, workers=workers)
        self.wp_fingerprint = WPCoreFingerprint(self.event_bus)
        self.surface_enumerator = EnhancedAttackSurfaceEnumerator(self.event_bus)
        self.risk_scorer = EnhancedRiskScorer(self.event_bus)
        self.output_manager = EnhancedOutputManager(self.event_bus, output_file)
    


    async def setup_producers(self):
        """Setup producers"""
        if self.targets_file:
            print(f"[Pipeline] Mode: Targeted scan từ {self.targets_file}")
            producer = TargetFileProducer(self.event_bus, self.targets_file)
            self.producers.append(producer)
        elif self.discovery:
            print(f"[Pipeline] Mode: Full discovery + deep scan")
            self.producers.extend([
                DorkProducer(self.event_bus),
                PassiveDNSProducer(self.event_bus),
            ])
        else:
            print("[Pipeline] Không có producers nào được cấu hình!")
            return False
        return True
    
    async def run(self):
        """Chạy enhanced pipeline"""
        print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║         WORDPRESS ATTACK SURFACE ENGINE (WASE) v1.5                   ║
║                     Tối ưu hóa Version Detection                      ║
╚════════════════════════════════════════════════════════════════════════╝
        """)
        
        self.is_running = True
        
        try:
            # Setup producers
            if not await self.setup_producers():
                return
            
            # Start event bus
            bus_task = asyncio.create_task(self.event_bus.run())
            
            # Start producers
            for producer in self.producers:
                await producer.start()
                print(f"[Pipeline] Đã khởi động producer: {producer.name}")
            
            print(f"\n{'═' * 80}")
            print("🚀 ENHANCED PIPELINE ĐÃ BẮT ĐẦU - Deep enumeration enabled")
            print(f"{'═' * 80}\n")
            print("📢 NHẤN CTRL+C ĐỂ DỪNG NGAY\n")
            
            # ĐỢI producers hoàn thành hoặc bị interrupt
            try:
                # Chờ tất cả producers hoàn thành
                producer_tasks = [asyncio.create_task(self._wait_for_producer(p)) 
                                 for p in self.producers]
                
                # Chờ một trong hai: producers hoàn thành HOẶC keyboard interrupt
                done, pending = await asyncio.wait(
                    producer_tasks,
                    timeout=None,
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Nếu có pending tasks, cancel chúng
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
            # DỪNG MỌI THỨ
            await self._force_shutdown()
            
            # Final stats
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
            
            # THOÁT NGAY LẬP TỨC - QUAN TRỌNG!
            import sys
            sys.exit(0)  # <-- THÊM DÒNG NÀY!
    
    async def _wait_for_producer(self, producer):
        """Chờ producer hoàn thành"""
        # Giả lập chờ producer
        while producer.is_running:
            await asyncio.sleep(0.5)
        return True
    
    
    async def _force_shutdown(self):
        """Force shutdown với cleanup đầy đủ"""
        print("\n" + "!" * 80)
        print("🛑 FORCE SHUTDOWN - ĐANG DỪNG TẤT CẢ!")
        print("!" * 80)

        self.is_running = False

        # 1️⃣ Dừng producers
        print("[Shutdown] Stopping producers...")
        for producer in self.producers:
            try:
                await producer.stop()
            except Exception as e:
                print(f"[Producer stop error] {producer.name}: {e}")

        # 2️⃣ Dừng event bus
        print("[Shutdown] Stopping event bus...")
        if hasattr(self.event_bus, 'stop'):
            try:
                await self.event_bus.stop()
            except Exception as e:
                print(f"[EventBus stop error] {e}")

        # 3️⃣ 🆕 Cleanup EnhancedAttackSurfaceEnumerator
        print("[Shutdown] Cleaning up all components...")
        
        components_to_cleanup = [
            ('WPGateDetector', self.wp_detector),
            ('WPCoreFingerprint', self.wp_fingerprint),
            ('EnhancedAttackSurfaceEnumerator', self.surface_enumerator),
        ]
        
        for name, component in components_to_cleanup:
            if hasattr(component, 'cleanup'):
                try:
                    await component.cleanup()
                    print(f"[Cleanup] ✓ {name} cleaned up")
                except Exception as e:
                    print(f"[Cleanup error] {name}: {e}")

        # 4️⃣ Cancel tất cả tasks còn lại
        print("[Shutdown] Cancelling remaining tasks...")
        current_task = asyncio.current_task()
        all_tasks = [t for t in asyncio.all_tasks() if t is not current_task and not t.done()]

        if all_tasks:
            print(f"[Shutdown] Cancelling {len(all_tasks)} tasks...")
            for task in all_tasks:
                task.cancel()

            try:
                await asyncio.wait(all_tasks, timeout=3.0)
            except Exception as e:
                print(f"[Task cancel error] {e}")

        # 5️⃣ Cleanup TẤT CẢ aiohttp ClientSession
        print("[Shutdown] Closing all sessions...")
        sessions_to_close = []

        # Thu thập sessions từ các components
        if hasattr(self, 'wp_detector') and hasattr(self.wp_detector, 'session') and self.wp_detector.session:
            sessions_to_close.append(('WPGateDetector', self.wp_detector.session))
            
        if hasattr(self, 'wp_fingerprint') and hasattr(self.wp_fingerprint, 'session') and self.wp_fingerprint.session:
            sessions_to_close.append(('WPCoreFingerprint', self.wp_fingerprint.session))
            
        if hasattr(self, 'surface_enumerator') and hasattr(self.surface_enumerator, 'session') and self.surface_enumerator.session:
            sessions_to_close.append(('EnhancedAttackSurfaceEnumerator', self.surface_enumerator.session))

        # Close tất cả sessions
        for name, session in sessions_to_close:
            try:
                if not session.closed:
                    await session.close()
                    print(f"[Cleanup] ✓ Closed session: {name}")
            except Exception as e:
                print(f"[Session close error] {name}: {e}")

        # 6️⃣ 🆕 Force wait để đảm bảo connectors đóng hoàn toàn
        print("[Shutdown] Waiting for connectors to close...")
        await asyncio.sleep(0.5)  # Cho connectors thời gian đóng

        print("✅ SHUTDOWN HOÀN TẤT - All cleanup done")

# =================== MAIN ===================
async def main():
    """Entry point"""
    args = parse_args()
    
    if args.targets and not os.path.exists(args.targets):
        print(f"❌ Không tìm thấy file targets: {args.targets}")
        return
    
    # Tạo pipeline
    pipeline = EnhancedWASEPipeline(
        targets_file=args.targets,
        output_file=args.output,
        workers=args.workers,
        discovery=not args.no_discovery,
        history_file=args.history 
    )
    
    # CHẠY VÀ THOÁT
    try:
        await pipeline.run()
    except KeyboardInterrupt:
        print("\n\n👋 Dừng theo yêu cầu người dùng")
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
        import traceback
        traceback.print_exc()
    
    # THOÁT CHƯƠNG TRÌNH
    print("\n🏁 Kết thúc chương trình")

def parse_args():
    parser = argparse.ArgumentParser(
        description='WordPress Attack Surface Engine (WASE) - Deep Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full discovery mode (no targets file)
  python gemini.py --workers 12 --output results.json
  
  # Targeted scan from file
  python gemini.py --targets targets.txt --output scan_results.json
  
  # Quick scan với ít workers
  python gemini.py --targets urls.txt --workers 4 --output quick.json
        """
    )
    
    parser.add_argument('--targets', '-t', type=str,
                       help='File chứa targets (mỗi dòng 1 domain/URL). Nếu không có, chạy discovery mode')
    
    parser.add_argument('--output', '-o', type=str, default='wase_results.json',
                       help='File output JSON (default: wase_results.json)')
    
    parser.add_argument('--workers', '-w', type=int, default=8,
                       help='Số concurrent workers (default: 8)')
    
    parser.add_argument('--no-discovery', action='store_true',
                       help='Tắt discovery mode (chỉ dùng nếu có --targets)')
    parser.add_argument('--history', type=str, default='scanned_history.txt',  # 🆕 THÊM OPTION NÀY
                   help='File lưu domains đã scan (default: scanned_history.txt)')
    return parser.parse_args()

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n🛑 KeyboardInterrupt - Cleaning up...")
    finally:
        # Cleanup loop
        tasks = asyncio.all_tasks(loop)
        for t in tasks:
            t.cancel()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
    print("Exit hoàn toàn")