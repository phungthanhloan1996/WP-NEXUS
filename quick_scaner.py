import requests
import re
import concurrent.futures
import urllib3
import random
import socket
import time
from threading import Lock
from urllib.parse import urlparse
from tqdm import tqdm

# Cấu hình tối ưu
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
R, G, Y, B, C, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[0m'

class ShadowStrikeV12:
    def __init__(self):
        self.raw_seeds = set()
        self.processed_entities = set()
        self.found_targets = []
        self.lock = Lock()
        self.session = requests.Session()
        self.session.max_redirects = 2
        self.user_agents = ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']

    # --- PHASE 1: DISCOVERY ---
    def discovery_phase(self):
        print(f"{B}[*] PHASE 1: Khởi động Discovery (Vét cạn)...{W}")
        sources = [
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
            "https://rapiddns.io/subdomain/wp-content?full=1"
        ]
        for url in sources:
            try:
                r = requests.get(url, timeout=10)
                self.raw_seeds.update(re.findall(r'(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})', r.text))
            except: pass
        print(f"{G}[✓] Tổng: {len(self.raw_seeds):,} hạt giống.{W}")

    # --- TIERED AUDIT LOGIC (CHỐNG TREO & TIẾT KIỆM BUDGET) ---
    def audit_tiered(self, url):
        report = {
            'url': url, 'score': 0, 'ver': 'Unknown', 'conf': 'Low',
            'exposures': [], 'misconfigs': [], 'leaks': []
        }
        
        try:
            # TIER 1: LIGHTWEIGHT (1-2 Requests) - Quyết định có đi tiếp không
            res = self.session.get(url, timeout=5, verify=False)
            body = res.text.lower()
            
            # Smart Version Check (Meta + Script/Style + Feed)
            v_match = re.search(r'content="WordPress\s?([\d.]+)"', body) or \
                      re.search(r'ver=([\d.]+)', body)
            if v_match: 
                report['ver'] = v_match.group(1)
                report['score'] += 2
                report['conf'] = 'Medium'

            # Early Abort: Nếu không thấy dấu hiệu WP rõ ràng hoặc site quá Hardened (403 toàn bộ)
            if 'wp-content' not in body and 'wp-includes' not in body:
                return None

            # TIER 2: CONFIGURATION (2-3 Requests) - Chỉ chạy khi qua Tier 1
            # Check Login & XML-RPC
            for path, category in [('/wp-login.php', 'exposure'), ('/xmlrpc.php', 'misconfig')]:
                r = self.session.get(url + path, timeout=4, verify=False)
                if r.status_code == 200:
                    report['score'] += 2
                    if 'exposure' in category: report['exposures'].append(path)
                    else: report['misconfigs'].append(path)

            # TIER 3: DEEP LEAK (Chỉ chạy khi score >= 4) - Tiết kiệm Audit Budget
            if report['score'] >= 4:
                # Directory Listing
                r_up = self.session.get(url + '/wp-content/uploads/', timeout=4, verify=False)
                if 'index of' in r_up.text.lower():
                    report['score'] += 4
                    report['misconfigs'].append('Uploads Dir Listing')

                # User Enumeration (REST API)
                r_usr = self.session.get(url + '/wp-json/wp/v2/users', timeout=4, verify=False)
                if r_usr.status_code == 200 and 'slug' in r_usr.text:
                    report['score'] += 5
                    report['leaks'].append('REST User Enumeration')

                # Critical Sensitive Files
                for spath, sname in [('/.env', 'Env File'), ('/wp-config.php.bak', 'Config Backup')]:
                    rs = self.session.get(url + spath, timeout=3, verify=False)
                    if rs.status_code == 200 and any(k in rs.text for k in ['DB_', 'APP_ENV']):
                        report['score'] += 10
                        report['leaks'].append(f'CRITICAL: {sname}')

            return report
        except: return None

    # --- PIPELINE ENGINE ---
    def process_worker(self, domain, pbar):
        try:
            socket.gethostbyname(domain)
            for proto in ['https://', 'http://']:
                u = f"{proto}{domain}"
                try:
                    # Dùng HEAD để normalize & check alive trước
                    r = self.session.head(u, timeout=3, verify=False, allow_redirects=True)
                    netloc = urlparse(r.url).netloc.lower()
                    
                    with self.lock:
                        if netloc in self.processed_entities: return
                        self.processed_entities.add(netloc)
                    
                    # Tiến hành Audit phân tầng
                    data = self.audit_tiered(r.url.rstrip('/'))
                    if data and data['score'] >= 1:
                        with self.lock:
                            self.found_targets.append(data)
                            if data['score'] >= 6:
                                tqdm.write(f"\n{Y}[!] HIGH WEAKNESS: {data['url']} (Score: {data['score']}){W}")
                                if data['exposures']: tqdm.write(f"  |-- Exposure: {', '.join(data['exposures'])}")
                                if data['leaks']: tqdm.write(f"  {R}|-- Leaks: {', '.join(data['leaks'])}{W}")
                    break
                except: continue
        except: pass
        finally: pbar.update(1)

    def run(self, threads=80):
        start_t = time.time()
        self.discovery_phase()
        
        seeds = list(self.raw_seeds)
        random.shuffle(seeds)
        
        print(f"{Y}[*] Bắt đầu quét phân tầng (Tiered Audit)...{W}")
        pbar = tqdm(total=len(seeds), desc="Auditing", unit="site")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for d in seeds: ex.submit(self.process_worker, d, pbar)
        
        pbar.close()
        self.save_report()
        print(f"\n{B}✅ XONG! Báo cáo lưu tại: AUDIT_REPORT.txt (Time: {time.time()-start_t:.1f}s){W}")

    def save_report(self):
        with open("AUDIT_REPORT.txt", "w") as f:
            for t in sorted(self.found_targets, key=lambda x: x['score'], reverse=True):
                f.write(f"URL: {t['url']} | Score: {t['score']} | Ver: {t['ver']}\n")
                if t['exposures']: f.write(f" - Exposures: {t['exposures']}\n")
                if t['leaks']: f.write(f" - Leaks: {t['leaks']}\n")
                f.write("-" * 50 + "\n")

if __name__ == "__main__":
    scanner = ShadowStrikeV12()
    scanner.run(threads=100)
