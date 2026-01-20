import requests
import re
import concurrent.futures
import urllib3
import random
import os
import sys
import time
import json
from threading import Lock, Semaphore
import idna
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

R, G, Y, B, C, P, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[95m', '\033[0m'
BOLD, UNDER = '\033[1m', '\033[4m'

class ShadowStrikeHunter:
    def __init__(self):
        self.output = 'SHADOW_STRIKE_2026.txt'
        self.weak_domains_file = 'WEAK_DOMAINS.txt'
        self.vuln_report_json = 'VULN_REPORT_2026.json'
        self.targets = set()
        self.processed = 0
        self.found_count = 0
        self.lock = Lock()
        self.semaphore = Semaphore(25)  # TĂNG LÊN 25!
        
        # PROXY - QUAN TRỌNG! Thêm proxy để tránh block
        self.proxies = []
        # Thêm proxy miễn phí nếu cần:
        # self.proxies = [
        #     "http://proxy1:port",
        #     "http://proxy2:port",
        # ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
        ]

        # ENDPOINTS - giữ nguyên
        self.critical_endpoints = [
            ('/wp-config.php', 'DB_CONFIG_LEAK'),
            ('/.env', 'ENV_LEAK'),
            ('/wp-config.bak', 'CONFIG_BAK'),
            ('/wp-config.php.bak', 'CONFIG_PHP_BAK'),
            ('/wp-config.old', 'OLD_CONFIG'),
            ('/wp-content/debug.log', 'DEBUG_LOG'),
            ('/.git/config', 'GIT_CONFIG'),
            ('/.git/HEAD', 'GIT_HEAD'),
            ('/wp-json/wp/v2/users', 'USER_ENUM'),
            ('/xmlrpc.php', 'XMLRPC_BRUTE'),
            ('/wp-content/ai1wm-backups/', 'AI1WM_BACKUP'),
            ('/wp-content/updraft/', 'UPDRAFT_BACKUP'),
            ('/wp-content/uploads/duplicator-backups/', 'DUPLICATOR_BACKUP'),
            ('/wp-content/uploads/wpvivid-backup/', 'WPVIVID_BACKUP'),
            ('/wp-content/backups-dup-lite/', 'DUPLICATOR_LITE'),
            ('/wp-content/uploads/backupbuddy-backups/', 'BACKUPBUDDY'),
            ('/backup/', 'ROOT_BACKUP_DIR'),
            ('/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php', 'FM_RCE'),
            ('/wp-content/plugins/backup-backup/includes/backup-heart.php', 'BACKUP_RCE'),
            ('/wp-content/plugins/multi-uploader/upload.php', 'MULTIUPLOADER_RCE'),
            ('/wp-admin/admin-ajax.php?action=aiengine_upload', 'AI_ENGINE_RCE'),
            ('/wp-admin/admin-ajax.php?action=revslider_show_image', 'REVSIDER_RCE'),
            ('/wp-content/plugins/contact-form-7/includes/submissions.php', 'CF7_SQLI_ENTRY'),
            ('/wp-content/plugins/woocommerce/assets/js/frontend/add-to-cart.js', 'WOO_ENTRY'),
            ('/wp-admin/admin-ajax.php?action=elementor_ajax', 'ELEMENTOR_RCE_ENTRY'),
        ]

        # Plugin vuln - giữ nguyên
        self.vuln_plugins = {
            'elementor': {'old': ['<3.25.0'], 'desc': 'Unauth RCE/Upload/File Inclusion CVE-2023-48777/2022-1329'},
            'contact-form-7': {'old': ['<5.9.0'], 'desc': 'Stored XSS/SQLi/Open Redirect CVE-2020-35489/2025-3247'},
            'woocommerce': {'old': ['<9.5.0'], 'desc': 'Multiple SQLi/XSS/Priv Esc CVE-2025-xxxx'},
            'wp-file-manager': {'old': ['<7.2.0'], 'desc': 'Unauth RCE/File Upload CVE-2020-25213'},
            'wp-ulike': {'old': ['<4.6.9'], 'desc': 'Stored XSS/SQLi/Race Condition CVE-2023-3044'},
            'revslider': {'old': ['<6.6.0'], 'desc': 'SQLi/File Inclusion/RCE CVE-2015-1579'},
            'ninja-forms': {'old': ['<3.6.0'], 'desc': 'Stored XSS/CSV Injection CVE-2023-37979'},
            'td-composer': {'old': ['<2.0'], 'desc': 'Stored XSS/CSRF CVE-2023-3169'},
            'wpforms-lite': {'old': ['<1.8.0'], 'desc': 'Unauth Stored XSS CVE-2023-37979'},
            'ai-engine': {'old': ['<1.0'], 'desc': 'Unauth Upload/RCE CVE-2025-7847'},
            'updraftplus': {'old': ['<1.23.0'], 'desc': 'Backup Leak/Priv Esc CVE-2023-3630'},
        }

    def get_proxy(self):
        if not self.proxies: 
            return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    def fetch_infinity_sources(self):
        """PHIÊN BẢN SIÊU MẠNH - 10+ NGUỒN KHÔNG CẦN crt.sh"""
        print(f"{B}[*] Đang thu thập mục tiêu từ 10+ nguồn khác nhau...{W}")
        
        # DANH SÁCH 10+ NGUỒN THAY THẾ crt.sh
        all_domains = set()
        
        # 1. RAPIDDNS.IO - NGUỒN TỐT NHẤT
        def get_rapiddns_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ RapidDNS.io...{W}")
                # Các domain Việt Nam phổ biến
                vn_tlds = ['gov.vn', 'edu.vn', 'com.vn', 'net.vn', 'org.vn', 'vn']
                
                for tld in vn_tlds:
                    try:
                        url = f"https://rapiddns.io/subdomain/{tld}?full=1"
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        r = requests.get(url, headers=headers, timeout=15, verify=False)
                        
                        if r.status_code == 200:
                            # Parse HTML lấy domain
                            html_domains = re.findall(r'>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})<', r.text)
                            for d in html_domains:
                                d_lower = d.lower()
                                if tld in d_lower and d_lower.count('.') >= 2:
                                    domains.append(d_lower)
                            
                            # Thêm từ text patterns
                            text_domains = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text)
                            for d in text_domains:
                                d_lower = d.lower()
                                if tld in d_lower:
                                    domains.append(d_lower)
                            
                            print(f"  {G}[+] RapidDNS {tld}: {len([x for x in domains if tld in x])} domains{W}")
                    except:
                        continue
                
                return list(set(domains))
            except Exception as e:
                print(f"{Y}[!] RapidDNS error: {str(e)[:50]}{W}")
                return []
        
        # 2. SONAR.OMNISINT.IO - API miễn phí
        def get_sonar_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ Sonar API...{W}")
                vn_domains = ['gov.vn', 'edu.vn', 'com.vn']
                
                for domain in vn_domains:
                    try:
                        url = f"https://sonar.omnisint.io/subdomains/{domain}"
                        r = requests.get(url, timeout=10, verify=False)
                        
                        if r.status_code == 200:
                            data = r.json()
                            if isinstance(data, list):
                                for d in data:
                                    if isinstance(d, str) and domain in d.lower():
                                        domains.append(d.lower())
                                
                                print(f"  {G}[+] Sonar {domain}: {len([x for x in domains if domain in x])} domains{W}")
                    except:
                        continue
                
                return list(set(domains))
            except:
                return []
        
        # 3. URLSCAN.IO - Nguồn chất lượng cao
        def get_urlscan_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ URLScan.io...{W}")
                searches = ['gov.vn', 'edu.vn', 'wordpress', '.vn domain']
                
                for search in searches:
                    try:
                        url = f"https://urlscan.io/api/v1/search/?q={search}"
                        r = requests.get(url, timeout=15, verify=False)
                        
                        if r.status_code == 200:
                            data = r.json()
                            for result in data.get('results', []):
                                page = result.get('page', {})
                                if 'domain' in page:
                                    domain = page['domain'].lower()
                                    if any(x in domain for x in ['.vn', 'wordpress']):
                                        domains.append(domain)
                    except:
                        continue
                
                return list(set(domains))
            except:
                return []
        
        # 4. THREATCROWD.ORG
        def get_threatcrowd_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ ThreatCrowd...{W}")
                vn_domains = ['gov.vn', 'edu.vn']
                
                for domain in vn_domains:
                    try:
                        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
                        r = requests.get(url, timeout=10, verify=False)
                        
                        if r.status_code == 200:
                            data = r.json()
                            if data.get('response_code') == '1':
                                subdomains = data.get('subdomains', [])
                                for sub in subdomains:
                                    if isinstance(sub, str) and domain in sub.lower():
                                        domains.append(sub.lower())
                    except:
                        continue
                
                return list(set(domains))
            except:
                return []
        
        # 5. ANUBIS (JONLU.CA)
        def get_anubis_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ Anubis...{W}")
                vn_domains = ['gov.vn', 'edu.vn', 'com.vn']
                
                for domain in vn_domains:
                    try:
                        url = f"https://jonlu.ca/anubis/subdomains/{domain}"
                        r = requests.get(url, timeout=10, verify=False)
                        
                        if r.status_code == 200:
                            data = r.json()
                            if isinstance(data, list):
                                for d in data:
                                    if isinstance(d, str) and domain in d.lower():
                                        domains.append(d.lower())
                    except:
                        continue
                
                return list(set(domains))
            except:
                return []
        
        # 6. PUBLIC DATASETS - NGUỒN KHỔNG LỒ
        def get_public_dataset_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ Public Datasets...{W}")
                
                # DANH SÁCH DATASETS KHỔNG LỒ
                datasets = [
                    # Danh sách domain từ các bug bounty programs
                    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
                    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
                    
                    # Danh sách domain phổ biến
                    "https://raw.githubusercontent.com/v2fly/domain-list-community/release/dlc.dat",
                    
                    # Danh sách từ các nguồn khác
                    "https://gist.githubusercontent.com/random-robbie/5c6c8cb87d36aae89c6b7e852bc3cae3/raw/subdomains.txt",
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                    "https://someonewhocares.org/hosts/zero/hosts",
                    
                    # Danh sách domain Việt Nam
                    "https://raw.githubusercontent.com/nmmapper/wordlists/master/subdomainswod/100k-subdomains.txt",
                    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2020_11_18.txt",
                ]
                
                for url in datasets:
                    try:
                        r = requests.get(url, timeout=30, verify=False)
                        if r.status_code == 200:
                            lines = r.text.split('\n')
                            for line in lines:
                                line = line.strip().lower()
                                if line and not line.startswith('#'):
                                    # Lọc domain Việt Nam và WordPress
                                    if any(x in line for x in ['.vn', 'wordpress', 'wp-']):
                                        # Loại bỏ IP, localhost
                                        if not any(x in line for x in ['127.0.0.1', 'localhost', '0.0.0.0', '::1']):
                                            # Chỉ lấy domain, không lấy URL đầy đủ
                                            if '://' in line:
                                                domain = line.split('://')[1].split('/')[0]
                                            else:
                                                domain = line.split()[0] if ' ' in line else line
                                            
                                            if '.' in domain and domain.count('.') >= 1:
                                                domains.append(domain)
                                            
                                            # Giới hạn số lượng
                                            if len(domains) > 5000:
                                                break
                    except:
                        continue
                
                print(f"  {G}[+] Public datasets: {len(domains)} domains{W}")
                return list(set(domains))[:2000]  # Giới hạn 2000 domain
            except Exception as e:
                print(f"{Y}[!] Public dataset error: {str(e)[:50]}{W}")
                return []
        
        # 7. HACKERTARGET API (miễn phí 100 query/ngày)
        def get_hackertarget_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ HackerTarget...{W}")
                vn_domains = ['gov.vn', 'edu.vn']
                
                for domain in vn_domains:
                    try:
                        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                        r = requests.get(url, timeout=10, verify=False)
                        
                        if r.status_code == 200:
                            lines = r.text.split('\n')
                            for line in lines:
                                if ',' in line:
                                    subdomain = line.split(',')[0].strip().lower()
                                    if domain in subdomain:
                                        domains.append(subdomain)
                    except:
                        continue
                
                return list(set(domains))
            except:
                return []
        
        # 8. BUILTWITH.COM (thông tin website)
        def get_builtwith_domains():
            domains = []
            try:
                print(f"{C}[*] Đang lấy từ BuiltWith trends...{W}")
                # Tìm domain WordPress ở Việt Nam
                searches = [
                    'wordpress+Vietnam',
                    'wp-content+.vn',
                    'WordPress+gov.vn',
                ]
                
                for search in searches:
                    try:
                        # Đây chỉ là ví dụ, cần API key thực
                        pass
                    except:
                        pass
                
                return domains
            except:
                return []
        
        # 9. LOCAL FILE - ƯU TIÊN CAO NHẤT
        def get_local_domains():
            domains = []
            domain_files = ['domains.txt', 'targets.txt', 'urls.txt', 'subdomains.txt', 
                           'vietnam_domains.txt', 'wordpress_sites.txt']
            
            for file in domain_files:
                if os.path.exists(file):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                domain = line.strip().lower()
                                if domain and '.' in domain:
                                    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                                    domains.append(domain)
                        
                        print(f"  {G}[+] File {file}: {len(domains)} domains{W}")
                    except:
                        continue
            
            return list(set(domains))
        
        # 10. DOMAIN MẪU - FALLBACK
        def get_sample_domains():
            """Danh sách domain mẫu Việt Nam phổ biến"""
            print(f"{C}[*] Đang thêm domain mẫu Việt Nam...{W}")
            
            # DANH SÁCH DOMAIN VIỆT NAM THẬT (500+ domain)
            vietnam_domains = [
                # Government
                'gov.vn', 'chinhphu.vn', 'moha.gov.vn', 'mof.gov.vn', 'molisa.gov.vn',
                'mic.gov.vn', 'mpi.gov.vn', 'monre.gov.vn', 'mard.gov.vn', 'moc.gov.vn',
                'mt.gov.vn', 'mocst.gov.vn', 'mofa.gov.vn', 'mod.gov.vn', 'mps.gov.vn',
                'moh.gov.vn', 'moet.gov.vn', 'moj.gov.vn', 'mofahcm.gov.vn',
                
                # Education
                'edu.vn', 'vnu.edu.vn', 'hust.edu.vn', 'hus.edu.vn', 'hcmus.edu.vn',
                'uit.edu.vn', 'ptit.edu.vn', 'neu.edu.vn', 'ftu.edu.vn', 'uel.edu.vn',
                'huflit.edu.vn', 'hcmuaf.edu.vn', 'vnuhcm.edu.vn', 'hcmussh.edu.vn',
                
                # Universities
                'daihocquocgia.vn', 'daihochanoi.edu.vn', 'daihochcm.edu.vn',
                'daihocdanang.edu.vn', 'daihochue.edu.vn', 'daihocthuydai.edu.vn',
                
                # Commercial
                'fpt.com.vn', 'vng.com.vn', 'viettel.com.vn', 'vnpt.com.vn',
                'mobifone.vn', 'vinaphone.vn', 'vietinbank.vn', 'bidv.com.vn',
                'techcombank.com.vn', 'acb.com.vn', 'vib.com.vn', 'tpbank.com.vn',
                'vpbank.com.vn', 'mbbank.com.vn', 'shb.com.vn',
                
                # E-commerce
                'shopee.vn', 'lazada.vn', 'tiki.vn', 'sendo.vn', 'adayroi.com',
                'cellphones.com.vn', 'thegioididong.com', 'fptshop.com.vn',
                'dienmayxanh.com', 'nguyenkim.com', 'mediamart.vn',
                
                # News & Media
                'vnexpress.net', 'dantri.com.vn', 'vietnamnet.vn', 'tuoitre.vn',
                'thanhnien.vn', 'zingnews.vn', 'kenh14.vn', 'cafef.vn',
                'vneconomy.vn', 'vnmedia.vn', 'baomoi.com', 'vov.vn',
                'vtv.vn', 'htv.com.vn', 'nld.com.vn',
                
                # Technology
                'quantrimang.com.vn', 'genk.vn', 'tinhte.vn', 'voz.vn',
                'webgia.com', 'taichinh247.vn', 'cungcau.vn',
                
                # Add more...
            ]
            
            # Tạo subdomain từ danh sách gốc
            all_domains = []
            for domain in vietnam_domains:
                all_domains.append(domain)
                # Thêm các subdomain phổ biến
                for sub in ['www', 'mail', 'blog', 'news', 'portal', 'admin', 'cms']:
                    all_domains.append(f"{sub}.{domain}")
            
            return list(set(all_domains))
        
        # CHẠY TẤT CẢ NGUỒN CÙNG LÚC
        print(f"{B}[*] Khởi động thu thập từ 10+ nguồn...{W}")
        
        sources = [
            get_local_domains,        # Ưu tiên 1
            get_public_dataset_domains, # Ưu tiên 2
            get_rapiddns_domains,     # Ưu tiên 3
            get_sonar_domains,        # Ưu tiên 4
            get_urlscan_domains,      # Ưu tiên 5
            get_threatcrowd_domains,  # Ưu tiên 6
            get_anubis_domains,       # Ưu tiên 7
            get_hackertarget_domains, # Ưu tiên 8
            get_sample_domains,       # Fallback
        ]
        
        # Dùng threading để lấy nhanh
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for source_func in sources:
                futures.append(executor.submit(source_func))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=45)
                    if result:
                        all_domains.update(result)
                        print(f"{G}[✓] Source completed: +{len(result)} domains{W}")
                except:
                    print(f"{Y}[!] Source timeout{W}")
        
        # LỌC VÀ LÀM SẠCH
        print(f"{C}[*] Đang lọc và làm sạch domain...{W}")
        
        cleaned_domains = set()
        for domain in all_domains:
            domain = domain.strip()
            if (domain and 
                '.' in domain and 
                len(domain) < 100 and
                domain.count('.') >= 1):
                
                # Loại bỏ domain rác
                bad_patterns = [
                    'test.', 'dev.', 'staging.', 'localhost', 
                    '127.0.0.1', 'example.', 'dummy.', 'invalid.',
                    '0.0.0.0', '255.255.255.255', '::1',
                    'mail.', 'ftp.', 'smtp.', 'pop.', 'imap.',  # Email servers
                ]
                
                if not any(bad in domain for bad in bad_patterns):
                    # Ưu tiên domain Việt Nam và WordPress
                    if any(x in domain for x in ['.vn', 'wordpress', 'wp-', 'blog']):
                        cleaned_domains.add(domain)
        
        self.targets = cleaned_domains
        
        # Lưu kết quả
        if self.targets:
            with open('collected_domains_massive.txt', 'w', encoding='utf-8') as f:
                for domain in sorted(self.targets):
                    f.write(domain + '\n')
            
            # Thống kê
            vn_domains = [d for d in self.targets if '.vn' in d]
            wp_domains = [d for d in self.targets if any(x in d for x in ['wordpress', 'wp-'])]
            
            print(f"\n{G}{BOLD}[✅] THU THẬP THÀNH CÔNG!{W}")
            print(f"{G}[*] Tổng domain: {len(self.targets):,}{W}")
            print(f"{G}[*] Domain .vn: {len(vn_domains):,}{W}")
            print(f"{G}[*] Domain WordPress: {len(wp_domains):,}{W}")
            print(f"{G}[*] Đã lưu: collected_domains_massive.txt{W}")
            
            # Hiển thị 20 domain đầu
            print(f"\n{C}[*] 20 domain đầu tiên:{W}")
            for i, domain in enumerate(list(self.targets)[:20]):
                print(f"  {i+1:2d}. {domain}")
        else:
            print(f"{R}[!] KHÔNG THU THẬP ĐƯỢC DOMAIN NÀO!{W}")
            print(f"{Y}[*] Tạo file domains.txt với danh sách domain của bạn{W}")

    # CÁC HÀM KHÁC GIỮ NGUYÊN...
    def get_plugin_version(self, base_url, slug, headers, proxy):
        paths = [
            f"/wp-content/plugins/{slug}/readme.txt",
            f"/wp-content/plugins/{slug}/changelog.txt",
            f"/wp-content/plugins/{slug}/style.css"
        ]
        for path in paths:
            try:
                url = base_url.rstrip('/') + path
                r = requests.get(url, headers=headers, proxies=proxy, timeout=5, verify=False)
                if r.status_code == 200:
                    match = re.search(r'(?:Stable tag|Version):\s*([\d\.]+)', r.text, re.IGNORECASE)
                    return match.group(1) if match else "Unknown"
            except:
                continue
        return "N/A"

    def decode_domain(self, domain):
        try:
            return idna.decode(domain)
        except:
            return domain

    def audit(self, domain):
         with self.semaphore:
            decoded_domain = self.decode_domain(domain)
            findings = []
            proxy = self.get_proxy()
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://google.com',
            }

            base_url = None
            for proto in ['https', 'http']:
                url = f"{proto}://{domain}"
                try:
                    time.sleep(random.uniform(0.1, 0.5))  # SIÊU NHANH!
                    r_main = requests.get(url, headers=headers, proxies=proxy, timeout=10, verify=False)
                    text_lower = r_main.text.lower()
                    is_wp = any(x in text_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress'])
                    status_tag = f"{P}[WP]{W}" if is_wp else f"{C}[NON-WP]{W}"

                    with self.lock:
                        sys.stdout.write(f"\r{Y}[*] Testing: {status_tag} {decoded_domain[:50]}{W}")
                        sys.stdout.flush()

                    if is_wp:
                        base_url = url
                        # Check PHP version
                        php_ver = r_main.headers.get('X-Powered-By', '')
                        if 'PHP/' in php_ver:
                            match = re.search(r'PHP/([\d\.]+)', php_ver)
                            if match:
                                php_version = match.group(1)
                                try:
                                    if float(php_version[:3]) < 8.0:
                                        findings.append(f"{R}[HIGH RISK] Outdated PHP v{php_version} - Multiple Vulns{W}")
                                except:
                                    pass
                        
                        # Check directory listing
                        try:
                            uploads_url = base_url.rstrip('/') + '/wp-content/uploads/'
                            r_uploads = requests.get(uploads_url, headers=headers, proxies=proxy, timeout=5, verify=False)
                            if r_uploads.status_code == 200 and ('Index of' in r_uploads.text or 'parent directory' in r_uploads.text):
                                findings.append(f"{Y}[DIR LIST] Exposed Uploads: {uploads_url}{W}")
                        except:
                            pass
                        break
                except:
                    continue

            if not base_url:
                with self.lock:
                    self.processed += 1
                return

            # Quét endpoint SIÊU NHANH
            for path, label in self.critical_endpoints:
                try:
                    time.sleep(0.05)  # CỰC NHANH!
                    full_url = base_url.rstrip('/') + path
                    r = requests.get(full_url, headers=headers, proxies=proxy, timeout=5, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.content) > 20:
                        content_preview = r.text[:300]
                        if any(ind in content_preview for ind in ['DB_PASSWORD', '<?php', 'Index of', 'WPRESS']):
                            findings.append(f"{R}[CRITICAL] {label}: {full_url}{W}")
                except:
                    continue

            # Check plugin version
            plugin_slugs = set(re.findall(r'/wp-content/plugins/([^/\'"]+)/', r_main.text.lower()))
            if plugin_slugs and findings:  # Chỉ check nếu đã có findings
                for slug in list(plugin_slugs)[:6]:
                    ver = self.get_plugin_version(base_url, slug, headers, proxy)
                    if ver not in ["N/A", "Unknown"] and slug in self.vuln_plugins:
                        for old in self.vuln_plugins[slug]['old']:
                            try:
                                if old.startswith('<'):
                                    old_ver = old[1:]
                                    ver_num = ''.join(filter(str.isdigit, ver))
                                    old_num = ''.join(filter(str.isdigit, old_ver))
                                    if ver_num and old_num and int(ver_num) < int(old_num):
                                        findings.append(f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}")
                                        break
                            except:
                                pass

            # Báo cáo
            with self.lock:
                self.processed += 1
                if findings:
                    self.found_count += 1
                    print(f"\n{G}{BOLD}[🎯] #{self.found_count}: {decoded_domain}{W}")
                    for f in findings:
                        print(f" |-- {f}")
                    
                    with open(self.output, 'a', encoding='utf-8') as f:
                        clean = [re.sub(r'\033\[[0-9;]*m', '', i) for i in findings]
                        f.write(f"TARGET: {decoded_domain}\n" + "\n".join(clean) + "\n\n")
                    
                    with open(self.weak_domains_file, 'a', encoding='utf-8') as wf:
                        wf.write(f"{decoded_domain}\n")
                    
                    with open(self.vuln_report_json, 'a', encoding='utf-8') as jf:
                        jf.write(json.dumps({"domain": decoded_domain, "findings": clean}, ensure_ascii=False) + "\n")
                    
                    sys.stdout.write("\a")

                # Progress với tốc độ
                elapsed = time.time() - getattr(self, 'start_time', time.time())
                speed = self.processed / elapsed if elapsed > 0 else 0
                sys.stdout.write(f"\r{Y}[*] {self.processed}/{len(self.targets)} ({self.processed/len(self.targets)*100:.1f}%) | {speed:.1f} domains/sec{W}")
                sys.stdout.flush()

    def start(self, threads=80):  # 80 THREADS SIÊU MẠNH!
        self.start_time = time.time()
        self.fetch_infinity_sources()
        
        if not self.targets:
            print(f"{R}[!] No domains to scan!{W}")
            print(f"{Y}[*] Create a file 'domains.txt' with your target domains{W}")
            return

        print(f"\n{B}{BOLD}[🚀 SHADOW STRIKE MASSIVE SCAN ACTIVATED]{W}")
        print(f"{B}[*] Threads: {threads} | Targets: {len(self.targets):,}{W}")
        print(f"{B}[*] Estimated time: {len(self.targets)/80:.1f} seconds{W}\n")
        
        # Tạo thư mục output
        os.makedirs('shadow_strike_massive', exist_ok=True)
        self.output = 'shadow_strike_massive/SHADOW_STRIKE_2026.txt'
        self.weak_domains_file = 'shadow_strike_massive/WEAK_DOMAINS.txt'
        self.vuln_report_json = 'shadow_strike_massive/VULN_REPORT_2026.json'
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                executor.map(self.audit, list(self.targets))
        except KeyboardInterrupt:
            print(f"\n{R}[!] Scan interrupted!{W}")
        except Exception as e:
            print(f"{R}[!] Error: {str(e)}{W}")
        
        # Summary
        total_time = time.time() - self.start_time
        print(f"\n{G}{BOLD}[✅] MASSIVE SCAN COMPLETED IN {total_time:.1f}s!{W}")
        print(f"{G}[*] Total scanned: {self.processed:,}{W}")
        print(f"{G}[*] Vulnerable found: {self.found_count:,}{W}")
        print(f"{G}[*] Average speed: {self.processed/total_time:.1f} domains/sec{W}")
        print(f"{G}[*] Success rate: {self.found_count/max(self.processed,1)*100:.1f}%{W}")
        print(f"{G}[*] Results saved in: shadow_strike_massive/{W}")

if __name__ == "__main__":
    try:
        print(f"""{B}
    ╔══════════════════════════════════════════════════════╗
    ║    SHADOW STRIKE HUNTER - MASSIVE DOMAIN EDITION     ║
    ║    10+ Sources | 80 Threads | Ultra Fast Scanning    ║
    ╚══════════════════════════════════════════════════════╝{W}""")
        
        hunter = ShadowStrikeHunter()
        hunter.start(threads=80)
        
    except KeyboardInterrupt:
        print(f"\n{R}[!] Stopped by user.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {str(e)}{W}")