import requests
import re
import concurrent.futures
import urllib3
import random
import os
import sys
import time
import json  # THÊM DÒNG NÀY
from threading import Lock, Semaphore
import idna
import hashlib  # THÊM DÒNG NÀY

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
        self.semaphore = Semaphore(15)

        # PROXY & UA
        self.proxies = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
            'Mozilla/5.0 (Android 14; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
        ]

        # ENDPOINTS NÂNG CẤP
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

        # Plugin phổ biến
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

        # THÊM PARAMETERS CHO FUZZING (nếu muốn thêm tính năng fuzz)
        self.fuzz_parameters = [
            'debug', 'test', 'admin', 'file', 'cmd', 'action', 'download',
            'path', 'dir', 'show', 'display', 'view', 'load', 'config',
            'setting', 'option', 'backup', 'wp-config', 'plugins', 'themes',
            'upload', 'delete', 'edit', 'id', 'page', 'post', 'attachment',
        ]

        self.fuzz_values = [
            'true', 'false', '1', '0', 'yes', 'no', 'on', 'off',
            'null', 'NULL', 'None', 'none', 'undefined',
            'test', 'test123', 'admin', 'administrator', 'root',
            'wp-config.php', '../../../../etc/passwd',
            'file:///etc/passwd', 'http://evil.com',
            '<?php phpinfo(); ?>', '<script>alert(1)</script>',
        ]

    def get_proxy(self):
        if not self.proxies: return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    def fetch_infinity_sources(self):
        """PHIÊN BẢN MỚI - ĐA NGUỒN DOMAIN KHÔNG DÙNG crt.sh"""
        print(f"{B}[*] Đang thu thập mục tiêu từ đa nguồn...{W}")
        
        # 1. NGUỒN PUBLIC DATASETS
        def get_public_datasets():
            sources = [
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
                "https://raw.githubusercontent.com/v2fly/domain-list-community/release/dlc.dat",
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            ]
            domains = []
            for url in sources:
                try:
                    r = requests.get(url, timeout=45, verify=False)
                    if r.status_code == 200:
                        lines = r.text.split('\n')
                        for line in lines:
                            line = line.strip().lower()
                            if line and not line.startswith('#') and '.' in line:
                                # Lọc domain .vn và wordpress
                                if any(x in line for x in ['.vn', 'wordpress', 'wp-']):
                                    # Loại bỏ IP và localhost
                                    if not any(x in line for x in ['127.0.0.1', 'localhost', '0.0.0.0']):
                                        domains.append(line.split()[0] if ' ' in line else line)
                except:
                    continue
            return list(set(domains))
        
        # 2. NGUỒN SUBDOMAIN SEARCH
        def get_subdomains_from_api(domain):
            apis = [
                f"https://sonar.omnisint.io/subdomains/{domain}",
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                f"https://crt.sh/?q={domain}&output=json",  # Vẫn thử nhưng có fallback
            ]
            domains = []
            for api in apis:
                try:
                    r = requests.get(api, timeout=30, verify=False)
                    if r.status_code == 200:
                        if 'crt.sh' in api:
                            try:
                                data = r.json()
                                for entry in data:
                                    name = entry.get('name_value', '')
                                    if name:
                                        for d in name.split('\n'):
                                            d = d.strip().lower().replace('*.', '')
                                            if d and domain in d:
                                                domains.append(d)
                            except:
                                pass
                        else:
                            # Parse HTML/text response
                            text = r.text
                            found = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
                            for d in found:
                                d_lower = d.lower()
                                if domain in d_lower:
                                    domains.append(d_lower)
                except:
                    continue
            return list(set(domains))
        
        # 3. TÌM TỪ SEARCH ENGINES (giả lập)
        def get_search_engine_results(keyword):
            # Đây là giả lập, có thể tích hợp real search API sau
            domains = []
            try:
                # Tìm domain liên quan đến keyword
                url = f"https://www.google.com/search?q=site:{keyword}+wordpress"
                headers = {'User-Agent': 'Mozilla/5.0'}
                r = requests.get(url, headers=headers, timeout=30, verify=False)
                if r.status_code == 200:
                    # Parse kết quả đơn giản
                    found = re.findall(r'https?://([a-zA-Z0-9.-]+)', r.text)
                    for d in found:
                        if keyword in d.lower():
                            domains.append(d.lower())
            except:
                pass
            return domains
        
        # BẮT ĐẦU THU THẬP
        print(f"{C}[*] Lấy domain từ public datasets...{W}")
        public_domains = get_public_datasets()
        if public_domains:
            self.targets.update(public_domains)
            print(f"{G}[+] Public datasets: {len(public_domains)} domain{W}")
        
        # DANH SÁCH DOMAIN GỐC ĐỂ TÌM SUBDOMAIN
        base_domains = [
            'gov.vn', 'edu.vn', 'com.vn', 'net.vn', 'org.vn',
            'ac.vn', 'biz.vn', 'info.vn', 'name.vn',
            'wordpress.com', 'blogger.com'
        ]
        
        print(f"{C}[*] Quét subdomain từ {len(base_domains)} domain gốc...{W}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for domain in base_domains:
                futures.append(executor.submit(get_subdomains_from_api, domain))
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=60)
                    if result:
                        self.targets.update(result)
                        completed += 1
                        print(f"{G}[+] Domain {base_domains[completed-1]}: {len(result)} subdomain{W}")
                except:
                    completed += 1
                    print(f"{Y}[!] Timeout domain {base_domains[completed-1]}{W}")
        
        # 4. TÌM TỪ LOCAL FILE NẾU CÓ
        domain_files = ['domains.txt', 'targets.txt', 'urls.txt']
        for file in domain_files:
            if os.path.exists(file):
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        file_domains = []
                        for line in f:
                            domain = line.strip().lower()
                            if domain and '.' in domain:
                                domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                                file_domains.append(domain)
                    
                    self.targets.update(file_domains)
                    print(f"{G}[+] File {file}: {len(file_domains)} domain{W}")
                except Exception as e:
                    print(f"{Y}[!] Lỗi đọc file {file}: {str(e)}{W}")
        
        # 5. NẾU KHÔNG CÓ DOMAIN, DÙNG DANH SÁCH MẪU
        if not self.targets:
            print(f"{Y}[!] Không lấy được domain, dùng danh sách mẫu...{W}")
            sample_domains = [
                'example.gov.vn', 'demo.edu.vn', 'test.com.vn',
                'wordpress.demo.vn', 'blog.sample.vn',
                # Thêm domain thật của bạn ở đây
            ]
            self.targets.update(sample_domains)
        
        # LỌC VÀ LÀM SẠCH DOMAIN
        cleaned_targets = set()
        for domain in self.targets:
            domain = domain.strip()
            if (domain and 
                '.' in domain and 
                len(domain) < 100 and
                domain.count('.') >= 1):
                
                # Loại bỏ domain rác
                bad_patterns = ['test.', 'dev.', 'staging.', 'localhost', 
                              '127.0.0.1', 'example.', 'dummy.', 'invalid.',
                              '0.0.0.0', '255.255.255.255']
                if not any(bad in domain for bad in bad_patterns):
                    # Giữ lại domain có .vn hoặc wordpress
                    if '.vn' in domain or any(x in domain for x in ['wordpress', 'wp-', 'blog']):
                        cleaned_targets.add(domain)
        
        self.targets = cleaned_targets
        
        # Lưu domain đã thu thập để kiểm tra
        if self.targets:
            with open('collected_domains.txt', 'w', encoding='utf-8') as f:
                for domain in sorted(self.targets):
                    f.write(domain + '\n')
            print(f"{G}[*] Danh sách domain đã lưu: collected_domains.txt{W}")
        
        print(f"{G}[✅] Tổng kho mục tiêu: {len(self.targets):,} domain.{W}")

    def get_plugin_version(self, base_url, slug, headers, proxy):
        paths = [
            f"/wp-content/plugins/{slug}/readme.txt",
            f"/wp-content/plugins/{slug}/changelog.txt",
            f"/wp-content/plugins/{slug}/style.css"
        ]
        for path in paths:
            try:
                url = base_url.rstrip('/') + path
                r = requests.get(url, headers=headers, proxies=proxy, timeout=6, verify=False)
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

    # THÊM HÀM FUZZ PARAMETERS (tùy chọn)
    def fuzz_parameters(self, base_url, headers, proxy):
        """Fuzz các parameter trên URL"""
        findings = []
        
        fuzz_urls = [
            base_url,
            base_url.rstrip('/') + '/wp-admin/',
            base_url.rstrip('/') + '/wp-login.php',
        ]
        
        for url in fuzz_urls:
            try:
                orig_resp = requests.get(url, headers=headers, proxies=proxy, timeout=5, verify=False)
                orig_hash = hashlib.md5(orig_resp.content).hexdigest()
                
                # Test một số parameter
                for param in self.fuzz_parameters[:5]:  # Chỉ test 5 param đầu
                    for value in self.fuzz_values[:3]:  # Chỉ test 3 giá trị đầu
                        try:
                            time.sleep(0.1)
                            
                            if '?' in url:
                                fuzz_url = f"{url}&{param}={value}"
                            else:
                                fuzz_url = f"{url}?{param}={value}"
                            
                            resp = requests.get(fuzz_url, headers=headers, proxies=proxy, 
                                              timeout=5, verify=False)
                            
                            new_hash = hashlib.md5(resp.content).hexdigest()
                            
                            if new_hash != orig_hash:
                                diff = abs(len(resp.content) - len(orig_resp.content))
                                if diff > 100:  # Nếu khác biệt lớn
                                    findings.append(f"{Y}[PARAM_FUZZ] {param}={value} tại {url} - Diff: {diff} bytes{W}")
                                    break
                        except:
                            continue
            except:
                continue
        
        return findings

    def audit(self, domain):
        decoded_domain = self.decode_domain(domain)
        findings = []
        proxy = self.get_proxy()
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'vi-VN,vi;q=0.9,en;q=0.8']),
            'Referer': random.choice(['https://google.com', 'https://bing.com', 'https://yahoo.com']),
        }

        base_url = None
        for proto in ['https', 'http']:
            url = f"{proto}://{domain}"
            try:
                time.sleep(random.uniform(1.5, 3.5))
                r_main = requests.get(url, headers=headers, proxies=proxy, timeout=12, verify=False)
                text_lower = r_main.text.lower()
                is_wp = any(x in text_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress'])
                status_tag = f"{P}[WP]{W}" if is_wp else f"{C}[NON-WP]{W}"

                with self.lock:
                    sys.stdout.write(f"\r{Y}[*] Testing: {status_tag} {decoded_domain[:30]}{W} " + " " * 20)
                    sys.stdout.flush()

                if is_wp:
                    base_url = url
                    # Check PHP version
                    php_ver = r_main.headers.get('X-Powered-By', '')
                    if 'PHP/' in php_ver:
                        php_version = re.search(r'PHP/([\d\.]+)', php_ver).group(1) if re.search(r'PHP/([\d\.]+)', php_ver) else ''
                        if php_version:
                            try:
                                if float(php_version[:3]) < 8.0:
                                    findings.append(f"{R}[HIGH RISK] Outdated PHP v{php_version} - Multiple Vulns{W}")
                            except:
                                pass
                    
                    # Check directory listing
                    uploads_url = base_url.rstrip('/') + '/wp-content/uploads/'
                    try:
                        r_uploads = requests.get(uploads_url, headers=headers, proxies=proxy, timeout=7)
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

        # Quét endpoint với semaphore
        for path, label in self.critical_endpoints:
            with self.semaphore:
                try:
                    time.sleep(random.uniform(0.4, 1.2))
                    full_url = base_url.rstrip('/') + path
                    r = requests.get(full_url, headers=headers, proxies=proxy, timeout=7, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.content) > 50:
                        if any(ind in r.text for ind in ['DB_PASSWORD', '<?php', 'Index of', 'WPRESS', 'Stable tag']):
                            findings.append(f"{R}[CRITICAL] {label}: {full_url}{W}")
                except:
                    continue

        # Check plugin version
        plugin_slugs = set(re.findall(r'/wp-content/plugins/([^/\'"]+)/', r_main.text.lower()))
        if plugin_slugs:
            print(f"\n{Y}[PLUGIN] Detected on {decoded_domain}: {', '.join(list(plugin_slugs)[:6])}{W}")
            for slug in list(plugin_slugs)[:10]:
                ver = self.get_plugin_version(base_url, slug, headers, proxy)
                if ver != "N/A" and ver != "Unknown":
                    status = f"{P}[PLUGIN] {slug} v{ver}{W}"
                    if slug in self.vuln_plugins:
                        for old in self.vuln_plugins[slug]['old']:
                            try:
                                # Try version comparison
                                from packaging import version
                                old_ver = old.lstrip('<')
                                if version.parse(ver) < version.parse(old_ver):
                                    status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                    findings.append(status)
                            except:
                                # Fallback string comparison
                                if ver.startswith(tuple(old.split('.'))) or ver < old.lstrip('<'):
                                    status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                    findings.append(status)
                    print(f" → {status}")

        # THÊM FUZZ PARAMETERS (tùy chọn)
        # if is_wp and findings:  # Chỉ fuzz nếu đã tìm thấy lỗ hổng
        #     fuzz_findings = self.fuzz_parameters(base_url, headers, proxy)
        #     findings.extend(fuzz_findings)

        # Báo cáo
        with self.lock:
            self.processed += 1
            if findings:
                self.found_count += 1
                print(f"\n{G}{BOLD}[🎯] SUCCESS #{self.found_count}: {decoded_domain}{W}")
                for f in findings:
                    print(f" |-- {f}")
                
                with open(self.output, 'a', encoding='utf-8') as f:
                    clean = [re.sub(r'\033\[[0-9;]*m', '', i) for i in findings]
                    f.write(f"TARGET: {decoded_domain} (original: {domain})\n" + "\n".join(clean) + "\n\n")
                
                with open(self.weak_domains_file, 'a', encoding='utf-8') as wf:
                    wf.write(f"{decoded_domain}\n")
                
                # Lưu JSON report
                with open(self.vuln_report_json, 'a', encoding='utf-8') as jf:
                    jf.write(json.dumps({"domain": decoded_domain, "findings": clean}, ensure_ascii=False) + "\n")
                
                sys.stdout.write("\a")  # Beep

            perc = (self.processed / len(self.targets)) * 100 if self.targets else 0
            sys.stdout.write(f"\r{Y}[*] Progress: {self.processed}/{len(self.targets)} ({perc:.2f}%) | Ghosting: {decoded_domain[:25]}...{W}")
            sys.stdout.flush()

    def start(self, threads=50):
        self.fetch_infinity_sources()
        if not self.targets: 
            print(f"{R}[!] Không có domain để scan!{W}")
            return

        print(f"\n{B}{BOLD}[SHADOW STRIKE ACTIVATED] Threads: {threads} | Targets: {len(self.targets)}{W}\n")
        
        # Tạo thư mục output nếu chưa có
        os.makedirs('shadow_strike_results', exist_ok=True)
        self.output = 'shadow_strike_results/SHADOW_STRIKE_2026.txt'
        self.weak_domains_file = 'shadow_strike_results/WEAK_DOMAINS.txt'
        self.vuln_report_json = 'shadow_strike_results/VULN_REPORT_2026.json'
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                executor.map(self.audit, list(self.targets))
        except KeyboardInterrupt:
            print(f"\n{R}[!] Scan bị dừng!{W}")
        except Exception as e:
            print(f"{R}[!] Lỗi khi scan: {str(e)}{W}")
        
        # Summary
        print(f"\n{G}{BOLD}[✅] SCAN HOÀN TẤT!{W}")
        print(f"{G}[*] Đã quét: {self.processed} domain{W}")
        print(f"{G}[*] Tìm thấy lỗ hổng: {self.found_count} domain{W}")
        print(f"{G}[*] Kết quả lưu tại thư mục: shadow_strike_results/{W}")

if __name__ == "__main__":
    try:
        print(f"""{B}
    ╔══════════════════════════════════════════════════════╗
    ║      SHADOW STRIKE HUNTER v1.0 - MULTI-SOURCE        ║
    ║      Auto Domain Collection + WordPress Audit        ║
    ╚══════════════════════════════════════════════════════╝{W}""")
        
        ShadowStrikeHunter().start(threads=50)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Dừng bởi người dùng.{W}")
    except Exception as e:
        print(f"{R}[!] Lỗi không mong muốn: {str(e)}{W}")
        import traceback
        traceback.print_exc()