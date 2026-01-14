#!/usr/bin/env python3
"""
WordPress/PHP Security Audit FULL - Passive + CVE + Plugin Focus (2026)
Kết hợp đầy đủ từ hai script gốc, không brute force, chỉ kiểm tra thụ động + config vuln
"""

import requests
import sys
import re
import json
from urllib.parse import urljoin, quote
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# Danh sách CVE plugin phổ biến (cập nhật đến 2026)
KNOWN_PLUGIN_CVES = {
    "wp-automatic": {"max_safe": "3.92.3", "cves": ["CVE-2025-2563 (9.8 RCE)"]},
    "essential-addons-for-elementor-lite": {"max_safe": "5.9.21", "cves": ["CVE-2025-1034 (9.8)"]},
    "the-plus-addons-for-elementor-page-builder": {"max_safe": "5.6.1", "cves": ["CVE-2025-1062 (9.8)"]},
    "ti-woocommerce-wishlist": {"max_safe": "2.5.1", "cves": ["CVE-2025-47577 (10.0)"]},
    "revslider": {"max_safe": "6.7.5", "cves": ["Multiple pre-6.7 RCE"]},
    "layer-slider": {"max_safe": "7.10.0", "cves": ["Older versions - Arbitrary File Upload"]},
    "contact-form-7": {"max_safe": "5.9", "cves": ["Pre-5.9 - XSS/CSRF"]},
    "wp-file-manager": {"max_safe": "6.9", "cves": ["CVE-2020-25213 (9.8 RCE)"]},
}

class FullWPSecurityAudit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Audit Tool - Passive Scan 2026)'
        })
        self.results = {
            'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []
        }
        self.plugins = {}
        self.accessible_files = []

    def log(self, status, message, detail=""):
        colors = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.YELLOW,
            "MEDIUM": Fore.CYAN,
            "LOW": Fore.GREEN,
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN
        }
        print(f"{colors.get(status, Fore.WHITE)}[{status}] {message}")
        if detail:
            print(f"   → {detail[:200]}{'...' if len(detail) > 200 else ''}")

    def safe_get(self, url, timeout=10):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except:
            return None

    def safe_head(self, url):
        try:
            return self.session.head(url, timeout=6)
        except:
            return None

    def add_finding(self, level, title, description, evidence=None, recommendation=None):
        entry = {
            'title': title,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.utcnow().isoformat(),
            'recommendation': recommendation
        }
        self.results[level].append(entry)
        self.log(level, title, evidence)

    # ================= CHECKS =================

    def check_headers_and_php_version_cves(self):
        r = self.safe_get(self.target)
        if not r:
            return

        if 'X-Powered-By' in r.headers and 'PHP' in r.headers['X-Powered-By']:
            header = r.headers['X-Powered-By']
            version_match = re.search(r'PHP/([\d\.]+)', header)
            if version_match:
                ver = version_match.group(1)
                self.add_finding('high', "PHP version disclosure in headers", header,
                                 recommendation="Remove or mask X-Powered-By header in server config")
                self._check_php_cves(ver)

        if 'Server' in r.headers and 'PHP' in r.headers['Server']:
            self.add_finding('medium', "Server header leaks PHP info", r.headers['Server'],
                             recommendation="Minimize Server header information")

    def _check_php_cves(self, version):
        if version.startswith(('7.4', '7.3', '7.2')):
            cves = [
                ("CVE-2022-37454", "9.8", "Buffer overflow in mb_decode_numericentity"),
                ("CVE-2022-31630", "7.5", "Use-after-free in Phar extension"),
                ("CVE-2022-31629", "6.1", "XSS in phpinfo()"),
            ]
            for cve, score, desc in cves:
                self.add_finding('critical', f"EOL PHP {version} - {cve}", f"{desc} (CVSS {score})",
                                 recommendation="Upgrade to PHP 8.2+ immediately - PHP 7.4 EOL since 2022")

    def check_phpinfo_and_dangerous_configs(self):
        paths = ['/phpinfo.php', '/info.php', '/test.php', '/?phpinfo=1', '/server-info']
        for path in paths:
            url = urljoin(self.target + '/', path)
            r = self.safe_get(url)
            if r and r.status_code == 200 and 'phpinfo' in r.text.lower():
                self.add_finding('critical', "phpinfo page publicly accessible", url,
                                 recommendation="Delete all phpinfo/test/info files immediately")

                text = r.text.lower()

                # disable_functions
                if re.search(r'disable_functions\s*</td><td[^>]*>(no value|\s*)', text, re.I):
                    self.add_finding('critical', "disable_functions is empty", "",
                                     recommendation="Set disable_functions = system,exec,passthru,shell_exec,popen,proc_open,eval,assert,pcntl_exec")

                # allow_url_fopen
                if re.search(r'allow_url_fopen\s*</td><td[^>]*>on', text, re.I):
                    self.add_finding('critical', "allow_url_fopen = On", "",
                                     recommendation="Set allow_url_fopen = Off to prevent RFI attacks")

                # open_basedir
                if re.search(r'open_basedir\s*</td><td[^>]*>(no value|\s*none\s*)', text, re.I):
                    self.add_finding('high', "No open_basedir restriction", "",
                                     recommendation="Set open_basedir to your web root directory")

                break

    def detect_plugins_versions_and_cves(self):
        r = self.safe_get(self.target)
        if not r:
            return

        content = r.text
        slugs = set(re.findall(r'wp-content/plugins/([a-z0-9][a-z0-9\-_]{1,80})/', content))

        # ===== RECON CỨNG: wp-file-manager (KHÔNG PHỤ THUỘC HTML) =====
        fm_readme = urljoin(self.target + '/', 'wp-content/plugins/wp-file-manager/readme.txt')
        fm_resp = self.safe_get(fm_readme)

        if fm_resp and fm_resp.status_code == 200 and 'wp file manager' in fm_resp.text.lower():
            version = "Unknown"
            m = re.search(r'Stable tag:\s*([0-9\.]+)', fm_resp.text, re.I)
            if m:
                version = m.group(1)

            self.plugins['wp-file-manager'] = version

            self.add_finding(
                'critical',
                f"Vulnerable plugin detected: wp-file-manager (v{version})",
                "Known RCE: CVE-2020-25213 (unauthenticated file upload)",
                recommendation="Remove plugin or update immediately to >= 6.9"
            )

            slugs.add('wp-file-manager')
        # ============================================================

        self.log('INFO', f"Detected {len(slugs)} potential plugins")

        for slug in sorted(slugs):
            version = self.plugins.get(slug, "Unknown")

            if version == "Unknown":
                for file_name in ["readme.txt", "changelog.txt", "style.css", "readme.md"]:
                    url = urljoin(self.target + '/', f'wp-content/plugins/{slug}/{file_name}')
                    rv = self.safe_get(url)
                    if rv and rv.status_code == 200:
                        match = re.search(
                            r'(?:Stable tag|Version|Plugin Version):\s*([0-9][\d\.\-a-z+]+)',
                            rv.text, re.I
                        )
                        if match:
                            version = match.group(1).strip()
                            break

                self.plugins[slug] = version

            # Check CVE
            if slug in KNOWN_PLUGIN_CVES:
                info = KNOWN_PLUGIN_CVES[slug]
                max_safe = info["max_safe"]
                cves_str = ", ".join(info["cves"])
                if version == "Unknown" or (max_safe and version <= max_safe):
                    self.add_finding(
                        'critical',
                        f"Vulnerable plugin detected: {slug} (v{version})",
                        f"Known CVEs: {cves_str}",
                        recommendation=f"Update immediately to > {max_safe or 'latest version'}"
                    )

            print(f"  • {slug.ljust(45)} → v{version}")

    def check_sensitive_files_and_backups(self):
        files = [
            "/wp-config.php", "/.env", "/.env.local", "/wp-config.php.bak", "/wp-config.php.old",
            "/wp-config.php.save", "/wp-config.php.backup", "/backup.zip", "/backup.tar.gz",
            "/database.sql", "/backup.sql", "/error_log", "/debug.log", "/wp-content/debug.log",
            "/wp-content/error_log", "/.git/config", "/.git/HEAD", "/.gitignore"
        ]

        for path in files:
            url = urljoin(self.target + '/', path)
            r = self.safe_head(url)
            if r and r.status_code == 200:
                self.accessible_files.append((path, url))
                self.add_finding(
                    'critical',
                    f"Sensitive file accessible: {path}",
                    url,
                    recommendation="Block access via server config (.htaccess / nginx) immediately"
                )
                if any(kw in path.lower() for kw in ['wp-config', '.env', 'backup', 'sql']):
                    gr = self.safe_get(url)
                    if gr and ('DB_' in gr.text or 'password' in gr.text.lower()):
                        self.add_finding('critical', f"{path} contains credentials or DB info", url,
                                         recommendation="Block access immediately, change passwords if leaked")

    def check_rest_api_information_leaks(self):
        endpoints = [
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/pages",
            "/wp-json/wp/v2/comments"
        ]

        for ep in endpoints:
            url = urljoin(self.target + '/', ep)
            r = self.safe_get(url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if ep.endswith('/users') and isinstance(data, list) and data:
                        users = [u.get('slug', u.get('name', 'N/A')) for u in data[:8]]
                        self.add_finding('critical', "REST API user enumeration possible", users,
                                         recommendation="Disable user enumeration via REST (add filter or plugin)")
                    elif isinstance(data, list) and len(data) > 0:
                        self.add_finding('high', f"REST API exposes data: {ep}", f"Items: {len(data)}")
                except:
                    pass

    def check_uploads_directory_and_listing(self):
        url = urljoin(self.target + '/', "/wp-content/uploads/")
        r = self.safe_get(url)
        if r and r.status_code == 200:
            if "Index of" in r.text or "Parent Directory" in r.text:
                self.add_finding('high', "Uploads directory listing enabled", url,
                                 recommendation="Disable directory listing (Options -Indexes in .htaccess)")
                php_files = re.findall(r'href="([^"]+\.php)"', r.text)
                if php_files:
                    self.add_finding('critical', "PHP files found in uploads directory", php_files[:6])

    def check_theme_lfi_and_vulns(self):
        test_params = [
            ('template', '../../../../etc/passwd'),
            ('file', '../../../wp-config.php'),
            ('page', 'php://filter/convert.base64-encode/resource=../../../wp-config.php')
        ]

        for param, payload in test_params:
            test_url = f"{self.target}/?{param}={quote(payload)}"
            r = self.safe_get(test_url)
            if r and r.status_code == 200:
                content = r.text.lower()
                if 'root:' in content and '/bin/' in content:
                    self.add_finding('critical', f"Possible LFI via parameter '{param}'", test_url)
                if 'db_name' in content or 'db_password' in content:
                    self.add_finding('critical', f"wp-config.php leak via parameter '{param}'", test_url)

    def run_full_scan(self):
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"   WordPress/PHP Security Audit - FULL Passive + CVE Focus (2026)")
        print(f"   Target: {self.target}")
        print(f"{'='*80}\n")

        checks = [
            self.check_headers_and_php_version_cves,
            self.check_phpinfo_and_dangerous_configs,
            self.detect_plugins_versions_and_cves,
            self.check_sensitive_files_and_backups,
            self.check_rest_api_information_leaks,
            self.check_uploads_directory_and_listing,
            self.check_theme_lfi_and_vulns,
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"Error during {check.__name__}: {e}")

        # Summary Report
        total_findings = sum(len(v) for v in self.results.values())
        print("\n" + "="*80)
        print(f"SCAN SUMMARY - Total findings: {total_findings}")
        print("="*80)

        for level in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(self.results[level])
            if count > 0:
                print(f"{Fore.RED if level=='critical' else Fore.YELLOW}{level.upper()}: {count} issues")

        if self.plugins:
            print("\nDetected Plugins:")
            for slug, ver in self.plugins.items():
                print(f"  • {slug.ljust(45)} v{ver}")

        if self.accessible_files:
            print("\nAccessible Sensitive Files:")
            for path, url in self.accessible_files:
                print(f"  • {path} → {url}")

        # Save JSON report
        fname = f"wp_full_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_data = {
            'target': self.target,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {k: len(v) for k, v in self.results.items()},
            'plugins': self.plugins,
            'accessible_files': self.accessible_files,
            'detailed_findings': self.results
        }
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        print(f"\nFull report saved to: {fname}")
        print("="*80)

def main():
    if len(sys.argv) != 2:
        print("Cách dùng: python3 wp_full_audit.py <target_url>")
        print("Ví dụ: python3 wp_full_audit.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    audit = FullWPSecurityAudit(target)
    audit.run_full_scan()

if __name__ == "__main__":
    main()