#!/usr/bin/env python3
import sys, re, ssl, socket, requests, time, signal, random
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import threading

requests.packages.urllib3.disable_warnings()

# ================= CONFIG =================
THREADS = 50
TIMEOUT = 8
MAX_HTML = 500_000
DELAY_MIN = 0.1
DELAY_MAX = 0.5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

HEADERS_TEMPLATE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
    "DNT": "1",
}

PLUGIN_REGEXS = [
    re.compile(r"wp-content/plugins/([a-z0-9][a-z0-9._\-]{1,50})/", re.I),
    re.compile(r"/plugins/([a-z0-9][a-z0-9._\-]{1,50})/assets/", re.I),
    re.compile(r'"plugin":"([^"]+)"', re.I),
    re.compile(r"'plugin':'([^']+)'", re.I),
]

VERSION_REGEX = re.compile(
    r"(?:Stable\s+tag|Version|Plugin\s+Version):\s*([0-9][0-9a-zA-Z.\-_\+]+)",
    re.I
)

COMMON_PLUGINS = [
    "wp-file-manager", "wp-automatic", "backup", "duplicator",
    "all-in-one-wp-migration", "revslider", "layer-slider",
    "elementor", "contact-form-7", "wpforms", "akismet",
    "woocommerce", "yoast-seo", "jetpack", "really-simple-ssl",
    "updraftplus", "wordfence", "google-site-kit", "seo-by-rank-math",
    "litespeed-cache", "w3-total-cache", "wp-rocket", "wp-super-cache",
]

VERSION_FILES = ["readme.txt", "changelog.txt", "readme.md"]
SUSPICIOUS_FILES = [
    "upload.php", "ajax.php", "import.php", "backup.php",
    "export.php", "shell.php", "cmd.php", "admin-ajax.php"
]

SUSPICIOUS_PATHS = [
    "/wp-content/uploads/",
    "/wp-content/debug.log",
    "/wp-config.php",
    "/.env",
    "/.git/config",
]

# Global variables
output_lock = threading.Lock()
OUTPUT_FILE = None
SCAN_STATS = {
    "total_ips": 0,
    "scanned": 0,
    "domains_found": 0,
    "wp_sites": 0,
    "plugins_found": 0,
    "vulnerabilities": 0,
    "errors": 0,
    "start_time": time.time()
}

# Store only VULN findings
VULN_FINDINGS = []

# ================= DISPLAY =================
def update_progress_line():
    """Display single progress line at bottom - ONLY THIS LINE SHOWS"""
    scanned = SCAN_STATS["scanned"]
    total = SCAN_STATS["total_ips"]
    percent = (scanned / total * 100) if total > 0 else 0
    elapsed = time.time() - SCAN_STATS["start_time"]
    ips_per_sec = scanned / elapsed if elapsed > 0 else 0
    
    with output_lock:
        sys.stdout.write('\r\033[K')
        sys.stdout.write(f"🔄 Quét: {scanned}/{total} IP ({percent:.1f}%) | ")
        sys.stdout.write(f"Tốc độ: {ips_per_sec:.1f} IP/s | ")
        sys.stdout.write(f"Lỗ hổng: {SCAN_STATS['vulnerabilities']}")
        sys.stdout.flush()

def print_vuln_only(ip, info=""):
    """ONLY print when vulnerability is found - this stays on screen"""
    with output_lock:
        print(f"\r\033[K\033[31m⚠️  VULN: {ip} → {info}\033[0m")
        # Store for summary
        VULN_FINDINGS.append((ip, info, time.time()))
        # Redisplay progress line
        update_progress_line()

def show_final_summary():
    """Show final summary after scan"""
    elapsed = time.time() - SCAN_STATS["start_time"]
    
    print("\n\n" + "="*60)
    print("📊 TỔNG KẾT QUÉT")
    print("="*60)
    print(f"⏱️  Thời gian: {elapsed:.1f}s")
    print(f"🎯 IP đã quét: {SCAN_STATS['scanned']}/{SCAN_STATS['total_ips']}")
    print(f"🌐 Domain tìm thấy: {SCAN_STATS['domains_found']}")
    print(f"🅆🄿 Site WordPress: {SCAN_STATS['wp_sites']}")
    print(f"🔌 Plugin phát hiện: {SCAN_STATS['plugins_found']}")
    print(f"⚠️  Lỗ hổng tìm thấy: {SCAN_STATS['vulnerabilities']}")
    print(f"🚫 Lỗi: {SCAN_STATS['errors']}")
    
    # Only show VULN findings
    if VULN_FINDINGS:
        print(f"\n\033[31m⚠️  CÁC SITE CÓ LỖ HỔNG:\033[0m")
        print("-" * 60)
        for ip, info, _ in VULN_FINDINGS:
            print(f"  • {ip} - {info}")

# ================= SIGNAL HANDLER =================
def signal_handler(sig, frame):
    print("\n\n[!] Đang dừng quét...")
    show_final_summary()
    if OUTPUT_FILE:
        OUTPUT_FILE.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ================= UTILITY FUNCTIONS =================
def get_random_headers():
    headers = HEADERS_TEMPLATE.copy()
    headers["User-Agent"] = random.choice(USER_AGENTS)
    return headers

def safe_request(url, method="GET", **kwargs):
    """Safe HTTP request with retry and delay"""
    time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
    
    try:
        headers = kwargs.pop('headers', get_random_headers())
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
            **kwargs
        )
        return response
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException as e:
        return None

def resolve_domains_from_ip(ip):
    """Resolve domains from IP using multiple methods"""
    domains = set()
    
    # Method 1: TLS Certificate
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                cert = ss.getpeercert()
                # Common Name
                for field in cert.get('subject', []):
                    for key, value in field:
                        if key == 'commonName' and '.' in value and '*' not in value:
                            domains.add(value.lower())
                # Subject Alternative Names
                for san_type, san_value in cert.get('subjectAltName', []):
                    if san_type == 'DNS' and '*' not in san_value:
                        domains.add(san_value.lower())
    except:
        pass
    
    # Method 2: DNS Reverse Lookup
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and '.' in hostname:
            domains.add(hostname.lower())
    except:
        pass
    
    return list(domains)

def is_wordpress_site(domain):
    """Check if domain is WordPress"""
    checks = [
        f"http://{domain}/wp-json/",
        f"https://{domain}/wp-json/",
        f"http://{domain}/readme.html",
        f"https://{domain}/readme.html",
        f"http://{domain}/wp-includes/js/wp-embed.min.js",
        f"https://{domain}/wp-includes/js/wp-embed.min.js",
    ]
    
    for url in checks:
        response = safe_request(url, timeout=5)
        if response and response.status_code in [200, 401, 403, 301, 302]:
            if response.status_code in [301, 302]:
                final_url = response.url
                if any(wp_sig in final_url for wp_sig in ['wp-json', 'wp-admin', 'wp-content']):
                    return get_base_url(final_url)
            elif response.text and 'wp-content' in response.text.lower():
                return get_base_url(response.url)
    
    return None

def get_base_url(url):
    """Extract base URL from response URL"""
    parsed = urlparse(url)
    scheme = parsed.scheme if parsed.scheme else "http"
    return f"{scheme}://{parsed.netloc}"

def find_plugins_in_html(html):
    """Extract plugin names from HTML"""
    plugins = set()
    
    for pattern in PLUGIN_REGEXS:
        matches = pattern.findall(html)
        for match in matches:
            plugin = match.split('/')[0].split('?')[0].strip()
            if len(plugin) > 1 and '.' not in plugin:
                plugins.add(plugin.lower())
    
    return plugins

def get_plugin_version(base_url, plugin_name):
    """Get plugin version"""
    version = None
    
    # Check version files
    for vfile in VERSION_FILES:
        url = f"{base_url}/wp-content/plugins/{plugin_name}/{vfile}"
        response = safe_request(url)
        if response and response.status_code == 200:
            match = VERSION_REGEX.search(response.text)
            if match:
                version = match.group(1)
                break
    
    return version

def check_suspicious_files(base_url, plugin_name):
    """Check for suspicious files in plugin directory"""
    suspicious = []
    
    for sfile in SUSPICIOUS_FILES:
        url = f"{base_url}/wp-content/plugins/{plugin_name}/{sfile}"
        response = safe_request(url)
        if response and response.status_code in [200, 403]:
            suspicious.append(sfile)
    
    return suspicious

def check_suspicious_paths(base_url):
    """Check for suspicious paths on WordPress site"""
    suspicious = []
    
    for path in SUSPICIOUS_PATHS:
        url = f"{base_url}{path}"
        response = safe_request(url)
        if response and response.status_code == 200:
            content = response.text.lower()
            if path.endswith('.log') and ('error' in content or 'warning' in content):
                suspicious.append((path, "DEBUG_LOG"))
            elif path.endswith('.env') and ('db_' in content or 'password' in content):
                suspicious.append((path, "ENV_FILE"))
            elif path.endswith('.php') and ('database' in content or 'password' in content):
                suspicious.append((path, "CONFIG_FILE"))
            elif path.endswith('/') and 'index of' in content:
                suspicious.append((path, "DIRECTORY_LISTING"))
    
    return suspicious

def scan_wordpress_site(ip, base_url):
    """Full scan of a WordPress site"""
    results = {
        "ip": ip,
        "url": base_url,
        "plugins": {},
        "suspicious_paths": [],
        "vulnerabilities": []
    }
    
    try:
        # Get homepage for plugin detection
        response = safe_request(base_url)
        if not response:
            return results
        
        html = response.text[:MAX_HTML]
        
        # Find plugins
        plugins_found = find_plugins_in_html(html)
        all_plugins = plugins_found.union(set(COMMON_PLUGINS[:10]))
        
        # Check each plugin
        for plugin in list(all_plugins)[:20]:  # Limit to 20 plugins per site
            # Check if plugin exists
            plugin_url = f"{base_url}/wp-content/plugins/{plugin}/"
            resp = safe_request(plugin_url)
            if not resp or resp.status_code not in [200, 403]:
                continue
            
            plugin_info = {"version": None, "suspicious": []}
            
            # Get version
            version = get_plugin_version(base_url, plugin)
            if version:
                plugin_info["version"] = version
            
            # Check suspicious files for dangerous plugins
            if plugin in ['wp-file-manager', 'revslider', 'duplicator', 'backup', 'wp-automatic']:
                suspicious = check_suspicious_files(base_url, plugin)
                if suspicious:
                    plugin_info["suspicious"] = suspicious
            
            if plugin_info["version"] or plugin_info["suspicious"]:
                results["plugins"][plugin] = plugin_info
        
        # Check suspicious paths
        suspicious_paths = check_suspicious_paths(base_url)
        if suspicious_paths:
            results["suspicious_paths"] = suspicious_paths
        
        # Check for vulnerabilities
        if results["plugins"]:
            for plugin, info in results["plugins"].items():
                if info["suspicious"]:
                    results["vulnerabilities"].append(f"{plugin}: {', '.join(info['suspicious'])}")
        
        if results["suspicious_paths"]:
            for path, status in results["suspicious_paths"]:
                results["vulnerabilities"].append(f"{path} ({status})")
        
        return results
        
    except Exception as e:
        return results

def save_results(results):
    """Save detailed results to file"""
    if not results["plugins"] and not results["vulnerabilities"]:
        return
    
    with output_lock:
        if not OUTPUT_FILE:
            return
        
        OUTPUT_FILE.write(f"\n{'='*80}\n")
        OUTPUT_FILE.write(f"IP: {results['ip']}\n")
        OUTPUT_FILE.write(f"URL: {results['url']}\n")
        OUTPUT_FILE.write(f"Time: {time.ctime()}\n")
        OUTPUT_FILE.write(f"{'='*80}\n")
        
        if results["plugins"]:
            OUTPUT_FILE.write("\n🔌 PLUGINS:\n")
            OUTPUT_FILE.write("-" * 40 + "\n")
            for plugin, info in results["plugins"].items():
                OUTPUT_FILE.write(f"  • {plugin}")
                if info["version"]:
                    OUTPUT_FILE.write(f" (v{info['version']})")
                if info["suspicious"]:
                    OUTPUT_FILE.write(f" [SUSPICIOUS: {', '.join(info['suspicious'])}]")
                OUTPUT_FILE.write("\n")
        
        if results["vulnerabilities"]:
            OUTPUT_FILE.write("\n⚠️  VULNERABILITIES:\n")
            OUTPUT_FILE.write("-" * 40 + "\n")
            for vuln in results["vulnerabilities"]:
                OUTPUT_FILE.write(f"  • {vuln}\n")
        
        OUTPUT_FILE.write("\n" + "="*80 + "\n\n")
        OUTPUT_FILE.flush()

# ================= MAIN SCAN FUNCTION =================
def scan_ip_address(ip_str):
    """Main function to scan a single IP address - SILENT MODE"""
    try:
        # Update progress counter (silently)
        with output_lock:
            SCAN_STATS["scanned"] += 1
        
        # Resolve domains from IP
        domains = resolve_domains_from_ip(ip_str)
        if not domains:
            # SILENT - no output
            update_progress_line()
            return
        
        # For each domain found (silently update stats)
        for domain in domains[:3]:  # Limit to 3 domains per IP
            with output_lock:
                SCAN_STATS["domains_found"] += 1
            
            # SILENT - don't print domain finding
            
            # Check if WordPress
            base_url = is_wordpress_site(domain)
            if not base_url:
                continue
            
            # Found WordPress! (silently update stats)
            with output_lock:
                SCAN_STATS["wp_sites"] += 1
            
            # SILENT - don't print WordPress finding
            
            # Scan the WordPress site
            results = scan_wordpress_site(ip_str, base_url)
            
            if results["plugins"]:
                with output_lock:
                    SCAN_STATS["plugins_found"] += len(results["plugins"])
                
                # SILENT - don't print plugin finding
            
            # Check for vulnerabilities - ONLY PRINT THIS!
            if results["vulnerabilities"]:
                with output_lock:
                    SCAN_STATS["vulnerabilities"] += len(results["vulnerabilities"])
                
                vuln_info = results["vulnerabilities"][0]
                if len(results["vulnerabilities"]) > 1:
                    vuln_info += f" (+{len(results['vulnerabilities'])-1} nữa)"
                
                # ONLY PRINT VULNERABILITIES!
                print_vuln_only(ip_str, f"{domain} - {vuln_info}")
                
                # Save detailed results
                save_results(results)
        
        # Update progress line
        update_progress_line()
        
    except Exception as e:
        with output_lock:
            SCAN_STATS["errors"] += 1
        # SILENT - don't print errors
        update_progress_line()

# ================= MAIN =================
def main():
    global OUTPUT_FILE, SCAN_STATS
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <IP_RANGE> <OUTPUT_FILE>")
        print(f"Example: {sys.argv[0]} 118.68.0.0/14 results.txt")
        sys.exit(1)
    
    ip_range = sys.argv[1]
    output_filename = sys.argv[2]
    
    # Parse IP range
    try:
        network = ip_network(ip_range, strict=False)
        ip_list = [str(ip) for ip in network]
        SCAN_STATS["total_ips"] = len(ip_list)
    except ValueError as e:
        print(f"[!] Invalid IP range: {e}")
        sys.exit(1)
    
    # Open output file
    try:
        OUTPUT_FILE = open(output_filename, "w", encoding="utf-8")
        OUTPUT_FILE.write(f"WordPress Security Scan Report\n")
        OUTPUT_FILE.write(f"Time: {time.ctime()}\n")
        OUTPUT_FILE.write(f"Target: {ip_range}\n")
        OUTPUT_FILE.write(f"Total IPs: {SCAN_STATS['total_ips']}\n")
        OUTPUT_FILE.write("="*80 + "\n\n")
    except Exception as e:
        print(f"[!] Cannot open output file: {e}")
        sys.exit(1)
    
    # Display banner
    print("\n" + "="*60)
    print("🛡️  WORDPRESS SECURITY SCANNER - SILENT MODE")
    print("="*60)
    print(f"🎯 Target: {ip_range}")
    print(f"📊 Total IPs: {SCAN_STATS['total_ips']}")
    print(f"🧵 Threads: {THREADS}")
    print("="*60)
    print("\n[+] Chế độ hiển thị:")
    print("   • Chỉ 1 dòng tiến trình duy nhất")
    print("   • Chỉ hiển thị khi tìm thấy LỖ HỔNG")
    print("   • Các phát hiện lỗ hổng sẽ được 'ghim' lại")
    print("\n" + "="*60 + "\n")
    
    # Initial progress display
    update_progress_line()
    
    # Start scanning
    batch_size = 100
    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i + batch_size]
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(scan_ip_address, ip) for ip in batch]
            
            for future in as_completed(futures):
                try:
                    future.result(timeout=30)
                except Exception as e:
                    with output_lock:
                        SCAN_STATS["errors"] += 1
                    update_progress_line()
    
    # Final summary
    show_final_summary()
    
    # Save final stats to file
    if OUTPUT_FILE:
        OUTPUT_FILE.write(f"\n\n{'='*80}\n")
        OUTPUT_FILE.write("SCAN STATISTICS\n")
        OUTPUT_FILE.write(f"{'='*80}\n")
        OUTPUT_FILE.write(f"Total IPs: {SCAN_STATS['total_ips']}\n")
        OUTPUT_FILE.write(f"IPs Scanned: {SCAN_STATS['scanned']}\n")
        OUTPUT_FILE.write(f"Domains Found: {SCAN_STATS['domains_found']}\n")
        OUTPUT_FILE.write(f"WordPress Sites: {SCAN_STATS['wp_sites']}\n")
        OUTPUT_FILE.write(f"Plugins Found: {SCAN_STATS['plugins_found']}\n")
        OUTPUT_FILE.write(f"Vulnerabilities: {SCAN_STATS['vulnerabilities']}\n")
        OUTPUT_FILE.write(f"Errors: {SCAN_STATS['errors']}\n")
        OUTPUT_FILE.write(f"Duration: {time.time() - SCAN_STATS['start_time']:.1f}s\n")
        OUTPUT_FILE.close()
    
    print(f"\n[+] Results saved to: {output_filename}")

if __name__ == "__main__":
    main()