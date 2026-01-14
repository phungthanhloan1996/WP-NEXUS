#!/usr/bin/env python3
import sys, re, ssl, socket, time, signal, random
from ipaddress import ip_network
from urllib.parse import urlparse
import threading
import asyncio
import aiohttp
from aiohttp import TCPConnector, ClientTimeout
import async_timeout

# ================= CONFIG =================
THREADS = 100  # Increased for async
TIMEOUT = 8
MAX_HTML = 500_000
DELAY_MIN = 0.1
DELAY_MAX = 0.5
MAX_CONCURRENT = 200  # Max concurrent connections

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

# SSL context for faster connections
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

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

# ================= ASYNC HTTP CLIENT =================
async def safe_request(session, url, method="GET", headers=None, timeout=TIMEOUT):
    """Async HTTP request with delay"""
    await asyncio.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
    
    try:
        if headers is None:
            headers = HEADERS_TEMPLATE.copy()
            headers["User-Agent"] = random.choice(USER_AGENTS)
        
        async with async_timeout.timeout(timeout):
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                ssl=ssl_context,
                allow_redirects=True
            ) as response:
                # Read response text (but limit size)
                text = await response.text()
                return {
                    'status': response.status,
                    'url': str(response.url),
                    'text': text[:MAX_HTML],
                    'headers': dict(response.headers)
                }
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        return None

# ================= SYNC FUNCTIONS (for SSL cert extraction) =================
def resolve_domains_from_ip_sync(ip):
    """Resolve domains from IP using SSL certificate (sync)"""
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
    
    return list(domains)

# ================= ASYNC SCANNING FUNCTIONS =================
async def is_wordpress_site_async(session, domain):
    """Async check if domain is WordPress"""
    checks = [
        f"http://{domain}/wp-json/",
        f"https://{domain}/wp-json/",
        f"http://{domain}/readme.html",
        f"https://{domain}/readme.html",
        f"http://{domain}/wp-includes/js/wp-embed.min.js",
        f"https://{domain}/wp-includes/js/wp-embed.min.js",
    ]
    
    for url in checks:
        response = await safe_request(session, url, timeout=5)
        if response and response['status'] in [200, 401, 403, 301, 302]:
            if response['status'] in [301, 302]:
                final_url = response['url']
                if any(wp_sig in final_url for wp_sig in ['wp-json', 'wp-admin', 'wp-content']):
                    return get_base_url(final_url)
            elif response['text'] and 'wp-content' in response['text'].lower():
                return get_base_url(response['url'])
    
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

async def get_plugin_version_async(session, base_url, plugin_name):
    """Async get plugin version"""
    version = None
    
    # Check version files
    for vfile in VERSION_FILES:
        url = f"{base_url}/wp-content/plugins/{plugin_name}/{vfile}"
        response = await safe_request(session, url, timeout=5)
        if response and response['status'] == 200:
            match = VERSION_REGEX.search(response['text'])
            if match:
                version = match.group(1)
                break
    
    return version

async def check_suspicious_files_async(session, base_url, plugin_name):
    """Async check for suspicious files in plugin directory"""
    suspicious = []
    
    for sfile in SUSPICIOUS_FILES:
        url = f"{base_url}/wp-content/plugins/{plugin_name}/{sfile}"
        response = await safe_request(session, url, timeout=5)
        if response and response['status'] in [200, 403]:
            suspicious.append(sfile)
    
    return suspicious

async def check_suspicious_paths_async(session, base_url):
    """Async check for suspicious paths on WordPress site"""
    suspicious = []
    
    for path in SUSPICIOUS_PATHS:
        url = f"{base_url}{path}"
        response = await safe_request(session, url, timeout=5)
        if response and response['status'] == 200:
            content = response['text'].lower()
            if path.endswith('.log') and ('error' in content or 'warning' in content):
                suspicious.append((path, "DEBUG_LOG"))
            elif path.endswith('.env') and ('db_' in content or 'password' in content):
                suspicious.append((path, "ENV_FILE"))
            elif path.endswith('.php') and ('database' in content or 'password' in content):
                suspicious.append((path, "CONFIG_FILE"))
            elif path.endswith('/') and 'index of' in content:
                suspicious.append((path, "DIRECTORY_LISTING"))
    
    return suspicious

async def scan_wordpress_site_async(session, ip, base_url):
    """Async full scan of a WordPress site"""
    results = {
        "ip": ip,
        "url": base_url,
        "plugins": {},
        "suspicious_paths": [],
        "vulnerabilities": []
    }
    
    try:
        # Get homepage for plugin detection
        response = await safe_request(session, base_url, timeout=10)
        if not response:
            return results
        
        html = response['text']
        
        # Find plugins
        plugins_found = find_plugins_in_html(html)
        all_plugins = plugins_found.union(set(COMMON_PLUGINS[:10]))
        
        # Check each plugin concurrently
        plugin_tasks = []
        for plugin in list(all_plugins)[:20]:  # Limit to 20 plugins per site
            plugin_tasks.append(check_plugin_async(session, base_url, plugin, results))
        
        if plugin_tasks:
            await asyncio.gather(*plugin_tasks)
        
        # Check suspicious paths
        suspicious_paths = await check_suspicious_paths_async(session, base_url)
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

async def check_plugin_async(session, base_url, plugin, results):
    """Async check a single plugin"""
    # Check if plugin directory exists
    plugin_url = f"{base_url}/wp-content/plugins/{plugin}/"
    response = await safe_request(session, plugin_url, timeout=5)
    
    if not response or response['status'] not in [200, 403]:
        return
    
    plugin_info = {"version": None, "suspicious": []}
    
    # Get version (async)
    version = await get_plugin_version_async(session, base_url, plugin)
    if version:
        plugin_info["version"] = version
    
    # Check suspicious files for dangerous plugins
    if plugin in ['wp-file-manager', 'revslider', 'duplicator', 'backup', 'wp-automatic']:
        suspicious = await check_suspicious_files_async(session, base_url, plugin)
        if suspicious:
            plugin_info["suspicious"] = suspicious
    
    if plugin_info["version"] or plugin_info["suspicious"]:
        results["plugins"][plugin] = plugin_info

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

# ================= MAIN ASYNC SCAN FUNCTION =================
async def scan_ip_address_async(session, semaphore, ip_str):
    """Async function to scan a single IP address - SILENT MODE"""
    async with semaphore:
        try:
            # Update progress counter
            with output_lock:
                SCAN_STATS["scanned"] += 1
            
            # Resolve domains from IP (sync but fast)
            domains = resolve_domains_from_ip_sync(ip_str)
            if not domains:
                update_progress_line()
                return
            
            # For each domain found
            for domain in domains[:3]:  # Limit to 3 domains per IP
                with output_lock:
                    SCAN_STATS["domains_found"] += 1
                
                # Check if WordPress (async)
                base_url = await is_wordpress_site_async(session, domain)
                if not base_url:
                    continue
                
                # Found WordPress!
                with output_lock:
                    SCAN_STATS["wp_sites"] += 1
                
                # Scan the WordPress site (async)
                results = await scan_wordpress_site_async(session, ip_str, base_url)
                
                if results["plugins"]:
                    with output_lock:
                        SCAN_STATS["plugins_found"] += len(results["plugins"])
                
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
            update_progress_line()

async def process_batch_async(ip_batch):
    """Process a batch of IPs concurrently"""
    # Create aiohttp session with connection pooling
    connector = TCPConnector(
        limit=MAX_CONCURRENT,
        limit_per_host=10,
        ssl=ssl_context,
        force_close=False,
        enable_cleanup_closed=True
    )
    
    timeout = ClientTimeout(total=TIMEOUT * 2, connect=5)
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=HEADERS_TEMPLATE
    ) as session:
        
        # Semaphore to limit concurrency
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        # Create tasks for all IPs in batch
        tasks = []
        for ip in ip_batch:
            task = asyncio.create_task(scan_ip_address_async(session, semaphore, ip))
            tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)

# ================= MAIN =================
async def main_async():
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
        OUTPUT_FILE.write(f"WordPress Security Scan Report (Async)\n")
        OUTPUT_FILE.write(f"Time: {time.ctime()}\n")
        OUTPUT_FILE.write(f"Target: {ip_range}\n")
        OUTPUT_FILE.write(f"Total IPs: {SCAN_STATS['total_ips']}\n")
        OUTPUT_FILE.write("="*80 + "\n\n")
    except Exception as e:
        print(f"[!] Cannot open output file: {e}")
        sys.exit(1)
    
    # Display banner
    print("\n" + "="*70)
    print("🛡️  WORDPRESS SECURITY SCANNER - ASYNC MODE")
    print("="*70)
    print(f"🎯 Target: {ip_range}")
    print(f"📊 Total IPs: {SCAN_STATS['total_ips']}")
    print(f"⚡ Max concurrent: {MAX_CONCURRENT}")
    print("="*70)
    print("\n[+] Chế độ hiển thị:")
    print("   • Chỉ 1 dòng tiến trình duy nhất")
    print("   • Chỉ hiển thị khi tìm thấy LỖ HỔNG")
    print("   • Các phát hiện lỗ hổng sẽ được 'ghim' lại")
    print("\n[+] Công nghệ: aiohttp + asyncio (nhanh hơn 5-10x)")
    print("\n" + "="*70 + "\n")
    
    # Initial progress display
    update_progress_line()
    
    # Process IPs in batches
    batch_size = 500  # Larger batch size for async
    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i + batch_size]
        await process_batch_async(batch)
    
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
        OUTPUT_FILE.write(f"Speed: {SCAN_STATS['scanned']/(time.time() - SCAN_STATS['start_time']):.1f} IPs/s\n")
        OUTPUT_FILE.close()
    
    print(f"\n[+] Results saved to: {output_filename}")

def main():
    try:
        # Run async main
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n\n[!] Đang dừng quét...")
        show_final_summary()
        if OUTPUT_FILE:
            OUTPUT_FILE.close()
        sys.exit(0)

if __name__ == "__main__":
    main()