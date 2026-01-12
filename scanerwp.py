#!/usr/bin/env python3
import asyncio
import aiohttp
import re
import json
from urllib.parse import urljoin

TIMEOUT = aiohttp.ClientTimeout(total=10)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (WP-Audit)",
    "Accept": "*/*"
}

COMMON_PLUGINS = [
    "akismet",
    "elementor",
    "contact-form-7",
    "woocommerce",
    "yoast-seo",
    "wordfence",
    "wpforms",
    "wpbakery",
    "slider-revolution"
]

VERSION_REGEX = re.compile(r"Stable tag:\s*([0-9.]+)", re.I)

async def fetch(session, url):
    try:
        async with session.get(url, headers=HEADERS, allow_redirects=True) as r:
            text = await r.text(errors="ignore")
            return r.status, text
    except:
        return None, None

async def detect_html_plugins(session, target):
    found = {}
    status, html = await fetch(session, target)
    if not html:
        return found

    plugins = set(re.findall(r"wp-content/plugins/([^/]+)/", html))
    for p in plugins:
        found[p] = {
            "detected_by": "html",
            "version": None,
            "version_status": "unknown"
        }
    return found

async def probe_plugin(session, target, plugin):
    base = f"{target}/wp-content/plugins/{plugin}/"
    status, _ = await fetch(session, base)
    if status not in (200, 403):
        return None

    plugin_data = {
        "detected_by": "probe",
        "version": None,
        "version_status": "hidden"
    }

    readme = urljoin(base, "readme.txt")
    r_status, r_text = await fetch(session, readme)

    if r_status == 200 and r_text:
        m = VERSION_REGEX.search(r_text)
        if m:
            plugin_data["version"] = m.group(1)
            plugin_data["version_status"] = "exposed"

    return plugin_data

async def scan_target(session, target):
    if not target.startswith("http"):
        target = "http://" + target

    result = {
        "target": target,
        "plugins": {}
    }

    # HTML passive detect
    html_plugins = await detect_html_plugins(session, target)
    result["plugins"].update(html_plugins)

    # Active probe
    for plugin in COMMON_PLUGINS:
        if plugin in result["plugins"]:
            continue

        data = await probe_plugin(session, target, plugin)
        if data:
            result["plugins"][plugin] = data

    return result

async def main():
    with open("targets.txt") as f:
        targets = [t.strip() for t in f if t.strip()]

    results = []

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        tasks = [scan_target(session, t) for t in targets]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)

            print(f"\n[+] {res['target']}")
            if not res["plugins"]:
                print("  No plugins detected")
            for p, info in res["plugins"].items():
                print(
                    f"  - {p} | {info['detected_by']} | "
                    f"version: {info['version'] or 'N/A'} "
                    f"({info['version_status']})"
                )

    with open("report.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[✓] Scan completed")

if __name__ == "__main__":
    asyncio.run(main())
