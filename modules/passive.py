import asyncio
import os
import re

import aiohttp
from colorama import Fore, Style

TIMEOUT = 120

RATE_LIMITS = {
    "crtsh": 2.0,
    "virustotal": 15.0,
    "securitytrails": 1.0,
    "urlscan": 1.5,
    "shodan": 1.0,
    "otx": 1.0,
}


def _write_output(output_dir, filename, data):
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        f.write(data)
    return path


async def _run_subprocess(cmd_list, timeout=TIMEOUT):
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=timeout,
        )
        stdout, stderr = await proc.communicate()
        return stdout.decode(errors="ignore")
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        return ""


async def _fetch(session, url, headers=None, params=None):
    try:
        async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.text()
    except Exception:
        return ""


async def _rate_limited_fetch(session, url, delay, headers=None, params=None):
    result = await _fetch(session, url, headers=headers, params=params)
    await asyncio.sleep(delay)
    return result


async def _source_subfinder(target, output_dir):
    print(f"  [*] subfinder")
    out = await _run_subprocess(
        ["subfinder", "-d", target, "-silent"]
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        _write_output(output_dir, "subfinder.txt", "\n".join(lines) + "\n")
    return {"tool": "subfinder", "count": len(lines), "file": "subfinder.txt"}


async def _source_assetfinder(target, output_dir):
    print(f"  [*] assetfinder")
    out = await _run_subprocess(
        ["assetfinder", "--subs-only", target]
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        _write_output(output_dir, "assetfinder.txt", "\n".join(lines) + "\n")
    return {"tool": "assetfinder", "count": len(lines), "file": "assetfinder.txt"}


async def _source_findomain(target, output_dir):
    print(f"  [*] findomain")
    out = await _run_subprocess(
        ["findomain", "-t", target, "--quiet"]
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        _write_output(output_dir, "findomain.txt", "\n".join(lines) + "\n")
    return {"tool": "findomain", "count": len(lines), "file": "findomain.txt"}


async def _source_amass(target, output_dir):
    print(f"  [*] amass (passive)")
    out = await _run_subprocess(
        ["amass", "enum", "-passive", "-d", target, "-quiet"],
        timeout=180,
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        _write_output(output_dir, "amass_passive.txt", "\n".join(lines) + "\n")
    return {"tool": "amass_passive", "count": len(lines), "file": "amass_passive.txt"}


async def _source_crtsh(session, target, output_dir):
    print(f"  [*] crt.sh")
    html = await _rate_limited_fetch(
        session,
        f"https://crt.sh/?q=%25.{target}&output=json",
        delay=RATE_LIMITS["crtsh"],
    )
    subs = set()
    for match in re.finditer(r'"name_value":"([^"]+)"', html):
        for s in match.group(1).split("\n"):
            s = s.strip().lower()
            if s.endswith(f".{target}") or s == target:
                subs.add(s)
    if subs:
        _write_output(output_dir, "crtsh.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "crtsh", "count": len(subs), "file": "crtsh.txt"}


async def _source_dnsdumpster(session, target, output_dir):
    print(f"  [*] dnsdumpster")
    html = await _fetch(
        session, f"https://dnsdumpster.com/domain/{target}"
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "dnsdumpster.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "dnsdumpster", "count": len(subs), "file": "dnsdumpster.txt"}


async def _source_bufferover(session, target, output_dir):
    print(f"  [*] tls.bufferover.run")
    html = await _fetch(
        session,
        f"https://tls.bufferover.run/dns?q=.{target}",
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "bufferover.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "bufferover", "count": len(subs), "file": "bufferover.txt"}


async def _source_riddler(session, target, output_dir):
    print(f"  [*] riddler.io")
    html = await _fetch(
        session,
        f"https://riddler.io/search?q=pld:{target}",
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "riddler.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "riddler", "count": len(subs), "file": "riddler.txt"}


async def _source_commoncrawl(session, target, output_dir):
    print(f"  [*] CommonCrawl")
    html = await _fetch(
        session,
        f"http://index.commoncrawl.org/CC-MAIN-2024-33-index?url=*.{target}&output=json",
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "commoncrawl.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "commoncrawl", "count": len(subs), "file": "commoncrawl.txt"}


async def _source_wayback(session, target, output_dir):
    print(f"  [*] Wayback Machine")
    html = await _fetch(
        session,
        f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey",
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "wayback.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "wayback", "count": len(subs), "file": "wayback.txt"}


async def _source_virustotal(session, target, output_dir, api_key):
    print(f"  [*] VirusTotal")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] VIRUSTOTAL_API_KEY not set → skipping{Style.RESET_ALL}")
        return {"tool": "virustotal", "count": 0, "skipped": True}

    html = await _rate_limited_fetch(
        session,
        f"https://www.virustotal.com/api/v3/domains/{target}/subdomains",
        delay=RATE_LIMITS["virustotal"],
        headers={"x-apikey": api_key},
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "virustotal.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "virustotal", "count": len(subs), "file": "virustotal.txt"}


async def _source_securitytrails(session, target, output_dir, api_key):
    print(f"  [*] SecurityTrails")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] SECURITYTRAILS_API_KEY not set → skipping{Style.RESET_ALL}")
        return {"tool": "securitytrails", "count": 0, "skipped": True}

    html = await _rate_limited_fetch(
        session,
        f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
        delay=RATE_LIMITS["securitytrails"],
        headers={"APIKEY": api_key},
    )
    subs = set()
    for match in re.finditer(r'"subdomains":\[(.*?)\]', html):
        parts = re.findall(r'"([^"]+)"', match.group(1))
        for p in parts:
            subs.add(f"{p}.{target}")
    if subs:
        _write_output(output_dir, "securitytrails.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "securitytrails", "count": len(subs), "file": "securitytrails.txt"}


async def _source_urlscan(session, target, output_dir, api_key):
    print(f"  [*] URLScan.io")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] URLSCAN_API_KEY not set → skipping{Style.RESET_ALL}")
        return {"tool": "urlscan", "count": 0, "skipped": True}

    html = await _rate_limited_fetch(
        session,
        f"https://urlscan.io/api/v1/search/?q=domain:{target}",
        delay=RATE_LIMITS["urlscan"],
        headers={"API-Key": api_key},
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "urlscan.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "urlscan", "count": len(subs), "file": "urlscan.txt"}


async def _source_shodan(session, target, output_dir, api_key):
    print(f"  [*] Shodan")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] SHODAN_API_KEY not set → skipping{Style.RESET_ALL}")
        return {"tool": "shodan", "count": 0, "skipped": True}

    html = await _rate_limited_fetch(
        session,
        f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{target}",
        delay=RATE_LIMITS["shodan"],
    )
    subs = set(re.findall(rf'(?:[a-zA-Z0-9-]+\.)+{re.escape(target)}', html))
    if subs:
        _write_output(output_dir, "shodan.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "shodan", "count": len(subs), "file": "shodan.txt"}


async def _source_github(session, target, output_dir, api_key):
    print(f"  [*] github-subdomains")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] GITHUB_TOKEN not set → skipping{Style.RESET_ALL}")
        return {"tool": "github", "count": 0, "skipped": True}

    out = await _run_subprocess(
        ["github-subdomains", "-d", target, "-t", api_key, "-o", "/dev/stdout"]
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        _write_output(output_dir, "github.txt", "\n".join(lines) + "\n")
    return {"tool": "github", "count": len(lines), "file": "github.txt"}


async def _source_hackertarget(session, target, output_dir):
    print(f"  [*] HackerTarget")
    html = await _fetch(
        session,
        f"https://api.hackertarget.com/hostsearch/?q={target}",
    )
    subs = set()
    for line in html.splitlines():
        parts = line.split(",")
        if parts and (parts[0].endswith(f".{target}") or parts[0] == target):
            subs.add(parts[0].strip().lower())
    if subs:
        _write_output(output_dir, "hackertarget.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "hackertarget", "count": len(subs), "file": "hackertarget.txt"}


def run_passive(target, output_dir, config, scope_path=None):
    import os

    api_shodan = os.environ.get("SHODAN_API_KEY", "")
    api_vt = os.environ.get("VIRUSTOTAL_API_KEY", "")
    api_st = os.environ.get("SECURITYTRAILS_API_KEY", "")
    api_urlscan = os.environ.get("URLSCAN_API_KEY", "")
    api_gh = os.environ.get("GITHUB_TOKEN", "")

    async def _run_all():
        async with aiohttp.ClientSession() as session:
            tasks = [
                _source_subfinder(target, output_dir),
                _source_assetfinder(target, output_dir),
                _source_findomain(target, output_dir),
                _source_amass(target, output_dir),
                _source_crtsh(session, target, output_dir),
                _source_dnsdumpster(session, target, output_dir),
                _source_bufferover(session, target, output_dir),
                _source_riddler(session, target, output_dir),
                _source_commoncrawl(session, target, output_dir),
                _source_wayback(session, target, output_dir),
                _source_virustotal(session, target, output_dir, api_vt),
                _source_securitytrails(session, target, output_dir, api_st),
                _source_urlscan(session, target, output_dir, api_urlscan),
                _source_shodan(session, target, output_dir, api_shodan),
                _source_github(session, target, output_dir, api_gh),
                _source_hackertarget(session, target, output_dir),
            ]
            results = await asyncio.gather(*tasks)
            return results

    results = asyncio.run(_run_all())

    total_raw = sum(r.get("count", 0) for r in results)
    print(f"\n  [*] Passive enumeration complete — {total_raw} raw subdomains collected")
    return {"sources": results, "total_raw": total_raw}
