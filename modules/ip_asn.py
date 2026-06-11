import asyncio
import os
import re

import aiohttp
from colorama import Fore, Style


RATE_LIMITS = {
    "virustotal": 15.0,
    "securitytrails": 1.0,
    "urlscan": 1.5,
    "shodan": 1.0,
    "otx": 1.0,
}


async def _run_subprocess(cmd_list, timeout=60):
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=timeout,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode(errors="ignore")
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        return ""


async def _fetch(session, url, headers=None):
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.text()
    except Exception:
        return ""


async def _resolve_subdomains(output_dir, target):
    print(f"  [*] Resolving subdomains to IPs (dnsx)")
    sub_file = os.path.join(output_dir, "final_subdomains.txt")
    if not os.path.exists(sub_file):
        print(f"  {Fore.YELLOW}  [!] final_subdomains.txt not found{Style.RESET_ALL}")
        return []

    out = await _run_subprocess(
        ["dnsx", "-silent", "-a", "-resp", "-l", sub_file],
        timeout=120,
    )
    sub_to_ip = {}
    ips = set()
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            sub_to_ip[parts[0]] = parts[1:]
            ips.update(parts[1:])

    if sub_to_ip:
        path = os.path.join(output_dir, "resolved_ips.txt")
        with open(path, "w") as f:
            for sub, ip_list in sorted(sub_to_ip.items()):
                f.write(f"{sub} {' '.join(ip_list)}\n")
        print(f"      {len(sub_to_ip)} subdomains resolved to {len(ips)} unique IPs")
    return list(ips)


async def _asn_lookup(target, output_dir):
    print(f"  [*] ASN lookup (asnmap)")
    out = await _run_subprocess(
        ["asnmap", "-d", target],
        timeout=60,
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        path = os.path.join(output_dir, "asn_ranges.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"      {len(lines)} ASN ranges found")
    return lines


async def _amass_intel(target, output_dir):
    print(f"  [*] Amass intel")
    out = await _run_subprocess(
        ["amass", "intel", "-whois", "-d", target],
        timeout=120,
    )
    orgs = [l.strip() for l in out.splitlines() if l.strip()]
    if orgs:
        path = os.path.join(output_dir, "amass_intel.txt")
        with open(path, "w") as f:
            f.write("\n".join(orgs) + "\n")
        print(f"      {len(orgs)} org/CIDR findings")
    return orgs


async def _api_ip_harvest(session, target, output_dir, api_key, source, url, delay):
    print(f"  [*] {source}")
    if not api_key:
        print(f"  {Fore.YELLOW}  [!] {source} key not set → skipping{Style.RESET_ALL}")
        return []

    headers = {"x-apikey": api_key} if source == "VirusTotal" else (
        {"APIKEY": api_key} if source == "SecurityTrails" else (
            {"API-Key": api_key} if source == "URLScan" else (
                {"key": api_key} if source == "OTX" else None
            )
        )
    )

    if source == "Shodan":
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{target}"

    html = await _fetch(session, url, headers=headers)
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', html))
    await asyncio.sleep(delay)

    if ips:
        fname = f"{source.lower().replace(' ', '_')}_ips.txt"
        path = os.path.join(output_dir, fname)
        with open(path, "w") as f:
            f.write("\n".join(sorted(ips)) + "\n")
        print(f"      {len(ips)} IPs from {source}")
    return list(ips)


def run_ip_asn(target, output_dir, config, scope_path=None):
    resolved_ips = asyncio.run(_resolve_subdomains(output_dir, target))
    asn_ranges = asyncio.run(_asn_lookup(target, output_dir))
    amass_intel = asyncio.run(_amass_intel(target, output_dir))

    api_st = os.environ.get("SECURITYTRAILS_API_KEY", "")
    api_vt = os.environ.get("VIRUSTOTAL_API_KEY", "")
    api_otx = os.environ.get("OTX_API_KEY", "")
    api_urlscan = os.environ.get("URLSCAN_API_KEY", "")
    api_shodan = os.environ.get("SHODAN_API_KEY", "")

    async def _harvest_all():
        async with aiohttp.ClientSession() as session:
            tasks = [
                _api_ip_harvest(session, target, output_dir, api_vt, "VirusTotal",
                                f"https://www.virustotal.com/api/v3/domains/{target}/resolutions", RATE_LIMITS["virustotal"]),
                _api_ip_harvest(session, target, output_dir, api_st, "SecurityTrails",
                                f"https://api.securitytrails.com/v1/domain/{target}/subdomains", RATE_LIMITS["securitytrails"]),
                _api_ip_harvest(session, target, output_dir, api_otx, "OTX",
                                f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns", RATE_LIMITS["otx"]),
                _api_ip_harvest(session, target, output_dir, api_urlscan, "URLScan",
                                f"https://urlscan.io/api/v1/search/?q=domain:{target}", RATE_LIMITS["urlscan"]),
                _api_ip_harvest(session, target, output_dir, api_shodan, "Shodan",
                                "", RATE_LIMITS["shodan"]),
            ]
            all_ips = await asyncio.gather(*tasks)
            return all_ips

    api_ips = asyncio.run(_harvest_all())
    all_api_ips = set()
    for ip_list in api_ips:
        all_api_ips.update(ip_list)

    all_ips = set(resolved_ips) | all_api_ips

    print(f"\n  [*] IP & ASN mapping complete — {len(all_ips)} unique IPs identified")
    return {
        "resolved_count": len(resolved_ips),
        "api_ip_count": len(all_api_ips),
        "asn_count": len(asn_ranges),
        "total_unique_ips": len(all_ips),
    }
