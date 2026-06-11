import asyncio
import os
import re
import random

from colorama import Fore, Style


async def _run_subprocess(cmd_list, timeout=30):
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


def _collect_source_files(output_dir):
    files = sorted(os.listdir(output_dir))
    sources = {}
    for f in files:
        if f.endswith(".txt") and f not in ("final_subdomains.txt", "subdomains_alive.txt"):
            path = os.path.join(output_dir, f)
            with open(path) as fh:
                subs = {l.strip().lower() for l in fh if l.strip()}
            if subs:
                sources[f] = subs
    return sources


def _detect_wildcards(subs, target):
    if len(subs) < 5:
        return set()

    sample = random.sample(list(subs), min(50, len(subs)))
    test_subs = [f"reconify-{os.urandom(4).hex()}.{target}",
                 f"x-{os.urandom(3).hex()}.{target}",
                 f"test-{os.urandom(4).hex()}.{target}"]
    all_test = sample + test_subs

    async def _resolve():
        tasks = []
        for s in all_test:
            tasks.append(_run_subprocess(["dnsx", "-silent", "-a", "-d", s]))
        resolved = await asyncio.gather(*tasks)
        return resolved

    resolved = asyncio.run(_resolve())

    ip_map = {}
    for s, out in zip(all_test, resolved):
        ips = out.strip().split()
        for ip in ips:
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(s)

    wildcard_ips = {ip for ip, domains in ip_map.items()
                    if len(domains) >= 3 and any("reconify-" in d or d.startswith("x-") or d.startswith("test-") for d in domains)}

    wildcard_subs = set()
    for s in subs:
        async def _check():
            out = await _run_subprocess(["dnsx", "-silent", "-a", "-d", s])
            return out.strip()
        try:
            out = asyncio.run(_check())
            for ip in out.strip().split():
                if ip in wildcard_ips:
                    wildcard_subs.add(s)
                    break
        except Exception:
            pass

    return wildcard_subs


def _load_scope(scope_path):
    if not scope_path or not os.path.exists(scope_path):
        return None
    patterns = []
    with open(scope_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    patterns.append(re.compile(line))
                except re.error:
                    pass
    return patterns


def _filter_scope(subs, scope_patterns):
    if not scope_patterns:
        return subs
    filtered = set()
    for s in subs:
        if any(p.search(s) for p in scope_patterns):
            filtered.add(s)
    return filtered


def run_merge(target, output_dir, config, scope_path=None):
    print(f"  [*] Collecting source files from {output_dir}")
    sources = _collect_source_files(output_dir)

    if not sources:
        print(f"  {Fore.YELLOW}  [!] No subdomain files found to merge{Style.RESET_ALL}")
        return {"total_raw": 0, "total_unique": 0, "sources": {}, "file": None}

    source_counts = {}
    for fname, subs in sources.items():
        source_counts[fname] = len(subs)

    all_subs = set()
    for subs in sources.values():
        all_subs.update(subs)

    total_raw = sum(source_counts.values())
    print(f"  [*] Raw total across all sources: {total_raw}")
    for fname, cnt in sorted(source_counts.items()):
        print(f"      {fname:<30} {cnt}")

    print(f"\n  [*] Before dedup: {len(all_subs)} unique")

    print(f"  [*] Checking for wildcard resolutions...")
    wildcards = _detect_wildcards(all_subs, target)
    if wildcards:
        print(f"  {Fore.YELLOW}  [!] Detected {len(wildcards)} wildcard subdomains, removing{Style.RESET_ALL}")
        all_subs -= wildcards

    if scope_path:
        print(f"  [*] Applying scope filter: {scope_path}")
        scope_patterns = _load_scope(scope_path)
        before = len(all_subs)
        all_subs = _filter_scope(all_subs, scope_patterns)
        print(f"      {before} → {len(all_subs)} (removed {before - len(all_subs)} out of scope)")

    final_path = os.path.join(output_dir, "final_subdomains.txt")
    with open(final_path, "w") as f:
        for s in sorted(all_subs):
            f.write(s + "\n")

    delta = total_raw - len(all_subs)
    print(f"\n  [*] {Fore.GREEN}Merged: {len(all_subs)} unique from {total_raw} total ({delta} duplicates/wildcards removed){Style.RESET_ALL}")

    return {
        "total_raw": total_raw,
        "total_unique": len(all_subs),
        "sources": source_counts,
        "file": "final_subdomains.txt",
    }
