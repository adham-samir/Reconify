import asyncio
import os

from colorama import Fore, Style


async def _run_subprocess(cmd_list, timeout=300):
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


def _write_output(output_dir, filename, data):
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        f.write(data)
    return path


def _get_config_value(config, key, default):
    val = config.get(key, default)
    return os.environ.get(key.upper()) or str(val)


def run_livehosts(target, output_dir, config, scope_path=None):
    sub_file = os.path.join(output_dir, "final_subdomains.txt")
    threads = _get_config_value(config, "default_threads", "200")
    ports = _get_config_value(config, "default_ports", "80,443,8080,8000,8888")

    if not os.path.exists(sub_file):
        print(f"  {Fore.YELLOW}  [!] final_subdomains.txt not found — nothing to probe{Style.RESET_ALL}")
        return {"cdn_filtered": 0, "ports_open": 0, "live_count": 0, "file": None}

    cdn_count = 0

    print(f"  [*] CDN filtering (cdncheck)")
    cdn_out = asyncio.run(_run_subprocess(
        ["cdncheck", "-l", sub_file, "-silent"],
        timeout=120,
    ))
    cdn_results = set()
    non_cdn = set()
    for line in cdn_out.splitlines():
        parts = line.strip().split()
        if parts:
            sub = parts[0].lower()
            is_cdn = "true" in line.lower() or "cdn" in line.lower()
            if is_cdn:
                cdn_results.add(sub)
            else:
                non_cdn.add(sub)

    if cdn_results or non_cdn:
        with open(sub_file) as f:
            all_subs = {l.strip().lower() for l in f if l.strip()}
        filtered = all_subs - cdn_results
        cdn_count = len(cdn_results)
        print(f"      {cdn_count} CDN subdomains filtered out, {len(filtered)} remaining")
        temp_path = os.path.join(output_dir, "_filtered_no_cdn.txt")
        with open(temp_path, "w") as f:
            f.write("\n".join(sorted(filtered)) + "\n")
        probe_file = temp_path
    else:
        probe_file = sub_file
        print(f"      No CDN results (cdncheck may have failed)")

    print(f"  [*] Port probing (naabu)")
    naabu_out = asyncio.run(_run_subprocess(
        [
            "naabu", "-l", probe_file,
            "-p", ports,
            "-silent",
        ],
        timeout=300,
    ))
    naabu_hosts = set()
    for line in naabu_out.splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 2:
            naabu_hosts.add(parts[0].strip().lower())
    port_count = len(naabu_hosts)
    print(f"      {port_count} hosts with open ports")

    print(f"  [*] HTTP probing (httpx)")
    httpx_out = asyncio.run(_run_subprocess(
        [
            "httpx", "-l", probe_file,
            "-ports", ports,
            "-threads", str(threads),
            "-silent",
            "-status-code",
            "-title",
            "-content-length",
            "-web-server",
        ],
        timeout=300,
    ))
    live_lines = []
    live_subs = set()
    for line in httpx_out.splitlines():
        line = line.strip()
        if line:
            live_lines.append(line)
            url_part = line.split()[0] if line.split() else line
            live_subs.add(url_part.lower())

    if live_lines:
        _write_output(output_dir, "subdomains_alive.txt", "\n".join(live_lines) + "\n")

    print(f"\n  [*] {Fore.GREEN}Live hosts: {len(live_subs)} responding{Style.RESET_ALL}")

    if probe_file.endswith("_filtered_no_cdn.txt"):
        os.remove(probe_file)

    return {
        "cdn_filtered": cdn_count,
        "ports_open": port_count,
        "live_count": len(live_subs),
        "file": "subdomains_alive.txt",
    }
