import asyncio
import json
import os

from colorama import Fore, Style

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")


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


def _load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def _get_wordlist(config):
    wordlist = config.get("default_wordlist", "")
    if wordlist and os.path.exists(wordlist):
        use = input(f"  Use saved wordlist [{wordlist}]? [Y/n]: ").strip().lower()
        if use in ("", "y", "yes"):
            return wordlist
    path = input(f"  Enter wordlist path: ").strip()
    if os.path.exists(path):
        save = input(f"  Save as default? [y/N]: ").strip().lower()
        if save == "y":
            config["default_wordlist"] = path
            _save_config(config)
        return path
    print(f"  {Fore.RED}File not found: {path}{Style.RESET_ALL}")
    return None


async def _run_ffuf(target, output_dir, wordlist):
    print(f"  [*] FFUF subdomain brute-force")
    out = await _run_subprocess(
        [
            "ffuf", "-w", wordlist,
            "-u", f"https://FUZZ.{target}",
            "-t", "100",
            "-mc", "200,301,302,401,403,405,500",
            "-o", os.path.join(output_dir, "ffuf_output.json"),
            "-of", "json",
            "-s",
        ],
    )
    subs = set()
    for line in out.splitlines():
        if line.strip():
            sub = line.strip().lower()
            if sub.endswith(f".{target}"):
                subs.add(sub)
    if subs:
        _write_output(output_dir, "ffuf.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "ffuf", "count": len(subs), "file": "ffuf.txt"}


async def _run_alterx(target, output_dir):
    print(f"  [*] alterx permutations")
    try:
        proc1 = await asyncio.create_subprocess_exec(
            "subfinder", "-d", target, "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        proc2 = await asyncio.create_subprocess_exec(
            "alterx", "-silent",
            stdin=proc1.stdout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        proc3 = await asyncio.create_subprocess_exec(
            "dnsx", "-silent", "-a",
            stdin=proc2.stdout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc3.communicate(), timeout=180)
        lines = [l.strip().split()[0] for l in stdout.decode(errors="ignore").splitlines() if l.strip()]
        subs = {l.lower() for l in lines if l.lower().endswith(f".{target}")}
        if subs:
            _write_output(output_dir, "alterx.txt", "\n".join(sorted(subs)) + "\n")
        return {"tool": "alterx", "count": len(subs), "file": "alterx.txt"}
    except Exception:
        return {"tool": "alterx", "count": 0, "error": True}


async def _run_amass_active(target, output_dir):
    print(f"  [*] amass (active)")
    out = await _run_subprocess(
        ["amass", "enum", "-active", "-d", target, "-quiet"],
        timeout=300,
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    subs = {l.lower() for l in lines if l.lower().endswith(f".{target}")}
    if subs:
        _write_output(output_dir, "amass_active.txt", "\n".join(sorted(subs)) + "\n")
    return {"tool": "amass_active", "count": len(subs), "file": "amass_active.txt"}


def run_active(target, output_dir, config, scope_path=None):
    config_data = _load_config()

    wordlist = _get_wordlist(config_data)
    if not wordlist:
        print(f"  {Fore.YELLOW}  [!] No wordlist — skipping FFUF brute-force{Style.RESET_ALL}")

    async def _run_all():
        tasks = []
        if wordlist:
            tasks.append(_run_ffuf(target, output_dir, wordlist))
        tasks.append(_run_alterx(target, output_dir))
        tasks.append(_run_amass_active(target, output_dir))
        results = await asyncio.gather(*tasks)
        return results

    results = asyncio.run(_run_all())
    total_raw = sum(r.get("count", 0) for r in results)
    print(f"\n  [*] Active discovery complete — {total_raw} raw subdomains collected")
    return {"sources": results, "total_raw": total_raw}
