import os
import subprocess
import sys

from colorama import init, Fore, Style

init(autoreset=True)

TOOLS = {
    "subfinder": {
        "check_cmd": "subfinder -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "assetfinder": {
        "check_cmd": "assetfinder --version 2>/dev/null",
        "install_cmd": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "findomain": {
        "check_cmd": "findomain --version 2>/dev/null",
        "install_cmd": "cargo install findomain",
    },
    "amass": {
        "check_cmd": "amass -version 2>/dev/null",
        "install_cmd": "go install github.com/owasp-amass/amass/v4/...@master",
    },
    "httpx": {
        "check_cmd": "httpx -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "dnsx": {
        "check_cmd": "dnsx -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
    "asnmap": {
        "check_cmd": "asnmap -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    },
    "naabu": {
        "check_cmd": "naabu -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "cdncheck": {
        "check_cmd": "cdncheck -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    },
    "ffuf": {
        "check_cmd": "ffuf -V 2>/dev/null",
        "install_cmd": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "alterx": {
        "check_cmd": "alterx -version 2>/dev/null",
        "install_cmd": "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
    },
    "github-subdomains": {
        "check_cmd": "github-subdomains -version 2>/dev/null",
        "install_cmd": "go install github.com/gwen001/github-subdomains@latest",
    },
}


def _run(cmd, timeout=30):
    try:
        subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_tool(name):
    config = TOOLS.get(name)
    if not config:
        return False
    return _run(config["check_cmd"])


def check_deps():
    return _run("go version")


def install_deps():
    print(f"  {Fore.YELLOW}Go not found. Attempting install...{Style.RESET_ALL}")
    if _run("command -v apt-get"):
        cmd = "sudo apt-get update -qq && sudo apt-get install -y -qq golang-go"
    elif _run("command -v brew"):
        cmd = "brew install go"
    elif _run("command -v pacman"):
        cmd = "sudo pacman -S --noconfirm go"
    else:
        print(f"  {Fore.RED}Could not detect package manager. Install Go manually.{Style.RESET_ALL}")
        return False
    return _run(cmd, timeout=120)


def install_tool(name):
    config = TOOLS.get(name)
    if not config:
        return False
    print(f"  Installing {name}...")
    return _run(config["install_cmd"], timeout=180)


def check_all_tools():
    results = {}
    for name in TOOLS:
        results[name] = check_tool(name)
    return results


def run_installer():
    all_ok = True
    for name in TOOLS:
        if check_tool(name):
            continue
        all_ok = False
        print(f"\n  {Fore.YELLOW}[!] {name} not found{Style.RESET_ALL}")
        ans = input(f"  Install {name}? [Y/n/s]: ").strip().lower()
        if ans in ("", "y", "yes"):
            if not check_deps():
                print(f"  {Fore.YELLOW}Missing dependency: Go{Style.RESET_ALL}")
                if not install_deps():
                    print(f"  {Fore.RED}Failed to install Go. Skipping.{Style.RESET_ALL}")
                    continue
            if install_tool(name):
                print(f"  {Fore.GREEN}✓ {name} installed{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}✗ {name} install failed{Style.RESET_ALL}")
                ans2 = input(f"  [S]kip or [T]erminate? ").strip().lower()
                if ans2 == "t":
                    sys.exit(1)
        elif ans == "s":
            print(f"  Skipping {name}")
        else:
            ans2 = input(f"  [S]kip or [T]erminate? ").strip().lower()
            if ans2 == "t":
                sys.exit(1)
    if all_ok:
        print(f"\n  {Fore.GREEN}All tools are installed.{Style.RESET_ALL}")
