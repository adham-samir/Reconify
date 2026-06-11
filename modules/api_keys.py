import os
import sys
from getpass import getpass

from colorama import init, Fore, Style

init(autoreset=True)

CONFIG_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.env")

TRACKED_KEYS = {
    "SHODAN_API_KEY": "Shodan",
    "VIRUSTOTAL_API_KEY": "VirusTotal",
    "GITHUB_TOKEN": "GitHub Subdomains",
    "SECURITYTRAILS_API_KEY": "SecurityTrails",
    "OTX_API_KEY": "AlienVault OTX",
    "URLSCAN_API_KEY": "URLScan.io",
}


def load_keys():
    keys = {}
    if not os.path.exists(CONFIG_ENV_PATH):
        return keys
    with open(CONFIG_ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()
    return keys


def save_keys(keys):
    with open(CONFIG_ENV_PATH, "w") as f:
        f.write("# Recon Toolkit -- API Keys\n")
        f.write("# Uncomment and fill in your keys. This file is gitignored.\n")
        for key in TRACKED_KEYS:
            val = keys.get(key, "")
            if val:
                f.write(f"{key}={val}\n")
            else:
                f.write(f"# {key}=\n")


def mask_key(value):
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def run_key_manager():
    keys = load_keys()
    while True:
        print(f"\n{Fore.CYAN}API Key Manager{Style.RESET_ALL}")
        print("─" * 60)

        items = list(TRACKED_KEYS.items())
        for i, (key, desc) in enumerate(items, 1):
            value = keys.get(key, "")
            if value:
                status = f"{Fore.GREEN}✅ configured{Style.RESET_ALL}"
                masked = mask_key(value)
                line = f"[{i}] {key:<25} {status}  {masked}"
            else:
                status = f"{Fore.RED}❌ missing{Style.RESET_ALL}"
                line = f"[{i}] {key:<25} {status}"
            print(f"  {line}")

        print("─" * 60)
        print("  [E] Edit a key   [D] Delete a key   [Q] Quit")
        choice = input(f"\n{Fore.YELLOW}Select option:{Style.RESET_ALL} ").strip().upper()

        if choice == "Q":
            break
        elif choice == "E":
            idx = input(f"{Fore.YELLOW}Enter key number to edit:{Style.RESET_ALL} ").strip()
            if idx.isdigit() and 1 <= int(idx) <= len(items):
                key, desc = items[int(idx) - 1]
                current = keys.get(key, "")
                prompt = f"  {key} ({desc})"
                if current:
                    prompt += f" [current: {mask_key(current)}]"
                prompt += ": "
                new_val = getpass(prompt).strip()
                if new_val:
                    keys[key] = new_val
                    save_keys(keys)
                    print(f"  {Fore.GREEN}✓ {key} updated{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}No value entered — unchanged{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}Invalid selection{Style.RESET_ALL}")
        elif choice == "D":
            idx = input(f"{Fore.YELLOW}Enter key number to delete:{Style.RESET_ALL} ").strip()
            if idx.isdigit() and 1 <= int(idx) <= len(items):
                key, desc = items[int(idx) - 1]
                if key in keys and keys[key]:
                    confirm = input(f"  Delete {key}? [y/N]: ").strip().lower()
                    if confirm == "y":
                        keys[key] = ""
                        save_keys(keys)
                        print(f"  {Fore.GREEN}✓ {key} deleted{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}No value to delete{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}Invalid selection{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}Invalid option{Style.RESET_ALL}")

    print(f"{Fore.CYAN}Key manager closed.{Style.RESET_ALL}")
