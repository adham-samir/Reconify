import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from modules.api_keys import TRACKED_KEYS, run_key_manager
from modules.installer import check_all_tools, run_installer

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "config.env")
    if os.path.exists(env_path):
        load_dotenv(env_path)


def missing_keys():
    missing = []
    for key in TRACKED_KEYS:
        if not os.environ.get(key):
            missing.append(key)
    return missing


def build_output_dir(target):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    out_dir = os.path.join("outputs", f"{target}_{ts}")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def parse_stages(stage_arg):
    if not stage_arg:
        return []
    parts = [s.strip() for s in stage_arg.split(",")]
    return [int(p) for p in parts if p.isdigit()]


def main():
    parser = argparse.ArgumentParser(
        description="Recon Toolkit — Subdomain & asset recon for bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", help="Target domain (e.g. example.com)")
    parser.add_argument("--all", action="store_true", help="Run all stages (1,3,4,5)")
    parser.add_argument("--stage", help="Comma-separated stage numbers (e.g. 1,3,5)")
    parser.add_argument(
        "--active", action="store_true", help="Include active discovery (Stage 2)"
    )
    parser.add_argument("--keys", action="store_true", help="Open API key manager")
    parser.add_argument(
        "--check-tools", action="store_true", help="Check installed tools and exit"
    )
    parser.add_argument("--scope", help="Path to scope file (regex patterns)")

    args = parser.parse_args()

    load_env()

    if args.keys:
        run_key_manager()
        return

    if args.check_tools:
        run_installer()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    config = load_config()

    stages_to_run = set()
    if args.all:
        stages_to_run = {1, 3, 4, 5}
    elif args.stage:
        stages_to_run = set(parse_stages(args.stage))

    if args.active:
        stages_to_run.add(2)

    if not stages_to_run:
        print("[!] No stages specified. Use --all or --stage.")
        sys.exit(1)

    missing = missing_keys()
    if missing:
        print("[!] Some API keys are missing. Run with --keys to configure.")
        for key in missing:
            print(f"    {key:<30} → skipping {TRACKED_KEYS[key]}")
        print()

    print(f"[*] Target: {args.target}")
    print(f"[*] Stages: {', '.join(str(s) for s in sorted(stages_to_run))}")
    print()

    out_dir = build_output_dir(args.target)
    start_time = time.time()

    reporter_data = {
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration": None,
        "stages": {},
        "output_dir": out_dir,
    }

    if 1 in stages_to_run:
        from modules.passive import run_passive

        print(f"{'='*60}")
        print(f"  Stage 1 — Passive Subdomain Enumeration")
        print(f"{'='*60}")
        results = run_passive(
            target=args.target,
            output_dir=out_dir,
            config=config,
            scope_path=args.scope,
        )
        reporter_data["stages"]["1_passive"] = results

    if 2 in stages_to_run:
        from modules.active import run_active

        print(f"\n{'='*60}")
        print(f"  Stage 2 — Active Discovery")
        print(f"{'='*60}")
        results = run_active(
            target=args.target,
            output_dir=out_dir,
            config=config,
            scope_path=args.scope,
        )
        reporter_data["stages"]["2_active"] = results

    if 3 in stages_to_run:
        from modules.merge import run_merge

        print(f"\n{'='*60}")
        print(f"  Stage 3 — Merge & Deduplicate")
        print(f"{'='*60}")
        results = run_merge(
            target=args.target,
            output_dir=out_dir,
            config=config,
            scope_path=args.scope,
        )
        reporter_data["stages"]["3_merge"] = results

    if 4 in stages_to_run:
        from modules.ip_asn import run_ip_asn

        print(f"\n{'='*60}")
        print(f"  Stage 4 — IP & ASN Mapping")
        print(f"{'='*60}")
        results = run_ip_asn(
            target=args.target,
            output_dir=out_dir,
            config=config,
            scope_path=args.scope,
        )
        reporter_data["stages"]["4_ip_asn"] = results

    if 5 in stages_to_run:
        from modules.livehosts import run_livehosts

        print(f"\n{'='*60}")
        print(f"  Stage 5 — Live Host Filtering")
        print(f"{'='*60}")
        results = run_livehosts(
            target=args.target,
            output_dir=out_dir,
            config=config,
            scope_path=args.scope,
        )
        reporter_data["stages"]["5_livehosts"] = results

    duration = time.time() - start_time
    reporter_data["duration"] = duration

    from modules.reporter import generate_report

    report_path = generate_report(reporter_data)
    print(f"\n{'='*60}")
    print(f"  Done in {duration:.0f}s")
    print(f"  Report: {report_path}")
    print(f"  Output: {out_dir}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
