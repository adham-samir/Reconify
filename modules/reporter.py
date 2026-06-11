import os
from datetime import timedelta


def _fmt_duration(seconds):
    td = timedelta(seconds=int(seconds))
    parts = []
    if td.seconds // 3600:
        parts.append(f"{td.seconds // 3600}h")
    if td.seconds % 3600 // 60:
        parts.append(f"{td.seconds % 3600 // 60}m")
    parts.append(f"{td.seconds % 60}s")
    return " ".join(parts) if parts else "0s"


def _passive_table(stage_data):
    if not stage_data:
        return "*Stage not executed*"
    sources = stage_data.get("sources", [])
    if not sources:
        return "*No data collected*"
    rows = ["| Source | Count | Status |", "|--------|------:|--------|"]
    for s in sources:
        tool = s.get("tool", "?")
        count = s.get("count", 0)
        if s.get("skipped"):
            status = "⚠ skipped (no key)"
            count_str = "—"
        elif s.get("error"):
            status = "✗ error"
            count_str = str(count)
        else:
            status = "✓ ok"
            count_str = str(count)
        rows.append(f"| {tool} | {count_str} | {status} |")
    rows.append(f"| **Total** | **{stage_data.get('total_raw', 0)}** | |")
    return "\n".join(rows)


def _active_table(stage_data):
    if not stage_data:
        return "*Stage not executed*"
    sources = stage_data.get("sources", [])
    if not sources:
        return "*No data collected*"
    rows = ["| Source | Count | Status |", "|--------|------:|--------|"]
    for s in sources:
        tool = s.get("tool", "?")
        count = s.get("count", 0)
        if s.get("error"):
            status = "✗ error"
            count_str = str(count)
        else:
            status = "✓ ok"
            count_str = str(count) if count else "0"
        rows.append(f"| {tool} | {count_str} | {status} |")
    rows.append(f"| **Total** | **{stage_data.get('total_raw', 0)}** | |")
    return "\n".join(rows)


def _merge_section(stage_data):
    if not stage_data:
        return "*Stage not executed*"
    total_raw = stage_data.get("total_raw", 0)
    total_unique = stage_data.get("total_unique", 0)
    sources = stage_data.get("sources", {})
    lines = [
        f"| Total raw | {total_raw} |",
        f"| Unique after dedup | {total_unique} |",
        f"| Removed | {total_raw - total_unique} |",
    ]
    if sources:
        lines.append("\n**Per-source breakdown:**")
        lines.append("| Source | Count |")
        lines.append("|--------|------:|")
        for fname, cnt in sorted(sources.items()):
            lines.append(f"| {fname} | {cnt} |")
    return "\n".join(lines)


def _ip_asn_section(stage_data):
    if not stage_data:
        return "*Stage not executed*"
    return (
        f"| Resolved subdomains | {stage_data.get('resolved_count', 0)} |\n"
        f"| API harvest IPs | {stage_data.get('api_ip_count', 0)} |\n"
        f"| ASN ranges | {stage_data.get('asn_count', 0)} |\n"
        f"| Total unique IPs | {stage_data.get('total_unique_ips', 0)} |"
    )


def _livehosts_section(stage_data):
    if not stage_data:
        return "*Stage not executed*"
    return (
        f"| CDN filtered | {stage_data.get('cdn_filtered', 0)} |\n"
        f"| Hosts with open ports | {stage_data.get('ports_open', 0)} |\n"
        f"| Live (HTTP responding) | {stage_data.get('live_count', 0)} |"
    )


def _output_files(out_dir):
    if not os.path.exists(out_dir):
        return "*No output directory*"
    files = sorted(os.listdir(out_dir))
    txt_files = [f for f in files if f.endswith(".txt")]
    if not txt_files:
        return "*No output files*"
    lines = []
    for f in txt_files:
        path = os.path.join(out_dir, f)
        size = os.path.getsize(path)
        lines.append(f"- `{f}` ({size} bytes)")
    return "\n".join(lines)


def generate_report(data):
    target = data.get("target", "unknown")
    ts = data.get("timestamp", "?")
    duration = data.get("duration", 0)
    out_dir = data.get("output_dir", ".")

    report = [
        f"# Recon Report — {target}",
        f"**Date:** {ts}  \n**Duration:** {_fmt_duration(duration)}",
        "",
        "---",
        "",
        "## Stage 1 — Passive Subdomain Enumeration",
        _passive_table(data.get("stages", {}).get("1_passive")),
        "",
        "## Stage 2 — Active Discovery",
        _active_table(data.get("stages", {}).get("2_active")),
        "",
        "## Stage 3 — Merge & Deduplicate",
        _merge_section(data.get("stages", {}).get("3_merge")),
        "",
        "## Stage 4 — IP & ASN Mapping",
        _ip_asn_section(data.get("stages", {}).get("4_ip_asn")),
        "",
        "## Stage 5 — Live Host Filtering",
        _livehosts_section(data.get("stages", {}).get("5_livehosts")),
        "",
        "---",
        "",
        "## Output Files",
        _output_files(out_dir),
    ]

    ts_safe = data.get("timestamp", "unknown").replace(" ", "_").replace(":", "").replace("/", "-")
    report_path = os.path.join(out_dir, f"recon_{target}_{ts_safe}.md")
    os.makedirs(out_dir, exist_ok=True)
    with open(report_path, "w") as f:
        f.write("\n".join(report))

    print(f"\n  Report written to {report_path}")
    return report_path
