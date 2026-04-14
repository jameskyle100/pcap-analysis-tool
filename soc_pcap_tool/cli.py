from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .constants import DEFAULT_MODE, DEFAULT_TOP_N, SCRIPT_COPYRIGHT, SCRIPT_NOTICE, SCRIPT_PRODUCT
from .parsers import analyze_pcap_file
from .reporting import export_markdown


def print_header(title: str) -> None:
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)


def print_summary(summary: dict) -> None:
    print_header("SOC TRIAGE SUMMARY")
    for key, value in summary.items():
        print(f"{key}: {value}")


def print_takeaway(lines: list[str]) -> None:
    print_header("ANALYST TAKEAWAY")
    if not lines:
        print("No immediate high-signal takeaway generated.")
        return
    for line in lines:
        print(f"- {line}")


def print_findings(findings: list[dict]) -> None:
    print_header("PRIORITIZED FINDINGS")
    if not findings:
        print("No notable findings detected by current heuristics.")
        return
    for idx, finding in enumerate(findings, start=1):
        print(f"[{idx}] {finding['severity'].upper()} - {finding['title']}")
        print(f"Why it matters: {finding['why_it_matters']}")
        print(f"Evidence: {json.dumps(finding['evidence'], ensure_ascii=False)}")
        print(f"Next step: {finding['next_step']}")
        print("-" * 90)


def print_top(title: str, items: list) -> None:
    print_header(title)
    if not items:
        print("No data.")
        return
    for item in items:
        print(item)


def export_csv(records, path: Path) -> None:
    import csv
    fieldnames = list(asdict(records[0]).keys()) if records else [
        "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
        "length", "dns_query", "http_host", "http_uri", "tls_sni"
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow(asdict(rec))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOC-friendly PCAP triage tool with local dashboard")
    parser.add_argument("pcap", nargs="?", help="Path to PCAP or PCAPNG file. If omitted, dashboard mode starts.")
    parser.add_argument("--mode", choices=["quick", "hunt", "web", "dns"], default=DEFAULT_MODE)
    parser.add_argument("--top", type=int, default=DEFAULT_TOP_N, help="How many top items to display")
    parser.add_argument("--export-json", help="Write full JSON report")
    parser.add_argument("--export-md", help="Write Markdown report")
    parser.add_argument("--export-csv", help="Write normalized packet CSV")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser in dashboard mode")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.pcap:
        from .webapp import launch_dashboard
        launch_dashboard(args.host, args.port, open_browser=not args.no_browser)
        return 0

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[!] File not found: {pcap_path}")
        return 1
    try:
        records, report = analyze_pcap_file(pcap_path, mode=args.mode, top_n=args.top)
    except Exception as exc:
        print(f"[!] Failed to read PCAP: {exc}")
        return 1

    print(f"[*] Loaded {len(records)} packets from {pcap_path.name}")
    print_summary(report["summary"])
    print_takeaway(report["analyst_takeaway"])
    print_findings(report["findings"])
    print_top("TOP SOURCE IPS", report["top_source_ips"])
    print_top("TOP DESTINATION IPS", report["top_destination_ips"])
    print_top("TOP PROTOCOLS", report["top_protocols"])
    print_top("TOP DESTINATION PORTS", report["top_destination_ports"])
    print_top("TOP DNS QUERIES", report["top_dns_queries"])
    print_top("TOP TLS SNI", report["top_tls_sni"])
    print_top("TOP HTTP REQUESTS", report["top_http_requests"])
    print_top("TOP CONVERSATIONS", report["top_conversations"])

    if args.export_json:
        Path(args.export_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report written to {args.export_json}")
    if args.export_md:
        export_markdown(report, SCRIPT_NOTICE, SCRIPT_PRODUCT, SCRIPT_COPYRIGHT, Path(args.export_md))
        print(f"[+] Markdown report written to {args.export_md}")
    if args.export_csv:
        export_csv(records, Path(args.export_csv))
        print(f"[+] CSV written to {args.export_csv}")

    print(f"\n{SCRIPT_COPYRIGHT}")
    print("[+] Triage complete.")
    return 0
