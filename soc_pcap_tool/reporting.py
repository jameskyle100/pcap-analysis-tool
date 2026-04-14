from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any

from .detections import run_detections
from .ioc import enrich_indicator
from .models import PacketRecord
from .utils import (
    domain_is_known_benign,
    entropy_from_counts,
    is_private_ip,
    is_probably_noise_record,
    packet_record_to_dict,
    rating_from_score,
    score_findings,
)


def build_host_summary(records: list[PacketRecord], top_n: int = 10) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    host_map: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "external_destinations": Counter(),
        "dns_queries": Counter(),
        "ports": Counter(),
        "bytes_sent": 0,
        "packet_count": 0,
        "flows": Counter(),
        "http_requests": Counter(),
        "sample_packets": [],
    })
    for r in records:
        if not r.src_ip or is_probably_noise_record(r):
            continue
        host = host_map[r.src_ip]
        host["packet_count"] += 1
        host["bytes_sent"] += r.length
        if len(host["sample_packets"]) < 5:
            host["sample_packets"].append(packet_record_to_dict(r))
        if r.dst_ip and not is_private_ip(r.dst_ip):
            host["external_destinations"][r.dst_ip] += 1
        if r.dns_query and not domain_is_known_benign(r.dns_query):
            host["dns_queries"][r.dns_query] += 1
        if r.dst_port is not None:
            host["ports"][r.dst_port] += 1
        if r.flow_id:
            host["flows"][r.flow_id] += 1
        if r.http_host or r.http_uri:
            host["http_requests"][f"{r.http_method or 'HTTP'} {r.http_host or ''}{r.http_uri or ''}".strip()] += 1
    ranked = []
    details = {}
    for src_ip, info in host_map.items():
        details[src_ip] = {
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "top_external_destinations": info["external_destinations"].most_common(10),
            "top_dns_queries": info["dns_queries"].most_common(10),
            "top_ports": info["ports"].most_common(10),
            "top_flows": info["flows"].most_common(10),
            "top_http_requests": info["http_requests"].most_common(10),
            "sample_packets": info["sample_packets"],
        }
        ranked.append({
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "top_external_destinations": info["external_destinations"].most_common(3),
            "top_dns_queries": info["dns_queries"].most_common(3),
            "top_ports": info["ports"].most_common(3),
        })
    ranked.sort(key=lambda x: (len(x["top_external_destinations"]), x["bytes_sent"], x["packet_count"]), reverse=True)
    return ranked[:top_n], details


def build_domain_summary(records: list[PacketRecord], top_n: int = 10) -> dict[str, Any]:
    domain_map: dict[str, dict[str, Any]] = defaultdict(lambda: {"dns": 0, "sni": 0, "http": 0, "hosts": Counter(), "sample_packets": []})
    for r in records:
        for domain, source in ((r.dns_query, "dns"), (r.tls_sni, "sni"), (r.http_host, "http")):
            if not domain or domain_is_known_benign(domain):
                continue
            domain_map[domain][source] += 1
            if r.src_ip:
                domain_map[domain]["hosts"][r.src_ip] += 1
            if len(domain_map[domain]["sample_packets"]) < 5:
                domain_map[domain]["sample_packets"].append(packet_record_to_dict(r))
    details = {}
    ranked = []
    for domain, info in domain_map.items():
        details[domain] = {
            "domain": domain,
            "dns_hits": info["dns"],
            "sni_hits": info["sni"],
            "http_hits": info["http"],
            "hosts": info["hosts"].most_common(10),
            "sample_packets": info["sample_packets"],
            "ioc": enrich_indicator(domain, "domain"),
        }
        ranked.append({"domain": domain, "hits": info["dns"] + info["sni"] + info["http"], "ioc": enrich_indicator(domain, "domain")})
    ranked.sort(key=lambda x: x["hits"], reverse=True)
    return {"top_domains": ranked[:top_n], "domain_details": details}


def build_dns_relationships(records: list[PacketRecord], top_n: int = 10) -> list[dict[str, Any]]:
    outstanding: dict[tuple[int, str | None, str | None], PacketRecord] = {}
    pairs = []
    for r in records:
        if r.dns_id is None or not r.src_ip or not r.dst_ip:
            continue
        key = (r.dns_id, r.src_ip, r.dst_ip)
        rev_key = (r.dns_id, r.dst_ip, r.src_ip)
        if not r.dns_is_response:
            outstanding[key] = r
        elif rev_key in outstanding:
            q = outstanding[rev_key]
            pairs.append({
                "query": q.dns_query,
                "resolver": q.dst_ip,
                "client": q.src_ip,
                "response_code": r.dns_rcode,
                "answers": r.dns_answers,
                "first_seen": q.timestamp,
                "last_seen": r.timestamp,
            })
    return pairs[:top_n]


def build_flow_summary(records: list[PacketRecord], top_n: int = 10) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    flow_map: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "bytes": 0,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "sample_packets": [],
        "times": [],
    })
    for r in records:
        if not r.flow_id:
            continue
        flow = flow_map[r.flow_id]
        flow["count"] += 1
        flow["bytes"] += r.length
        flow["src_ip"] = flow["src_ip"] or r.src_ip
        flow["dst_ip"] = flow["dst_ip"] or r.dst_ip
        flow["src_port"] = flow["src_port"] or r.src_port
        flow["dst_port"] = flow["dst_port"] or r.dst_port
        flow["protocol"] = flow["protocol"] or r.protocol
        flow["times"].append(r.timestamp)
        if len(flow["sample_packets"]) < 5:
            flow["sample_packets"].append(packet_record_to_dict(r))
    details = {}
    ranked = []
    for flow_id, info in flow_map.items():
        details[flow_id] = {**info, "first_seen": min(info["times"]) if info["times"] else None, "last_seen": max(info["times"]) if info["times"] else None}
        ranked.append({
            "flow_id": flow_id,
            "src_ip": info["src_ip"],
            "dst_ip": info["dst_ip"],
            "src_port": info["src_port"],
            "dst_port": info["dst_port"],
            "protocol": info["protocol"],
            "count": info["count"],
            "bytes": info["bytes"],
        })
    ranked.sort(key=lambda x: (x["count"], x["bytes"]), reverse=True)
    return ranked[:top_n], details


def build_report(records: list[PacketRecord], mode: str, top_n: int, file_name: str | None = None) -> dict[str, Any]:
    proto_counter = Counter(r.protocol for r in records)
    src_counter = Counter(r.src_ip for r in records if r.src_ip)
    dst_counter = Counter(r.dst_ip for r in records if r.dst_ip)
    dns_counter = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    sni_counter = Counter(r.tls_sni for r in records if r.tls_sni and not domain_is_known_benign(r.tls_sni))
    http_counter = Counter(f"{r.http_method or 'HTTP'} {r.http_host or ''}{r.http_uri or ''}".strip() for r in records if (r.http_host or r.http_uri) and not domain_is_known_benign(r.http_host))
    dst_port_counter = Counter(r.dst_port for r in records if r.dst_port is not None)
    top_conversations, flow_details = build_flow_summary(records, top_n=top_n)
    host_summary, host_details = build_host_summary(records, top_n=top_n)
    domain_summary = build_domain_summary(records, top_n=top_n)
    findings = run_detections(records, mode)
    triage_score = score_findings(findings)
    triage_rating = rating_from_score(triage_score)
    first_seen = records[0].timestamp if records else None
    last_seen = records[-1].timestamp if records else None
    packet_sizes = Counter(r.length for r in records)

    suspicious_host = host_summary[0]["source_ip"] if host_summary else None

    summary = {
        "mode": mode,
        "packet_count": len(records),
        "first_seen_utc": first_seen,
        "last_seen_utc": last_seen,
        "unique_source_ips": len(src_counter),
        "unique_destination_ips": len(dst_counter),
        "top_protocol": proto_counter.most_common(1)[0][0] if proto_counter else None,
        "avg_packet_size": round(statistics.mean([r.length for r in records]), 2) if records else 0,
        "median_packet_size": round(statistics.median([r.length for r in records]), 2) if records else 0,
        "packet_size_entropy": entropy_from_counts(packet_sizes),
        "triage_score": triage_score,
        "triage_rating": triage_rating,
        "finding_count": len(findings),
        "most_suspicious_host": suspicious_host,
    }

    analyst_takeaway = []
    if findings:
        analyst_takeaway.append(f"Top concern: {findings[0].title}")
    if suspicious_host:
        analyst_takeaway.append(f"Most suspicious host candidate: {suspicious_host}")
    if dns_counter:
        analyst_takeaway.append(f"Most queried domain: {dns_counter.most_common(1)[0][0]}")
    if sni_counter:
        analyst_takeaway.append(f"Most seen TLS SNI: {sni_counter.most_common(1)[0][0]}")

    return {
        "fileName": file_name or "capture",
        "summary": summary,
        "analyst_takeaway": analyst_takeaway,
        "top_source_ips": src_counter.most_common(top_n),
        "top_destination_ips": dst_counter.most_common(top_n),
        "top_protocols": proto_counter.most_common(top_n),
        "top_destination_ports": dst_port_counter.most_common(top_n),
        "top_dns_queries": dns_counter.most_common(top_n),
        "top_tls_sni": sni_counter.most_common(top_n),
        "top_http_requests": http_counter.most_common(top_n),
        "top_conversations": top_conversations,
        "flow_details": flow_details,
        "dns_pairs": build_dns_relationships(records, top_n=top_n),
        "host_summary": host_summary,
        "host_details": host_details,
        "top_domains": domain_summary["top_domains"],
        "domain_details": domain_summary["domain_details"],
        "findings": [asdict(f) for f in findings],
        "sample_packets": [packet_record_to_dict(r) for r in records[:10]],
    }


def export_markdown(report: dict[str, Any], notice: str, product: str, copyright_text: str, path) -> None:
    lines: list[str] = [f"# {product}", "", f"{copyright_text}", "", "## Summary"]
    for key, value in report["summary"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Analyst Takeaway"]
    for line in report["analyst_takeaway"] or ["No immediate high-signal takeaway generated."]:
        lines.append(f"- {line}")
    lines += ["", "## Prioritized Findings"]
    if report["findings"]:
        for i, f in enumerate(report["findings"], start=1):
            lines += [
                f"### {i}. {f['severity'].upper()} - {f['title']}",
                f"- Why it matters: {f['why_it_matters']}",
                f"- Confidence: {f.get('confidence', 0)} | Score: {f.get('score', 0)}",
                f"- Evidence: `{json.dumps(f['evidence'], ensure_ascii=False)}`",
                f"- Next step: {f['next_step']}",
                "",
            ]
    else:
        lines += ["No notable findings detected by current heuristics.", ""]
    lines += ["---", notice]
    path.write_text("\n".join(lines), encoding="utf-8")
