from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from .constants import COMMON_PORTS, DNS_TUNNEL_KEYWORDS, SUSPICIOUS_PORTS
from .ioc import enrich_indicator
from .models import Finding, PacketRecord
from .utils import (
    domain_is_known_benign,
    is_private_ip,
    is_probably_noise_record,
    packet_record_to_dict,
)


HIGH_RISK_HTTP_PATHS = ("/login", "/admin", "/wp-admin", "/api", "/shell", "/cmd")


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _sample_packets(records: list[PacketRecord], limit: int = 3) -> list[dict]:
    return [packet_record_to_dict(r) for r in records[:limit]]


def _time_range(records: list[PacketRecord]) -> dict:
    ordered = sorted(records, key=lambda r: r.timestamp)
    return {
        "first_seen": ordered[0].timestamp if ordered else None,
        "last_seen": ordered[-1].timestamp if ordered else None,
    }


def _common_evidence(records: list[PacketRecord]) -> dict:
    hosts = Counter(r.src_ip for r in records if r.src_ip)
    dests = Counter((r.http_host or r.tls_sni or r.dns_query or r.dst_ip) for r in records if (r.http_host or r.tls_sni or r.dns_query or r.dst_ip))
    return {
        "source_host": hosts.most_common(1)[0][0] if hosts else None,
        "destination": dests.most_common(1)[0][0] if dests else None,
        "packet_count": len(records),
        **_time_range(records),
        "sample_packets": _sample_packets(records, limit=5),
        "representative_packets": _sample_packets(records, limit=5),
        "related_flows": list(dict.fromkeys(r.flow_id for r in records if r.flow_id))[:5],
        "related_dns": list(dict.fromkeys(r.dns_query for r in records if r.dns_query))[:5],
        "related_tls": list(dict.fromkeys(r.tls_sni for r in records if r.tls_sni))[:5],
        "related_sni": list(dict.fromkeys(r.tls_sni for r in records if r.tls_sni))[:5],
        "related_http": list(dict.fromkeys(f"{r.http_method or ''} {r.http_host or ''}{r.http_uri or ''}".strip() for r in records if r.http_host or r.http_uri))[:5],
    }


def _make_finding(severity: str, title: str, why: str, records: list[PacketRecord], next_step: str, confidence: float, score: int, tags: list[str], extra: dict | None = None) -> Finding:
    evidence = _common_evidence(records)
    if extra:
        evidence.update(extra)
    return Finding(severity=severity, title=title, why_it_matters=why, evidence=evidence, next_step=next_step, confidence=confidence, score=score, tags=tags)


def detect_external_connections(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_ip and not is_private_ip(r.dst_ip) and not is_probably_noise_record(r)]
    external = Counter(r.dst_ip for r in filtered)
    if not external:
        return []
    top_dest, count = external.most_common(1)[0]
    sample = [r for r in filtered if r.dst_ip == top_dest][:5]
    return [_make_finding(
        severity="info",
        title="External network communication detected",
        why="Shows outbound traffic leaving the local/private network after noisy local services were filtered out.",
        records=sample,
        next_step="Review the top external IPs and correlate with DNS, TLS SNI, proxy logs, or EDR telemetry.",
        confidence=0.45,
        score=min(40, count),
        tags=["external", "network"],
        extra={
            "top_external_destinations": [
                {"destination": ip, "count": cnt, "ioc": enrich_indicator(ip, "ip")}
                for ip, cnt in external.most_common(top_n)
            ]
        },
    )]


def detect_uncommon_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [
        r for r in records
        if r.dst_port is not None and r.dst_port not in COMMON_PORTS and r.dst_port < 49152
        and not is_probably_noise_record(r) and r.dst_ip and not is_private_ip(r.dst_ip)
    ]
    ports = Counter(r.dst_port for r in filtered)
    uncommon = [(p, c) for p, c in ports.most_common() if c >= 3][:top_n]
    if not uncommon:
        return []
    target_port = uncommon[0][0]
    sample = [r for r in filtered if r.dst_port == target_port][:5]
    return [_make_finding(
        "medium",
        "Repeated traffic to uncommon destination service ports",
        "Repeated external traffic to non-standard service ports can indicate custom services, tunnels, malware C2, or shadow IT.",
        sample,
        "Check the destination IPs behind these ports and validate whether the service is expected in the environment.",
        confidence=0.66,
        score=45,
        tags=["port-anomaly", "network"],
        extra={"ports": [{"port": p, "count": c} for p, c in uncommon]},
    )]


def detect_known_suspicious_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_port in SUSPICIOUS_PORTS and not is_probably_noise_record(r)]
    suspicious = Counter(r.dst_port for r in filtered)
    if not suspicious:
        return []
    port = suspicious.most_common(1)[0][0]
    sample = [r for r in filtered if r.dst_port == port][:5]
    return [_make_finding(
        "high",
        "Traffic seen on ports commonly abused by tools or backdoors",
        "These ports are often associated with tunnels, remote shells, and non-standard admin channels.",
        sample,
        "Pivot to flows and identify which host initiated the traffic and whether the service is authorized.",
        confidence=0.82,
        score=72,
        tags=["suspicious-port", "c2"],
        extra={"ports": [{"port": p, "count": c} for p, c in suspicious.most_common(top_n)]},
    )]


def detect_dns_volume(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dns_query and not domain_is_known_benign(r.dns_query)]
    dns = Counter(r.dns_query for r in filtered)
    noisy = [(d, c) for d, c in dns.most_common(top_n) if c >= 10]
    if not noisy:
        return []
    domain = noisy[0][0]
    sample = [r for r in filtered if r.dns_query == domain][:5]
    return [_make_finding(
        "low",
        "High-volume DNS query activity",
        "Could be normal application behavior, but can also indicate beaconing or DNS-based data staging.",
        sample,
        "Review repeated domains and confirm whether the volume aligns with expected software or browser behavior.",
        confidence=0.5,
        score=30,
        tags=["dns-volume"],
        extra={"domains": [{"domain": d, "count": c, "ioc": enrich_indicator(d, "domain")} for d, c in noisy]},
    )]


def detect_suspicious_dns_patterns(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    filtered = [r for r in records if r.dns_query and not domain_is_known_benign(r.dns_query)]
    dns = Counter(r.dns_query for r in filtered)
    suspicious_domains: list[tuple[str, int, int]] = []
    for domain, count in dns.items():
        first_label = domain.split(".")[0] if "." in domain else domain
        score = 0
        if len(first_label) >= 25:
            score += 1
        if sum(ch.isdigit() for ch in first_label) >= 8:
            score += 1
        if any(k in domain.lower() for k in DNS_TUNNEL_KEYWORDS):
            score += 1
        if len(set(first_label)) >= 15:
            score += 1
        if score >= 2 and count >= 3:
            suspicious_domains.append((domain, count, score))
    for domain, count, score in suspicious_domains[:top_n]:
        sample = [r for r in filtered if r.dns_query == domain][:5]
        findings.append(_make_finding(
            "high" if score >= 3 else "medium",
            "Suspicious DNS naming pattern detected",
            "Long, high-entropy, or patterned labels may indicate DNS tunneling, staging, or beaconing.",
            sample,
            "Inspect full query sequences, NXDOMAIN rate, and related destinations to confirm whether this is tunneling or unusual software behavior.",
            confidence=min(0.9, 0.45 + (score * 0.12)),
            score=55 + score * 8,
            tags=["dns", "tunneling-candidate"],
            extra={"domain": domain, "query_count": count, "pattern_score": score, "ioc": enrich_indicator(domain, "domain")},
        ))
    return findings


def detect_http_interesting(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if (r.http_host or r.http_uri) and not is_probably_noise_record(r)]
    if not filtered:
        return []
    interesting = [r for r in filtered if (r.http_uri or "").lower().startswith(HIGH_RISK_HTTP_PATHS) or (r.http_method in {"POST", "PUT", "DELETE"})]
    if not interesting:
        return []
    focus = interesting[: min(top_n, len(interesting))]
    return [_make_finding(
        "medium",
        "Interesting HTTP request patterns identified",
        "Administrative paths, API-heavy traffic, and state-changing methods can be useful triage pivots for suspicious web behavior.",
        focus,
        "Validate the destination host, request path, and user agent against expected browsing or application patterns.",
        confidence=0.62,
        score=46,
        tags=["http", "web"],
        extra={
            "requests": [
                {
                    "host": r.http_host,
                    "uri": r.http_uri,
                    "method": r.http_method,
                    "user_agent": r.http_user_agent,
                    "ioc": enrich_indicator(r.http_host, "domain") if r.http_host else None,
                }
                for r in focus
            ]
        },
    )]


def detect_beaconing(records: list[PacketRecord]) -> list[Finding]:
    findings: list[Finding] = []
    buckets: dict[tuple[str, str, int | None, str], list[float]] = defaultdict(list)
    record_map: dict[tuple[str, str, int | None, str], list[PacketRecord]] = defaultdict(list)
    for r in records:
        if not r.src_ip or not r.dst_ip or is_private_ip(r.dst_ip) or is_probably_noise_record(r):
            continue
        key = (r.src_ip, r.dst_ip, r.dst_port, r.protocol)
        try:
            ts = _parse_ts(r.timestamp).timestamp()
        except Exception:
            continue
        buckets[key].append(ts)
        record_map[key].append(r)
    for key, times in buckets.items():
        if len(times) < 8:
            continue
        times.sort()
        deltas = [round(times[i] - times[i - 1], 2) for i in range(1, len(times))]
        if len(deltas) < 7:
            continue
        avg = statistics.mean(deltas)
        stdev = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        if avg < 5 or stdev > max(2.0, avg * 0.20):
            continue
        src, dst, port, proto = key
        sample = sorted(record_map[key], key=lambda r: r.timestamp)[:5]
        findings.append(_make_finding(
            severity="high" if avg >= 15 and len(times) >= 10 else "medium",
            title="Possible beaconing pattern detected",
            why="Regular repeated outbound communication to the same external destination can indicate automated check-ins or command-and-control traffic.",
            records=sample,
            next_step="Pivot on the source host in EDR, review process lineage, and check whether this destination appears in DNS, proxy, or firewall logs.",
            confidence=min(0.92, 0.55 + (len(times) / 40.0)),
            score=min(90, 50 + len(times)),
            tags=["beaconing", "c2"],
            extra={
                "destination": f"{dst}:{port}" if port is not None else dst,
                "protocol": proto,
                "events": len(times),
                "average_interval_seconds": round(avg, 2),
                "interval_stdev_seconds": round(stdev, 2),
                "ioc": enrich_indicator(dst, "ip"),
            },
        ))
    return findings


def detect_large_data_transfer(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    byte_count: dict[tuple[str, str], int] = defaultdict(int)
    rec_map: dict[tuple[str, str], list[PacketRecord]] = defaultdict(list)
    for r in records:
        if r.src_ip and r.dst_ip and not is_probably_noise_record(r):
            byte_count[(r.src_ip, r.dst_ip)] += r.length
            rec_map[(r.src_ip, r.dst_ip)].append(r)
    heavy = sorted(byte_count.items(), key=lambda x: x[1], reverse=True)[:top_n]
    suspicious = [x for x in heavy if x[1] >= 500000 and not is_private_ip(x[0][1])]
    if not suspicious:
        return []
    (src, dst), total = suspicious[0]
    sample = sorted(rec_map[(src, dst)], key=lambda r: r.timestamp)[:5]
    return [_make_finding(
        "medium",
        "Large outbound data transfer observed",
        "Large transfers to external destinations may indicate downloads, uploads, backups, or possible exfiltration depending on business context.",
        sample,
        "Validate whether each destination is sanctioned and whether the transfer volume aligns with expected application behavior.",
        confidence=0.68,
        score=58,
        tags=["transfer", "exfiltration-candidate"],
        extra={"flows": [{"source": s, "destination": d, "bytes": b, "ioc": enrich_indicator(d, "ip")} for (s, d), b in suspicious]},
    )]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.title, json.dumps(finding.evidence, sort_keys=True, default=str))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def correlate_multi_signal(findings: list[Finding]) -> list[Finding]:
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        host = finding.evidence.get("source_host")
        if host:
            by_host[host].append(finding)
    correlated: list[Finding] = []
    for host, host_findings in by_host.items():
        if len(host_findings) < 2:
            continue
        tags = sorted({tag for f in host_findings for tag in f.tags})
        score = min(95, sum(f.score for f in host_findings) // len(host_findings) + 20)
        severity = "high" if score >= 75 else "medium"
        correlated.append(Finding(
            severity=severity,
            title="Multi-signal activity concentrated on one host",
            why_it_matters="A host that shows multiple independent signals is more suspicious than isolated single heuristics.",
            evidence={
                "source_host": host,
                "signals": [{"title": f.title, "severity": f.severity, "score": f.score} for f in host_findings],
                "signal_count": len(host_findings),
                "combined_tags": tags,
            },
            next_step="Open the per-host investigation view and validate whether the combined DNS, web, and network behavior maps to one process or user session.",
            confidence=min(0.95, 0.5 + len(host_findings) * 0.12),
            score=score,
            tags=["correlation", "host"],
        ))
    return correlated


def run_detections(records: list[PacketRecord], mode: str) -> list[Finding]:
    findings: list[Finding] = []
    if mode == "quick":
        findings.extend(detect_beaconing(records))
        findings.extend(detect_known_suspicious_ports(records))
        findings.extend(detect_external_connections(records, top_n=5))
    elif mode == "hunt":
        findings.extend(detect_external_connections(records))
        findings.extend(detect_uncommon_ports(records))
        findings.extend(detect_beaconing(records))
        findings.extend(detect_known_suspicious_ports(records))
        findings.extend(detect_large_data_transfer(records))
        findings.extend(detect_dns_volume(records))
        findings.extend(detect_suspicious_dns_patterns(records))
        findings.extend(detect_http_interesting(records))
    elif mode == "web":
        findings.extend(detect_http_interesting(records))
        findings.extend(detect_external_connections(records))
        findings.extend(detect_beaconing(records))
    elif mode == "dns":
        findings.extend(detect_dns_volume(records))
        findings.extend(detect_suspicious_dns_patterns(records))
    findings = deduplicate_findings(findings)
    findings.extend(correlate_multi_signal(findings))
    findings = deduplicate_findings(findings)
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 0), f.score, f.confidence), reverse=True)
    return findings
