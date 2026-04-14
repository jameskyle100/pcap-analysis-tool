from __future__ import annotations

import csv
import io
import math
from collections import Counter
from ipaddress import ip_address, ip_network

from .allowlist import load_allowlist
from .constants import KNOWN_BENIGN_DOMAINS, PRIVATE_MULTICAST_PREFIXES
from .models import Finding, PacketRecord


def safe_decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            pass
    return ""


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def is_multicast_or_broadcast_ip(value: str | None) -> bool:
    if not value:
        return False
    if value == "255.255.255.255":
        return True
    if any(value.lower().startswith(prefix) for prefix in PRIVATE_MULTICAST_PREFIXES):
        return True
    try:
        return ip_address(value).is_multicast
    except ValueError:
        return False


def is_link_local_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_link_local
    except ValueError:
        return value.lower().startswith("fe80:")


def is_noisy_service_port(port: int | None) -> bool:
    allowlist = load_allowlist()
    noisy = set(allowlist.get("noisy_ports", []))
    return port in noisy if port is not None else False


def domain_is_known_benign(domain: str | None) -> bool:
    if not domain:
        return False
    d = domain.lower().strip(".")
    allowlist = load_allowlist()
    trusted = set(KNOWN_BENIGN_DOMAINS) | set(allowlist.get("trusted_domains", []))
    return d in trusted or any(d.endswith("." + base) for base in trusted)


def ip_in_internal_subnet(value: str | None) -> bool:
    if not value:
        return False
    allowlist = load_allowlist()
    try:
        ip = ip_address(value)
        return any(ip in ip_network(net) for net in allowlist.get("internal_subnets", []))
    except ValueError:
        return False


def is_probably_noise_record(record: PacketRecord) -> bool:
    if is_multicast_or_broadcast_ip(record.src_ip) or is_multicast_or_broadcast_ip(record.dst_ip):
        return True
    if is_link_local_ip(record.src_ip) or is_link_local_ip(record.dst_ip):
        return True
    if is_noisy_service_port(record.src_port) or is_noisy_service_port(record.dst_port):
        return True
    if domain_is_known_benign(record.dns_query) or domain_is_known_benign(record.tls_sni) or domain_is_known_benign(record.http_host):
        return True
    return False


def score_findings(findings: list[Finding]) -> int:
    total = 0.0
    for f in findings:
        base = {"critical": 40, "high": 22, "medium": 12, "low": 5, "info": 1}.get(f.severity, 0)
        confidence = max(0.2, min(1.0, f.confidence or 0.5))
        multiplier = 1.0 + min(0.75, (f.score or 0) / 100.0)
        total += base * confidence * multiplier
    return min(100, round(total))


def rating_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "informational"


def entropy_from_counts(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            result -= p * math.log2(p)
    return round(result, 4)


def pretty_severity_label(sev: str) -> str:
    labels = {
        "critical": "high confidence",
        "high": "elevated",
        "medium": "review",
        "low": "low confidence",
        "info": "context",
    }
    return labels.get(sev, sev)


def packet_record_to_dict(record: PacketRecord) -> dict:
    return {
        "timestamp": record.timestamp,
        "src_ip": record.src_ip,
        "dst_ip": record.dst_ip,
        "protocol": record.protocol,
        "src_port": record.src_port,
        "dst_port": record.dst_port,
        "length": record.length,
        "flow_id": record.flow_id,
        "direction": record.direction,
        "dns_query": record.dns_query,
        "dns_answers": record.dns_answers,
        "dns_rcode": record.dns_rcode,
        "http_method": record.http_method,
        "http_host": record.http_host,
        "http_uri": record.http_uri,
        "http_status": record.http_status,
        "tls_sni": record.tls_sni,
        "tcp_flags": record.tcp_flags,
        "payload_preview": record.payload_preview,
        "payload_length": record.payload_length,
        "tcp_seq": record.tcp_seq,
        "tcp_ack": record.tcp_ack,
    }


def findings_to_csv(findings: list[dict]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "title", "confidence", "score", "next_step", "tags"])
    for finding in findings:
        writer.writerow([
            finding.get("severity"),
            finding.get("title"),
            finding.get("confidence"),
            finding.get("score"),
            finding.get("next_step"),
            ", ".join(finding.get("tags", [])),
        ])
    return buffer.getvalue().encode("utf-8")
