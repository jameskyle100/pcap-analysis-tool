from __future__ import annotations

import json
from datetime import datetime, timezone
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
    safe_decode,
)




def _direction_key(record: PacketRecord, client_ip: str | None, client_port: int | None, server_ip: str | None, server_port: int | None) -> str:
    if record.src_ip == client_ip and record.src_port == client_port and record.dst_ip == server_ip and record.dst_port == server_port:
        return "client_to_server"
    return "server_to_client"


def _guess_flow_roles(flow_records: list[PacketRecord]) -> tuple[tuple[str | None, int | None], tuple[str | None, int | None]]:
    if not flow_records:
        return (None, None), (None, None)
    for r in flow_records:
        flags = (r.tcp_flags or "").upper()
        if "S" in flags and "A" not in flags:
            return (r.src_ip, r.src_port), (r.dst_ip, r.dst_port)
    first = flow_records[0]
    if (first.dst_port or 0) in {80, 443, 8080, 8000, 8443}:
        return (first.src_ip, first.src_port), (first.dst_ip, first.dst_port)
    if (first.src_port or 65535) < (first.dst_port or 65535):
        return (first.dst_ip, first.dst_port), (first.src_ip, first.src_port)
    return (first.src_ip, first.src_port), (first.dst_ip, first.dst_port)


def _assemble_stream(records: list[PacketRecord]) -> bytes:
    if not records:
        return b""
    if any(r.tcp_seq is not None for r in records):
        ordered = sorted(records, key=lambda r: ((r.tcp_seq if r.tcp_seq is not None else 10**18), r.timestamp))
        out = bytearray()
        cursor = None
        for r in ordered:
            payload = r.raw_payload or b""
            if not payload:
                continue
            seq = r.tcp_seq if r.tcp_seq is not None else None
            if cursor is None or seq is None:
                out.extend(payload)
                if seq is not None:
                    cursor = seq + len(payload)
                continue
            if seq >= cursor:
                out.extend(payload)
                cursor = seq + len(payload)
                continue
            overlap = cursor - seq
            if overlap < len(payload):
                out.extend(payload[overlap:])
                cursor = seq + len(payload)
        return bytes(out)
    return b"".join(r.raw_payload for r in records if r.raw_payload)


def _find_header_end(data: bytes, start: int = 0) -> int | None:
    idx = data.find(b"\r\n\r\n", start)
    if idx != -1:
        return idx + 4
    idx = data.find(b"\n\n", start)
    if idx != -1:
        return idx + 2
    return None


def _parse_headers(block: bytes) -> tuple[str, dict[str, str]]:
    text = safe_decode(block)
    lines = [line for line in text.replace("\r", "").split("\n") if line]
    if not lines:
        return "", {}
    first = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return first, headers


def _parse_http_transactions_from_stream(client_stream: bytes, server_stream: bytes, flow_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    requests = []
    objects = []
    offset = 0
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
    while offset < len(client_stream):
        start = next((i for i in [client_stream.find(m, offset) for m in methods] if i != -1), -1)
        if start == -1:
            break
        header_end = _find_header_end(client_stream, start)
        if header_end is None:
            break
        first, headers = _parse_headers(client_stream[start:header_end])
        parts = first.split()
        if len(parts) < 2:
            offset = header_end
            continue
        req = {
            "flow_id": flow_id,
            "method": parts[0],
            "uri": parts[1],
            "host": headers.get("host"),
            "user_agent": headers.get("user-agent"),
            "headers": headers,
        }
        requests.append(req)
        body_len = int(headers.get("content-length", "0") or 0) if headers.get("content-length", "0").isdigit() else 0
        offset = header_end + body_len

    responses = []
    offset = 0
    while offset < len(server_stream):
        start = server_stream.find(b"HTTP/", offset)
        if start == -1:
            break
        header_end = _find_header_end(server_stream, start)
        if header_end is None:
            break
        first, headers = _parse_headers(server_stream[start:header_end])
        parts = first.split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        body_len = int(headers.get("content-length", "0") or 0) if headers.get("content-length", "0").isdigit() else 0
        body = server_stream[header_end:header_end + body_len] if body_len else b""
        resp = {
            "status": status,
            "status_line": first,
            "headers": headers,
            "content_type": headers.get("content-type"),
            "content_length": body_len or len(body),
            "body_preview": safe_decode(body[:256]),
        }
        responses.append(resp)
        obj = _extract_object_from_http_body(body, headers, flow_id)
        if obj:
            objects.append(obj)
        offset = header_end + max(body_len, 0)
        if offset <= header_end:
            offset = header_end

    transactions = []
    for idx, req in enumerate(requests):
        txn = dict(req)
        if idx < len(responses):
            txn["response"] = responses[idx]
            txn["status"] = responses[idx].get("status")
            txn["content_type"] = responses[idx].get("content_type")
            txn["response_body_preview"] = responses[idx].get("body_preview")
        transactions.append(txn)
    return transactions, objects


def _extract_object_from_http_body(body: bytes, headers: dict[str, str], flow_id: str) -> dict[str, Any] | None:
    if not body:
        return None
    content_type = (headers.get("content-type") or "").lower()
    detected = None
    ext = None
    if body.startswith(b"MZ"):
        detected, ext = "PE executable", "exe"
    elif body.startswith(b"PK\x03\x04"):
        detected, ext = "ZIP archive", "zip"
    elif body.startswith(b"%PDF"):
        detected, ext = "PDF document", "pdf"
    elif body.startswith(b"\x89PNG\r\n\x1a\n"):
        detected, ext = "PNG image", "png"
    elif body.startswith(b"\xff\xd8\xff"):
        detected, ext = "JPEG image", "jpg"
    elif body.startswith(b"GIF87a") or body.startswith(b"GIF89a"):
        detected, ext = "GIF image", "gif"
    elif "json" in content_type:
        detected, ext = "JSON object", "json"
    elif "html" in content_type:
        detected, ext = "HTML document", "html"
    elif "javascript" in content_type:
        detected, ext = "JavaScript", "js"
    if not detected:
        return None
    return {
        "flow_id": flow_id,
        "detected_type": detected,
        "suggested_extension": ext,
        "content_type": headers.get("content-type"),
        "size_bytes": len(body),
        "preview": safe_decode(body[:256]),
        "sha256_preview_basis": __import__("hashlib").sha256(body).hexdigest(),
    }


def _build_stream_overview(flow_records: list[PacketRecord], client: tuple[str | None, int | None], server: tuple[str | None, int | None]) -> dict[str, Any]:
    c_recs = [r for r in flow_records if _direction_key(r, client[0], client[1], server[0], server[1]) == "client_to_server"]
    s_recs = [r for r in flow_records if _direction_key(r, client[0], client[1], server[0], server[1]) == "server_to_client"]
    c_stream = _assemble_stream(c_recs)
    s_stream = _assemble_stream(s_recs)
    txns, objs = _parse_http_transactions_from_stream(c_stream, s_stream, flow_records[0].flow_id or "flow")
    return {
        "client": {"ip": client[0], "port": client[1], "payload_bytes": len(c_stream), "packet_count": len(c_recs)},
        "server": {"ip": server[0], "port": server[1], "payload_bytes": len(s_stream), "packet_count": len(s_recs)},
        "client_preview": safe_decode(c_stream[:512]),
        "server_preview": safe_decode(s_stream[:512]),
        "http_transactions": txns[:20],
        "extracted_objects": objs[:10],
    }

def build_host_summary(records: list[PacketRecord], top_n: int = 10) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    host_map: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "external_destinations": Counter(),
        "dns_queries": Counter(),
        "ports": Counter(),
        "bytes_sent": 0,
        "bytes_received": 0,
        "packet_count": 0,
        "flows": Counter(),
        "http_requests": Counter(),
        "tls_sni": Counter(),
        "sample_packets": [],
        "related_domains": Counter(),
    })
    for r in records:
        if not r.src_ip or is_probably_noise_record(r):
            continue
        host = host_map[r.src_ip]
        host["packet_count"] += 1
        host["bytes_sent"] += r.length
        if len(host["sample_packets"]) < 8:
            host["sample_packets"].append(packet_record_to_dict(r))
        if r.dst_ip and not is_private_ip(r.dst_ip):
            host["external_destinations"][r.dst_ip] += 1
        if r.dns_query and not domain_is_known_benign(r.dns_query):
            host["dns_queries"][r.dns_query] += 1
            host["related_domains"][r.dns_query] += 1
        if r.tls_sni and not domain_is_known_benign(r.tls_sni):
            host["tls_sni"][r.tls_sni] += 1
            host["related_domains"][r.tls_sni] += 1
        if r.http_host and not domain_is_known_benign(r.http_host):
            host["related_domains"][r.http_host] += 1
        if r.dst_port is not None:
            host["ports"][r.dst_port] += 1
        if r.flow_id:
            host["flows"][r.flow_id] += 1
        if r.http_host or r.http_uri:
            host["http_requests"][f"{r.http_method or 'HTTP'} {r.http_host or ''}{r.http_uri or ''}".strip()] += 1
        if r.dst_ip and host_map.get(r.dst_ip) and r.dst_ip != r.src_ip:
            host_map[r.dst_ip]["bytes_received"] += r.length
    ranked = []
    details = {}
    for src_ip, info in host_map.items():
        details[src_ip] = {
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "bytes_received": info["bytes_received"],
            "top_external_destinations": info["external_destinations"].most_common(10),
            "top_dns_queries": info["dns_queries"].most_common(10),
            "top_ports": info["ports"].most_common(10),
            "top_flows": info["flows"].most_common(10),
            "top_http_requests": info["http_requests"].most_common(10),
            "top_tls_sni": info["tls_sni"].most_common(10),
            "related_domains": info["related_domains"].most_common(10),
            "sample_packets": info["sample_packets"],
        }
        details[src_ip]["narrative"] = host_narrative(details[src_ip])
        ranked.append({
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "top_external_destinations": info["external_destinations"].most_common(3),
            "top_dns_queries": info["dns_queries"].most_common(3),
            "top_ports": info["ports"].most_common(3),
            "top_tls_sni": info["tls_sni"].most_common(3),
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
        "bytes_by_direction": Counter(),
        "http_requests": [],
        "http_responses": [],
        "tls_sni": Counter(),
        "dns_queries": Counter(),
        "records": [],
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
        flow["records"].append(r)
        if r.src_ip and r.dst_ip:
            flow["bytes_by_direction"][f"{r.src_ip}->{r.dst_ip}"] += r.length
        if r.http_method and len(flow["http_requests"]) < 10:
            flow["http_requests"].append(packet_record_to_dict(r))
        if r.http_status is not None and len(flow["http_responses"]) < 10:
            flow["http_responses"].append(packet_record_to_dict(r))
        if r.tls_sni:
            flow["tls_sni"][r.tls_sni] += 1
        if r.dns_query:
            flow["dns_queries"][r.dns_query] += 1
        if len(flow["sample_packets"]) < 10:
            flow["sample_packets"].append(packet_record_to_dict(r))
    details = {}
    ranked = []
    http_pairs = build_http_pairs(records, top_n=top_n * 4)
    pairs_by_flow = defaultdict(list)
    for pair in http_pairs:
        pairs_by_flow[pair["flow_id"]].append(pair)
    for flow_id, info in flow_map.items():
        ordered_records = sorted(info["records"], key=lambda r: r.timestamp)
        client, server = _guess_flow_roles(ordered_records)
        stream = _build_stream_overview(ordered_records, client, server)
        upload_download = info["bytes_by_direction"].most_common()
        details[flow_id] = {
            "count": info["count"],
            "bytes": info["bytes"],
            "src_ip": info["src_ip"],
            "dst_ip": info["dst_ip"],
            "src_port": info["src_port"],
            "dst_port": info["dst_port"],
            "protocol": info["protocol"],
            "sample_packets": info["sample_packets"],
            "first_seen": min(info["times"]) if info["times"] else None,
            "last_seen": max(info["times"]) if info["times"] else None,
            "upload_download_visibility": upload_download,
            "http_pairs": pairs_by_flow.get(flow_id, [])[:10],
            "top_tls_sni": info["tls_sni"].most_common(10),
            "top_dns_queries": info["dns_queries"].most_common(10),
            "stream_overview": stream,
            "http_transactions": stream.get("http_transactions", []),
            "extracted_objects": stream.get("extracted_objects", []),
        }
        ranked.append({
            "flow_id": flow_id,
            "src_ip": info["src_ip"],
            "dst_ip": info["dst_ip"],
            "src_port": info["src_port"],
            "dst_port": info["dst_port"],
            "protocol": info["protocol"],
            "count": info["count"],
            "bytes": info["bytes"],
            "transactions": len(stream.get("http_transactions", [])),
            "objects": len(stream.get("extracted_objects", [])),
        })
    ranked.sort(key=lambda x: (x["count"], x["bytes"], x.get("transactions", 0)), reverse=True)
    return ranked[:top_n], details


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except Exception:
        return None


def build_timeline(records: list[PacketRecord], findings: list, bucket_minutes: int = 30, top_n: int = 96) -> list[dict[str, Any]]:
    if not records:
        return []
    buckets: dict[str, dict[str, Any]] = {}
    severity_times: list[tuple[datetime, str]] = []
    for finding in findings:
        ev = getattr(finding, 'evidence', {}) or {}
        ts = _parse_ts(ev.get('first_seen') or ev.get('last_seen'))
        if ts:
            severity_times.append((ts, getattr(finding, 'severity', 'info')))
    for r in records:
        ts = _parse_ts(r.timestamp)
        if not ts:
            continue
        minute = (ts.minute // bucket_minutes) * bucket_minutes
        bucket_dt = ts.replace(minute=minute, second=0, microsecond=0)
        key = bucket_dt.isoformat()
        entry = buckets.setdefault(key, {
            'bucket_start': key,
            'packet_count': 0,
            'hosts': Counter(),
            'destinations': Counter(),
            'protocols': Counter(),
            'finding_counts': {'critical':0,'high':0,'medium':0,'low':0,'info':0},
        })
        entry['packet_count'] += 1
        if r.src_ip:
            entry['hosts'][r.src_ip] += 1
        if r.dst_ip:
            entry['destinations'][r.dst_ip] += 1
        entry['protocols'][r.protocol] += 1
    for ts, sev in severity_times:
        minute = (ts.minute // bucket_minutes) * bucket_minutes
        bucket_dt = ts.replace(minute=minute, second=0, microsecond=0)
        key = bucket_dt.isoformat()
        entry = buckets.setdefault(key, {
            'bucket_start': key,
            'packet_count': 0,
            'hosts': Counter(),
            'destinations': Counter(),
            'protocols': Counter(),
            'finding_counts': {'critical':0,'high':0,'medium':0,'low':0,'info':0},
        })
        entry['finding_counts'][sev if sev in entry['finding_counts'] else 'info'] += 1
    ranked=[]
    for key, entry in sorted(buckets.items()):
        ranked.append({
            'bucket_start': key,
            'packet_count': entry['packet_count'],
            'top_host': entry['hosts'].most_common(1)[0][0] if entry['hosts'] else None,
            'top_destination': entry['destinations'].most_common(1)[0][0] if entry['destinations'] else None,
            'top_protocol': entry['protocols'].most_common(1)[0][0] if entry['protocols'] else None,
            'finding_counts': entry['finding_counts'],
        })
    return ranked[:top_n]


def build_http_pairs(records: list[PacketRecord], top_n: int = 20) -> list[dict[str, Any]]:
    pending: dict[str, list[PacketRecord]] = defaultdict(list)
    pairs: list[dict[str, Any]] = []
    for r in records:
        if not r.flow_id:
            continue
        if r.http_method:
            pending[r.flow_id].append(r)
        elif r.http_status is not None and pending.get(r.flow_id):
            req = pending[r.flow_id].pop(0)
            pairs.append({
                'flow_id': r.flow_id,
                'client': req.src_ip,
                'server': req.dst_ip,
                'host': req.http_host,
                'uri': req.http_uri,
                'method': req.http_method,
                'status': r.http_status,
                'request_time': req.timestamp,
                'response_time': r.timestamp,
            })
    return pairs[:top_n]


def host_narrative(detail: dict[str, Any]) -> str:
    dests = [d[0] for d in detail.get('top_external_destinations', [])[:3]]
    dns = [d[0] for d in detail.get('top_dns_queries', [])[:3]]
    ports = [str(p[0]) for p in detail.get('top_ports', [])[:4]]
    findings = detail.get('findings', [])
    pieces = []
    if dests:
        pieces.append(f"Top outbound destinations: {', '.join(dests)}")
    if dns:
        pieces.append(f"DNS lookups: {', '.join(dns)}")
    if ports:
        pieces.append(f"Ports used: {', '.join(ports)}")
    if findings:
        pieces.append(f"Signals tied to this host: {', '.join(findings[:4])}")
    return '. '.join(pieces) or 'Host has limited high-signal context in this capture.'


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
    finding_dicts = [asdict(f) for f in findings]
    # map findings back to host details
    for fd in finding_dicts:
        host = (fd.get('evidence') or {}).get('source_host')
        if host and host in host_details:
            host_details[host].setdefault('findings', []).append(fd.get('title'))
    for host in host_details.values():
        host['narrative'] = host_narrative(host)
    triage_score = score_findings(findings)
    triage_rating = rating_from_score(triage_score)
    first_seen = records[0].timestamp if records else None
    last_seen = records[-1].timestamp if records else None
    packet_sizes = Counter(r.length for r in records)
    suspicious_host = host_summary[0]["source_ip"] if host_summary else None
    timeline = build_timeline(records, findings, bucket_minutes=30, top_n=96)
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
    if finding_dicts:
        analyst_takeaway.append(f"Top concern: {finding_dicts[0]['title']}")
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
        "findings": finding_dicts,
        "sample_packets": [packet_record_to_dict(r) for r in records[:20]],
        "timeline": timeline,
        "http_pairs": build_http_pairs(records, top_n=top_n * 2),
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
