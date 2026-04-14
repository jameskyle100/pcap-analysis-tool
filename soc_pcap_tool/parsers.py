from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import MAX_PACKET_READ
from .models import PacketRecord
from .utils import safe_decode


def _scapy():
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw  # type: ignore
    return {
        "PcapReader": PcapReader, "IP": IP, "IPv6": IPv6, "TCP": TCP, "UDP": UDP,
        "ICMP": ICMP, "DNS": DNS, "DNSQR": DNSQR, "DNSRR": DNSRR, "Raw": Raw,
    }


def get_ips(pkt: Any, layers: dict[str, Any]) -> tuple[str | None, str | None]:
    if pkt.haslayer(layers["IP"]):
        return pkt[layers["IP"]].src, pkt[layers["IP"]].dst
    if pkt.haslayer(layers["IPv6"]):
        return pkt[layers["IPv6"]].src, pkt[layers["IPv6"]].dst
    return None, None


def get_ports(pkt: Any, layers: dict[str, Any]) -> tuple[int | None, int | None]:
    if pkt.haslayer(layers["TCP"]):
        return int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)
    if pkt.haslayer(layers["UDP"]):
        return int(pkt[layers["UDP"]].sport), int(pkt[layers["UDP"]].dport)
    return None, None


def guess_protocol(pkt: Any, layers: dict[str, Any]) -> str:
    if pkt.haslayer(layers["DNS"]):
        return "DNS"
    if pkt.haslayer(layers["TCP"]):
        ports = {int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)}
        if 443 in ports:
            return "TLS/HTTPS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        return "TCP"
    if pkt.haslayer(layers["UDP"]):
        ports = {int(pkt[layers["UDP"]].sport), int(pkt[layers["UDP"]].dport)}
        if 53 in ports:
            return "DNS"
        if 123 in ports:
            return "NTP"
        return "UDP"
    if pkt.haslayer(layers["ICMP"]):
        return "ICMP"
    return "OTHER"


def extract_dns(pkt: Any, layers: dict[str, Any]) -> dict[str, Any]:
    if not pkt.haslayer(layers["DNS"]):
        return {}
    try:
        dns = pkt[layers["DNS"]]
        qname = None
        if pkt.haslayer(layers["DNSQR"]):
            q = pkt[layers["DNSQR"]].qname
            qname = q.decode(errors="ignore").rstrip(".") if isinstance(q, bytes) else str(q).rstrip(".")
        answers: list[str] = []
        an = getattr(dns, "an", None)
        if an:
            current = an
            for _ in range(getattr(dns, "ancount", 0) or 0):
                rrname = getattr(current, "rdata", None)
                if isinstance(rrname, bytes):
                    answers.append(rrname.decode(errors="ignore").rstrip("."))
                elif rrname is not None:
                    answers.append(str(rrname).rstrip("."))
                current = getattr(current, "payload", None)
                if not current:
                    break
        return {
            "dns_id": int(getattr(dns, "id", 0)),
            "dns_query": qname,
            "dns_is_response": bool(getattr(dns, "qr", 0)),
            "dns_rcode": int(getattr(dns, "rcode", 0)),
            "dns_answers": answers,
        }
    except Exception:
        return {}


def parse_http_payload(data: str) -> dict[str, Any]:
    lines = [line for line in data.splitlines() if line]
    if not lines:
        return {}
    first = lines[0]
    result: dict[str, Any] = {}
    methods = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH")
    if any(first.startswith(m + " ") for m in methods):
        parts = first.split()
        result["http_method"] = parts[0]
        if len(parts) >= 2:
            result["http_uri"] = parts[1]
    elif first.startswith("HTTP/"):
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            result["http_status"] = int(parts[1])
    else:
        return {}
    for line in lines[1:40]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "host":
            result["http_host"] = value
        elif key == "user-agent":
            result["http_user_agent"] = value[:160]
    return result


def extract_http(pkt: Any, layers: dict[str, Any]) -> dict[str, Any]:
    if not pkt.haslayer(layers["Raw"]):
        return {}
    data = safe_decode(bytes(pkt[layers["Raw"]].load))
    if not data:
        return {}
    return parse_http_payload(data)


def extract_tls_sni_from_payload(payload: bytes) -> tuple[str | None, bool]:
    try:
        if len(payload) < 11 or payload[0] != 0x16:
            return None, False
        record_len = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + record_len or payload[5] != 0x01:
            return None, False
        hs_len = int.from_bytes(payload[6:9], "big")
        body = payload[9:9 + hs_len]
        if len(body) < 42:
            return None, True
        offset = 34
        session_len = body[offset]
        offset += 1 + session_len
        cipher_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2 + cipher_len
        comp_len = body[offset]
        offset += 1 + comp_len
        ext_total_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        end = offset + ext_total_len
        while offset + 4 <= len(body) and offset < end:
            ext_type = int.from_bytes(body[offset:offset + 2], "big")
            ext_len = int.from_bytes(body[offset + 2:offset + 4], "big")
            ext_data = body[offset + 4:offset + 4 + ext_len]
            if ext_type == 0x0000 and len(ext_data) >= 5:
                list_len = int.from_bytes(ext_data[0:2], "big")
                cursor = 2
                while cursor + 3 <= min(len(ext_data), 2 + list_len):
                    name_type = ext_data[cursor]
                    name_len = int.from_bytes(ext_data[cursor + 1:cursor + 3], "big")
                    cursor += 3
                    if name_type == 0 and cursor + name_len <= len(ext_data):
                        return ext_data[cursor:cursor + name_len].decode("utf-8", errors="ignore"), True
                    cursor += name_len
            offset += 4 + ext_len
    except Exception:
        return None, False
    return None, False


def extract_tls_sni(pkt: Any, layers: dict[str, Any]) -> tuple[str | None, bool]:
    if not pkt.haslayer(layers["TCP"]) or not pkt.haslayer(layers["Raw"]):
        return None, False
    sport, dport = int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)
    if 443 not in {sport, dport}:
        return None, False
    return extract_tls_sni_from_payload(bytes(pkt[layers["Raw"]].load))


def get_flow_id(src_ip: str | None, src_port: int | None, dst_ip: str | None, dst_port: int | None, protocol: str) -> str | None:
    if not src_ip or not dst_ip:
        return None
    a = (src_ip, src_port or 0)
    b = (dst_ip, dst_port or 0)
    low, high = sorted([a, b], key=lambda x: (str(x[0]), int(x[1] or 0)))
    return f"{protocol}|{low[0]}:{low[1]}|{high[0]}:{high[1]}"


def packet_to_record(pkt: Any, layers: dict[str, Any]) -> PacketRecord:
    src_ip, dst_ip = get_ips(pkt, layers)
    src_port, dst_port = get_ports(pkt, layers)
    protocol = guess_protocol(pkt, layers)
    http = extract_http(pkt, layers)
    dns = extract_dns(pkt, layers)
    tls_sni, tls_hello = extract_tls_sni(pkt, layers)
    payload_preview = None
    if pkt.haslayer(layers["Raw"]):
        payload_preview = safe_decode(bytes(pkt[layers["Raw"]].load))[:160]
    tcp_flags = None
    if pkt.haslayer(layers["TCP"]):
        tcp_flags = str(pkt[layers["TCP"]].flags)
    return PacketRecord(
        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=len(pkt),
        flow_id=get_flow_id(src_ip, src_port, dst_ip, dst_port, protocol),
        direction="outbound" if src_ip and dst_ip else None,
        tcp_flags=tcp_flags,
        tls_sni=tls_sni,
        tls_is_client_hello=tls_hello,
        payload_preview=payload_preview,
        **dns,
        **http,
    )


def analyze_pcap_file(pcap_path: str | Path, mode: str = "quick", top_n: int = 10):
    from .reporting import build_report
    layers = _scapy()
    records: list[PacketRecord] = []
    with layers["PcapReader"](str(pcap_path)) as packets:
        for idx, pkt in enumerate(packets):
            if idx >= MAX_PACKET_READ:
                break
            try:
                records.append(packet_to_record(pkt, layers))
            except Exception:
                continue
    records.sort(key=lambda r: r.timestamp)
    report = build_report(records, mode=mode, top_n=top_n, file_name=Path(pcap_path).name)
    if len(records) >= MAX_PACKET_READ:
        report.setdefault("warnings", []).append(f"Packet read cap reached at {MAX_PACKET_READ:,} packets.")
    return records, report
