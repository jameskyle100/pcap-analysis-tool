from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    flow_id: str | None = None
    direction: str | None = None
    tcp_flags: str | None = None
    dns_id: int | None = None
    dns_query: str | None = None
    dns_is_response: bool = False
    dns_rcode: int | None = None
    dns_answers: list[str] = field(default_factory=list)
    http_method: str | None = None
    http_status: int | None = None
    http_host: str | None = None
    http_uri: str | None = None
    http_user_agent: str | None = None
    tls_sni: str | None = None
    tls_is_client_hello: bool = False
    payload_preview: str | None = None
    payload_length: int = 0
    raw_payload: bytes = b""
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_stream_role: str | None = None


@dataclass
class Finding:
    severity: str
    title: str
    why_it_matters: str
    evidence: dict[str, Any]
    next_step: str
    confidence: float = 0.0
    score: int = 0
    tags: list[str] = field(default_factory=list)
