from __future__ import annotations

from ipaddress import ip_address
import json
import tempfile
from pathlib import Path

from .allowlist import load_allowlist


PRIVATE_NET_LABEL = "internal"
_SETTINGS_PATH = Path(tempfile.gettempdir()) / "soc_pcap_tool_integrations.json"


def _configured_sources() -> list[str]:
    if not _SETTINGS_PATH.exists():
        return []
    try:
        data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
        return [name for name, values in data.items() if isinstance(values, dict) and values.get("enabled") and values.get("api_key")]
    except Exception:
        return []


def _domain_matches(value: str, domains: list[str]) -> bool:
    value = value.lower().strip(".")
    return any(value == d or value.endswith("." + d) for d in domains)


def enrich_indicator(indicator: str | None, kind: str) -> dict:
    if not indicator:
        return {"kind": kind, "indicator": indicator, "status": "unknown", "source": "local-hook"}

    allowlist = load_allowlist()
    if kind == "domain" and _domain_matches(indicator, allowlist.get("trusted_domains", [])):
        return {"kind": kind, "indicator": indicator, "status": "trusted", "source": "allowlist"}

    if kind == "ip":
        try:
            ip = ip_address(indicator)
            if ip.is_private:
                return {"kind": kind, "indicator": indicator, "status": PRIVATE_NET_LABEL, "source": "ip-classification"}
        except ValueError:
            pass

    configured = _configured_sources()
    return {
        "kind": kind,
        "indicator": indicator,
        "status": "unknown",
        "source": "ioc-hook",
        "configured_sources": configured,
        "note": (
            f"Live enrichment can be wired to: {', '.join(configured)}"
            if configured
            else "Hook ready for VirusTotal / OTX / AbuseIPDB / internal TI integration."
        ),
    }
