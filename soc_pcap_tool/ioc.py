from __future__ import annotations

import json
import ssl
import tempfile
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

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


def _load_settings() -> dict:
    if not _SETTINGS_PATH.exists():
        return {}
    try:
        data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


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


def _request_json(url: str, headers: dict[str, str], timeout: int = 8) -> dict:
    req = Request(url, headers=headers)
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=timeout, context=ctx) as resp:
        data = resp.read()
    return json.loads(data.decode("utf-8", errors="ignore") or "{}")


def _safe_error(provider: str, err: Exception) -> dict:
    msg = str(err)
    if isinstance(err, HTTPError):
        msg = f"HTTP {err.code}: {err.reason}"
    elif isinstance(err, URLError):
        msg = f"Network error: {getattr(err, 'reason', err)}"
    return {"provider": provider, "ok": False, "error": msg}


def _vt_enrich(indicator: str, kind: str, cfg: dict) -> dict:
    base = (cfg.get("base_url") or "https://www.virustotal.com/api/v3").rstrip("/")
    api_key = cfg.get("api_key", "")
    if kind == "ip":
        path = f"/ip_addresses/{quote(indicator)}"
    elif kind == "domain":
        path = f"/domains/{quote(indicator)}"
    elif kind == "hash":
        path = f"/files/{quote(indicator)}"
    else:
        return {"provider": "virustotal", "ok": False, "error": f"Unsupported VT kind: {kind}"}
    data = _request_json(base + path, {"x-apikey": api_key, "accept": "application/json"})
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    tags = attrs.get("tags", []) or []
    return {
        "provider": "virustotal",
        "ok": True,
        "reputation": attrs.get("reputation"),
        "detection_counts": stats,
        "tags": tags[:15],
        "confidence": attrs.get("popular_threat_classification", {}),
        "first_seen": attrs.get("first_submission_date") or attrs.get("creation_date"),
        "last_seen": attrs.get("last_modification_date") or attrs.get("last_analysis_date"),
        "link": data.get("data", {}).get("links", {}).get("self"),
    }


def _otx_enrich(indicator: str, kind: str, cfg: dict) -> dict:
    base = (cfg.get("base_url") or "https://otx.alienvault.com/api/v1").rstrip("/")
    api_key = cfg.get("api_key", "")
    if kind == "ip":
        path = f"/indicators/IPv4/{quote(indicator)}/general"
    elif kind == "domain":
        path = f"/indicators/domain/{quote(indicator)}/general"
    elif kind == "hash":
        path = f"/indicators/file/{quote(indicator)}/general"
    else:
        return {"provider": "otx", "ok": False, "error": f"Unsupported OTX kind: {kind}"}
    data = _request_json(base + path, {"X-OTX-API-KEY": api_key, "accept": "application/json"})
    pulses = data.get("pulse_info", {}).get("pulses", []) or []
    return {
        "provider": "otx",
        "ok": True,
        "reputation": data.get("reputation") or data.get("validation"),
        "detection_counts": {"pulse_count": len(pulses)},
        "tags": [t for p in pulses[:10] for t in p.get("tags", [])][:15],
        "pulse_matches": [{"name": p.get("name"), "created": p.get("created")} for p in pulses[:10]],
        "confidence": {"pulse_count": len(pulses), "indicator": data.get("indicator")},
        "first_seen": data.get("first_seen") or (pulses[0].get("created") if pulses else None),
        "last_seen": data.get("last_seen") or (pulses[-1].get("modified") if pulses else None),
    }


def _abuseipdb_enrich(indicator: str, kind: str, cfg: dict) -> dict:
    if kind != "ip":
        return {"provider": "abuseipdb", "ok": False, "error": "AbuseIPDB supports IP enrichment only."}
    base = (cfg.get("base_url") or "https://api.abuseipdb.com/api/v2").rstrip("/")
    api_key = cfg.get("api_key", "")
    url = f"{base}/check?ipAddress={quote(indicator)}&maxAgeInDays=90&verbose"
    data = _request_json(url, {"Key": api_key, "Accept": "application/json"})
    result = data.get("data", {}) or {}
    return {
        "provider": "abuseipdb",
        "ok": True,
        "reputation": result.get("abuseConfidenceScore"),
        "detection_counts": {"reports": result.get("totalReports", 0)},
        "tags": result.get("usageType") and [result.get("usageType")] or [],
        "abuse_score": result.get("abuseConfidenceScore"),
        "confidence": {"country": result.get("countryCode"), "isp": result.get("isp")},
        "first_seen": None,
        "last_seen": result.get("lastReportedAt"),
    }


def enrich_indicator_live(indicator: str | None, kind: str) -> dict:
    base = enrich_indicator(indicator, kind)
    if not indicator:
        return base
    settings = _load_settings()
    providers = []
    if settings.get("virustotal", {}).get("enabled") and settings.get("virustotal", {}).get("api_key"):
        try:
            providers.append(_vt_enrich(indicator, kind, settings["virustotal"]))
        except Exception as err:
            providers.append(_safe_error("virustotal", err))
    if settings.get("otx", {}).get("enabled") and settings.get("otx", {}).get("api_key"):
        try:
            providers.append(_otx_enrich(indicator, kind, settings["otx"]))
        except Exception as err:
            providers.append(_safe_error("otx", err))
    if settings.get("abuseipdb", {}).get("enabled") and settings.get("abuseipdb", {}).get("api_key"):
        try:
            providers.append(_abuseipdb_enrich(indicator, kind, settings["abuseipdb"]))
        except Exception as err:
            providers.append(_safe_error("abuseipdb", err))
    merged_tags = []
    pulse_matches = []
    detection_counts = {}
    first_seen = None
    last_seen = None
    reputation = None
    abuse_score = None
    for entry in providers:
        if not entry.get("ok"):
            continue
        for k, v in (entry.get("detection_counts") or {}).items():
            if isinstance(v, int):
                detection_counts[k] = detection_counts.get(k, 0) + v
            else:
                detection_counts[k] = v
        merged_tags.extend(entry.get("tags") or [])
        pulse_matches.extend(entry.get("pulse_matches") or [])
        if reputation is None and entry.get("reputation") is not None:
            reputation = entry.get("reputation")
        if abuse_score is None and entry.get("abuse_score") is not None:
            abuse_score = entry.get("abuse_score")
        first_seen = first_seen or entry.get("first_seen")
        last_seen = entry.get("last_seen") or last_seen
    return {
        **base,
        "providers": providers,
        "reputation": reputation,
        "detection_counts": detection_counts,
        "tags": sorted({t for t in merged_tags if t})[:20],
        "pulse_matches": pulse_matches[:10],
        "confidence": abuse_score if abuse_score is not None else reputation,
        "abuse_score": abuse_score,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }
