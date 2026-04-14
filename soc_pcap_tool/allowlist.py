from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DEFAULT_ALLOWLIST = {
    "internal_subnets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "trusted_domains": [
        "microsoft.com",
        "windowsupdate.com",
        "digicert.com",
    ],
    "approved_services": [],
    "noisy_ports": [53, 67, 68, 123, 137, 138, 139, 1900, 5353, 5355],
}


@lru_cache(maxsize=1)
def load_allowlist() -> dict:
    path = Path(__file__).with_name("allowlist.json")
    if not path.exists():
        return DEFAULT_ALLOWLIST.copy()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        merged = DEFAULT_ALLOWLIST.copy()
        merged.update({k: v for k, v in data.items() if isinstance(v, list)})
        return merged
    except Exception:
        return DEFAULT_ALLOWLIST.copy()
