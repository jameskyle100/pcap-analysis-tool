from __future__ import annotations

SCRIPT_OWNER = "Jimmy Meot"
SCRIPT_PRODUCT = "SOC PCAP Analysis Tool"
SCRIPT_COPYRIGHT = "© 2026 Jimmy Meot. All rights reserved."
SCRIPT_NOTICE = (
    "Unauthorized copying, redistribution, modification, resale, or reuse of this script "
    "without written permission from the author is prohibited."
)

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 389, 443, 445, 464, 465, 514, 515, 587, 636, 993,
    995, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985, 5986, 6379,
    8080, 8443,
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 6667, 9001, 9002, 1080, 8081, 8444}

DNS_TUNNEL_KEYWORDS = {"base64", "txt", "cdn", "data", "api", "cache", "cloud", "dns"}

KNOWN_BENIGN_DOMAINS = {
    "settings-win.data.microsoft.com",
    "graph.microsoft.com",
    "login.live.com",
    "ocsp.digicert.com",
    "ctldl.windowsupdate.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
}

NOISY_PORTS = {53, 67, 68, 123, 137, 138, 139, 1900, 5353, 5355}
PRIVATE_MULTICAST_PREFIXES = ("224.", "239.", "ff02:", "ff05:")

ALLOWED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}
DEFAULT_TOP_N = 10
DEFAULT_MODE = 'quick'
MAX_UPLOAD_MB = 128
MAX_PACKET_READ = 250000
