#!/usr/bin/env python3
# ============================================================
# SOC PCAP Analysis Tool
# Copyright (c) 2026 Jimmy Meot
# All rights reserved.
#
# Unauthorized copying, redistribution, modification, resale,
# reverse engineering for redistribution, or reuse of this
# source code in whole or in part is prohibited without
# explicit written permission from the author.
# ============================================================

"""
SOC PCAP Triage - CLI + Local Dashboard

Run as a normal CLI analyzer:
    python3 soc_pcap_triage.py capture.pcap
    python3 soc_pcap_triage.py capture.pcap --export-json report.json

Run as a local dashboard:
    python3 soc_pcap_triage.py

Dependencies:
    pip install flask scapy reportlab
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import tempfile
import threading
import webbrowser
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from io import BytesIO
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw  # type: ignore


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

SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 5555, 6666, 6667, 9001, 9002, 1080, 8081, 8444,
}

DNS_TUNNEL_KEYWORDS = {
    "base64", "txt", "cdn", "data", "api", "cache", "cloud", "dns"
}

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


@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    dns_query: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    tls_sni: str | None = None


@dataclass
class Finding:
    severity: str
    title: str
    why_it_matters: str
    evidence: dict[str, Any]
    next_step: str


DASHBOARD_HTML = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC PCAP Triage Dashboard</title>
  <style>
    :root {{
      --bg:#0f172a;
      --panel:#111827;
      --panel-2:#1f2937;
      --muted:#94a3b8;
      --text:#e5e7eb;
      --accent:#38bdf8;
      --border:#334155;
      --red1:#7f1d1d;
      --red2:#dc2626;
      --blue1:#0f2d5c;
      --blue2:#0b1f44;
    }}

    * {{ box-sizing:border-box; }}

    body {{
      margin:0;
      font-family:Arial,sans-serif;
      background:linear-gradient(180deg,#020617 0%,#0f172a 100%);
      color:var(--text);
    }}

    .container {{
      max-width:1400px;
      margin:0 auto;
      padding:24px;
    }}

    .hero,.card,.finding {{
      background:rgba(15,23,42,.92);
      border:1px solid var(--border);
      border-radius:22px;
      box-shadow:0 8px 24px rgba(0,0,0,.18);
    }}

    .hero {{
      padding:28px;
      margin-bottom:22px;
    }}

    .hero-top {{
      display:flex;
      justify-content:space-between;
      gap:16px;
      flex-wrap:wrap;
      align-items:end;
    }}

    .eyebrow {{
      display:inline-block;
      background:rgba(56,189,248,.12);
      color:#7dd3fc;
      border:1px solid rgba(56,189,248,.2);
      padding:8px 12px;
      border-radius:999px;
      font-size:13px;
      margin-bottom:12px;
    }}

    h1 {{
      margin:0 0 8px 0;
      font-size:34px;
      line-height:1.15;
    }}

    h3 {{ margin-top:0; }}

    .sub {{
      color:var(--muted);
      max-width:760px;
      line-height:1.55;
    }}

    .hero-actions,.tabs,.toolbar,.meta-row {{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
    }}

    button,.button-like,select,input[type="text"] {{
      border:1px solid var(--border);
      background:#0b1220;
      color:var(--text);
      border-radius:14px;
      padding:12px 16px;
      transition:.2s ease;
      font-weight:600;
    }}

    input[type="file"] {{
      color:var(--text);
      font-weight:600;
    }}

    button:hover,.button-like:hover {{
      border-color:#475569;
      transform:translateY(-1px);
      cursor:pointer;
    }}

    .primary {{
      background:linear-gradient(135deg,#0284c7,#0ea5e9);
      border-color:transparent;
      color:white;
    }}

    .summary-btn {{
      background:linear-gradient(135deg,var(--red1),var(--red2));
      border-color:transparent;
      color:white;
    }}

    .summary-btn:hover {{
      filter:brightness(1.05);
      border-color:transparent;
    }}

    .chip {{
      background:rgba(255,255,255,.04);
      border:1px solid var(--border);
      color:#cbd5e1;
      padding:8px 12px;
      border-radius:999px;
      font-size:13px;
    }}

    .stats {{
      display:grid;
      grid-template-columns:repeat(5,minmax(0,1fr));
      gap:16px;
      margin-bottom:22px;
    }}

    .card {{ padding:18px; }}

    .card-title {{
      font-size:13px;
      color:var(--muted);
      margin-bottom:10px;
    }}

    .card-value {{
      font-size:28px;
      font-weight:700;
      margin-bottom:6px;
    }}

    .card-sub {{
      font-size:12px;
      color:var(--muted);
    }}

    .main-grid {{
      display:grid;
      grid-template-columns:1.4fr .9fr;
      gap:18px;
      margin-bottom:22px;
    }}

    .risk-box,.health-box,.evidence,.flow-row,.row {{
      background:#0b1220;
      border:1px solid var(--border);
      border-radius:16px;
      padding:14px;
    }}

    .bar {{
      width:100%;
      height:12px;
      background:#111827;
      border-radius:999px;
      overflow:hidden;
      border:1px solid var(--border);
    }}

    .bar-fill {{
      height:100%;
      background:linear-gradient(90deg,#38bdf8,#facc15,#f97316,#ef4444);
      width:0;
      transition:width .4s ease;
    }}

    .health-label,.muted,.card-title {{ color:var(--muted); }}

    .health-value {{
      font-size:22px;
      font-weight:700;
      word-break:break-word;
    }}

    .tab-btn.active {{
      background:#1e293b;
      border-color:#475569;
    }}

    .tab-panel {{ display:none; }}
    .tab-panel.active {{ display:block; }}

    .finding {{
      padding:18px;
      margin-bottom:14px;
    }}

    .finding-top {{
      display:flex;
      align-items:center;
      gap:12px;
      margin-bottom:10px;
      flex-wrap:wrap;
    }}

    .badge {{
      display:inline-block;
      border-radius:999px;
      padding:6px 10px;
      font-size:12px;
      font-weight:700;
      text-transform:uppercase;
    }}

    .sev-critical {{ background:rgba(239,68,68,.12); color:#fca5a5; border:1px solid rgba(239,68,68,.25); }}
    .sev-high {{ background:rgba(249,115,22,.12); color:#fdba74; border:1px solid rgba(249,115,22,.25); }}
    .sev-medium {{ background:rgba(245,158,11,.12); color:#fcd34d; border:1px solid rgba(245,158,11,.25); }}
    .sev-low {{ background:rgba(34,197,94,.12); color:#86efac; border:1px solid rgba(34,197,94,.25); }}
    .sev-info {{ background:rgba(59,130,246,.12); color:#93c5fd; border:1px solid rgba(59,130,246,.25); }}

    .finding-title {{
      font-size:18px;
      font-weight:700;
    }}

    .finding-text {{
      color:#cbd5e1;
      font-size:14px;
      line-height:1.55;
      margin-bottom:12px;
    }}

    pre {{
      margin:0;
      white-space:pre-wrap;
      word-break:break-word;
      color:#dbeafe;
      font-size:12px;
      line-height:1.6;
    }}

    .section-grid {{
      display:grid;
      grid-template-columns:repeat(3,minmax(0,1fr));
      gap:16px;
    }}

    .list-card .row {{
      display:flex;
      justify-content:space-between;
      gap:12px;
      font-size:14px;
      margin-bottom:10px;
    }}

    .left {{
      color:#cbd5e1;
      word-break:break-word;
    }}

    .right {{
      font-weight:700;
      white-space:nowrap;
    }}

    .flow-row {{
      display:flex;
      justify-content:space-between;
      gap:12px;
      align-items:center;
      margin-bottom:10px;
      flex-wrap:wrap;
    }}

    .status {{
      margin-top:12px;
      color:#93c5fd;
      font-size:14px;
    }}

    .loader {{
      display:none;
      margin-top:14px;
    }}

    .loader.active {{ display:block; }}

    .formal-split {{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:18px;
      margin-top:16px;
    }}

    .formal-panel {{
      background:#0b1220;
      border:1px solid #24364f;
      border-radius:16px;
      padding:18px;
    }}

    .formal-panel-title {{
      font-size:16px;
      font-weight:700;
      color:#f8fafc;
      margin-bottom:14px;
      padding-bottom:10px;
      border-bottom:1px solid #22324d;
      letter-spacing:0.2px;
    }}

    .formal-list {{
      display:flex;
      flex-direction:column;
      gap:10px;
    }}

    .formal-list-item {{
      position:relative;
      padding:10px 12px 10px 18px;
      border-radius:10px;
      background:rgba(255,255,255,.02);
      color:#dbe4f0;
      line-height:1.5;
      border-left:3px solid #3b82f6;
    }}

    .formal-list-item::before {{
      content:"";
      position:absolute;
      left:8px;
      top:17px;
      width:5px;
      height:5px;
      border-radius:50%;
      background:#93c5fd;
    }}

    .ownership-footer {{
      margin-top:18px;
      padding-top:14px;
      border-top:1px solid #22324d;
      font-size:12px;
      color:#7f8ea3;
      line-height:1.5;
    }}

    .ownership-footer .owner {{
      color:#cbd5e1;
    }}

    .summary-modal {{
      display:none;
      position:fixed;
      inset:0;
      background:rgba(2,6,23,.82);
      z-index:9999;
      padding:28px;
      overflow-y:auto;
    }}

    .summary-modal.active {{ display:block; }}

    .summary-modal-content {{
      max-width:1100px;
      margin:0 auto;
      background:linear-gradient(180deg,#081225 0%,#0f172a 100%);
      border:1px solid #1e3a5f;
      border-radius:20px;
      box-shadow:0 20px 60px rgba(0,0,0,.45);
      overflow:hidden;
    }}

    .summary-header {{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:16px;
      padding:24px 28px;
      background:linear-gradient(135deg,var(--blue1),var(--blue2));
      border-bottom:1px solid #1e3a5f;
    }}

    .summary-header h2 {{
      margin:8px 0 0 0;
      color:#ffffff;
      font-size:30px;
    }}

    .summary-badge {{
      display:inline-block;
      background:rgba(220,38,38,.18);
      color:#fecaca;
      border:1px solid rgba(220,38,38,.35);
      padding:6px 10px;
      border-radius:999px;
      font-size:12px;
      font-weight:700;
    }}

    .close-summary-btn {{
      background:var(--red1);
      color:white;
      border:1px solid #b91c1c;
    }}

    .summary-body {{
      padding:28px;
      display:grid;
      gap:18px;
    }}

    .summary-section {{
      background:rgba(15,23,42,.95);
      border:1px solid #22324d;
      border-radius:16px;
      padding:18px;
    }}

    .summary-section h3 {{
      margin:0 0 12px 0;
      color:#f8fafc;
      font-size:18px;
    }}

    .summary-grid {{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:14px;
    }}

    .summary-kv {{
      background:#0b1220;
      border:1px solid #24364f;
      border-radius:12px;
      padding:12px;
    }}

    .summary-kv-label {{
      font-size:12px;
      color:#93c5fd;
      margin-bottom:6px;
    }}

    .summary-kv-value {{
      font-size:20px;
      font-weight:700;
      color:#ffffff;
      word-break:break-word;
    }}

    .summary-list {{
      margin:0;
      padding-left:18px;
      color:#e2e8f0;
      line-height:1.6;
    }}

    .summary-findings {{
      display:grid;
      gap:12px;
    }}

    .summary-finding {{
      background:#0b1220;
      border-left:6px solid #3b82f6;
      border-radius:12px;
      padding:14px;
      border-top:1px solid #24364f;
      border-right:1px solid #24364f;
      border-bottom:1px solid #24364f;
    }}

    .summary-finding.high {{ border-left-color:#dc2626; }}
    .summary-finding.medium {{ border-left-color:#f59e0b; }}
    .summary-finding.low {{ border-left-color:#22c55e; }}
    .summary-finding.info {{ border-left-color:#3b82f6; }}
    .summary-finding.critical {{ border-left-color:#b91c1c; }}

    .summary-finding-title {{
      color:#ffffff;
      font-weight:700;
      margin-bottom:6px;
    }}

    .summary-finding-text {{
      color:#cbd5e1;
      font-size:14px;
      line-height:1.5;
    }}

    .summary-footer {{
      background:#09111f;
      border:1px solid #22324d;
      border-radius:14px;
      padding:16px;
      color:#e2e8f0;
    }}

    .summary-footer strong {{ color:#fca5a5; }}

    @media (max-width:1100px) {{
      .stats {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .main-grid,.section-grid,.formal-split,.summary-grid {{ grid-template-columns:1fr; }}
    }}

    @media (max-width:800px) {{
      .summary-modal {{ padding:16px; }}
      .summary-header {{ flex-direction:column; align-items:flex-start; }}
    }}

    @media (max-width:700px) {{
      .stats {{ grid-template-columns:1fr; }}
      h1 {{ font-size:28px; }}
      .container {{ padding:16px; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="hero-top">
        <div>
          <div class="eyebrow">SOC PCAP Triage Dashboard</div>
          <h1>PCAP ANALYSIS TOOL</h1>
          <div class="sub">Upload a .pcap or .pcapng file and the Python backend will analyze it immediately. Beaconing and noisy local service chatter are filtered more aggressively.</div>
          <div class="meta-row">
            <div class="chip" id="chipFilename">File: none loaded</div>
            <div class="chip" id="chipMode">Mode: hunt</div>
            <div class="chip" id="chipRating">Rating: informational</div>
          </div>
        </div>
        <div class="hero-actions">
          <input id="pcapUpload" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream" />
          <select id="modeUpload">
            <option value="quick">quick</option>
            <option value="hunt" selected>hunt</option>
            <option value="web">web</option>
            <option value="dns">dns</option>
          </select>
          <button class="primary" id="analyzeBtn">Analyze PCAP</button>
          <button id="summaryBtn" class="summary-btn">Analysis Summary</button>
        </div>
      </div>
      <div class="status" id="statusText">Server ready. Choose a PCAP and click Analyze PCAP.</div>
      <div class="loader" id="loader">Analyzing capture, please wait...</div>
    </div>

    <div class="stats">
      <div class="card"><div class="card-title">Packets</div><div class="card-value" id="statPackets">0</div><div class="card-sub" id="statPacketsSub">Top protocol: -</div></div>
      <div class="card"><div class="card-title">Unique destinations</div><div class="card-value" id="statDestinations">0</div><div class="card-sub" id="statDestinationsSub">0 sources</div></div>
      <div class="card"><div class="card-title">Triage score</div><div class="card-value" id="statScore">0</div><div class="card-sub" id="statScoreSub">informational</div></div>
      <div class="card"><div class="card-title">Findings</div><div class="card-value" id="statFindings">0</div><div class="card-sub">Prioritized by severity</div></div>
      <div class="card"><div class="card-title">Capture window</div><div class="card-value" id="statWindow">-</div><div class="card-sub" id="statWindowSub">-</div></div>
    </div>

    <div class="main-grid">
      <div class="card">
        <div class="toolbar">
          <select id="severityFilter">
            <option value="all">all findings</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>

        <div class="risk-box">
          <div style="display:flex;justify-content:space-between;gap:12px;margin-bottom:10px;font-size:14px;">
            <div>Risk rating</div>
            <div id="riskRating" style="font-weight:700;text-transform:uppercase;">INFORMATIONAL</div>
          </div>
          <div class="bar"><div id="riskBar" class="bar-fill"></div></div>
        </div>

        <div class="formal-split">
          <div class="formal-panel">
            <div class="formal-panel-title">Analyst Takeaway</div>
            <div id="takeawayList" class="formal-list"></div>
          </div>

          <div class="formal-panel">
            <div class="formal-panel-title">Recommended Actions</div>
            <div class="formal-list" id="quickActionsList">
              <div class="formal-list-item">Review host activity first for noisy captures.</div>
              <div class="formal-list-item">Validate external IPs under Network and Flows.</div>
              <div class="formal-list-item">Review suspicious DNS names in DNS & TLS.</div>
              <div class="formal-list-item">Open the formal analysis summary report for documentation.</div>
            </div>
          </div>
        </div>

        <div class="ownership-footer">
          <div class="owner">{SCRIPT_PRODUCT}</div>
          <div>{SCRIPT_COPYRIGHT}</div>
          <div>{SCRIPT_NOTICE}</div>
        </div>
      </div>

      <div class="card">
        <h3>Capture health</h3>
        <div class="health-box"><div class="health-label">Average packet size</div><div class="health-value" id="healthAvg">-</div></div>
        <div class="health-box"><div class="health-label">Median packet size</div><div class="health-value" id="healthMedian">-</div></div>
        <div class="health-box"><div class="health-label">Most used destination port</div><div class="health-value" id="healthPort">-</div></div>
        <div class="health-box"><div class="health-label">Most queried DNS</div><div class="health-value" id="healthDns">-</div></div>
      </div>
    </div>

    <div class="tabs">
      <button class="tab-btn active" data-tab="findings">Findings</button>
      <button class="tab-btn" data-tab="hosts">Hosts</button>
      <button class="tab-btn" data-tab="network">Network</button>
      <button class="tab-btn" data-tab="dns">DNS & TLS</button>
      <button class="tab-btn" data-tab="web">Web</button>
      <button class="tab-btn" data-tab="flows">Flows</button>
    </div>

    <div id="panel-findings" class="tab-panel active"><div id="findingsContainer" class="findings"></div></div>
    <div id="panel-hosts" class="tab-panel"><div class="card list-card"><h3>Host summary</h3><div id="hostList"></div></div></div>
    <div id="panel-network" class="tab-panel"><div class="section-grid"><div class="card list-card"><h3>Top source IPs</h3><div id="sourceList"></div></div><div class="card list-card"><h3>Top destination IPs</h3><div id="destinationList"></div></div><div class="card list-card"><h3>Top protocols</h3><div id="protocolList"></div></div></div></div>
    <div id="panel-dns" class="tab-panel"><div class="section-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));"><div class="card list-card"><h3>Top DNS queries</h3><div id="dnsList"></div></div><div class="card list-card"><h3>Top TLS SNI</h3><div id="tlsList"></div></div></div></div>
    <div id="panel-web" class="tab-panel"><div class="section-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));"><div class="card list-card"><h3>Top HTTP requests</h3><div id="httpList"></div></div><div class="card list-card"><h3>Top destination ports</h3><div id="portList"></div></div></div></div>
    <div id="panel-flows" class="tab-panel"><div class="card"><h3>Top conversations</h3><p class="muted">Useful for spotting likely compromised hosts, C2, or bulk transfers.</p><div id="flowsList"></div></div></div>
  </div>

  <div id="summaryModal" class="summary-modal">
    <div class="summary-modal-content">
      <div class="summary-header">
        <div>
          <div class="summary-badge">FORMAL REPORT</div>
          <h2>Analysis Summary</h2>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button id="downloadPdfBtn" class="summary-btn">Download PDF</button>
          <button id="closeSummaryBtn" class="close-summary-btn">Close</button>
        </div>
      </div>
      <div id="summaryBody" class="summary-body"></div>
    </div>
  </div>

  <script>
    let currentReport = {{ summary: {{}}, findings: [], analyst_takeaway: [], host_summary: [] }};
    const el = (id) => document.getElementById(id);
    const safe = (v, fallback='-') => (v === undefined || v === null || v === '' ? fallback : v);
    const formatNumber = (v) => typeof v === 'number' ? v.toLocaleString() : safe(v);
    const findTopName = (arr) => Array.isArray(arr) && arr.length ? arr[0][0] : '-';
    const severityClass = (sev) => `sev-${{sev || 'info'}}`;

    function renderMiniList(containerId, items) {{
      const box = el(containerId);
      box.innerHTML = '';
      if (!items || !items.length) {{
        box.innerHTML = '<div class="formal-list-item">No data available.</div>';
        return;
      }}
      items.forEach(item => {{
        const div = document.createElement('div');
        div.className = 'formal-list-item';
        div.textContent = item;
        box.appendChild(div);
      }});
    }}

    function renderRows(containerId, items) {{
      const box = el(containerId);
      box.innerHTML = '';
      if (!items || !items.length) {{
        box.innerHTML = '<div class="row"><div class="left">No data</div><div class="right">-</div></div>';
        return;
      }}
      items.forEach(item => {{
        const row = document.createElement('div');
        row.className = 'row';
        const left = document.createElement('div');
        left.className = 'left';
        const right = document.createElement('div');
        right.className = 'right';
        if (Array.isArray(item)) {{
          left.textContent = String(item[0]);
          right.textContent = String(item[1]);
        }} else {{
          left.textContent = JSON.stringify(item);
          right.textContent = '';
        }}
        row.appendChild(left);
        row.appendChild(right);
        box.appendChild(row);
      }});
    }}

    function renderHostSummary(items) {{
      const box = el('hostList');
      box.innerHTML = '';
      const filtered = items || [];
      if (!filtered.length) {{
        box.innerHTML = '<div class="row"><div class="left">No matching hosts</div><div class="right">-</div></div>';
        return;
      }}
      filtered.forEach(row => {{
        const wrap = document.createElement('div');
        wrap.className = 'row';
        const external = (row.top_external_destinations || []).map(x => `${{x[0]}} (${{x[1]}})`).join(', ') || 'none';
        const dns = (row.top_dns_queries || []).map(x => `${{x[0]}} (${{x[1]}})`).join(', ') || 'none';
        const ports = (row.top_ports || []).map(x => `${{x[0]}} (${{x[1]}})`).join(', ') || 'none';
        wrap.innerHTML = `<div class="left"><strong>${{row.source_ip}}</strong><br>packets=${{row.packet_count}} | bytes=${{row.bytes_sent}}<br>external=${{external}}<br>dns=${{dns}}<br>ports=${{ports}}</div><div class="right">host</div>`;
        box.appendChild(wrap);
      }});
    }}

    function renderFlows(items) {{
      const box = el('flowsList');
      box.innerHTML = '';
      const filtered = items || [];
      if (!filtered.length) {{
        box.innerHTML = '<div class="flow-row"><div>No matching flows</div><div class="chip">0 packets</div></div>';
        return;
      }}
      filtered.forEach(row => {{
        const wrap = document.createElement('div');
        wrap.className = 'flow-row';
        wrap.innerHTML = `<div><strong>${{safe(row.src_ip)}}</strong> <span class="muted">→</span> <strong>${{safe(row.dst_ip)}}</strong></div><div class="chip">${{safe(row.count, 0)}} packets</div>`;
        box.appendChild(wrap);
      }});
    }}

    function renderFindings(report, severityFilter) {{
      const box = el('findingsContainer');
      box.innerHTML = '';
      const findings = (report.findings || []).filter(
        f => (severityFilter === 'all' || f.severity === severityFilter)
      );
      if (!findings.length) {{
        box.innerHTML = '<div class="finding"><div class="finding-text">No findings match the current filters.</div></div>';
        return;
      }}
      findings.forEach(f => {{
        const item = document.createElement('div');
        item.className = 'finding';
        item.innerHTML = `<div class="finding-top"><span class="badge ${{severityClass(f.severity)}}">${{safe(f.severity, 'info')}}</span><div class="finding-title">${{safe(f.title)}}</div></div><div class="finding-text">${{safe(f.why_it_matters)}}</div><div class="evidence"><div style="font-weight:700;margin-bottom:8px;">Evidence</div><pre>${{JSON.stringify(f.evidence || {{}}, null, 2)}}</pre></div><div class="finding-text"><strong>Next step:</strong> ${{safe(f.next_step)}}</div>`;
        box.appendChild(item);
      }});
    }}

    function buildSummaryHTML(report) {{
      const s = report.summary || {{}};
      const findings = report.findings || [];
      const takeaway = report.analyst_takeaway || [];
      const hosts = report.host_summary || [];

      const topHosts = hosts.slice(0, 5).map(h => `
        <li>
          <strong>${{h.source_ip}}</strong> —
          packets: ${{h.packet_count}},
          bytes: ${{h.bytes_sent}},
          external: ${{(h.top_external_destinations || []).map(x => `${{x[0]}} (${{x[1]}})`).join(', ') || 'none'}}
        </li>
      `).join('');

      const topFindings = findings.slice(0, 8).map(f => `
        <div class="summary-finding ${{f.severity || 'info'}}">
          <div class="summary-finding-title">${{(f.severity || 'info').toUpperCase()}} — ${{f.title || '-'}}</div>
          <div class="summary-finding-text">${{f.why_it_matters || '-'}}</div>
          <div class="summary-finding-text"><strong>Next step:</strong> ${{f.next_step || '-'}}</div>
        </div>
      `).join('');

      const takeawayHtml = takeaway.length
        ? takeaway.map(x => `<li>${{x}}</li>`).join('')
        : '<li>No immediate high-signal takeaway generated.</li>';

      return `
        <div class="summary-section">
          <h3>Executive Overview</h3>
          <div class="summary-grid">
            <div class="summary-kv">
              <div class="summary-kv-label">Analyzed File</div>
              <div class="summary-kv-value">${{report.fileName || '-'}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Mode</div>
              <div class="summary-kv-value">${{s.mode || '-'}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Risk Rating</div>
              <div class="summary-kv-value">${{(s.triage_rating || 'informational').toUpperCase()}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Triage Score</div>
              <div class="summary-kv-value">${{s.triage_score ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Packets</div>
              <div class="summary-kv-value">${{s.packet_count ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Findings</div>
              <div class="summary-kv-value">${{s.finding_count ?? 0}}</div>
            </div>
          </div>
        </div>

        <div class="summary-section">
          <h3>Analyst Takeaway</h3>
          <ul class="summary-list">${{takeawayHtml}}</ul>
        </div>

        <div class="summary-section">
          <h3>Priority Findings</h3>
          <div class="summary-findings">
            ${{topFindings || '<div class="summary-finding info"><div class="summary-finding-title">No notable findings</div><div class="summary-finding-text">No notable findings detected by current heuristics.</div></div>'}}
          </div>
        </div>

        <div class="summary-section">
          <h3>Most Relevant Hosts</h3>
          <ul class="summary-list">
            ${{topHosts || '<li>No host summary available.</li>'}}
          </ul>
        </div>

        <div class="summary-section">
          <h3>Capture Metrics</h3>
          <div class="summary-grid">
            <div class="summary-kv">
              <div class="summary-kv-label">Top Protocol</div>
              <div class="summary-kv-value">${{s.top_protocol || '-'}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Unique Source IPs</div>
              <div class="summary-kv-value">${{s.unique_source_ips ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Unique Destination IPs</div>
              <div class="summary-kv-value">${{s.unique_destination_ips ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Average Packet Size</div>
              <div class="summary-kv-value">${{s.avg_packet_size ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Median Packet Size</div>
              <div class="summary-kv-value">${{s.median_packet_size ?? 0}}</div>
            </div>
            <div class="summary-kv">
              <div class="summary-kv-label">Capture Window</div>
              <div class="summary-kv-value">${{(s.first_seen_utc || '-') + ' to ' + (s.last_seen_utc || '-')}}</div>
            </div>
          </div>
        </div>

        <div class="summary-footer">
          <strong>Recommendation:</strong> Validate the priority findings against EDR, proxy, DNS, and firewall telemetry, then pivot to the most active hosts and suspicious external destinations for confirmation.
          <br><br>
          <span style="font-size:12px;color:#93a4b8;">{SCRIPT_COPYRIGHT} Unauthorized copying or redistribution is prohibited.</span>
        </div>
      `;
    }}

    function openSummaryModal() {{
      const modal = el('summaryModal');
      const body = el('summaryBody');
      body.innerHTML = buildSummaryHTML(currentReport);
      modal.classList.add('active');
    }}

    function closeSummaryModal() {{
      el('summaryModal').classList.remove('active');
    }}

    async function downloadSummaryPdf() {{
      try {{
        const resp = await fetch('/download-summary-pdf', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(currentReport),
        }});

        if (!resp.ok) {{
          const err = await resp.json();
          throw new Error(err.error || 'PDF generation failed');
        }}

        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        const safeName = (currentReport.fileName || 'analysis-summary').replace(/\\.[^/.]+$/, '');
        a.href = url;
        a.download = `${{safeName}}-analysis-summary.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      }} catch (err) {{
        alert(err.message || String(err));
      }}
    }}

    function render(report) {{
      const s = report.summary || {{}};
      const severityFilter = el('severityFilter').value;

      el('chipFilename').textContent = `File: ${{safe(report.fileName, 'none loaded')}}`;
      el('chipMode').textContent = `Mode: ${{safe(s.mode, 'hunt')}}`;
      el('chipRating').textContent = `Rating: ${{safe(s.triage_rating, 'informational')}}`;
      el('statPackets').textContent = formatNumber(s.packet_count || 0);
      el('statPacketsSub').textContent = `Top protocol: ${{safe(s.top_protocol)}}`;
      el('statDestinations').textContent = formatNumber(s.unique_destination_ips || 0);
      el('statDestinationsSub').textContent = `${{formatNumber(s.unique_source_ips || 0)}} sources`;
      el('statScore').textContent = formatNumber(s.triage_score || 0);
      el('statScoreSub').textContent = safe(s.triage_rating, 'informational');
      el('statFindings').textContent = formatNumber(s.finding_count || 0);
      el('statWindow').textContent = s.first_seen_utc && s.last_seen_utc ? 'loaded' : '-';
      el('statWindowSub').textContent = `${{safe(s.first_seen_utc)}} to ${{safe(s.last_seen_utc)}}`;
      el('riskRating').textContent = String(safe(s.triage_rating, 'informational')).toUpperCase();
      el('riskBar').style.width = `${{Math.max(0, Math.min(100, Number(s.triage_score || 0)))}}%`;
      el('healthAvg').textContent = safe(s.avg_packet_size);
      el('healthMedian').textContent = safe(s.median_packet_size);
      el('healthPort').textContent = findTopName(report.top_destination_ports);
      el('healthDns').textContent = findTopName(report.top_dns_queries);

      renderMiniList('takeawayList', report.analyst_takeaway || []);
      renderFindings(report, severityFilter);
      renderHostSummary(report.host_summary || []);
      renderRows('sourceList', report.top_source_ips || []);
      renderRows('destinationList', report.top_destination_ips || []);
      renderRows('protocolList', report.top_protocols || []);
      renderRows('dnsList', report.top_dns_queries || []);
      renderRows('tlsList', report.top_tls_sni || []);
      renderRows('httpList', report.top_http_requests || []);
      renderRows('portList', report.top_destination_ports || []);
      renderFlows(report.top_conversations || []);
    }}

    document.querySelectorAll('.tab-btn').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`panel-${{btn.dataset.tab}}`).classList.add('active');
      }});
    }});

    el('severityFilter').addEventListener('change', () => render(currentReport));

    el('analyzeBtn').addEventListener('click', async () => {{
      const fileInput = el('pcapUpload');
      const mode = el('modeUpload').value;
      const file = fileInput.files && fileInput.files[0];
      if (!file) {{
        alert('Please choose a .pcap or .pcapng file first.');
        return;
      }}

      const form = new FormData();
      form.append('pcap', file);
      form.append('mode', mode);
      el('loader').classList.add('active');
      el('statusText').textContent = `Analyzing ${{file.name}} in ${{mode}} mode...`;

      try {{
        const resp = await fetch('/analyze', {{ method: 'POST', body: form }});
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Analysis failed');
        currentReport = data;
        render(currentReport);
        el('statusText').textContent = `Analysis complete for ${{file.name}}`;
      }} catch (err) {{
        alert(err.message || String(err));
        el('statusText').textContent = 'Analysis failed.';
      }} finally {{
        el('loader').classList.remove('active');
      }}
    }});

    el('summaryBtn').addEventListener('click', () => {{
      openSummaryModal();
    }});

    el('closeSummaryBtn').addEventListener('click', () => {{
      closeSummaryModal();
    }});

    el('downloadPdfBtn').addEventListener('click', () => {{
      downloadSummaryPdf();
    }});

    el('summaryModal').addEventListener('click', (e) => {{
      if (e.target.id === 'summaryModal') {{
        closeSummaryModal();
      }}
    }});

    render(currentReport);
  </script>
</body>
</html>
"""


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
    return port in NOISY_PORTS if port is not None else False


def domain_is_known_benign(domain: str | None) -> bool:
    if not domain:
        return False
    d = domain.lower().strip(".")
    return d in KNOWN_BENIGN_DOMAINS or any(d.endswith("." + base) for base in KNOWN_BENIGN_DOMAINS)


def is_probably_noise_record(record: PacketRecord) -> bool:
    if is_multicast_or_broadcast_ip(record.src_ip) or is_multicast_or_broadcast_ip(record.dst_ip):
        return True
    if is_link_local_ip(record.src_ip) or is_link_local_ip(record.dst_ip):
        return True
    if is_noisy_service_port(record.src_port) or is_noisy_service_port(record.dst_port):
        return True
    if (
        domain_is_known_benign(record.dns_query)
        or domain_is_known_benign(record.tls_sni)
        or domain_is_known_benign(record.http_host)
    ):
        return True
    return False


def get_ips(pkt: Any) -> tuple[str | None, str | None]:
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def get_ports(pkt: Any) -> tuple[int | None, int | None]:
    if pkt.haslayer(TCP):
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None


def guess_protocol(pkt: Any) -> str:
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        ports = {int(pkt[TCP].sport), int(pkt[TCP].dport)}
        if 443 in ports:
            return "TLS/HTTPS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):
        ports = {int(pkt[UDP].sport), int(pkt[UDP].dport)}
        if 53 in ports:
            return "DNS"
        if 123 in ports:
            return "NTP"
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def extract_dns_query(pkt: Any) -> str | None:
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                return qname.decode(errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
        except Exception:
            return None
    return None


def extract_http(pkt: Any) -> tuple[str | None, str | None]:
    if not pkt.haslayer(Raw):
        return None, None
    data = safe_decode(bytes(pkt[Raw].load))
    if not data:
        return None, None
    methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")
    if not data.startswith(methods):
        return None, None
    lines = data.splitlines()
    uri = None
    host = None
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            uri = parts[1]
    for line in lines[1:30]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return host, uri


def extract_tls_sni(pkt: Any) -> str | None:
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return None
    sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    if 443 not in {sport, dport}:
        return None
    text = safe_decode(bytes(pkt[Raw].load))
    if not text:
        return None
    for token in text.replace("\x00", " ").split():
        token = token.strip()
        if "." in token and 4 <= len(token) <= 255:
            if all(ch.isalnum() or ch in "-._" for ch in token):
                if not token.replace(".", "").isdigit():
                    return token
    return None


def packet_to_record(pkt: Any) -> PacketRecord:
    src_ip, dst_ip = get_ips(pkt)
    src_port, dst_port = get_ports(pkt)
    http_host, http_uri = extract_http(pkt)
    return PacketRecord(
        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=guess_protocol(pkt),
        src_port=src_port,
        dst_port=dst_port,
        length=len(pkt),
        dns_query=extract_dns_query(pkt),
        http_host=http_host,
        http_uri=http_uri,
        tls_sni=extract_tls_sni(pkt),
    )


def score_findings(findings: list[Finding]) -> int:
    caps = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    weights = {"critical": 45, "high": 22, "medium": 10, "low": 4, "info": 1}
    counts = Counter(f.severity for f in findings)
    score = 0
    for severity, count in counts.items():
        score += min(count, caps.get(severity, 1)) * weights.get(severity, 0)
    return min(score, 100)


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


def entropy_from_counts(counter: Counter[Any]) -> float:
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


def generate_summary_pdf(report: dict[str, Any]) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.white,
        alignment=TA_LEFT,
        spaceAfter=6,
    )

    badge_style = ParagraphStyle(
        "BadgeStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=colors.HexColor("#FECACA"),
        backColor=colors.HexColor("#7F1D1D"),
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    section_title_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.white,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalBlue",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#E2E8F0"),
        spaceAfter=4,
    )

    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.white,
        spaceAfter=4,
    )

    recommendation_style = ParagraphStyle(
        "RecommendationStyle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#E2E8F0"),
        spaceAfter=0,
    )

    story: list[Any] = []

    header_badge = Table([[Paragraph("FORMAL REPORT", badge_style)]], colWidths=[180 * mm])
    header_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F2D5C")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(header_badge)

    header_title = Table([[Paragraph("Analysis Summary", title_style)]], colWidths=[180 * mm])
    header_title.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F2D5C")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(header_title)
    story.append(Spacer(1, 8))

    summary = report.get("summary", {})
    findings = report.get("findings", [])
    takeaways = report.get("analyst_takeaway", [])
    hosts = report.get("host_summary", [])

    def section_box(title: str, inner_flowables: list[Any]) -> Table:
        rows = [[Paragraph(title, section_title_style)]]
        for item in inner_flowables:
            rows.append([item])
        table = Table(rows, colWidths=[180 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#22324D")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        return table

    def kv_table(items: list[tuple[str, str]]) -> Table:
        rows: list[list[Any]] = []
        for i in range(0, len(items), 2):
            left = items[i]
            right = items[i + 1] if i + 1 < len(items) else ("", "")
            rows.append([
                Paragraph(f"<font color='#93C5FD'>{left[0]}</font><br/><font color='white'><b>{left[1]}</b></font>", normal_style),
                Paragraph(f"<font color='#93C5FD'>{right[0]}</font><br/><font color='white'><b>{right[1]}</b></font>", normal_style),
            ])
        t = Table(rows, colWidths=[88 * mm, 88 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#08111F")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    executive_items = [
        ("Analyzed File", str(report.get("fileName", "-"))),
        ("Mode", str(summary.get("mode", "-"))),
        ("Risk Rating", str(summary.get("triage_rating", "informational")).upper()),
        ("Triage Score", str(summary.get("triage_score", 0))),
        ("Packets", str(summary.get("packet_count", 0))),
        ("Findings", str(summary.get("finding_count", 0))),
    ]
    story.append(section_box("Executive Overview", [kv_table(executive_items)]))
    story.append(Spacer(1, 8))

    takeaway_lines = takeaways or ["No immediate high-signal takeaway generated."]
    story.append(section_box("Analyst Takeaway", [Paragraph(f"• {line}", normal_style) for line in takeaway_lines]))
    story.append(Spacer(1, 8))

    finding_flowables: list[Any] = []
    if findings:
        for f in findings[:8]:
            sev = str(f.get("severity", "info")).lower()
            border_color = {
                "critical": "#B91C1C",
                "high": "#DC2626",
                "medium": "#F59E0B",
                "low": "#22C55E",
                "info": "#3B82F6",
            }.get(sev, "#3B82F6")

            ft = Table([
                [Paragraph(f"<font color='white'><b>{sev.upper()} — {f.get('title', '-')}</b></font>", finding_title_style)],
                [Paragraph(str(f.get("why_it_matters", "-")), normal_style)],
                [Paragraph(f"<font color='#FCA5A5'><b>Next step:</b></font> {f.get('next_step', '-')}", normal_style)],
            ], colWidths=[176 * mm])

            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#08111F")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(border_color)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            finding_flowables.append(ft)
            finding_flowables.append(Spacer(1, 6))
    else:
        finding_flowables.append(Paragraph("No notable findings detected by current heuristics.", normal_style))

    story.append(section_box("Priority Findings", finding_flowables))
    story.append(Spacer(1, 8))

    host_lines = []
    for h in hosts[:5]:
        ext = ", ".join([f"{ip} ({count})" for ip, count in h.get("top_external_destinations", [])]) or "none"
        host_lines.append(
            f"• <b>{h.get('source_ip', '-')}</b> — packets: {h.get('packet_count', 0)}, "
            f"bytes: {h.get('bytes_sent', 0)}, external: {ext}"
        )
    if not host_lines:
        host_lines = ["• No host summary available."]
    story.append(section_box("Most Relevant Hosts", [Paragraph(line, normal_style) for line in host_lines]))
    story.append(Spacer(1, 8))

    metric_items = [
        ("Top Protocol", str(summary.get("top_protocol", "-"))),
        ("Unique Source IPs", str(summary.get("unique_source_ips", 0))),
        ("Unique Destination IPs", str(summary.get("unique_destination_ips", 0))),
        ("Average Packet Size", str(summary.get("avg_packet_size", 0))),
        ("Median Packet Size", str(summary.get("median_packet_size", 0))),
        ("Capture Window", f"{summary.get('first_seen_utc', '-')} to {summary.get('last_seen_utc', '-')}"),
    ]
    story.append(section_box("Capture Metrics", [kv_table(metric_items)]))
    story.append(Spacer(1, 8))

    recommendation = Paragraph(
        "<font color='#FCA5A5'><b>Recommendation:</b></font> "
        "Validate the priority findings against EDR, proxy, DNS, and firewall telemetry, "
        "then pivot to the most active hosts and suspicious external destinations for confirmation.",
        recommendation_style,
    )
    rec_table = Table([[recommendation]], colWidths=[180 * mm])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#09111F")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#22324D")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(rec_table)

    def add_pdf_footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        footer_text = f"{SCRIPT_COPYRIGHT} Unauthorized copying or redistribution is prohibited."
        canvas.drawString(14 * mm, 8 * mm, footer_text)
        canvas.restoreState()

    doc.build(story, onFirstPage=add_pdf_footer, onLaterPages=add_pdf_footer)
    buffer.seek(0)
    return buffer


# -----------------------------
# Detection logic
# -----------------------------

def detect_external_connections(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_ip and not is_private_ip(r.dst_ip) and not is_probably_noise_record(r)]
    external = Counter(r.dst_ip for r in filtered)
    if not external:
        return []
    return [Finding(
        severity="info",
        title="External network communication detected",
        why_it_matters="Shows outbound traffic leaving the local/private network after common noisy traffic was filtered out.",
        evidence={
            "top_external_destinations": external.most_common(top_n),
            "note": "Multicast, link-local, service discovery, and known benign background domains were de-prioritized.",
        },
        next_step="Review the top external IPs and correlate with DNS, TLS SNI, proxy logs, or EDR telemetry.",
    )]


def detect_uncommon_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [
        r for r in records
        if r.dst_port is not None
        and r.dst_port not in COMMON_PORTS
        and r.dst_port < 49152
        and not is_probably_noise_record(r)
        and r.dst_ip
        and not is_private_ip(r.dst_ip)
    ]
    ports = Counter(r.dst_port for r in filtered)
    uncommon = [(p, c) for p, c in ports.most_common() if c >= 3][:top_n]
    if not uncommon:
        return []
    return [Finding(
        severity="medium",
        title="Repeated traffic to uncommon destination service ports",
        why_it_matters="Repeated external traffic to non-standard service ports can indicate custom services, tunnels, malware C2, or shadow IT. High ephemeral client ports were excluded.",
        evidence={"ports": uncommon},
        next_step="Check the destination IPs behind these ports and validate whether the service is expected in the environment.",
    )]


def detect_known_suspicious_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_port in SUSPICIOUS_PORTS and not is_probably_noise_record(r)]
    suspicious = Counter(r.dst_port for r in filtered)
    if not suspicious:
        return []
    return [Finding(
        severity="high",
        title="Traffic seen on ports commonly abused by tools or backdoors",
        why_it_matters="These ports are often associated with tunnels, remote shells, and non-standard admin channels.",
        evidence={"ports": suspicious.most_common(top_n)},
        next_step="Pivot to flows and identify which host initiated the traffic and whether the service is authorized.",
    )]


def detect_dns_volume(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    dns = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    noisy = [(d, c) for d, c in dns.most_common(top_n) if c >= 10]
    if not noisy:
        return []
    return [Finding(
        severity="low",
        title="High-volume DNS query activity",
        why_it_matters="Could be normal application behavior, but can also indicate beaconing or DNS-based data staging. Common benign domains were excluded.",
        evidence={"domains": noisy},
        next_step="Review repeated domains and confirm whether the volume aligns with expected software or browser behavior.",
    )]


def detect_suspicious_dns_patterns(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    suspicious_domains: list[tuple[str, int, int]] = []
    dns = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    for domain, count in dns.items():
        first_label = domain.split(".")[0] if "." in domain else domain
        long_label = len(first_label) >= 25
        many_digits = sum(ch.isdigit() for ch in first_label) >= 8
        keyword_hit = any(k in domain.lower() for k in DNS_TUNNEL_KEYWORDS)
        if (long_label or many_digits or keyword_hit) and count >= 3:
            suspicious_domains.append((domain, count, len(first_label)))
    suspicious_domains.sort(key=lambda x: x[1], reverse=True)
    if not suspicious_domains:
        return []
    return [Finding(
        severity="medium",
        title="DNS queries with suspicious naming patterns",
        why_it_matters="Very long or oddly structured subdomains may indicate encoded data, tracking, or tunneling behavior. Common benign domains were excluded.",
        evidence={"domains": suspicious_domains[:top_n]},
        next_step="Inspect the full DNS request pattern and verify whether the queried domains are legitimate for the environment.",
    )]


def detect_http_interesting(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    hits = []
    keywords = ("login", "admin", "upload", "shell", "api", "token", "auth", "cmd")
    for r in records:
        if is_probably_noise_record(r):
            continue
        if r.http_uri and any(k in r.http_uri.lower() for k in keywords):
            hits.append((r.http_host or "unknown-host", r.http_uri))
    counter = Counter(hits)
    if not counter:
        return []
    return [Finding(
        severity="low",
        title="Interesting HTTP request paths observed",
        why_it_matters="Administrative, upload, auth, or command-like paths can be useful leads during triage when common background noise is filtered out.",
        evidence={"http_paths": [{"host": h, "uri": u, "count": c} for (h, u), c in counter.most_common(top_n)]},
        next_step="Review whether these web requests were expected and identify the originating client.",
    )]


def detect_beaconing(records: list[PacketRecord]) -> list[Finding]:
    buckets: dict[tuple[str, str, int | None, str], list[float]] = defaultdict(list)
    for r in records:
        if not r.src_ip or not r.dst_ip:
            continue
        if is_probably_noise_record(r):
            continue
        if is_private_ip(r.dst_ip) or is_multicast_or_broadcast_ip(r.dst_ip) or is_link_local_ip(r.dst_ip):
            continue
        if r.protocol not in {"TCP", "TLS/HTTPS", "HTTP", "UDP"}:
            continue
        key = (r.src_ip, r.dst_ip, r.dst_port, r.protocol)
        buckets[key].append(datetime.fromisoformat(r.timestamp).timestamp())

    findings: list[Finding] = []
    for (src, dst, port, proto), times in buckets.items():
        if len(times) < 8:
            continue
        times.sort()
        deltas = [round(times[i] - times[i - 1], 2) for i in range(1, len(times))]
        if len(deltas) < 7:
            continue
        try:
            avg = statistics.mean(deltas)
            stdev = statistics.pstdev(deltas)
        except statistics.StatisticsError:
            continue
        if avg < 5:
            continue
        if stdev > max(2.0, avg * 0.20):
            continue
        severity = "high" if avg >= 15 and len(times) >= 10 else "medium"
        findings.append(Finding(
            severity=severity,
            title="Possible beaconing pattern detected",
            why_it_matters="Regular repeated outbound communication to the same external destination can indicate automated check-ins or command-and-control traffic. Short noisy intervals and local chatter were filtered out.",
            evidence={
                "source": src,
                "destination": f"{dst}:{port}" if port is not None else dst,
                "protocol": proto,
                "events": len(times),
                "average_interval_seconds": round(avg, 2),
                "interval_stdev_seconds": round(stdev, 2),
                "confidence": pretty_severity_label(severity),
            },
            next_step="Pivot on the source host in EDR, review process lineage, and check whether this destination appears in DNS, proxy, or firewall logs.",
        ))
    return findings


def detect_large_data_transfer(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    byte_count: dict[tuple[str, str], int] = defaultdict(int)
    for r in records:
        if r.src_ip and r.dst_ip and not is_probably_noise_record(r):
            byte_count[(r.src_ip, r.dst_ip)] += r.length
    heavy = sorted(byte_count.items(), key=lambda x: x[1], reverse=True)[:top_n]
    suspicious = [x for x in heavy if x[1] >= 500000 and not is_private_ip(x[0][1])]
    if not suspicious:
        return []
    return [Finding(
        severity="medium",
        title="Large outbound data transfer observed",
        why_it_matters="Large transfers to external destinations may indicate downloads, uploads, backups, or possible exfiltration depending on business context.",
        evidence={"flows": [{"source": src, "destination": dst, "bytes": total} for (src, dst), total in suspicious]},
        next_step="Validate whether each destination is sanctioned and whether the transfer volume aligns with expected application behavior.",
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


def run_detections(records: list[PacketRecord], mode: str) -> list[Finding]:
    findings: list[Finding] = []
    if mode in {"quick", "hunt", "web"}:
        findings.extend(detect_external_connections(records))
        findings.extend(detect_uncommon_ports(records))
        findings.extend(detect_beaconing(records))
    if mode in {"quick", "hunt"}:
        findings.extend(detect_known_suspicious_ports(records))
        findings.extend(detect_large_data_transfer(records))
    if mode in {"quick", "web", "dns", "hunt"}:
        findings.extend(detect_dns_volume(records))
        findings.extend(detect_suspicious_dns_patterns(records))
        findings.extend(detect_http_interesting(records))
    findings = deduplicate_findings(findings)
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings.sort(key=lambda f: severity_order.get(f.severity, 0), reverse=True)
    return findings


# -----------------------------
# Report building
# -----------------------------

def build_host_summary(records: list[PacketRecord], top_n: int = 10) -> list[dict[str, Any]]:
    host_map: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "external_destinations": Counter(),
        "dns_queries": Counter(),
        "ports": Counter(),
        "bytes_sent": 0,
        "packet_count": 0,
    })
    for r in records:
        if not r.src_ip or is_probably_noise_record(r):
            continue
        host = host_map[r.src_ip]
        host["packet_count"] += 1
        host["bytes_sent"] += r.length
        if r.dst_ip and not is_private_ip(r.dst_ip):
            host["external_destinations"][r.dst_ip] += 1
        if r.dns_query and not domain_is_known_benign(r.dns_query):
            host["dns_queries"][r.dns_query] += 1
        if r.dst_port is not None:
            host["ports"][r.dst_port] += 1
    ranked = []
    for src_ip, info in host_map.items():
        ranked.append({
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "top_external_destinations": info["external_destinations"].most_common(3),
            "top_dns_queries": info["dns_queries"].most_common(3),
            "top_ports": info["ports"].most_common(3),
        })
    ranked.sort(key=lambda x: (len(x["top_external_destinations"]), x["bytes_sent"], x["packet_count"]), reverse=True)
    return ranked[:top_n]


def build_report(records: list[PacketRecord], mode: str, top_n: int, file_name: str | None = None) -> dict[str, Any]:
    proto_counter = Counter(r.protocol for r in records)
    src_counter = Counter(r.src_ip for r in records if r.src_ip)
    dst_counter = Counter(r.dst_ip for r in records if r.dst_ip)
    dns_counter = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    sni_counter = Counter(r.tls_sni for r in records if r.tls_sni and not domain_is_known_benign(r.tls_sni))
    http_counter = Counter(
        f"{r.http_host}{r.http_uri}"
        for r in records
        if r.http_host and r.http_uri and not domain_is_known_benign(r.http_host)
    )
    dst_port_counter = Counter(r.dst_port for r in records if r.dst_port is not None)
    conversations = Counter((r.src_ip, r.dst_ip) for r in records if r.src_ip and r.dst_ip and not is_probably_noise_record(r))
    packet_sizes = Counter(r.length for r in records)
    findings = run_detections(records, mode)
    triage_score = score_findings(findings)
    triage_rating = rating_from_score(triage_score)
    first_seen = records[0].timestamp if records else None
    last_seen = records[-1].timestamp if records else None

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
    }

    analyst_takeaway = []
    if findings:
        analyst_takeaway.append(f"Top concern: {findings[0].title}")
    if dns_counter:
        analyst_takeaway.append(f"Most queried domain: {dns_counter.most_common(1)[0][0]}")
    if sni_counter:
        analyst_takeaway.append(f"Most seen TLS SNI: {sni_counter.most_common(1)[0][0]}")
    if dst_port_counter:
        analyst_takeaway.append(f"Most used destination port: {dst_port_counter.most_common(1)[0][0]}")

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
        "top_conversations": [{"src_ip": src, "dst_ip": dst, "count": count} for (src, dst), count in conversations.most_common(top_n)],
        "host_summary": build_host_summary(records, top_n=top_n),
        "findings": [asdict(f) for f in findings],
        "copyright": SCRIPT_COPYRIGHT,
        "owner": SCRIPT_OWNER,
        "product": SCRIPT_PRODUCT,
    }


# -----------------------------
# CLI output helpers
# -----------------------------

def print_header(title: str) -> None:
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)


def print_summary(summary: dict[str, Any]) -> None:
    print_header("SOC TRIAGE SUMMARY")
    for key, value in summary.items():
        print(f"{key}: {value}")


def print_takeaway(lines: list[str]) -> None:
    print_header("ANALYST TAKEAWAY")
    if not lines:
        print("No immediate high-signal takeaway generated.")
        return
    for line in lines:
        print(f"- {line}")


def print_findings(findings: list[dict[str, Any]]) -> None:
    print_header("PRIORITIZED FINDINGS")
    if not findings:
        print("No notable findings detected by current heuristics.")
        return
    for idx, finding in enumerate(findings, start=1):
        print(f"[{idx}] {finding['severity'].upper()} - {finding['title']}")
        print(f"Why it matters: {finding['why_it_matters']}")
        print(f"Evidence: {json.dumps(finding['evidence'], ensure_ascii=False)}")
        print(f"Next step: {finding['next_step']}")
        print("-" * 90)


def print_top(title: str, items: list[Any]) -> None:
    print_header(title)
    if not items:
        print("No data.")
        return
    for item in items:
        print(item)


def export_csv(records: list[PacketRecord], path: Path) -> None:
    fieldnames = list(asdict(records[0]).keys()) if records else [
        "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
        "length", "dns_query", "http_host", "http_uri", "tls_sni"
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow(asdict(rec))


def export_markdown(report: dict[str, Any], path: Path) -> None:
    lines: list[str] = [f"# {SCRIPT_PRODUCT}", "", f"{SCRIPT_COPYRIGHT}", "", "## Summary"]
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
                f"- Evidence: `{json.dumps(f['evidence'], ensure_ascii=False)}`",
                f"- Next step: {f['next_step']}",
                "",
            ]
    else:
        lines += ["No notable findings detected by current heuristics.", ""]
    lines += ["---", SCRIPT_NOTICE]
    path.write_text("\n".join(lines), encoding="utf-8")


# -----------------------------
# Load/analyze helpers
# -----------------------------

def analyze_pcap_file(pcap_path: str | Path, mode: str = "quick", top_n: int = 10) -> tuple[list[PacketRecord], dict[str, Any]]:
    packets = rdpcap(str(pcap_path))
    records = [packet_to_record(pkt) for pkt in packets]
    records.sort(key=lambda r: r.timestamp)
    report = build_report(records, mode=mode, top_n=top_n, file_name=Path(pcap_path).name)
    return records, report


# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)


@app.get("/")
def dashboard() -> str:
    return render_template_string(DASHBOARD_HTML)


@app.post("/analyze")
def analyze_endpoint():
    uploaded = request.files.get("pcap")
    mode = request.form.get("mode", "hunt")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "No PCAP file uploaded."}), 400
    if mode not in {"quick", "hunt", "web", "dns"}:
        return jsonify({"error": "Invalid mode."}), 400

    suffix = Path(uploaded.filename).suffix or ".pcap"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            uploaded.save(tmp.name)
            tmp_path = tmp.name
        _, report = analyze_pcap_file(tmp_path, mode=mode, top_n=10)
        report["fileName"] = uploaded.filename
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": f"Failed to analyze PCAP: {exc}"}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.post("/download-summary-pdf")
def download_summary_pdf():
    try:
        report = request.get_json(force=True)
        pdf_buffer = generate_summary_pdf(report)
        file_name = str(report.get("fileName", "analysis-summary"))
        safe_name = Path(file_name).stem
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{safe_name}-analysis-summary.pdf",
        )
    except Exception as exc:
        return jsonify({"error": f"Failed to generate PDF: {exc}"}), 500


# -----------------------------
# CLI / launcher
# -----------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOC-friendly PCAP triage tool with local dashboard")
    parser.add_argument("pcap", nargs="?", help="Path to PCAP or PCAPNG file. If omitted, dashboard mode starts.")
    parser.add_argument("--mode", choices=["quick", "hunt", "web", "dns"], default="quick")
    parser.add_argument("--top", type=int, default=10, help="How many top items to display")
    parser.add_argument("--export-json", help="Write full JSON report")
    parser.add_argument("--export-md", help="Write Markdown report")
    parser.add_argument("--export-csv", help="Write normalized packet CSV")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser in dashboard mode")
    return parser.parse_args()


def launch_dashboard(host: str, port: int, open_browser: bool = True) -> None:
    url = f"http://{host}:{port}"
    print(f"[*] Starting SOC PCAP dashboard on {url}")
    print("[*] Open the page, upload a PCAP, and analyze from the UI.")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, debug=False)


def main() -> int:
    args = parse_args()

    if not args.pcap:
        launch_dashboard(args.host, args.port, open_browser=not args.no_browser)
        return 0

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[!] File not found: {pcap_path}")
        return 1

    try:
        records, report = analyze_pcap_file(pcap_path, mode=args.mode, top_n=args.top)
    except Exception as exc:
        print(f"[!] Failed to read PCAP: {exc}")
        return 1

    print(f"[*] Loaded {len(records)} packets from {pcap_path.name}")
    print_summary(report["summary"])
    print_takeaway(report["analyst_takeaway"])
    print_findings(report["findings"])
    print_top("TOP SOURCE IPS", report["top_source_ips"])
    print_top("TOP DESTINATION IPS", report["top_destination_ips"])
    print_top("TOP PROTOCOLS", report["top_protocols"])
    print_top("TOP DESTINATION PORTS", report["top_destination_ports"])
    print_top("TOP DNS QUERIES", report["top_dns_queries"])
    print_top("TOP TLS SNI", report["top_tls_sni"])
    print_top("TOP HTTP REQUESTS", report["top_http_requests"])
    print_top("TOP CONVERSATIONS", report["top_conversations"])

    if args.export_json:
        Path(args.export_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report written to {args.export_json}")

    if args.export_md:
        export_markdown(report, Path(args.export_md))
        print(f"[+] Markdown report written to {args.export_md}")

    if args.export_csv:
        export_csv(records, Path(args.export_csv))
        print(f"[+] CSV written to {args.export_csv}")

    print(f"\n{SCRIPT_COPYRIGHT}")
    print("[+] Triage complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
