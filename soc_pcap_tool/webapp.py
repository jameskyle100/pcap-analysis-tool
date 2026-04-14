from __future__ import annotations

import hashlib
import io
import json
import logging
import tempfile
import threading
import webbrowser
import zipfile
from pathlib import Path


from flask import Flask, jsonify, render_template, request, send_file

from .constants import ALLOWED_EXTENSIONS, MAX_UPLOAD_MB, SCRIPT_COPYRIGHT, SCRIPT_NOTICE, SCRIPT_PRODUCT
from .parsers import analyze_pcap_file
from .pdf_report import generate_summary_pdf
from .reporting import export_markdown
from .ioc import enrich_indicator_live
from .utils import findings_to_csv

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
log = logging.getLogger(__name__)
_ANALYSIS_CACHE: dict[tuple[str, str], dict] = {}
_SETTINGS_PATH = Path(tempfile.gettempdir()) / "soc_pcap_tool_integrations.json"
_DEFAULT_INTEGRATIONS = {
    "virustotal": {"enabled": False, "api_key": "", "base_url": "https://www.virustotal.com/api/v3"},
    "otx": {"enabled": False, "api_key": "", "base_url": "https://otx.alienvault.com/api/v1"},
    "abuseipdb": {"enabled": False, "api_key": "", "base_url": "https://api.abuseipdb.com/api/v2"},
}


def _load_integrations() -> dict:
    if _SETTINGS_PATH.exists():
        try:
            data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                merged = json.loads(json.dumps(_DEFAULT_INTEGRATIONS))
                for name, values in data.items():
                    if name in merged and isinstance(values, dict):
                        merged[name].update(values)
                return merged
        except Exception:
            log.exception("Failed to load integration settings")
    return json.loads(json.dumps(_DEFAULT_INTEGRATIONS))


def _save_integrations(data: dict) -> dict:
    merged = json.loads(json.dumps(_DEFAULT_INTEGRATIONS))
    for name, values in (data or {}).items():
        if name in merged and isinstance(values, dict):
            merged[name]["enabled"] = bool(values.get("enabled", False))
            merged[name]["api_key"] = str(values.get("api_key", "")).strip()
            merged[name]["base_url"] = str(values.get("base_url", merged[name]["base_url"])).strip() or merged[name]["base_url"]
    _SETTINGS_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def _allowed_file(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXTENSIONS


def _looks_like_pcap(data: bytes) -> bool:
    return data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"))


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@app.get("/")
def dashboard() -> str:
    return render_template("dashboard.html", script_product=SCRIPT_PRODUCT, script_copyright=SCRIPT_COPYRIGHT, script_notice=SCRIPT_NOTICE)


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/settings/integrations")
def get_integrations():
    return jsonify({"integrations": _load_integrations()})


@app.post("/settings/integrations")
def save_integrations():
    payload = request.get_json(silent=True) or {}
    integrations = payload.get("integrations", payload)
    if not isinstance(integrations, dict):
        return jsonify({"error": "Invalid integrations payload."}), 400
    saved = _save_integrations(integrations)
    masked = {}
    for name, values in saved.items():
        masked[name] = {
            **values,
            "api_key_configured": bool(values.get("api_key")),
            "api_key": values.get("api_key", ""),
        }
    return jsonify({"ok": True, "integrations": masked})




@app.post("/ioc/enrich")
def enrich_ioc():
    payload = request.get_json(silent=True) or {}
    indicator = str(payload.get("indicator") or "").strip()
    kind = str(payload.get("kind") or "").strip().lower()
    if not indicator or kind not in {"ip", "domain", "hash"}:
        return jsonify({"error": "Provide indicator and valid kind (ip, domain, hash)."}), 400
    try:
        return jsonify({"ok": True, "result": enrich_indicator_live(indicator, kind)})
    except Exception as exc:
        log.exception("IOC enrichment failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/analyze")
def analyze_endpoint():
    uploaded = request.files.get("pcap")
    mode = request.form.get("mode", "hunt")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "No PCAP file uploaded."}), 400
    if mode not in {"quick", "hunt", "web", "dns"}:
        return jsonify({"error": "Invalid mode."}), 400
    if not _allowed_file(uploaded.filename):
        return jsonify({"error": "Unsupported file type."}), 400

    raw = uploaded.read()
    uploaded.seek(0)
    if not _looks_like_pcap(raw[:8]):
        return jsonify({"error": "File does not look like a PCAP/PCAPNG capture."}), 400

    cache_key = (_hash_bytes(raw), mode)
    if cache_key in _ANALYSIS_CACHE:
        report = _ANALYSIS_CACHE[cache_key].copy()
        report["fileName"] = uploaded.filename
        report.setdefault("warnings", []).append("Served from in-memory cache for identical file + mode.")
        return jsonify(report)

    suffix = Path(uploaded.filename).suffix or ".pcap"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name
        _, report = analyze_pcap_file(tmp_path, mode=mode, top_n=10)
        report["fileName"] = uploaded.filename
        _ANALYSIS_CACHE[cache_key] = report.copy()
        return jsonify(report)
    except Exception:
        log.exception("Failed to analyze PCAP")
        return jsonify({"error": "Failed to analyze PCAP."}), 500
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass


@app.post("/download-summary-pdf")
def download_summary_pdf():
    try:
        report = request.get_json(silent=True) or {}
        pdf_buffer = generate_summary_pdf(report)
        file_name = str(report.get("fileName", "analysis-summary"))
        safe_name = Path(file_name).stem
        return send_file(pdf_buffer, mimetype="application/pdf", as_attachment=True, download_name=f"{safe_name}-analysis-summary.pdf")
    except Exception:
        log.exception("Failed to generate PDF")
        return jsonify({"error": "Failed to generate PDF."}), 500


@app.post("/export-json")
def export_json():
    report = request.get_json(silent=True) or {}
    payload = io.BytesIO(json.dumps(report, indent=2).encode("utf-8"))
    safe_name = Path(str(report.get("fileName", "analysis"))).stem
    return send_file(payload, mimetype="application/json", as_attachment=True, download_name=f"{safe_name}-evidence.json")


@app.post("/export-csv")
def export_csv():
    report = request.get_json(silent=True) or {}
    payload = io.BytesIO(findings_to_csv(report.get("findings", [])))
    safe_name = Path(str(report.get("fileName", "analysis"))).stem
    return send_file(payload, mimetype="text/csv", as_attachment=True, download_name=f"{safe_name}-findings.csv")


@app.post("/export-markdown")
def export_md():
    report = request.get_json(silent=True) or {}
    safe_name = Path(str(report.get("fileName", "analysis"))).stem
    temp = Path(tempfile.gettempdir()) / f"{safe_name}-analysis.md"
    export_markdown(report, SCRIPT_NOTICE, SCRIPT_PRODUCT, SCRIPT_COPYRIGHT, temp)
    return send_file(temp, mimetype="text/markdown", as_attachment=True, download_name=temp.name)


@app.post("/export-handoff")
def export_handoff():
    report = request.get_json(silent=True) or {}
    safe_name = Path(str(report.get("fileName", "analysis"))).stem
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{safe_name}-evidence.json", json.dumps(report, indent=2))
        zf.writestr(f"{safe_name}-findings.csv", findings_to_csv(report.get("findings", [])).decode("utf-8"))
        md_buf = Path(tempfile.gettempdir()) / f"{safe_name}-analysis.md"
        export_markdown(report, SCRIPT_NOTICE, SCRIPT_PRODUCT, SCRIPT_COPYRIGHT, md_buf)
        zf.writestr(md_buf.name, md_buf.read_text(encoding="utf-8"))
    memory.seek(0)
    return send_file(memory, mimetype="application/zip", as_attachment=True, download_name=f"{safe_name}-analyst-handoff.zip")


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    url = f"http://{host}:{port}"
    print(f"[*] Starting SOC PCAP dashboard on {url}")
    print("[*] Open the page, upload a PCAP, and analyze from the UI.")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
