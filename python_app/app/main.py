import os
import tempfile
from typing import Optional, List, Dict
from fastapi import FastAPI, UploadFile, File, Response, Query
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from app.types import AppType, PacketAction
from app.rule_manager import RuleManager
from app.dpi_engine import DpiEngine

app = FastAPI(
    title="DPI Engine - Network Packet Analyzer",
    description="Layer 7 Deep Packet Inspection engine with TLS SNI extraction, HTTP parsing, and firewall filtering."
)

rule_manager = RuleManager()
engine = DpiEngine(rule_manager=rule_manager)


# ============================================================================
# Dashboard HTML
# ============================================================================
@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>DPI Engine Dashboard</h1>"


# ============================================================================
# Analysis & Filtering Endpoints
# ============================================================================
@app.post("/api/analyze")
def analyze_pcap(file: UploadFile = File(...)):
    """
    Receives an uploaded PCAP file, runs Deep Packet Inspection, and returns
    inspection statistics, application distribution, terminal report, and tracked flows.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    try:
        stats = engine.process_pcap(tmp_path)
        report = engine.generate_report()
        connections = [c.to_dict() for c in engine.tracker.list_connections()]

        return {
            "filename": file.filename,
            "stats": stats.to_dict(),
            "report": report,
            "connections": connections,
            "rules": rule_manager.to_dict()
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/api/analyze/sample")
def analyze_sample_pcap():
    """
    Loads and inspects the built-in test_dpi.pcap file directly for instant demo.
    """
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_dpi.pcap")
    if not os.path.exists(sample_path):
        sample_path = "test_dpi.pcap"

    if not os.path.exists(sample_path):
        return {"error": "Sample test_dpi.pcap file not found"}

    stats = engine.process_pcap(sample_path)
    report = engine.generate_report()
    connections = [c.to_dict() for c in engine.tracker.list_connections()]

    return {
        "filename": "test_dpi.pcap (Sample)",
        "stats": stats.to_dict(),
        "report": report,
        "connections": connections,
        "rules": rule_manager.to_dict()
    }


@app.post("/api/filter")
def filter_pcap(file: UploadFile = File(...)):
    """
    Inspects and filters the uploaded PCAP based on active firewall rules,
    and returns the filtered PCAP file as a download.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as in_tmp:
        in_tmp.write(file.file.read())
        in_path = in_tmp.name

    out_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    out_path = out_tmp.name
    out_tmp.close()

    try:
        engine.process_pcap(in_path, output_pcap_path=out_path)
        return FileResponse(
            out_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=f"filtered_{file.filename}"
        )
    finally:
        if os.path.exists(in_path):
            os.remove(in_path)


@app.get("/api/stats")
def get_stats():
    return engine.stats.to_dict()


@app.get("/api/connections")
def get_connections():
    return [c.to_dict() for c in engine.tracker.list_connections()]


@app.post("/api/reset")
def reset_engine():
    engine.reset()
    return {"status": "engine reset"}


# ============================================================================
# Firewall Rule Management Endpoints
# ============================================================================
class AppRuleRequest(BaseModel):
    app: str


class DomainRuleRequest(BaseModel):
    domain: str


class IpRuleRequest(BaseModel):
    ip: str


class PortRuleRequest(BaseModel):
    port: int


@app.get("/api/rules")
def get_rules():
    return rule_manager.to_dict()


@app.post("/api/rules/app")
def add_app_rule(req: AppRuleRequest):
    try:
        app_type = AppType(req.app.upper())
        rule_manager.block_app(app_type)
        return {"status": f"blocked {app_type.value}", "rules": rule_manager.to_dict()}
    except ValueError:
        return {"error": f"Invalid AppType: {req.app}"}


@app.delete("/api/rules/app")
def remove_app_rule(app: str = Query(...)):
    try:
        app_type = AppType(app.upper())
        rule_manager.unblock_app(app_type)
        return {"status": f"unblocked {app_type.value}", "rules": rule_manager.to_dict()}
    except ValueError:
        return {"error": f"Invalid AppType: {app}"}


@app.post("/api/rules/domain")
def add_domain_rule(req: DomainRuleRequest):
    rule_manager.block_domain(req.domain)
    return {"status": f"blocked domain {req.domain}", "rules": rule_manager.to_dict()}


@app.delete("/api/rules/domain")
def remove_domain_rule(domain: str = Query(...)):
    rule_manager.unblock_domain(domain)
    return {"status": f"unblocked domain {domain}", "rules": rule_manager.to_dict()}


@app.post("/api/rules/ip")
def add_ip_rule(req: IpRuleRequest):
    rule_manager.block_ip(req.ip)
    return {"status": f"blocked IP {req.ip}", "rules": rule_manager.to_dict()}


@app.delete("/api/rules/ip")
def remove_ip_rule(ip: str = Query(...)):
    rule_manager.unblock_ip(ip)
    return {"status": f"unblocked IP {ip}", "rules": rule_manager.to_dict()}


@app.post("/api/rules/port")
def add_port_rule(req: PortRuleRequest):
    rule_manager.block_port(req.port)
    return {"status": f"blocked port {req.port}", "rules": rule_manager.to_dict()}


@app.delete("/api/rules/port")
def remove_port_rule(port: int = Query(...)):
    rule_manager.unblock_port(port)
    return {"status": f"unblocked port {port}", "rules": rule_manager.to_dict()}
