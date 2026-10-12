from pathlib import Path
from datetime import datetime, timezone
import asyncio, json
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List
from .scanner import demo_networks, live_scan
from .audit import audit_networks
from .storage import init_db, save_assessment, list_assessments, get_assessment
from .reports import make_pdf

app = FastAPI(
    title="WiFiSentinel AI",
    version="2.0.0",
    description="Real-time defensive wireless security assessment and threat detection dashboard"
)
STATIC = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")

class ManualNetwork(BaseModel):
    ssid: str = Field(min_length=1, max_length=128)
    security: str = Field(default="Unknown", max_length=64)
    signal: Optional[int] = Field(default=None, ge=0, le=100)
    channel: Optional[int] = Field(default=None, ge=1, le=233)
    cipher: Optional[str] = Field(default="None", max_length=32)

class ManualAudit(BaseModel):
    networks: List[ManualNetwork] = Field(min_length=1, max_length=100)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return (STATIC / "index.html").read_text(encoding="utf-8")

def summarize(networks, interface=None):
    findings = [f for n in networks for f in n.get("findings", [])]
    conn_net = next((n for n in networks if n.get("is_connected")), None)
    high_crit = sum(f["severity"] in ("High", "Critical") for f in findings)
    crit_count = sum(f["severity"] == "Critical" for f in findings)
    high_count = sum(f["severity"] == "High" for f in findings)
    med_count = sum(f["severity"] == "Medium" for f in findings)
    low_count = sum(f["severity"] == "Low" for f in findings)
    info_count = sum(f["severity"] == "Info" for f in findings)
    avg_risk = round(sum(n.get("risk_score", 0) for n in networks) / len(networks), 1) if networks else 0.0
    max_risk = max([n.get("risk_score", 0) for n in networks], default=0)

    # Active system connection security posture
    system_posture = "NO_WIFI"
    if interface and interface.get("is_connected"):
        conn_risk = conn_net.get("risk_score", 0) if conn_net else 0
        if conn_risk >= 30:
            system_posture = "VULNERABLE"
        elif conn_risk >= 10:
            system_posture = "MODERATE"
        else:
            system_posture = "SECURE"

    return {
        "networks": len(networks),
        "findings": len(findings),
        "critical": crit_count,
        "high": high_count,
        "high_critical": high_crit,
        "medium": med_count,
        "low": low_count,
        "info": info_count,
        "average_risk": avg_risk,
        "max_risk": max_risk,
        "system_posture": system_posture,
        "connected_network": conn_net.get("ssid") if conn_net else None,
        "interface": interface
    }

def persist(mode, raw_networks, interface=None):
    audited = audit_networks(raw_networks)
    summary = summarize(audited, interface)
    aid = save_assessment(mode, audited, summary)
    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "id": aid,
        "created_at": now_iso,
        "mode": mode,
        "networks": audited,
        "summary": summary,
        "interface": interface,
        "timestamp": now_iso
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "WiFiSentinel AI", "version": "2.0.0"}

@app.post("/api/scan/demo")
def scan_demo():
    demo_data = demo_networks()
    return persist("demo", demo_data, {
        "name": "Wi-Fi (Simulated)",
        "description": "Virtual 802.11ax Security Interface",
        "state": "connected",
        "is_connected": True,
        "connected_ssid": "Executive-WPA3-HQ",
        "connected_bssid": "02:00:00:00:10:04",
        "signal": 94,
        "channel": 48,
        "band": "5 GHz",
        "radio": "802.11ax",
        "security": "WPA3-Personal",
        "cipher": "CCMP"
    })

@app.get("/api/scan/live")
@app.post("/api/scan/live")
def scan_live_endpoint(persist_data: bool = Query(True, alias="persist")):
    try:
        result = live_scan()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    if not result.get("supported"):
        return JSONResponse(status_code=501, content=result)

    if persist_data:
        return persist("live", result["networks"], result.get("interface"))
    else:
        audited = audit_networks(result["networks"])
        summary = summarize(audited, result.get("interface"))
        return {
            "id": None,
            "mode": "live",
            "networks": audited,
            "summary": summary,
            "interface": result.get("interface"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@app.get("/api/scan/stream")
async def scan_stream():
    """Server-Sent Events (SSE) for continuous real-time wireless system scanning."""
    async def event_generator():
        while True:
            try:
                res = await asyncio.to_thread(live_scan)
                if res.get("supported"):
                    audited = audit_networks(res["networks"])
                    summary = summarize(audited, res.get("interface"))
                    payload = {
                        "supported": True,
                        "mode": "live-realtime",
                        "networks": audited,
                        "summary": summary,
                        "interface": res.get("interface"),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                else:
                    yield f"data: {json.dumps({'supported': False, 'message': res.get('message')})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'supported': False, 'message': str(e)})}\n\n"
            await asyncio.sleep(3.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.post("/api/audit/manual")
def audit_manual(payload: ManualAudit):
    raw = [n.model_dump() | {"source": "manual-authorized"} for n in payload.networks]
    return persist("manual", raw)

@app.get("/api/assessments")
def assessments():
    return {"assessments": list_assessments()}

@app.get("/api/assessments/{assessment_id}")
def assessment_detail(assessment_id: int):
    result = get_assessment(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result

@app.get("/api/assessments/{assessment_id}/json")
def assessment_json(assessment_id: int):
    result = get_assessment(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="wifisentinel-assessment-{assessment_id}.json"'})

@app.get("/api/assessments/{assessment_id}/pdf")
def assessment_pdf(assessment_id: int):
    result = get_assessment(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return Response(
        make_pdf(result),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="wifisentinel-assessment-{assessment_id}.pdf"'}
    )
