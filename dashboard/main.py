"""
NANDA Dashboard Service
=======================
Single-page visualization of the NANDA resolution flow.
Proxies API calls to all services so the browser has one origin.

Supports:
  - nanda-native two-step resolution
  - enterprise-routed two-hop resolution
  - tamper detection (red flash on tamper)
  - revocation status display
"""
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
import requests

app = FastAPI(title="NANDA Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REGISTRY   = os.getenv("REGISTRY_URL",   "http://localhost:8000")
AGENT_HOST = os.getenv("AGENT_HOST_URL", "http://localhost:8001")
ENTERPRISE = os.getenv("ENTERPRISE_URL", "http://localhost:8002")

DASHBOARD_HTML = (Path(__file__).parent / "index.html").read_text()


@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD_HTML


@app.get("/api/agents")
def list_agents():
    try:
        r = requests.get(f"{REGISTRY}/agents", timeout=3)
        return r.json()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/resolve/{agent_name:path}")
def resolve(agent_name: str):
    try:
        r = requests.get(f"{REGISTRY}/resolve/{agent_name}", timeout=3)
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/status/{agent_id}")
def credential_status(agent_id: str):
    try:
        r = requests.get(f"{REGISTRY}/status/{agent_id}", timeout=3)
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/facts/{agent_name:path}")
def facts(agent_name: str, path_type: str = "primary"):
    try:
        addr_r = requests.get(f"{REGISTRY}/resolve/{agent_name}", timeout=3)
        addr = addr_r.json()

        # Enterprise-routed: second hop
        if addr.get("registration_type") == "enterprise-routed" and addr.get("enterprise_registry_url"):
            ent_r = requests.get(addr["enterprise_registry_url"], timeout=3)
            addr = ent_r.json()

        url = addr.get("private_facts_url") if path_type == "private" else addr.get("primary_facts_url")
        if not url:
            return JSONResponse({"error": "No facts URL"}, status_code=404)
        facts_r = requests.get(url, timeout=3)
        return JSONResponse(facts_r.json())
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/enterprise/resolve/{agent_name:path}")
def enterprise_resolve(agent_name: str):
    try:
        r = requests.get(f"{ENTERPRISE}/enterprise/resolve/{agent_name}", timeout=3)
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/api/revoke/{agent_id}")
def revoke(agent_id: str, reason: str = "unspecified"):
    try:
        r = requests.post(f"{REGISTRY}/revoke/{agent_id}", params={"reason": reason}, timeout=3)
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.post("/api/unrevoke/{agent_id}")
def unrevoke(agent_id: str):
    try:
        r = requests.post(f"{REGISTRY}/unrevoke/{agent_id}", timeout=3)
        return JSONResponse(r.json(), status_code=r.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/pubkey")
def pubkey():
    try:
        r = requests.get(f"{REGISTRY}/pubkey", timeout=3)
        return r.json()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
