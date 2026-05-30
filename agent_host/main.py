"""
NANDA Agent Host Service — AgentFacts Tier
==========================================
Hosts signed AgentFacts JSON-LD documents for demo agents.
Each agent has its own Ed25519 keypair; AgentFacts are self-signed.

Exposes:
  GET   /agents/{slug}/agent-facts    → signed AgentFacts (PrimaryFactsURL)
  GET   /agents/{slug}/private-facts  → same document via "private" path
  GET   /agents/{slug}/pubkey         → agent's public key
  PATCH /agents/{slug}/agent-facts    → update + re-sign AgentFacts (no index update needed)
  GET   /agents/{slug}/rpc            → stub endpoint (shows static endpoint is reachable)

The PATCH endpoint demonstrates the two-tier architecture's key property:
facts can be updated (new endpoint URLs, revised performance scores, capability changes)
without touching the NANDA Index at all — clients re-fetch on TTL expiry.

Paper reference: Section V — AgentFacts Schema and Resolution Mechanism
"""
import json
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import generate_keypair, sign_payload, serialize_private_key, load_private_key

app = FastAPI(title="NANDA Agent Host", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

KEYS_DIR = Path(__file__).parent / "agent_keys"
KEYS_DIR.mkdir(exist_ok=True)

# Mutable overrides per agent — PATCH updates land here, merged before signing
_fact_overrides: dict[str, dict] = {}


def get_agent_keys(slug: str):
    key_file = KEYS_DIR / f"{slug}.json"
    if key_file.exists():
        data = json.loads(key_file.read_text())
        priv = load_private_key(data["private_b64"])
        return priv, data["public_b64"]
    priv, pub_b64 = generate_keypair()
    key_file.write_text(json.dumps({"private_b64": serialize_private_key(priv), "public_b64": pub_b64}))
    return priv, pub_b64


# ---------------------------------------------------------------------------
# AgentFacts builders
# ---------------------------------------------------------------------------

def build_translation_agent_facts(pub_b64: str) -> dict:
    now = int(time.time())
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://nanda.mit.edu/contexts/agent-facts/v1"
        ],
        "type": ["VerifiableCredential", "AgentFacts"],
        "id": "nanda:agent:translation-assistant:v1",
        "agent_name": "urn:agent:nanda:TranslationAssistant",
        "label": "Translation Assistant",
        "description": "Low-latency multilingual translation agent supporting 25+ languages",
        "version": "1.2.1",
        "jurisdiction": "USA",
        "registration_type": "nanda-native",
        "provider": {"name": "NANDA Demo", "url": "http://localhost:8001"},
        "endpoints": {
            "static": [{"url": "http://localhost:8001/agents/translation/rpc", "ttl": 3600}],
            "rotating": [{"url": "http://localhost:8001/agents/translation/rpc/r1", "ttl": 900}],
            "adaptive_resolver": {
                "url": "http://localhost:8001/agents/translation/resolve",
                "policies": ["geo", "load", "threat-shield"],
                "ttl": 60
            }
        },
        "capabilities": {
            "modalities": ["text", "audio"],
            "streaming": True,
            "batch": False,
            "authentication": {
                "methods": ["oauth2", "jwt"],
                "required_scopes": ["translate:real-time", "language:detect"]
            }
        },
        "skills": [
            {
                "id": "translation",
                "description": "Real-time translation between 25+ languages",
                "input_modes": ["text", "audio/ogg"],
                "output_modes": ["text", "audio/wav"],
                "supported_languages": ["en", "es", "fr", "de", "ja", "zh"],
                "latency_budget_ms": 300
            },
            {
                "id": "language-detection",
                "description": "Automatic source language identification",
                "input_modes": ["text"],
                "output_modes": ["text"],
            }
        ],
        "evaluations": {
            "performance_score": 4.8,
            "availability_90d": "99.93%",
            "last_audited": "2025-04-01T12:00:00Z",
            "auditor_id": "NANDA-Audit-v1"
        },
        "telemetry": {
            "enabled": True,
            "retention": "7d",
            "sampling": 0.1,
            "metrics": {"latency_p95_ms": 280, "throughput_rps": 125, "error_rate": 0.003}
        },
        "certification": {
            "level": "verified",
            "issuer": "NANDA-Demo-Registry",
            "issuance_date": "2025-03-15T09:30:00Z",
            "expiration_date": "2026-03-15T09:30:00Z"
        },
        "issuer": "http://localhost:8001/agents/translation",
        "issuance_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expiration_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400 * 365)),
        "agent_public_key": pub_b64,
        "ttl": 3600,
    }


def build_weather_agent_facts(pub_b64: str) -> dict:
    now = int(time.time())
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://nanda.mit.edu/contexts/agent-facts/v1"
        ],
        "type": ["VerifiableCredential", "AgentFacts"],
        "id": "nanda:agent:weather-agent:v1",
        "agent_name": "urn:agent:nanda:WeatherAgent",
        "label": "Weather & Forecast Agent",
        "description": "Real-time weather data and 7-day forecasts via open meteorological APIs",
        "version": "2.0.0",
        "jurisdiction": "USA",
        "registration_type": "nanda-native",
        "provider": {"name": "NANDA Demo", "url": "http://localhost:8001"},
        "endpoints": {
            "static": [{"url": "http://localhost:8001/agents/weather/rpc", "ttl": 3600}],
            "rotating": [{"url": "http://localhost:8001/agents/weather/rpc/r1", "ttl": 600}],
            "adaptive_resolver": None
        },
        "capabilities": {
            "modalities": ["text", "json"],
            "streaming": False,
            "batch": True,
            "authentication": {
                "methods": ["api-key", "jwt"],
                "required_scopes": ["weather:read", "forecast:read"]
            }
        },
        "skills": [
            {
                "id": "current-weather",
                "description": "Current conditions for any lat/lon or city name",
                "input_modes": ["text", "json"],
                "output_modes": ["json"],
                "latency_budget_ms": 500
            },
            {
                "id": "forecast",
                "description": "7-day hourly forecast",
                "input_modes": ["json"],
                "output_modes": ["json"],
                "max_days_ahead": 7
            },
            {
                "id": "alerts",
                "description": "Severe weather alerts for a region",
                "input_modes": ["text"],
                "output_modes": ["json"]
            }
        ],
        "evaluations": {
            "performance_score": 4.6,
            "availability_90d": "99.85%",
            "last_audited": "2025-05-01T08:00:00Z",
            "auditor_id": "NANDA-Audit-v1"
        },
        "telemetry": {
            "enabled": True,
            "retention": "3d",
            "sampling": 0.05,
            "metrics": {"latency_p95_ms": 450, "throughput_rps": 300, "error_rate": 0.005}
        },
        "certification": {
            "level": "verified",
            "issuer": "NANDA-Demo-Registry",
            "issuance_date": "2025-05-01T08:00:00Z",
            "expiration_date": "2026-05-01T08:00:00Z"
        },
        "issuer": "http://localhost:8001/agents/weather",
        "issuance_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expiration_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400 * 365)),
        "agent_public_key": pub_b64,
        "ttl": 1800,
    }


AGENT_BUILDERS = {
    "translation": build_translation_agent_facts,
    "weather": build_weather_agent_facts,
}


def _make_signed_facts(slug: str) -> dict:
    if slug not in AGENT_BUILDERS:
        raise HTTPException(404, f"Unknown agent '{slug}'")
    priv, pub_b64 = get_agent_keys(slug)
    facts = AGENT_BUILDERS[slug](pub_b64)
    # Merge any PATCH overrides
    if slug in _fact_overrides:
        facts = {**facts, **_fact_overrides[slug]}
        # Re-inject public key in case override clobbered it
        facts["agent_public_key"] = pub_b64
    signature = sign_payload(priv, facts)
    return {**facts, "proof": {"type": "Ed25519Signature2020", "signature": signature}}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/agents/{slug}/pubkey")
def agent_pubkey(slug: str):
    if slug not in AGENT_BUILDERS:
        raise HTTPException(404, f"Unknown agent '{slug}'")
    _, pub_b64 = get_agent_keys(slug)
    return {"agent": slug, "public_key_b64": pub_b64, "algorithm": "Ed25519"}


@app.get("/agents/{slug}/agent-facts")
def primary_facts(slug: str):
    return _make_signed_facts(slug)


@app.get("/agents/{slug}/private-facts")
def private_facts(slug: str):
    """
    PrivateFactsURL path — in production this would be hosted on IPFS/CDN.
    Same data, separate path, demonstrating the dual-URL model.
    """
    return _make_signed_facts(slug)


class FactsUpdateRequest(BaseModel):
    updates: dict[str, Any]

@app.patch("/agents/{slug}/agent-facts")
def update_agent_facts(slug: str, req: FactsUpdateRequest):
    """
    Update AgentFacts and re-sign — without touching the NANDA Index at all.
    This is the key decoupling property of the two-tier architecture:
    capability changes, endpoint rotations, and score updates stay in
    the AgentFacts layer. The index only needs to be updated if the facts
    URL itself changes.

    Example: bump performance_score, change an endpoint URL, add a skill.
    """
    if slug not in AGENT_BUILDERS:
        raise HTTPException(404, f"Unknown agent '{slug}'")

    _fact_overrides[slug] = {**_fact_overrides.get(slug, {}), **req.updates}
    updated_facts = _make_signed_facts(slug)
    return {
        "status": "updated",
        "agent": slug,
        "applied_overrides": list(req.updates.keys()),
        "new_signature": updated_facts["proof"]["signature"][:32] + "...",
    }


@app.get("/agents/{slug}/rpc")
def agent_rpc_stub(slug: str):
    return {"agent": slug, "status": "ready", "message": "Agent endpoint reachable. Send task payload to interact."}


@app.get("/health")
def health():
    return {"status": "ok", "service": "nanda-agent-host"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
