"""
NANDA Enterprise Registry — Two-Hop Resolution Demo
=====================================================
Demonstrates the enterprise-routed registration type from the paper (Table 1).

Flow:
  AgentName → NANDA Index (enterprise-routed AgentAddr + enterprise_registry_url)
            → Enterprise Registry /enterprise/resolve/{name} (enterprise-signed AgentAddr)
            → AgentFacts (hosted here on port 8002)
            → Endpoint

This shows that a company can run its own internal registry while still being
discoverable through the global NANDA Index. The enterprise registry signs its
own AgentAddr records with a separate keypair — clients verify both signatures.

Paper reference: Section IV, Table 1 — enterprise-routed registration type
"""
import json
import time
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import generate_keypair, sign_payload, serialize_private_key, load_private_key

KEYS_FILE = Path(__file__).parent / "enterprise_keys.json"

def _load_or_create_keys():
    if KEYS_FILE.exists():
        data = json.loads(KEYS_FILE.read_text())
        priv = load_private_key(data["private_b64"])
        return priv, data["public_b64"]
    priv, pub_b64 = generate_keypair()
    KEYS_FILE.write_text(json.dumps({"private_b64": serialize_private_key(priv), "public_b64": pub_b64}))
    return priv, pub_b64

AGENT_KEYS_DIR = Path(__file__).parent / "agent_keys"
AGENT_KEYS_DIR.mkdir(exist_ok=True)

def get_agent_keys(slug: str):
    key_file = AGENT_KEYS_DIR / f"{slug}.json"
    if key_file.exists():
        data = json.loads(key_file.read_text())
        priv = load_private_key(data["private_b64"])
        return priv, data["public_b64"]
    priv, pub_b64 = generate_keypair()
    key_file.write_text(json.dumps({"private_b64": serialize_private_key(priv), "public_b64": pub_b64}))
    return priv, pub_b64


# ---------------------------------------------------------------------------
# Enterprise agent catalogue
# ---------------------------------------------------------------------------

ENTERPRISE_AGENTS = {
    "urn:agent:acme:SalesAgent": "sales",
}

def build_sales_agent_facts(pub_b64: str) -> dict:
    now = int(time.time())
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://nanda.mit.edu/contexts/agent-facts/v1"
        ],
        "type": ["VerifiableCredential", "AgentFacts"],
        "id": "acme:agent:sales-agent:v1",
        "agent_name": "urn:agent:acme:SalesAgent",
        "label": "ACME Sales Assistant",
        "description": "Enterprise CRM agent — Salesforce-connected lead management and pipeline analytics",
        "version": "3.1.0",
        "jurisdiction": "USA",
        "registration_type": "enterprise-routed",
        "provider": {
            "name": "ACME Corp",
            "url": "http://localhost:8002",
            "enterprise_id": "acme-corp-001"
        },
        "endpoints": {
            "static": [
                {"url": "http://localhost:8002/enterprise/agents/sales/rpc", "ttl": 1800}
            ],
            "rotating": [],
            "adaptive_resolver": None
        },
        "capabilities": {
            "modalities": ["text", "json"],
            "streaming": False,
            "batch": True,
            "authentication": {
                "methods": ["oauth2", "saml"],
                "required_scopes": ["crm:read", "pipeline:write", "leads:manage"]
            }
        },
        "skills": [
            {
                "id": "lead-qualification",
                "description": "Score and qualify inbound leads against ICP criteria",
                "input_modes": ["json"],
                "output_modes": ["json"],
                "latency_budget_ms": 800
            },
            {
                "id": "pipeline-analytics",
                "description": "Revenue forecast and pipeline health metrics",
                "input_modes": ["json"],
                "output_modes": ["json"],
            },
            {
                "id": "crm-sync",
                "description": "Bidirectional Salesforce record sync",
                "input_modes": ["json"],
                "output_modes": ["json"],
            }
        ],
        "evaluations": {
            "performance_score": 4.7,
            "availability_90d": "99.91%",
            "last_audited": "2025-06-01T10:00:00Z",
            "auditor_id": "ACME-Internal-Audit"
        },
        "telemetry": {
            "enabled": True,
            "retention": "30d",
            "sampling": 0.01,
            "metrics": {
                "latency_p95_ms": 650,
                "throughput_rps": 50,
                "error_rate": 0.002
            }
        },
        "certification": {
            "level": "enterprise-verified",
            "issuer": "ACME-Enterprise-Registry",
            "issuance_date": "2025-06-01T10:00:00Z",
            "expiration_date": "2026-06-01T10:00:00Z"
        },
        "issuer": "http://localhost:8002/enterprise/agents/sales",
        "issuance_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expiration_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400 * 365)),
        "agent_public_key": pub_b64,
        "ttl": 1800,
    }

AGENT_BUILDERS = {
    "sales": build_sales_agent_facts,
}


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

ENTERPRISE_PRIVATE_KEY = None
ENTERPRISE_PUBLIC_KEY_B64 = None

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ENTERPRISE_PRIVATE_KEY, ENTERPRISE_PUBLIC_KEY_B64
    ENTERPRISE_PRIVATE_KEY, ENTERPRISE_PUBLIC_KEY_B64 = _load_or_create_keys()
    print(f"[Enterprise Registry] Public key: {ENTERPRISE_PUBLIC_KEY_B64[:32]}...")
    yield

app = FastAPI(title="NANDA Enterprise Registry (ACME Corp)", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/enterprise/pubkey")
def get_pubkey():
    """Expose enterprise registry's public key for second-hop signature verification."""
    return {
        "public_key_b64": ENTERPRISE_PUBLIC_KEY_B64,
        "algorithm": "Ed25519",
        "issuer": "ACME Corp Enterprise Registry",
    }


@app.get("/enterprise/resolve/{agent_name:path}")
def resolve_enterprise_agent(agent_name: str):
    """
    Second-hop resolution: enterprise registry returns its own signed AgentAddr.
    The client verifies this signature using the enterprise pubkey (not the NANDA registry key).
    This demonstrates that enterprise registries are independently trusted parties.
    """
    if agent_name not in ENTERPRISE_AGENTS:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not in enterprise registry")

    slug = ENTERPRISE_AGENTS[agent_name]
    now = int(time.time())
    ttl = 1800

    payload = {
        "agent_id": f"acme:{slug}",
        "agent_name": agent_name,
        "primary_facts_url": f"http://localhost:8002/enterprise/agents/{slug}/agent-facts",
        "private_facts_url": None,
        "adaptive_resolver_url": None,
        "enterprise_registry_url": None,
        "ttl": ttl,
        "issued_at": now,
        "expires_at": now + ttl,
        "registration_type": "enterprise-routed",
        "issuer": "ACME-Enterprise-Registry",
    }
    signature = sign_payload(ENTERPRISE_PRIVATE_KEY, payload)
    return {**payload, "signature": signature}


@app.get("/enterprise/agents/{slug}/agent-facts")
def enterprise_agent_facts(slug: str):
    if slug not in AGENT_BUILDERS:
        raise HTTPException(status_code=404, detail=f"Unknown agent '{slug}'")
    priv, pub_b64 = get_agent_keys(slug)
    facts = AGENT_BUILDERS[slug](pub_b64)
    signature = sign_payload(priv, facts)
    return {**facts, "proof": {"type": "Ed25519Signature2020", "signature": signature}}


@app.get("/enterprise/agents/{slug}/pubkey")
def enterprise_agent_pubkey(slug: str):
    if slug not in AGENT_BUILDERS:
        raise HTTPException(status_code=404, detail=f"Unknown agent '{slug}'")
    _, pub_b64 = get_agent_keys(slug)
    return {"agent": slug, "public_key_b64": pub_b64, "algorithm": "Ed25519"}


@app.get("/enterprise/agents/{slug}/rpc")
def enterprise_rpc_stub(slug: str):
    return {"agent": slug, "status": "ready", "message": "Enterprise agent endpoint reachable."}


@app.get("/enterprise/agents")
def list_enterprise_agents():
    return [{"agent_name": name, "slug": slug} for name, slug in ENTERPRISE_AGENTS.items()]


@app.get("/health")
def health():
    return {"status": "ok", "service": "nanda-enterprise-registry"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
