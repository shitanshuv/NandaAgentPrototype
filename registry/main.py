"""
NANDA Registry Service — The Lean Index
========================================
Implements the index tier of the NANDA architecture:
  - Maintains a minimal AgentAddr record per agent (≤120 bytes of routing data)
  - Signs every AgentAddr response with the registry's Ed25519 key
  - Exposes /register, /resolve/{agent_name}, /agents, /pubkey endpoints
  - Persists records in SQLite

Enhanced:
  - POST /revoke/{agent_id}    — mark a credential as revoked (sub-second revocation)
  - GET  /status/{agent_id}    — check revocation status (clients check before trusting)
  - registration_type field supports: nanda-native | enterprise-routed | did-based

Paper reference: Section IV — The Lean Index
"""
import json
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import generate_keypair, sign_payload, serialize_private_key, load_private_key

KEYS_FILE = Path(__file__).parent / "registry_keys.json"

def _load_or_create_keys():
    if KEYS_FILE.exists():
        data = json.loads(KEYS_FILE.read_text())
        priv = load_private_key(data["private_b64"])
        return priv, data["public_b64"]
    priv, pub_b64 = generate_keypair()
    KEYS_FILE.write_text(json.dumps({"private_b64": serialize_private_key(priv), "public_b64": pub_b64}))
    return priv, pub_b64

DB_PATH = Path(__file__).parent / "registry.db"

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id              TEXT PRIMARY KEY,
                agent_name            TEXT UNIQUE NOT NULL,
                primary_facts_url     TEXT NOT NULL,
                private_facts_url     TEXT,
                adaptive_resolver_url TEXT,
                enterprise_registry_url TEXT,
                ttl                   INTEGER DEFAULT 3600,
                owner_pubkey          TEXT NOT NULL,
                registration_type     TEXT DEFAULT 'nanda-native',
                revoked               INTEGER DEFAULT 0,
                revoked_at            INTEGER,
                revocation_reason     TEXT,
                created_at            INTEGER NOT NULL
            )
        """)
        # Migrate existing DBs that lack new columns
        for col, typedef in [
            ("revoked", "INTEGER DEFAULT 0"),
            ("revoked_at", "INTEGER"),
            ("revocation_reason", "TEXT"),
            ("enterprise_registry_url", "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typedef}")
            except Exception:
                pass
        conn.commit()


class RegistrationRequest(BaseModel):
    agent_name: str
    primary_facts_url: str
    private_facts_url: str | None = None
    adaptive_resolver_url: str | None = None
    enterprise_registry_url: str | None = None
    ttl: int = 3600
    owner_pubkey: str
    registration_type: str = "nanda-native"


class AgentAddr(BaseModel):
    agent_id: str
    agent_name: str
    primary_facts_url: str
    private_facts_url: str | None
    adaptive_resolver_url: str | None
    enterprise_registry_url: str | None
    ttl: int
    issued_at: int
    expires_at: int
    registration_type: str
    signature: str


REGISTRY_PRIVATE_KEY = None
REGISTRY_PUBLIC_KEY_B64 = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global REGISTRY_PRIVATE_KEY, REGISTRY_PUBLIC_KEY_B64
    init_db()
    REGISTRY_PRIVATE_KEY, REGISTRY_PUBLIC_KEY_B64 = _load_or_create_keys()
    print(f"[Registry] Public key: {REGISTRY_PUBLIC_KEY_B64[:32]}...")
    yield

app = FastAPI(title="NANDA Index Registry", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/pubkey")
def get_pubkey():
    return {"public_key_b64": REGISTRY_PUBLIC_KEY_B64, "algorithm": "Ed25519"}


@app.post("/register", status_code=201)
def register_agent(req: RegistrationRequest):
    agent_id = f"nanda:{uuid.uuid4()}"
    now = int(time.time())
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO agents
                  (agent_id, agent_name, primary_facts_url, private_facts_url,
                   adaptive_resolver_url, enterprise_registry_url,
                   ttl, owner_pubkey, registration_type, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (agent_id, req.agent_name, req.primary_facts_url,
                  req.private_facts_url, req.adaptive_resolver_url,
                  req.enterprise_registry_url,
                  req.ttl, req.owner_pubkey, req.registration_type, now))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail=f"Agent '{req.agent_name}' already registered")

    return {"agent_id": agent_id, "agent_name": req.agent_name, "status": "registered"}


@app.get("/resolve/{agent_name:path}", response_model=AgentAddr)
def resolve_agent(agent_name: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_name = ?", (agent_name,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found in index")

    now = int(time.time())
    payload = {
        "agent_id": row["agent_id"],
        "agent_name": row["agent_name"],
        "primary_facts_url": row["primary_facts_url"],
        "private_facts_url": row["private_facts_url"],
        "adaptive_resolver_url": row["adaptive_resolver_url"],
        "enterprise_registry_url": row["enterprise_registry_url"],
        "ttl": row["ttl"],
        "issued_at": now,
        "expires_at": now + row["ttl"],
        "registration_type": row["registration_type"],
    }
    signature = sign_payload(REGISTRY_PRIVATE_KEY, payload)
    return AgentAddr(**payload, signature=signature)


@app.get("/agents")
def list_agents():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT agent_name, agent_id, registration_type, revoked, created_at FROM agents"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Revocation — paper Section VII.D (VC-Status-List / sub-second revocation)
# ---------------------------------------------------------------------------

@app.post("/revoke/{agent_id}")
def revoke_agent(agent_id: str, reason: str = "unspecified"):
    """
    Mark an agent credential as revoked. Clients check /status before trusting.
    This is the sub-second revocation property that makes NANDA superior to DNS.
    """
    with get_db() as conn:
        row = conn.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
        conn.execute(
            "UPDATE agents SET revoked=1, revoked_at=?, revocation_reason=? WHERE agent_id=?",
            (int(time.time()), reason, agent_id)
        )
        conn.commit()
    return {"agent_id": agent_id, "status": "revoked", "reason": reason}


@app.post("/unrevoke/{agent_id}")
def unrevoke_agent(agent_id: str):
    """Restore a previously revoked credential (demo purposes)."""
    with get_db() as conn:
        row = conn.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
        conn.execute(
            "UPDATE agents SET revoked=0, revoked_at=NULL, revocation_reason=NULL WHERE agent_id=?",
            (agent_id,)
        )
        conn.commit()
    return {"agent_id": agent_id, "status": "active"}


@app.get("/status/{agent_id}")
def credential_status(agent_id: str):
    """
    VC-Status-List style endpoint. Clients call this after verifying AgentAddr
    to confirm the credential hasn't been revoked.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT agent_id, agent_name, revoked, revoked_at, revocation_reason FROM agents WHERE agent_id = ?",
            (agent_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {
        "agent_id": row["agent_id"],
        "agent_name": row["agent_name"],
        "status": "revoked" if row["revoked"] else "active",
        "revoked_at": row["revoked_at"],
        "revocation_reason": row["revocation_reason"],
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "nanda-registry"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
