# NANDA Index Prototype

A working prototype of the NANDA Index architecture described in  
**"Beyond DNS: Unlocking the Internet of AI Agents via the NANDA Index and Verified AgentFacts"**  
([arxiv.org/abs/2507.14263](https://arxiv.org/abs/2507.14263))

## What this demonstrates

The full paper flow, end-to-end:

```
AgentName → Index (AgentAddr + Ed25519 sig)
          → PrimaryFactsURL or PrivateFactsURL (AgentFacts + Ed25519 sig)
          → Endpoint (verified, ready to use)
```

Plus the enterprise-routed two-hop flow (paper Table 1):

```
AgentName → NANDA Index → Enterprise Registry (second Ed25519 sig)
          → AgentFacts → Endpoint
```

Tamper detection, revocation, and TTL caching at every step.

---

## Architecture

| Component | Port | Role |
|---|---|---|
| `registry/` | 8000 | Lean index — registers agents, serves signed `AgentAddr`, revocation status |
| `agent_host/` | 8001 | AgentFacts tier — hosts signed JSON-LD facts, supports live PATCH updates |
| `enterprise_registry/` | 8002 | Enterprise registry — second-hop resolution for `enterprise-routed` agents |
| `client/` | CLI | Resolver: TTL cache, per-step timing, enterprise hop, revocation check |
| `dashboard/` | 8080 | Live resolution visualizer with tamper flash |
| `tests/` | — | pytest suite |
| `crypto_utils.py` | — | Ed25519 sign/verify (RFC 8032, `cryptography` library) |

**Three demo agents:**
- `urn:agent:nanda:TranslationAssistant` — nanda-native, multilingual, streaming
- `urn:agent:nanda:WeatherAgent` — nanda-native, batch mode, shorter TTL
- `urn:agent:acme:SalesAgent` — **enterprise-routed** (two-hop via ACME Corp registry)

---

## Quickstart

### Option A — Docker (zero setup)

```bash
docker-compose up
```

All four services start, agents are seeded automatically. Open `http://localhost:8080`.

### Option B — Local

```bash
pip install fastapi uvicorn cryptography requests pytest httpx
bash start.sh
```

---

## Client commands

```bash
# List registered agents (shows registration type + revocation status)
python3 client/resolver.py list

# nanda-native resolution (verify → revocation check → facts → endpoint)
python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant"
python3 client/resolver.py resolve "urn:agent:nanda:WeatherAgent"

# Enterprise two-hop resolution
python3 client/resolver.py resolve "urn:agent:acme:SalesAgent"

# Privacy-preserving path (PrivateFactsURL)
python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --private

# Tamper detection demo — client catches injected field and aborts
python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --tamper

# TTL cache demo — first call fetches, second serves from cache
python3 client/resolver.py cache-demo "urn:agent:nanda:TranslationAssistant"

# Revocation demo — revoke, then resolve to see rejection
python3 client/resolver.py list                       # copy agent_id
python3 client/resolver.py revoke <agent_id>
python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant"   # rejected
python3 client/resolver.py unrevoke <agent_id>        # restore
```

**Dashboard:** Open `http://localhost:8080` — animated resolution flow, live data cards.  
Toggle "Tamper demo" to see nodes flash red on signature failure.  
Toggle "Private path" for the PrivateFactsURL flow.  
Click "Revoke credential" to demo sub-second revocation in the UI.

**Architecture diagram:** Open `http://localhost:8080/architecture` — four-tab interactive visual overview of the full system. Good starting point for walkthroughs and recordings.

| Tab | Content |
|---|---|
| **① Native Flow** | 5-step nanda-native chain with annotated steps and cache/signing callouts |
| **② Enterprise Two-Hop** | Full 3-signature chain diagram + Paper Table 1 registration types |
| **③ Key Properties** | Revocation, TTL cache, two-tier decoupling, measured timing numbers |
| **④ vs DNS** | Side-by-side comparison across 9 dimensions + tier architecture breakdown |

**Tests:**
```bash
pytest tests/test_nanda.py -v
```

---

## Feature highlights

### Enterprise-routed two-hop resolution
Paper Table 1 describes three registration types. This prototype implements all three conceptually and demonstrates `enterprise-routed` end-to-end:

```
Client → NANDA Index     → AgentAddr (sig: NANDA registry key)
       → Enterprise Reg. → EnterpriseAgentAddr (sig: enterprise key)
       → AgentFacts      → Endpoint
```

Two independent trust anchors. The enterprise registry is discovered through NANDA but signs with its own keypair — enterprises don't hand over their signing keys.

### Sub-second revocation
`POST /revoke/{agent_id}` flips a bit in the index. Every client call checks `/status/{agent_id}` after verifying the AgentAddr signature. This is the property that makes NANDA superior to DNS: a compromised agent is rejected within milliseconds, not after a DNS TTL.

### TTL-based caching
The client maintains an in-memory cache keyed by agent name. Subsequent resolves within TTL serve from cache with no network call to the index — this is the mechanism the paper cites for cutting index write load by 10,000x. The `cache-demo` command shows both calls side-by-side with timing.

### Per-step timing
Every resolution step is timed and printed:
```
Resolution timing:
  Step 1: index lookup              8.2ms  █
  Step 2a: fetch registry pubkey    4.1ms  
  Step 2b: verify Ed25519 sig       0.3ms  
  Step 2c: revocation check         3.8ms  
  Step 3: fetch AgentFacts          5.9ms  █
  Step 4: verify AgentFacts sig     0.2ms  
  ─────────────────────────────────────
  Total                            22.5ms
```

### AgentFacts live update (PATCH)
`PATCH /agents/{slug}/agent-facts` re-signs updated facts without touching the NANDA Index. Endpoint rotations, score updates, and capability changes propagate purely in the AgentFacts tier — the two-tier decoupling in practice.

### Capability-based search
Agents declare a capability list at registration time. The index stores a snapshot — no live fan-out to AgentFacts hosts:

```
GET /agents?capability=translation          → agents with "translation" in their capability list
GET /agents?capability=weather
GET /agents?registration_type=enterprise-routed
```

**Design tradeoff (O(1) vs O(N)):** The index answers capability queries from its local snapshot in a single DB query — O(1) regardless of how many agents are registered. The alternative (querying every AgentFacts host on each search) would be O(N) fan-out, defeating the lean-index principle (paper Section IV). The tradeoff is that snapshots can drift if an agent's facts change. The `PATCH /agents/{agent_name}/capabilities` endpoint exists to push updates:

```
PATCH /agents/urn:agent:nanda:WeatherAgent/capabilities
Body: ["weather","forecast","alerts","json","calendar"]
```

**Demo (PowerShell):**
```powershell
# Search by capability
Invoke-RestMethod "http://localhost:8000/agents?capability=translation"
Invoke-RestMethod "http://localhost:8000/agents?capability=weather"
Invoke-RestMethod "http://localhost:8000/agents?registration_type=enterprise-routed"

# Update cached capabilities
Invoke-RestMethod -Method PATCH `
  -Uri "http://localhost:8000/agents/urn:agent:nanda:WeatherAgent/capabilities" `
  -ContentType "application/json" `
  -Body '["weather","forecast","alerts","json","calendar"]'
```

**Seeded capabilities:**
| Agent | Capabilities |
|---|---|
| `urn:agent:nanda:TranslationAssistant` | `translation`, `language-detection`, `text`, `audio` |
| `urn:agent:nanda:WeatherAgent` | `weather`, `forecast`, `alerts`, `json` |
| `urn:agent:acme:SalesAgent` | `lead-qualification`, `pipeline-analytics`, `crm-sync`, `json` |

---

## Cryptography design choices

**Ed25519** (RFC 8032) via Python's `cryptography` library.  
Three-layer signing in the enterprise-routed path:
1. **Registry signs `AgentAddr`** — proves the NANDA index entry is authentic
2. **Enterprise registry signs its `AgentAddr`** — proves the enterprise hop is authentic
3. **Agent signs `AgentFacts`** — proves the metadata hasn't been tampered with

Signing covers canonically serialized JSON (`sort_keys=True`), so field reordering can't bypass verification.

I chose Ed25519 over W3C Verifiable Credentials (which the paper specifies as the target) because:
- It demonstrates the same cryptographic guarantee with far less scaffolding
- The VC library ecosystem in Python is fragmented; `cryptography` is stable and audited
- The README notes this as the main gap to production-readiness

---

## What's implemented

### Level 1 ✓
- End-to-end flow: `AgentName → Index → AgentAddr → AgentFacts → Endpoint`
- Two nanda-native agents + one enterprise-routed agent
- Ed25519 verification on `AgentAddr`, enterprise `AgentAddr`, and `AgentFacts`
- Tamper detection (client aborts on modified payload)
- Dual-path resolution: `PrimaryFactsURL` and `PrivateFactsURL`
- JSON-LD `@context` + W3C VC-compatible `type` fields
- SQLite persistence; keys persisted across restarts

### Level 2 ✓
- **Enterprise-routed two-hop resolution** (paper Table 1)
- **Credential revocation** (`POST /revoke`, `GET /status`, client checks before trusting)
- **TTL cache** in client with cache-hit indicator
- **Per-step timing** output in CLI
- **AgentFacts PATCH** — live re-sign without index update
- **Dashboard** — animated flow, tamper flash (red), revoke/unrevoke controls
- **`docker-compose up`** — zero-setup start
- **pytest suite** covering all flows

---

## Scope set aside

1. **Full W3C VC v2** — replace bare Ed25519 with `Ed25519Signature2020`, `proof.verificationMethod`, `credentialStatus`
2. **CRDT-based index updates** — paper Section IV.D; prototype uses synchronous SQLite
3. **PrivateFactsURL on IPFS** — both URLs served by same host; production pushes to CDN/IPFS
4. **DID-based agent identity** — `@DID:company:agent` registration type from paper

---

## AI tooling note

Built with Claude (claude.ai) as primary coding assistant — used for architecture planning, code generation, and debugging across all files.
