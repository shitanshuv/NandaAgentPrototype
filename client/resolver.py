"""
NANDA Client Resolver
=====================
Full resolution flow with:
  - TTL-based in-memory cache (demonstrates the 10,000x index write reduction)
  - Per-step timing output (makes "sub-second resolution" claim tangible)
  - Enterprise-routed two-hop resolution (NANDA Index → Enterprise Registry → AgentFacts)
  - Revocation check after AgentAddr verification (sub-second revocation demo)
  - Tamper detection on both AgentAddr and AgentFacts

Resolution flows:

  nanda-native:
    AgentName → Index → AgentAddr (verify) → revocation check →
    AgentFacts (verify) → Endpoint

  enterprise-routed:
    AgentName → Index → AgentAddr (verify) → revocation check →
    Enterprise Registry → EnterpriseAgentAddr (verify) →
    AgentFacts (verify) → Endpoint

Usage:
  python client/resolver.py resolve "urn:agent:nanda:TranslationAssistant"
  python client/resolver.py resolve "urn:agent:nanda:WeatherAgent"
  python client/resolver.py resolve "urn:agent:acme:SalesAgent"
  python client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --private
  python client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --tamper
  python client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --cache-demo
  python client/resolver.py revoke <agent_id>
  python client/resolver.py list
"""
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import verify_payload

REGISTRY_URL = "http://localhost:8000"
AGENT_HOST_URL = "http://localhost:8001"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):     print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg):   print(f"  {RED}✗{RESET} {msg}")
def info(msg):   print(f"  {CYAN}→{RESET} {msg}")
def header(msg): print(f"\n{BOLD}{msg}{RESET}")
def warn(msg):   print(f"  {YELLOW}⚠{RESET}  {msg}")
def dim(msg):    print(f"  {DIM}{msg}{RESET}")


# ---------------------------------------------------------------------------
# TTL Cache — demonstrates the core index load-reduction property
# Paper Section IV: "TTL-based caching cuts index write load by 10,000x"
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[float, dict]] = {}  # agent_name -> (fetched_at, agent_addr)

def _cache_get(agent_name: str) -> Optional[dict]:
    if agent_name not in _cache:
        return None
    fetched_at, cached = _cache[agent_name]
    age = time.time() - fetched_at
    if age < cached["ttl"]:
        return cached, age
    return None

def _cache_set(agent_name: str, agent_addr: dict):
    _cache[agent_name] = (time.time(), agent_addr)


# ---------------------------------------------------------------------------
# Timing — makes "sub-second global resolution" concrete
# ---------------------------------------------------------------------------

_timings: dict[str, float] = {}

def _timed(label: str, fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    ms = (time.perf_counter() - t0) * 1000
    _timings[label] = ms
    return result

def _print_timings():
    total = sum(_timings.values())
    print(f"\n{BOLD}Resolution timing:{RESET}")
    for step, ms in _timings.items():
        bar = "█" * max(1, int(ms / 5))
        print(f"  {DIM}{step:<35}{RESET} {CYAN}{ms:>6.1f}ms{RESET}  {DIM}{bar}{RESET}")
    print(f"  {'─'*35}  {'─'*8}")
    print(f"  {BOLD}{'Total':<35}{RESET} {GREEN}{total:>6.1f}ms{RESET}")


# ---------------------------------------------------------------------------
# Step 1: Resolve AgentName → AgentAddr (with TTL cache)
# ---------------------------------------------------------------------------

def resolve_agent_addr(agent_name: str, use_cache: bool = True) -> tuple[dict, bool]:
    """Returns (agent_addr, from_cache)."""
    if use_cache:
        cached = _cache_get(agent_name)
        if cached:
            agent_addr, age = cached
            header(f"Step 1 — Index Lookup (TTL cache hit)")
            warn(f"Serving from cache  age={int(age)}s / TTL={agent_addr['ttl']}s — skipping network call")
            ok(f"Agent ID   : {agent_addr['agent_id']}")
            ok(f"Reg. type  : {agent_addr['registration_type']}")
            return agent_addr, True

    header(f"Step 1 — Index Lookup: {agent_name}")
    info(f"GET {REGISTRY_URL}/resolve/{agent_name}")

    def _fetch():
        resp = requests.get(f"{REGISTRY_URL}/resolve/{agent_name}", timeout=5)
        if resp.status_code == 404:
            fail(f"Agent not found in index: {agent_name}")
            sys.exit(1)
        resp.raise_for_status()
        return resp.json()

    agent_addr = _timed("Step 1: index lookup", _fetch)
    _cache_set(agent_name, agent_addr)

    ok(f"Received AgentAddr for '{agent_addr['agent_name']}'")
    ok(f"Agent ID   : {agent_addr['agent_id']}")
    ok(f"Reg. type  : {agent_addr['registration_type']}")
    ok(f"TTL        : {agent_addr['ttl']}s  (cached until {time.strftime('%H:%M:%S', time.localtime(time.time() + agent_addr['ttl']))})")
    ok(f"FactsURL   : {agent_addr['primary_facts_url']}")
    if agent_addr.get("private_facts_url"):
        ok(f"PrivFactsURL: {agent_addr['private_facts_url']}")
    if agent_addr.get("enterprise_registry_url"):
        ok(f"EnterpriseReg: {agent_addr['enterprise_registry_url']}")

    return agent_addr, False


# ---------------------------------------------------------------------------
# Step 2: Verify AgentAddr signature
# ---------------------------------------------------------------------------

def verify_agent_addr(agent_addr: dict, tamper: bool = False) -> bool:
    header("Step 2 — Verify AgentAddr Signature (registry's Ed25519 key)")

    def _fetch_pubkey():
        r = requests.get(f"{REGISTRY_URL}/pubkey", timeout=5)
        r.raise_for_status()
        return r.json()["public_key_b64"]

    registry_pubkey = _timed("Step 2a: fetch registry pubkey", _fetch_pubkey)
    info(f"Registry pubkey : {registry_pubkey[:32]}...")

    signature = agent_addr["signature"]
    payload = {k: v for k, v in agent_addr.items() if k != "signature"}

    if tamper:
        warn("TAMPER MODE: Injecting false agent_id into AgentAddr payload")
        payload["agent_id"] = "nanda:EVIL-TAMPERED-ID"

    def _verify():
        return verify_payload(registry_pubkey, payload, signature)

    valid = _timed("Step 2b: verify Ed25519 sig", _verify)

    if valid:
        ok("Signature VALID — AgentAddr is authentic and untampered")
    else:
        fail("Signature INVALID — AgentAddr has been tampered with!")
        fail("Client REJECTS this record. Resolution aborted.")

    return valid


# ---------------------------------------------------------------------------
# Step 2c: Revocation check (sub-second revocation)
# Paper Section VII.D — VC-Status-List
# ---------------------------------------------------------------------------

def check_revocation(agent_addr: dict) -> bool:
    """Check credential status before trusting the AgentAddr."""
    header("Step 2c — Revocation Check (VC-Status-List)")
    agent_id = agent_addr["agent_id"]
    info(f"GET {REGISTRY_URL}/status/{agent_id}")

    def _check():
        r = requests.get(f"{REGISTRY_URL}/status/{agent_id}", timeout=5)
        r.raise_for_status()
        return r.json()

    status = _timed("Step 2c: revocation check", _check)

    if status["status"] == "revoked":
        fail(f"Credential REVOKED — reason: {status.get('revocation_reason', 'unspecified')}")
        fail(f"Revoked at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(status.get('revoked_at', 0)))}")
        fail("Client REJECTS revoked credential.")
        return False

    ok(f"Credential status: ACTIVE (not revoked)")
    return True


# ---------------------------------------------------------------------------
# Step 2d: Enterprise second hop (enterprise-routed agents only)
# Paper Table 1 — enterprise-routed registration type
# ---------------------------------------------------------------------------

def enterprise_second_hop(agent_addr: dict) -> Optional[dict]:
    """
    For enterprise-routed agents: query the enterprise registry for the
    enterprise-signed AgentAddr. Returns the enterprise AgentAddr or None on failure.
    """
    enterprise_url = agent_addr.get("enterprise_registry_url")
    if not enterprise_url:
        fail("enterprise-routed agent has no enterprise_registry_url")
        return None

    header("Step 2d — Enterprise Second Hop")
    info(f"Registration type is 'enterprise-routed' — querying enterprise registry")
    info(f"GET {enterprise_url}")

    def _fetch():
        r = requests.get(enterprise_url, timeout=5)
        r.raise_for_status()
        return r.json()

    enterprise_addr = _timed("Step 2d: enterprise hop", _fetch)

    ok(f"Received EnterpriseAgentAddr from '{enterprise_addr.get('issuer', 'enterprise registry')}'")
    ok(f"Enterprise facts URL: {enterprise_addr['primary_facts_url']}")
    ok(f"Enterprise TTL      : {enterprise_addr['ttl']}s")

    # Verify enterprise registry's signature
    header("Step 2e — Verify EnterpriseAgentAddr Signature (enterprise registry key)")

    # Derive enterprise pubkey URL from the enterprise_registry_url
    # e.g. http://localhost:8002/enterprise/resolve/... -> http://localhost:8002/enterprise/pubkey
    base = enterprise_url.split("/enterprise/resolve")[0]
    pubkey_url = f"{base}/enterprise/pubkey"
    info(f"GET {pubkey_url}")

    def _fetch_epubkey():
        r = requests.get(pubkey_url, timeout=5)
        r.raise_for_status()
        return r.json()["public_key_b64"]

    enterprise_pubkey = _timed("Step 2e: fetch enterprise pubkey", _fetch_epubkey)
    info(f"Enterprise pubkey: {enterprise_pubkey[:32]}...")

    sig = enterprise_addr["signature"]
    payload = {k: v for k, v in enterprise_addr.items() if k != "signature"}
    valid = _timed("Step 2e: verify enterprise sig", lambda: verify_payload(enterprise_pubkey, payload, sig))

    if valid:
        ok("Enterprise signature VALID — two-hop resolution chain verified")
    else:
        fail("Enterprise signature INVALID — enterprise record tampered!")
        return None

    return enterprise_addr


# ---------------------------------------------------------------------------
# Step 3: Fetch AgentFacts
# ---------------------------------------------------------------------------

def fetch_agent_facts(facts_url: str, use_private: bool = False,
                      agent_addr: Optional[dict] = None) -> dict:
    header("Step 3 — Fetch AgentFacts")

    if use_private and agent_addr and agent_addr.get("private_facts_url"):
        url = agent_addr["private_facts_url"]
        info(f"Using PrivateFactsURL (privacy-preserving path): {url}")
    else:
        url = facts_url
        info(f"Using PrimaryFactsURL: {url}")

    def _fetch():
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        return r.json()

    facts = _timed("Step 3: fetch AgentFacts", _fetch)

    ok(f"Received AgentFacts v{facts.get('version', '?')} — '{facts.get('label', '?')}'")
    ok(f"Description: {facts.get('description', '?')}")
    ok(f"Skills     : {[s['id'] for s in facts.get('skills', [])]}")
    ok(f"Modalities : {facts.get('capabilities', {}).get('modalities', [])}")
    ok(f"Auth       : {facts.get('capabilities', {}).get('authentication', {}).get('methods', [])}")

    return facts


# ---------------------------------------------------------------------------
# Step 4: Verify AgentFacts signature
# ---------------------------------------------------------------------------

def verify_agent_facts(facts: dict, tamper: bool = False) -> bool:
    header("Step 4 — Verify AgentFacts Signature (agent's Ed25519 key)")

    proof = facts.get("proof")
    if not proof:
        fail("No proof block found in AgentFacts — cannot verify!")
        return False

    signature = proof["signature"]
    agent_pubkey = facts.get("agent_public_key")
    if not agent_pubkey:
        fail("No agent_public_key field in AgentFacts!")
        return False

    info(f"Agent pubkey: {agent_pubkey[:32]}...")
    payload = {k: v for k, v in facts.items() if k != "proof"}

    if tamper:
        warn("TAMPER MODE: Injecting false performance_score into AgentFacts")
        payload["evaluations"] = {**payload.get("evaluations", {}), "performance_score": 9.9}

    def _verify():
        return verify_payload(agent_pubkey, payload, signature)

    valid = _timed("Step 4: verify AgentFacts sig", _verify)

    if valid:
        ok("Signature VALID — AgentFacts is authentic and untampered")
    else:
        fail("Signature INVALID — AgentFacts has been tampered with!")
        fail("Client REJECTS these facts.")

    return valid


# ---------------------------------------------------------------------------
# Step 5: Show resolved endpoint
# ---------------------------------------------------------------------------

def show_endpoint(facts: dict):
    header("Step 5 — Resolved Endpoint (ready to use)")
    endpoints = facts.get("endpoints", {})
    static = endpoints.get("static", [])
    rotating = endpoints.get("rotating", [])
    adaptive = endpoints.get("adaptive_resolver")

    if static:
        ep = static[0]
        url = ep["url"] if isinstance(ep, dict) else ep
        ok(f"Static endpoint  : {url}  (TTL {ep.get('ttl', '?')}s)")
        try:
            r = requests.get(url, timeout=3)
            ok(f"Endpoint probe   : HTTP {r.status_code} — {r.json().get('message', 'ok')}")
        except Exception as e:
            warn(f"Endpoint probe skipped: {e}")
    if rotating:
        ep = rotating[0]
        url = ep["url"] if isinstance(ep, dict) else ep
        ok(f"Rotating endpoint: {url}  (TTL {ep.get('ttl', '?')}s)")
    if adaptive:
        ok(f"Adaptive resolver: {adaptive['url']}  policies={adaptive.get('policies', [])}")


# ---------------------------------------------------------------------------
# Full resolution flow
# ---------------------------------------------------------------------------

def full_resolve(agent_name: str, use_private: bool = False,
                 tamper: bool = False, use_cache: bool = True):
    global _timings
    _timings = {}

    print(f"\n{'='*62}")
    print(f"{BOLD}NANDA Resolution Flow{RESET}")
    print(f"{'='*62}")

    # 1. Resolve (with TTL cache)
    agent_addr, from_cache = resolve_agent_addr(agent_name, use_cache=use_cache)

    # 2. Verify AgentAddr
    if not from_cache:
        addr_valid = verify_agent_addr(agent_addr, tamper=tamper)
        if not addr_valid:
            print(f"\n{RED}{BOLD}RESOLUTION FAILED — Tampered AgentAddr rejected.{RESET}\n")
            _print_timings()
            return

        # 2c. Revocation check
        if not check_revocation(agent_addr):
            print(f"\n{RED}{BOLD}RESOLUTION FAILED — Credential has been revoked.{RESET}\n")
            _print_timings()
            return

    # Determine facts URL — may require enterprise second hop
    facts_url = agent_addr["primary_facts_url"]

    if agent_addr.get("registration_type") == "enterprise-routed" and not from_cache:
        # 2d/2e: enterprise two-hop
        enterprise_addr = enterprise_second_hop(agent_addr)
        if not enterprise_addr:
            print(f"\n{RED}{BOLD}RESOLUTION FAILED — Enterprise hop failed.{RESET}\n")
            _print_timings()
            return
        facts_url = enterprise_addr["primary_facts_url"]

    # 3. Fetch AgentFacts
    facts = fetch_agent_facts(facts_url, use_private=use_private,
                              agent_addr=agent_addr if use_private else None)

    # 4. Verify AgentFacts
    facts_valid = verify_agent_facts(facts, tamper=tamper)
    if not facts_valid:
        print(f"\n{RED}{BOLD}RESOLUTION FAILED — Tampered AgentFacts rejected.{RESET}\n")
        _print_timings()
        return

    # 5. Endpoint
    show_endpoint(facts)

    print(f"\n{GREEN}{BOLD}✓ Resolution complete — agent verified and endpoint ready.{RESET}")
    print(f"{'='*62}")

    _print_timings()
    print()

    return {"agent_addr": agent_addr, "agent_facts": facts}


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_list(args):
    resp = requests.get(f"{REGISTRY_URL}/agents", timeout=5)
    resp.raise_for_status()
    agents = resp.json()
    print(f"\n{BOLD}Registered agents in NANDA Index:{RESET}")
    for a in agents:
        revoked_flag = f"  {RED}[REVOKED]{RESET}" if a.get("revoked") else ""
        print(f"  {GREEN}•{RESET} {a['agent_name']}  [{a['registration_type']}]  id={a['agent_id']}{revoked_flag}")
    print()


def cmd_resolve(args):
    full_resolve(
        agent_name=args.agent_name,
        use_private=args.private,
        tamper=args.tamper,
        use_cache=not args.no_cache,
    )


def cmd_cache_demo(args):
    """Resolve twice — second call shows TTL cache in action."""
    agent_name = args.agent_name
    print(f"\n{BOLD}Cache Demo — resolving '{agent_name}' twice{RESET}")
    print(f"{DIM}First call hits the network, second call serves from TTL cache.{RESET}")
    full_resolve(agent_name, use_cache=True)
    print(f"\n{YELLOW}{'─'*62}{RESET}")
    print(f"{YELLOW}Second resolve (should hit cache):{RESET}")
    full_resolve(agent_name, use_cache=True)


def cmd_revoke(args):
    """Revoke an agent credential and demonstrate the client refuses it."""
    resp = requests.post(
        f"{REGISTRY_URL}/revoke/{args.agent_id}",
        params={"reason": args.reason},
        timeout=5,
    )
    resp.raise_for_status()
    data = resp.json()
    print(f"\n{RED}{BOLD}✓ Agent {data['agent_id']} REVOKED{RESET}")
    print(f"  Reason: {data['reason']}")
    print(f"\n  Try resolving it now — the client will reject it:")
    print(f"  python client/resolver.py resolve <agent_name>  (should fail at revocation check)")
    print()


def cmd_unrevoke(args):
    resp = requests.post(f"{REGISTRY_URL}/unrevoke/{args.agent_id}", timeout=5)
    resp.raise_for_status()
    data = resp.json()
    print(f"\n{GREEN}✓ Agent {data['agent_id']} restored to ACTIVE{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="NANDA Index Client Resolver")
    sub = parser.add_subparsers()

    p_resolve = sub.add_parser("resolve", help="Resolve an agent name end-to-end")
    p_resolve.add_argument("agent_name")
    p_resolve.add_argument("--private", action="store_true", help="Use PrivateFactsURL path")
    p_resolve.add_argument("--tamper", action="store_true", help="Demonstrate tamper detection")
    p_resolve.add_argument("--no-cache", action="store_true", help="Bypass TTL cache")
    p_resolve.set_defaults(func=cmd_resolve)

    p_cache = sub.add_parser("cache-demo", help="Show TTL cache in action (resolves twice)")
    p_cache.add_argument("agent_name")
    p_cache.set_defaults(func=cmd_cache_demo)

    p_list = sub.add_parser("list", help="List registered agents")
    p_list.set_defaults(func=cmd_list)

    p_revoke = sub.add_parser("revoke", help="Revoke an agent credential")
    p_revoke.add_argument("agent_id", help="Agent ID (from /agents list)")
    p_revoke.add_argument("--reason", default="security-incident", help="Revocation reason")
    p_revoke.set_defaults(func=cmd_revoke)

    p_unrevoke = sub.add_parser("unrevoke", help="Restore a revoked agent")
    p_unrevoke.add_argument("agent_id")
    p_unrevoke.set_defaults(func=cmd_unrevoke)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
