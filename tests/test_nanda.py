"""
NANDA Prototype Test Suite
==========================
End-to-end tests against running services.
Covers: registration, resolution, AgentAddr verification, AgentFacts
verification, tamper detection, TTL, privacy path, enterprise two-hop,
revocation, and AgentFacts PATCH.

Run:  pytest tests/test_nanda.py -v
Pre-requisite: all services up and seeded (run start.sh first).
"""
import time
import pytest
import requests

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import verify_payload, generate_keypair

REGISTRY    = "http://localhost:8000"
AGENT_HOST  = "http://localhost:8001"
ENTERPRISE  = "http://localhost:8002"

TRANSLATION_NAME = "urn:agent:nanda:TranslationAssistant"
WEATHER_NAME     = "urn:agent:nanda:WeatherAgent"
SALES_NAME       = "urn:agent:acme:SalesAgent"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def registry_pubkey():
    r = requests.get(f"{REGISTRY}/pubkey")
    assert r.status_code == 200
    return r.json()["public_key_b64"]

@pytest.fixture(scope="session")
def enterprise_pubkey():
    r = requests.get(f"{ENTERPRISE}/enterprise/pubkey")
    assert r.status_code == 200
    return r.json()["public_key_b64"]

@pytest.fixture(scope="session")
def translation_addr():
    r = requests.get(f"{REGISTRY}/resolve/{TRANSLATION_NAME}")
    assert r.status_code == 200
    return r.json()

@pytest.fixture(scope="session")
def weather_addr():
    r = requests.get(f"{REGISTRY}/resolve/{WEATHER_NAME}")
    assert r.status_code == 200
    return r.json()

@pytest.fixture(scope="session")
def sales_addr():
    r = requests.get(f"{REGISTRY}/resolve/{SALES_NAME}")
    assert r.status_code == 200
    return r.json()

@pytest.fixture(scope="session")
def translation_facts(translation_addr):
    r = requests.get(translation_addr["primary_facts_url"])
    assert r.status_code == 200
    return r.json()

@pytest.fixture(scope="session")
def weather_facts(weather_addr):
    r = requests.get(weather_addr["primary_facts_url"])
    assert r.status_code == 200
    return r.json()


# ---------------------------------------------------------------------------
# Service health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_registry_healthy(self):
        r = requests.get(f"{REGISTRY}/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_agent_host_healthy(self):
        r = requests.get(f"{AGENT_HOST}/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_enterprise_registry_healthy(self):
        r = requests.get(f"{ENTERPRISE}/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_nanda_agents_registered(self):
        r = requests.get(f"{REGISTRY}/agents")
        names = [a["agent_name"] for a in r.json()]
        assert TRANSLATION_NAME in names
        assert WEATHER_NAME in names

    def test_enterprise_agent_registered(self):
        r = requests.get(f"{REGISTRY}/agents")
        names = [a["agent_name"] for a in r.json()]
        assert SALES_NAME in names

    def test_enterprise_agent_has_correct_type(self):
        r = requests.get(f"{REGISTRY}/agents")
        sales = next(a for a in r.json() if a["agent_name"] == SALES_NAME)
        assert sales["registration_type"] == "enterprise-routed"

    def test_duplicate_registration_rejected(self):
        _, pub = generate_keypair()
        r = requests.post(f"{REGISTRY}/register", json={
            "agent_name": TRANSLATION_NAME,
            "primary_facts_url": "http://example.com/facts",
            "owner_pubkey": pub,
        })
        assert r.status_code == 409

    def test_registry_pubkey_exposed(self):
        r = requests.get(f"{REGISTRY}/pubkey")
        assert r.status_code == 200
        assert r.json()["algorithm"] == "Ed25519"


# ---------------------------------------------------------------------------
# AgentAddr resolution
# ---------------------------------------------------------------------------

class TestAgentAddrResolution:
    def test_resolve_translation(self, translation_addr):
        assert translation_addr["agent_name"] == TRANSLATION_NAME
        assert translation_addr["registration_type"] == "nanda-native"
        assert translation_addr["ttl"] > 0
        assert "signature" in translation_addr

    def test_resolve_weather(self, weather_addr):
        assert weather_addr["agent_name"] == WEATHER_NAME
        assert weather_addr["ttl"] == 1800

    def test_resolve_sales_enterprise(self, sales_addr):
        assert sales_addr["agent_name"] == SALES_NAME
        assert sales_addr["registration_type"] == "enterprise-routed"
        assert sales_addr.get("enterprise_registry_url") is not None

    def test_resolve_unknown_returns_404(self):
        r = requests.get(f"{REGISTRY}/resolve/urn:agent:nanda:DoesNotExist")
        assert r.status_code == 404

    def test_ttl_and_expiry(self, translation_addr):
        now = int(time.time())
        assert translation_addr["expires_at"] > now
        assert translation_addr["expires_at"] - translation_addr["issued_at"] == translation_addr["ttl"]

    def test_agents_have_different_ids(self, translation_addr, weather_addr):
        assert translation_addr["agent_id"] != weather_addr["agent_id"]


# ---------------------------------------------------------------------------
# Crypto verification — AgentAddr
# ---------------------------------------------------------------------------

class TestAgentAddrVerification:
    def test_valid_signature(self, translation_addr, registry_pubkey):
        sig = translation_addr["signature"]
        payload = {k: v for k, v in translation_addr.items() if k != "signature"}
        assert verify_payload(registry_pubkey, payload, sig)

    def test_tampered_agent_id_fails(self, translation_addr, registry_pubkey):
        sig = translation_addr["signature"]
        payload = {**{k: v for k, v in translation_addr.items() if k != "signature"},
                   "agent_id": "nanda:EVIL"}
        assert not verify_payload(registry_pubkey, payload, sig)

    def test_tampered_facts_url_fails(self, translation_addr, registry_pubkey):
        sig = translation_addr["signature"]
        payload = {**{k: v for k, v in translation_addr.items() if k != "signature"},
                   "primary_facts_url": "http://evil.example.com/steal"}
        assert not verify_payload(registry_pubkey, payload, sig)

    def test_wrong_key_fails(self, translation_addr):
        _, wrong = generate_keypair()
        sig = translation_addr["signature"]
        payload = {k: v for k, v in translation_addr.items() if k != "signature"}
        assert not verify_payload(wrong, payload, sig)

    def test_weather_addr_valid(self, weather_addr, registry_pubkey):
        sig = weather_addr["signature"]
        payload = {k: v for k, v in weather_addr.items() if k != "signature"}
        assert verify_payload(registry_pubkey, payload, sig)


# ---------------------------------------------------------------------------
# Enterprise two-hop resolution
# ---------------------------------------------------------------------------

class TestEnterpriseResolution:
    def test_enterprise_registry_lists_sales_agent(self):
        r = requests.get(f"{ENTERPRISE}/enterprise/agents")
        assert r.status_code == 200
        names = [a["agent_name"] for a in r.json()]
        assert SALES_NAME in names

    def test_enterprise_resolve_returns_addr(self, enterprise_pubkey):
        r = requests.get(f"{ENTERPRISE}/enterprise/resolve/{SALES_NAME}")
        assert r.status_code == 200
        addr = r.json()
        assert addr["agent_name"] == SALES_NAME
        assert addr["registration_type"] == "enterprise-routed"
        assert "signature" in addr

    def test_enterprise_addr_signature_valid(self, enterprise_pubkey):
        r = requests.get(f"{ENTERPRISE}/enterprise/resolve/{SALES_NAME}")
        addr = r.json()
        sig = addr["signature"]
        payload = {k: v for k, v in addr.items() if k != "signature"}
        assert verify_payload(enterprise_pubkey, payload, sig)

    def test_enterprise_facts_reachable(self):
        r = requests.get(f"{ENTERPRISE}/enterprise/resolve/{SALES_NAME}")
        facts_url = r.json()["primary_facts_url"]
        rf = requests.get(facts_url)
        assert rf.status_code == 200
        facts = rf.json()
        assert facts["agent_name"] == SALES_NAME
        assert "proof" in facts

    def test_enterprise_facts_signature_valid(self):
        r = requests.get(f"{ENTERPRISE}/enterprise/resolve/{SALES_NAME}")
        facts_url = r.json()["primary_facts_url"]
        facts = requests.get(facts_url).json()
        sig = facts["proof"]["signature"]
        payload = {k: v for k, v in facts.items() if k != "proof"}
        assert verify_payload(facts["agent_public_key"], payload, sig)

    def test_full_two_hop_chain(self, sales_addr, registry_pubkey, enterprise_pubkey):
        """Full end-to-end: NANDA Index → Enterprise Registry → AgentFacts (two signatures verified)."""
        # Verify NANDA Index sig
        sig = sales_addr["signature"]
        payload = {k: v for k, v in sales_addr.items() if k != "signature"}
        assert verify_payload(registry_pubkey, payload, sig)

        # Enterprise hop
        ent_url = sales_addr["enterprise_registry_url"]
        ent_r = requests.get(ent_url)
        ent_addr = ent_r.json()
        ent_sig = ent_addr["signature"]
        ent_payload = {k: v for k, v in ent_addr.items() if k != "signature"}
        assert verify_payload(enterprise_pubkey, ent_payload, ent_sig)

        # AgentFacts
        facts = requests.get(ent_addr["primary_facts_url"]).json()
        f_sig = facts["proof"]["signature"]
        f_payload = {k: v for k, v in facts.items() if k != "proof"}
        assert verify_payload(facts["agent_public_key"], f_payload, f_sig)


# ---------------------------------------------------------------------------
# AgentFacts
# ---------------------------------------------------------------------------

class TestAgentFacts:
    def test_translation_facts_schema(self, translation_facts):
        assert translation_facts["agent_name"] == TRANSLATION_NAME
        assert "capabilities" in translation_facts
        assert "skills" in translation_facts
        assert "endpoints" in translation_facts
        assert "proof" in translation_facts

    def test_weather_facts_schema(self, weather_facts):
        assert weather_facts["agent_name"] == WEATHER_NAME
        skill_ids = [s["id"] for s in weather_facts["skills"]]
        assert "current-weather" in skill_ids

    def test_facts_valid_signature(self, translation_facts):
        proof = translation_facts["proof"]
        payload = {k: v for k, v in translation_facts.items() if k != "proof"}
        assert verify_payload(translation_facts["agent_public_key"], payload, proof["signature"])

    def test_tampered_facts_detected(self, translation_facts):
        sig = translation_facts["proof"]["signature"]
        payload = {**{k: v for k, v in translation_facts.items() if k != "proof"},
                   "evaluations": {**translation_facts.get("evaluations", {}), "performance_score": 9.9}}
        assert not verify_payload(translation_facts["agent_public_key"], payload, sig)

    def test_facts_json_ld_context(self, translation_facts):
        assert "@context" in translation_facts
        assert "VerifiableCredential" in translation_facts.get("type", [])

    def test_facts_have_ttl(self, translation_facts):
        assert translation_facts.get("ttl", 0) > 0

    def test_agents_have_different_pubkeys(self, translation_facts, weather_facts):
        assert translation_facts["agent_public_key"] != weather_facts["agent_public_key"]


# ---------------------------------------------------------------------------
# AgentFacts PATCH (decoupled update flow)
# ---------------------------------------------------------------------------

class TestAgentFactsUpdate:
    def test_patch_updates_facts_without_index_change(self):
        """Update AgentFacts in-place — the index is never touched."""
        r = requests.patch(
            f"{AGENT_HOST}/agents/translation/agent-facts",
            json={"updates": {"evaluations": {"performance_score": 4.9, "availability_90d": "99.99%",
                                               "last_audited": "2025-06-01T00:00:00Z",
                                               "auditor_id": "NANDA-Audit-v1"}}}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "updated"
        assert "evaluations" in data["applied_overrides"]

    def test_patched_facts_have_valid_new_signature(self):
        """After PATCH, fresh fetch should still have a valid signature."""
        requests.patch(
            f"{AGENT_HOST}/agents/translation/agent-facts",
            json={"updates": {"version": "1.2.2"}}
        )
        facts = requests.get(f"{AGENT_HOST}/agents/translation/agent-facts").json()
        assert facts.get("version") == "1.2.2"
        payload = {k: v for k, v in facts.items() if k != "proof"}
        assert verify_payload(facts["agent_public_key"], payload, facts["proof"]["signature"])


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_status_active_before_revoke(self, translation_addr):
        r = requests.get(f"{REGISTRY}/status/{translation_addr['agent_id']}")
        assert r.status_code == 200
        assert r.json()["status"] == "active"

    def test_revoke_and_check_status(self):
        # Register a throwaway agent
        _, pub = generate_keypair()
        reg = requests.post(f"{REGISTRY}/register", json={
            "agent_name": "urn:agent:test:ThrowawayAgent",
            "primary_facts_url": "http://localhost:8001/agents/translation/agent-facts",
            "owner_pubkey": pub,
        })
        if reg.status_code not in (201, 409):
            pytest.skip("Could not register throwaway agent")
        agent_id = reg.json().get("agent_id") or requests.get(
            f"{REGISTRY}/resolve/urn:agent:test:ThrowawayAgent"
        ).json()["agent_id"]

        # Revoke
        r = requests.post(f"{REGISTRY}/revoke/{agent_id}", params={"reason": "test-revocation"})
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

        # Confirm status
        s = requests.get(f"{REGISTRY}/status/{agent_id}").json()
        assert s["status"] == "revoked"
        assert s["revocation_reason"] == "test-revocation"

    def test_unrevoke_restores_active(self):
        r = requests.get(f"{REGISTRY}/agents")
        agents = r.json()
        throwaway = next((a for a in agents if "Throwaway" in a.get("agent_name", "")), None)
        if not throwaway:
            pytest.skip("Throwaway agent not found")
        agent_id = throwaway["agent_id"]
        requests.post(f"{REGISTRY}/revoke/{agent_id}", params={"reason": "test"})
        requests.post(f"{REGISTRY}/unrevoke/{agent_id}")
        s = requests.get(f"{REGISTRY}/status/{agent_id}").json()
        assert s["status"] == "active"

    def test_revoke_nonexistent_returns_404(self):
        r = requests.post(f"{REGISTRY}/revoke/nanda:does-not-exist")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Privacy path
# ---------------------------------------------------------------------------

class TestPrivacyPath:
    def test_private_facts_reachable(self, translation_addr):
        assert translation_addr.get("private_facts_url") is not None
        r = requests.get(translation_addr["private_facts_url"])
        assert r.status_code == 200

    def test_private_facts_same_identity(self, translation_addr, translation_facts):
        r = requests.get(translation_addr["private_facts_url"])
        private = r.json()
        assert private["agent_name"] == translation_facts["agent_name"]
        assert private["version"] == translation_facts["version"]


# ---------------------------------------------------------------------------
# Full end-to-end chains
# ---------------------------------------------------------------------------

class TestFullChains:
    def test_full_chain_translation(self, registry_pubkey):
        addr = requests.get(f"{REGISTRY}/resolve/{TRANSLATION_NAME}").json()
        sig = addr["signature"]
        payload = {k: v for k, v in addr.items() if k != "signature"}
        assert verify_payload(registry_pubkey, payload, sig)
        facts = requests.get(addr["primary_facts_url"]).json()
        f_payload = {k: v for k, v in facts.items() if k != "proof"}
        assert verify_payload(facts["agent_public_key"], f_payload, facts["proof"]["signature"])

    def test_full_chain_weather(self, registry_pubkey):
        addr = requests.get(f"{REGISTRY}/resolve/{WEATHER_NAME}").json()
        sig = addr["signature"]
        payload = {k: v for k, v in addr.items() if k != "signature"}
        assert verify_payload(registry_pubkey, payload, sig)
        facts = requests.get(addr["primary_facts_url"]).json()
        f_payload = {k: v for k, v in facts.items() if k != "proof"}
        assert verify_payload(facts["agent_public_key"], f_payload, facts["proof"]["signature"])
