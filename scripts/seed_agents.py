"""
Seed script — registers demo agents in the NANDA Index.
Run after all services are up (start.sh handles this automatically).

Service URLs are read from environment variables so the same script works
both locally (localhost) and inside Docker (service names as hostnames).
"""
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import generate_keypair

REGISTRY   = os.getenv("REGISTRY_URL",   "http://localhost:8000")
AGENT_HOST = os.getenv("AGENT_HOST_URL", "http://localhost:8001")
ENTERPRISE = os.getenv("ENTERPRISE_URL", "http://localhost:8002")

MAX_RETRIES = 15


def wait_for_registry():
    for i in range(MAX_RETRIES):
        try:
            r = requests.get(f"{REGISTRY}/health", timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        print(f"  Waiting for registry... ({i+1}/{MAX_RETRIES})")
        time.sleep(1)
    print("ERROR: Registry did not become healthy")
    sys.exit(1)


def register(payload: dict) -> dict:
    r = requests.post(f"{REGISTRY}/register", json=payload, timeout=5)
    if r.status_code == 409:
        print(f"  (already registered: {payload['agent_name']})")
        return {}
    r.raise_for_status()
    return r.json()


def main():
    print("Waiting for registry to be ready...")
    wait_for_registry()
    print("Registry ready.\n")

    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    _, pub3 = generate_keypair()

    agents = [
        {
            "agent_name": "urn:agent:nanda:TranslationAssistant",
            "primary_facts_url": f"{AGENT_HOST}/agents/translation/agent-facts",
            "private_facts_url": f"{AGENT_HOST}/agents/translation/private-facts",
            "adaptive_resolver_url": f"{AGENT_HOST}/agents/translation/resolve",
            "ttl": 3600,
            "owner_pubkey": pub1,
            "registration_type": "nanda-native",
            "capabilities": ["translation", "language-detection", "text", "audio"],
        },
        {
            "agent_name": "urn:agent:nanda:WeatherAgent",
            "primary_facts_url": f"{AGENT_HOST}/agents/weather/agent-facts",
            "private_facts_url": f"{AGENT_HOST}/agents/weather/private-facts",
            "ttl": 1800,
            "owner_pubkey": pub2,
            "registration_type": "nanda-native",
            "capabilities": ["weather", "forecast", "alerts", "json"],
        },
        {
            "agent_name": "urn:agent:acme:SalesAgent",
            "primary_facts_url": f"{ENTERPRISE}/enterprise/agents/sales/agent-facts",
            "enterprise_registry_url": f"{ENTERPRISE}/enterprise/resolve/urn:agent:acme:SalesAgent",
            "ttl": 1800,
            "owner_pubkey": pub3,
            "registration_type": "enterprise-routed",
            "capabilities": ["lead-qualification", "pipeline-analytics", "crm-sync", "json"],
        },
    ]

    for agent in agents:
        result = register(agent)
        if result:
            print(f"  ✓ Registered {agent['agent_name']}  [{agent['registration_type']}]  id={result.get('agent_id', '?')}")

    print("\nAll agents seeded.\n")


if __name__ == "__main__":
    main()
