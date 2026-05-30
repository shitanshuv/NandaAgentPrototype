"""
Shared cryptographic utilities for NANDA prototype.
Uses Ed25519 (RFC 8032) via the `cryptography` library.
Never roll your own crypto — this wraps established primitives only.
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate an Ed25519 keypair. Returns (private_key, public_key_b64)."""
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_b64 = base64.b64encode(public_bytes).decode()
    return private_key, public_b64


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    """Canonically serialize a dict and sign it. Returns base64 signature."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig_bytes = private_key.sign(canonical)
    return base64.b64encode(sig_bytes).decode()


def verify_payload(public_key_b64: str, payload: dict, signature_b64: str) -> bool:
    """
    Verify an Ed25519 signature over a canonically serialized dict.
    Returns True if valid, False if tampered or invalid.
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, canonical)
        return True
    except (InvalidSignature, Exception):
        return False


def serialize_private_key(private_key: Ed25519PrivateKey) -> str:
    """Serialize private key to base64 for storage/loading."""
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


def load_private_key(private_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from base64."""
    raw = base64.b64decode(private_b64)
    return Ed25519PrivateKey.from_private_bytes(raw)
