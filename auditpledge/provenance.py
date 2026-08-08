"""Cryptographic provenance for MCP tools: Ed25519 over a canonical manifest entry.

An MCP tool manifest is attacker-controlled data. A tool that merely *claims* a
publisher and *claims* a signature proves nothing, so AuditPledge verifies:

  1. the publisher string is normalised and matched **exactly** against a keyring
     (no suffix matching: `attacker.compound-finance` is not `compound-finance`);
  2. the detached signature verifies, with that publisher's Ed25519 public key,
     over the canonical bytes of the tool entry (name, version, publisher,
     sorted scopes, sorted ops).

Anything else fails closed: `verified=False`, and the auditor treats the tool as
unsigned. Tampering with any covered field (adding an op, widening a scope,
bumping a version) invalidates the signature, which is what `tests/` pins.

The demo publishers' *private* seeds live in `demo_keys.py` and exist only so the
offline demo manifest carries genuine signatures a reviewer can break by editing
one character. Real publishers hold their own keys; AuditPledge only ever needs
the public half, which is what `data/keyring.json` stores.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised by the "verifier unavailable" path
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

# Covered by the signature. Adding a field here invalidates every existing
# signature by design.
SIGNED_FIELDS = ("name", "version", "publisher", "scopes", "ops")


def normalize_publisher(publisher: Any) -> str:
    """Fold a publisher string to its comparison form. Exact match only."""
    return str(publisher or "").strip().lower().strip(".")


def canonical_bytes(tool: dict[str, Any]) -> bytes:
    """Deterministic bytes a publisher signs. Order-independent, whitespace-free."""
    payload = {
        "name": str(tool.get("name") or ""),
        "version": str(tool.get("version") or ""),
        "publisher": normalize_publisher(tool.get("publisher")),
        "scopes": sorted(str(s) for s in (tool.get("scopes") or [])),
        "ops": sorted(str(o) for o in (tool.get("ops") or [])),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ProvenanceResult:
    """Outcome of verifying one tool entry. `verified` is the only trust signal."""

    verified: bool
    signature_present: bool
    publisher_known: bool
    publisher: str
    reason: str

    @property
    def finding(self) -> str:
        return self.reason


class Keyring:
    """Publisher -> Ed25519 public key. Exact, normalised publisher bindings."""

    def __init__(self, keys: dict[str, str] | None = None) -> None:
        self._keys: dict[str, bytes] = {}
        for publisher, hex_key in (keys or {}).items():
            self.add(publisher, hex_key)

    def add(self, publisher: str, public_key_hex: str) -> None:
        raw = bytes.fromhex(public_key_hex)
        if len(raw) != 32:
            raise ValueError(f"Ed25519 public key for {publisher!r} must be 32 bytes, got {len(raw)}")
        self._keys[normalize_publisher(publisher)] = raw

    def __contains__(self, publisher: Any) -> bool:
        return normalize_publisher(publisher) in self._keys

    @property
    def publishers(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def verify(self, tool: dict[str, Any]) -> ProvenanceResult:
        """Verify one tool entry. Fails closed on every ambiguous path."""
        publisher = normalize_publisher(tool.get("publisher"))
        signature = tool.get("signature")
        present = bool(signature)

        if not present:
            return ProvenanceResult(False, False, publisher in self._keys, publisher,
                                    "unsigned (no detached signature)")
        if not _CRYPTO_AVAILABLE:  # pragma: no cover
            return ProvenanceResult(False, True, publisher in self._keys, publisher,
                                    "signature UNVERIFIED (cryptography not installed; failing closed)")

        key = self._keys.get(publisher)
        if key is None:
            return ProvenanceResult(False, True, False, publisher,
                                    f"signature UNVERIFIABLE: publisher '{tool.get('publisher')}' "
                                    f"has no key in the AuditPledge keyring")
        try:
            sig = bytes.fromhex(str(signature))
        except ValueError:
            return ProvenanceResult(False, True, True, publisher,
                                    "signature INVALID: not hex-encoded")
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, canonical_bytes(tool))
        except InvalidSignature:
            return ProvenanceResult(False, True, True, publisher,
                                    "signature INVALID: does not verify over the tool's "
                                    "canonical bytes (manifest tampered or re-signed)")
        except Exception as exc:
            return ProvenanceResult(False, True, True, publisher,
                                    f"signature INVALID: {exc.__class__.__name__}")
        return ProvenanceResult(True, True, True, publisher,
                                f"signature verified against publisher key '{publisher}'")


# --- committed public keyring ------------------------------------------------
# `data/keyring.json` holds public halves only. The verifier never imports the
# signing module, so the trust path depends on committed public keys alone.
# Regenerate with: python -m auditpledge.demo_keys --write-keyring

KEYRING_PATH = Path(__file__).with_name("data") / "keyring.json"


def load_keyring(path: Path | None = None) -> Keyring:
    """Load the committed publisher keyring. Missing file -> empty (fails closed)."""
    p = path or KEYRING_PATH
    if not p.exists():
        return Keyring()
    doc = json.loads(p.read_text(encoding="utf-8"))
    return Keyring(doc.get("publishers", {}))


DEFAULT_KEYRING = load_keyring()
