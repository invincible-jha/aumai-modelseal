"""Trusted publisher registry for aumai-modelseal."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from aumai_modelseal.core import ModelVerifier
from aumai_modelseal.models import (
    SignedManifest,
    TrustedPublisher,
    VerificationResult,
)


class PublisherRegistry:
    """Trusted publisher key registry with JSON file persistence.

    Maintain a set of trusted publishers and verify manifests against them.
    All mutating operations persist the change immediately to ensure durability.

    Security note: The registry file is stored as plain JSON without integrity
    protection.  An attacker with write access to the registry file can substitute
    public keys, allowing them to forge signatures that will pass verification.
    For production deployments, protect the registry file with filesystem-level
    access controls (e.g. read-only for the service account) and consider adding
    HMAC-based integrity verification over the serialised registry contents.
    """

    def __init__(self, registry_path: str | None = None) -> None:
        self._registry_path = Path(registry_path) if registry_path else None
        self._publishers: dict[str, TrustedPublisher] = {}

        if self._registry_path and self._registry_path.exists():
            self._load()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_publisher(self, publisher: TrustedPublisher) -> None:
        """Add or replace a trusted publisher entry."""
        self._publishers[publisher.publisher_id] = publisher
        self._save()

    def remove_publisher(self, publisher_id: str) -> None:
        """Remove a publisher from the trust registry.

        Raises:
            KeyError: if the publisher_id is not in the registry.
        """
        if publisher_id not in self._publishers:
            raise KeyError(f"Publisher not found: {publisher_id}")
        del self._publishers[publisher_id]
        self._save()

    def get_publisher(self, publisher_id: str) -> TrustedPublisher | None:
        """Return the :class:`TrustedPublisher` for *publisher_id*, or None."""
        return self._publishers.get(publisher_id)

    def list_publishers(self) -> list[TrustedPublisher]:
        """Return all trusted publishers."""
        return list(self._publishers.values())

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_against_registry(
        self, signed_manifest: SignedManifest
    ) -> VerificationResult:
        """Verify *signed_manifest* against the matching trusted publisher.

        The signer_id in the manifest's signature must correspond to a known
        publisher whose stored public key validates the signature.

        Returns:
            A :class:`VerificationResult`.  If the signer is unknown the result
            is invalid but contains a descriptive error message.
        """
        signer_id = signed_manifest.signature.signer_id
        publisher = self._publishers.get(signer_id)

        if publisher is None:
            return VerificationResult(
                valid=False,
                error=f"Signer '{signer_id}' is not in the trusted publisher registry.",
            )

        public_key_pem = base64.b64decode(publisher.public_key)
        verifier = ModelVerifier()
        return verifier.verify_manifest(signed_manifest, public_key_pem)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        if self._registry_path is None:
            return
        self._registry_path.parent.mkdir(parents=True, exist_ok=True)
        data = [p.model_dump(mode="json") for p in self._publishers.values()]
        self._registry_path.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )

    def _load(self) -> None:
        if self._registry_path is None or not self._registry_path.exists():
            return
        raw = json.loads(self._registry_path.read_text(encoding="utf-8"))
        for entry in raw:
            publisher = TrustedPublisher(**entry)
            self._publishers[publisher.publisher_id] = publisher


__all__ = ["PublisherRegistry"]
