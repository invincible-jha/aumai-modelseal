"""Tests for aumai_modelseal.registry — PublisherRegistry."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aumai_modelseal.core import KeyManager, ModelSigner
from aumai_modelseal.models import (
    SignatureAlgorithm,
    SignedManifest,
    TrustedPublisher,
)
from aumai_modelseal.registry import PublisherRegistry

# ===========================================================================
# CRUD operations
# ===========================================================================


class TestPublisherRegistryCRUD:
    def test_empty_registry_has_no_publishers(self) -> None:
        registry = PublisherRegistry()
        assert registry.list_publishers() == []

    def test_add_publisher_makes_it_retrievable(
        self, trusted_publisher_ed25519: TrustedPublisher
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        result = registry.get_publisher(trusted_publisher_ed25519.publisher_id)
        assert result is not None
        assert result.publisher_id == trusted_publisher_ed25519.publisher_id

    def test_get_missing_publisher_returns_none(self) -> None:
        registry = PublisherRegistry()
        assert registry.get_publisher("nonexistent-id") is None

    def test_list_publishers_returns_all_added(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        trusted_publisher_ecdsa: TrustedPublisher,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        registry.add_publisher(trusted_publisher_ecdsa)
        publishers = registry.list_publishers()
        assert len(publishers) == 2
        ids = {p.publisher_id for p in publishers}
        assert trusted_publisher_ed25519.publisher_id in ids
        assert trusted_publisher_ecdsa.publisher_id in ids

    def test_add_publisher_replaces_existing(
        self, trusted_publisher_ed25519: TrustedPublisher
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)

        updated = trusted_publisher_ed25519.model_copy(update={"name": "Updated Name"})
        registry.add_publisher(updated)

        result = registry.get_publisher(trusted_publisher_ed25519.publisher_id)
        assert result is not None
        assert result.name == "Updated Name"
        assert len(registry.list_publishers()) == 1  # still only one entry

    def test_remove_publisher_removes_it(
        self, trusted_publisher_ed25519: TrustedPublisher
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        registry.remove_publisher(trusted_publisher_ed25519.publisher_id)
        assert registry.get_publisher(trusted_publisher_ed25519.publisher_id) is None

    def test_remove_nonexistent_publisher_raises_key_error(self) -> None:
        registry = PublisherRegistry()
        with pytest.raises(KeyError, match="Publisher not found"):
            registry.remove_publisher("does-not-exist")

    def test_remove_leaves_other_publishers_intact(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        trusted_publisher_ecdsa: TrustedPublisher,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        registry.add_publisher(trusted_publisher_ecdsa)
        registry.remove_publisher(trusted_publisher_ed25519.publisher_id)

        assert registry.get_publisher(trusted_publisher_ed25519.publisher_id) is None
        assert registry.get_publisher(trusted_publisher_ecdsa.publisher_id) is not None

    def test_list_returns_list_type(self) -> None:
        registry = PublisherRegistry()
        result = registry.list_publishers()
        assert isinstance(result, list)


# ===========================================================================
# Persistence
# ===========================================================================


class TestPublisherRegistryPersistence:
    def test_add_publisher_writes_to_disk(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"
        registry = PublisherRegistry(str(registry_file))
        registry.add_publisher(trusted_publisher_ed25519)

        assert registry_file.exists()

    def test_persisted_json_is_valid(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"
        registry = PublisherRegistry(str(registry_file))
        registry.add_publisher(trusted_publisher_ed25519)

        raw = json.loads(registry_file.read_text(encoding="utf-8"))
        assert isinstance(raw, list)
        assert len(raw) == 1
        assert raw[0]["publisher_id"] == trusted_publisher_ed25519.publisher_id

    def test_loaded_registry_contains_saved_publisher(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"

        registry1 = PublisherRegistry(str(registry_file))
        registry1.add_publisher(trusted_publisher_ed25519)

        # New instance loading from same file
        registry2 = PublisherRegistry(str(registry_file))
        result = registry2.get_publisher(trusted_publisher_ed25519.publisher_id)
        assert result is not None
        assert result.name == trusted_publisher_ed25519.name

    def test_remove_publisher_persists_deletion(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
        trusted_publisher_ecdsa: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"

        registry1 = PublisherRegistry(str(registry_file))
        registry1.add_publisher(trusted_publisher_ed25519)
        registry1.add_publisher(trusted_publisher_ecdsa)
        registry1.remove_publisher(trusted_publisher_ed25519.publisher_id)

        registry2 = PublisherRegistry(str(registry_file))
        assert registry2.get_publisher(trusted_publisher_ed25519.publisher_id) is None
        assert registry2.get_publisher(trusted_publisher_ecdsa.publisher_id) is not None

    def test_no_path_registry_does_not_write_file(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry = PublisherRegistry()  # no path
        registry.add_publisher(trusted_publisher_ed25519)
        # No file should be written — nothing to assert on disk, just no exception

    def test_registry_creates_parent_dirs(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "nested" / "deep" / "registry.json"
        registry = PublisherRegistry(str(registry_file))
        registry.add_publisher(trusted_publisher_ed25519)
        assert registry_file.exists()

    def test_loading_nonexistent_file_starts_empty(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "does_not_exist.json"
        registry = PublisherRegistry(str(registry_file))
        assert registry.list_publishers() == []

    def test_multiple_publishers_persisted_and_restored(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
        trusted_publisher_ecdsa: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"
        registry1 = PublisherRegistry(str(registry_file))
        registry1.add_publisher(trusted_publisher_ed25519)
        registry1.add_publisher(trusted_publisher_ecdsa)

        registry2 = PublisherRegistry(str(registry_file))
        assert len(registry2.list_publishers()) == 2

    def test_public_key_survives_persistence_round_trip(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
    ) -> None:
        registry_file = tmp_path / "registry.json"
        registry1 = PublisherRegistry(str(registry_file))
        registry1.add_publisher(trusted_publisher_ed25519)

        registry2 = PublisherRegistry(str(registry_file))
        restored = registry2.get_publisher(trusted_publisher_ed25519.publisher_id)
        assert restored is not None
        assert restored.public_key == trusted_publisher_ed25519.public_key


# ===========================================================================
# verify_against_registry
# ===========================================================================


class TestPublisherRegistryVerify:
    def test_known_publisher_valid_signature_succeeds(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert result.valid is True

    def test_known_publisher_ecdsa_valid_signature_succeeds(
        self,
        trusted_publisher_ecdsa: TrustedPublisher,
        ecdsa_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ecdsa)
        result = registry.verify_against_registry(ecdsa_signed_manifest)
        assert result.valid is True

    def test_unknown_signer_returns_invalid(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert result.valid is False
        assert result.error is not None
        assert "not in the trusted publisher registry" in result.error

    def test_error_message_includes_signer_id(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert "test@example.com" in (result.error or "")

    def test_wrong_public_key_in_registry_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        # Register the signer_id with a completely different key
        km = KeyManager()
        _, wrong_public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)
        wrong_publisher = TrustedPublisher(
            publisher_id="test@example.com",
            name="Wrong Key Publisher",
            public_key=base64.b64encode(wrong_public_pem).decode("ascii"),
            trusted_since=datetime(2024, 1, 1, tzinfo=UTC),
        )
        registry = PublisherRegistry()
        registry.add_publisher(wrong_publisher)
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert result.valid is False

    def test_removed_publisher_cannot_verify(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        registry.remove_publisher(trusted_publisher_ed25519.publisher_id)
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert result.valid is False

    def test_valid_verification_includes_signer_id_in_result(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)
        result = registry.verify_against_registry(ed25519_signed_manifest)
        assert result.signer_id == "test@example.com"

    def test_verify_after_persist_and_reload(
        self,
        tmp_path: Path,
        trusted_publisher_ed25519: TrustedPublisher,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry_file = tmp_path / "registry.json"
        registry1 = PublisherRegistry(str(registry_file))
        registry1.add_publisher(trusted_publisher_ed25519)

        # New instance from disk
        registry2 = PublisherRegistry(str(registry_file))
        result = registry2.verify_against_registry(ed25519_signed_manifest)
        assert result.valid is True

    def test_tampered_manifest_fails_registry_verification(
        self,
        trusted_publisher_ed25519: TrustedPublisher,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        registry = PublisherRegistry()
        registry.add_publisher(trusted_publisher_ed25519)

        tampered_manifest = ed25519_signed_manifest.manifest.model_copy(
            update={"model_name": "tampered"}
        )
        tampered = SignedManifest(
            manifest=tampered_manifest,
            signature=ed25519_signed_manifest.signature,
        )
        result = registry.verify_against_registry(tampered)
        assert result.valid is False

    def test_full_pipeline_create_register_sign_verify(
        self,
        tmp_path: Path,
        model_dir: Path,
    ) -> None:
        """End-to-end: generate keys, register publisher, sign, verify via registry."""
        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)

        publisher = TrustedPublisher(
            publisher_id="pipeline-publisher@corp.example",
            name="Pipeline Publisher",
            public_key=base64.b64encode(public_pem).decode("ascii"),
            trusted_since=datetime.now(tz=UTC),
        )

        registry_file = tmp_path / "registry.json"
        registry = PublisherRegistry(str(registry_file))
        registry.add_publisher(publisher)

        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir), model_name="pipeline-model")
        signed = signer.sign_manifest(
            manifest, private_pem, signer_id="pipeline-publisher@corp.example"
        )

        result = registry.verify_against_registry(signed)
        assert result.valid is True
        assert result.signer_id == "pipeline-publisher@corp.example"
