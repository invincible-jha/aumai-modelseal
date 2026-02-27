"""Tests for Pydantic models in aumai_modelseal.models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aumai_modelseal.models import (
    FileEntry,
    ModelManifest,
    Signature,
    SignatureAlgorithm,
    SignedManifest,
    TrustedPublisher,
    VerificationResult,
)

# ---------------------------------------------------------------------------
# SignatureAlgorithm
# ---------------------------------------------------------------------------


class TestSignatureAlgorithm:
    def test_ed25519_value(self) -> None:
        assert SignatureAlgorithm.ed25519.value == "ed25519"

    def test_ecdsa_p256_value(self) -> None:
        assert SignatureAlgorithm.ecdsa_p256.value == "ecdsa_p256"

    def test_is_string_enum(self) -> None:
        assert isinstance(SignatureAlgorithm.ed25519, str)

    def test_round_trip_from_string(self) -> None:
        assert SignatureAlgorithm("ed25519") == SignatureAlgorithm.ed25519
        assert SignatureAlgorithm("ecdsa_p256") == SignatureAlgorithm.ecdsa_p256

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            SignatureAlgorithm("rsa2048")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# FileEntry
# ---------------------------------------------------------------------------


class TestFileEntry:
    def test_valid_entry(self) -> None:
        entry = FileEntry(path="model.bin", size_bytes=1024, sha256_hash="a" * 64)
        assert entry.path == "model.bin"
        assert entry.size_bytes == 1024
        assert entry.sha256_hash == "a" * 64

    def test_zero_size_is_valid(self) -> None:
        entry = FileEntry(path="empty.txt", size_bytes=0, sha256_hash="b" * 64)
        assert entry.size_bytes == 0

    def test_negative_size_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FileEntry(path="x", size_bytes=-1, sha256_hash="c" * 64)

    def test_short_hash_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FileEntry(path="x", size_bytes=0, sha256_hash="abc")

    def test_long_hash_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FileEntry(path="x", size_bytes=0, sha256_hash="d" * 65)

    def test_exactly_64_char_hash_accepted(self) -> None:
        entry = FileEntry(path="x", size_bytes=0, sha256_hash="e" * 64)
        assert len(entry.sha256_hash) == 64

    def test_nested_path_accepted(self) -> None:
        entry = FileEntry(
            path="subdir/weights.bin", size_bytes=512, sha256_hash="f" * 64
        )
        assert entry.path == "subdir/weights.bin"


# ---------------------------------------------------------------------------
# ModelManifest
# ---------------------------------------------------------------------------


def _sample_manifest(**overrides: object) -> ModelManifest:
    defaults: dict[str, object] = {
        "model_name": "my-model",
        "model_version": "1.0.0",
        "framework": "pytorch",
        "files": [],
        "total_size_bytes": 0,
        "created_at": datetime(2024, 6, 1, tzinfo=UTC),
        "author": "Alice",
        "description": "A test manifest",
    }
    defaults.update(overrides)
    return ModelManifest(**defaults)  # type: ignore[arg-type]


class TestModelManifest:
    def test_minimal_valid_manifest(self) -> None:
        m = _sample_manifest()
        assert m.model_name == "my-model"
        assert m.files == []

    def test_default_description_is_empty_string(self) -> None:
        m = _sample_manifest(description="")
        assert m.description == ""

    def test_files_populated(self) -> None:
        files = [
            FileEntry(path="a.bin", size_bytes=100, sha256_hash="a" * 64),
            FileEntry(path="b.bin", size_bytes=200, sha256_hash="b" * 64),
        ]
        m = _sample_manifest(files=files, total_size_bytes=300)
        assert len(m.files) == 2
        assert m.total_size_bytes == 300

    def test_negative_total_size_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _sample_manifest(total_size_bytes=-1)

    def test_model_dump_round_trip(self) -> None:
        m = _sample_manifest()
        dumped = m.model_dump(mode="json")
        restored = ModelManifest(**dumped)
        assert restored.model_name == m.model_name
        assert restored.model_version == m.model_version


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


def _sample_signature(**overrides: object) -> Signature:
    defaults: dict[str, object] = {
        "algorithm": SignatureAlgorithm.ed25519,
        "public_key": "base64encodedpublickey==",
        "signature_hex": "deadbeef" * 8,
        "signed_at": datetime(2024, 6, 1, tzinfo=UTC),
        "signer_id": "alice@example.com",
    }
    defaults.update(overrides)
    return Signature(**defaults)  # type: ignore[arg-type]


class TestSignature:
    def test_valid_signature(self) -> None:
        sig = _sample_signature()
        assert sig.signer_id == "alice@example.com"
        assert sig.algorithm == SignatureAlgorithm.ed25519

    def test_ecdsa_algorithm(self) -> None:
        sig = _sample_signature(algorithm=SignatureAlgorithm.ecdsa_p256)
        assert sig.algorithm == SignatureAlgorithm.ecdsa_p256

    def test_model_dump_preserves_algorithm(self) -> None:
        sig = _sample_signature()
        dumped = sig.model_dump(mode="json")
        assert dumped["algorithm"] == "ed25519"


# ---------------------------------------------------------------------------
# SignedManifest
# ---------------------------------------------------------------------------


class TestSignedManifest:
    def test_valid_signed_manifest(self) -> None:
        manifest = _sample_manifest()
        sig = _sample_signature()
        sm = SignedManifest(manifest=manifest, signature=sig)
        assert sm.manifest.model_name == "my-model"
        assert sm.signature.signer_id == "alice@example.com"

    def test_json_round_trip(self) -> None:
        manifest = _sample_manifest()
        sig = _sample_signature()
        sm = SignedManifest(manifest=manifest, signature=sig)
        json_str = sm.model_dump_json()
        restored = SignedManifest.model_validate_json(json_str)
        assert restored.manifest.model_name == sm.manifest.model_name
        assert restored.signature.signer_id == sm.signature.signer_id


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_valid_result_no_error(self) -> None:
        result = VerificationResult(valid=True, signer_id="alice@example.com")
        assert result.valid is True
        assert result.error is None

    def test_invalid_result_with_error(self) -> None:
        result = VerificationResult(valid=False, error="Signature mismatch")
        assert result.valid is False
        assert result.error == "Signature mismatch"

    def test_valid_result_with_manifest(self) -> None:
        manifest = _sample_manifest()
        result = VerificationResult(valid=True, manifest=manifest)
        assert result.manifest is not None
        assert result.manifest.model_name == "my-model"

    def test_defaults_are_none(self) -> None:
        result = VerificationResult(valid=False)
        assert result.manifest is None
        assert result.signer_id is None
        assert result.error is None


# ---------------------------------------------------------------------------
# TrustedPublisher
# ---------------------------------------------------------------------------


class TestTrustedPublisher:
    def test_valid_publisher(self) -> None:
        pub = TrustedPublisher(
            publisher_id="alice",
            name="Alice Corp",
            public_key="base64key==",
            trusted_since=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert pub.publisher_id == "alice"
        assert pub.name == "Alice Corp"

    def test_model_dump_round_trip(self) -> None:
        pub = TrustedPublisher(
            publisher_id="bob",
            name="Bob Ltd",
            public_key="key==",
            trusted_since=datetime(2024, 6, 15, tzinfo=UTC),
        )
        dumped = pub.model_dump(mode="json")
        restored = TrustedPublisher(**dumped)
        assert restored.publisher_id == "bob"
