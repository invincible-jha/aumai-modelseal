"""Shared test fixtures for aumai-modelseal."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aumai_modelseal.core import KeyManager, ModelSigner
from aumai_modelseal.models import (
    ModelManifest,
    SignatureAlgorithm,
    SignedManifest,
    TrustedPublisher,
)

# ---------------------------------------------------------------------------
# Key-pair fixtures — one per algorithm
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def key_manager() -> KeyManager:
    """A shared KeyManager instance (stateless, safe to share)."""
    return KeyManager()


@pytest.fixture(scope="session")
def ed25519_keypair(key_manager: KeyManager) -> tuple[bytes, bytes]:
    """(private_pem, public_pem) for Ed25519."""
    return key_manager.generate_keypair(SignatureAlgorithm.ed25519)


@pytest.fixture(scope="session")
def ecdsa_p256_keypair(key_manager: KeyManager) -> tuple[bytes, bytes]:
    """(private_pem, public_pem) for ECDSA P-256."""
    return key_manager.generate_keypair(SignatureAlgorithm.ecdsa_p256)


# ---------------------------------------------------------------------------
# Temporary model-directory fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def model_dir(tmp_path: Path) -> Path:
    """A temporary directory that looks like a small ML model artifact.

    Structure:
        model.bin   — 256 bytes of pseudo-random data
        config.json — minimal JSON config
        subdir/
            weights.bin — 128 bytes
    """
    (tmp_path / "model.bin").write_bytes(bytes(range(256)))
    (tmp_path / "config.json").write_text(
        json.dumps({"layers": 4, "hidden_size": 128}), encoding="utf-8"
    )
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "weights.bin").write_bytes(bytes(range(128)))
    return tmp_path


@pytest.fixture()
def empty_model_dir(tmp_path: Path) -> Path:
    """A temporary directory with no files (edge case)."""
    empty = tmp_path / "empty_model"
    empty.mkdir()
    return empty


@pytest.fixture()
def single_file_model_dir(tmp_path: Path) -> Path:
    """A model directory containing exactly one file."""
    d = tmp_path / "single"
    d.mkdir()
    (d / "model.pt").write_bytes(b"pytorch-weights" * 10)
    return d


# ---------------------------------------------------------------------------
# Manifest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def model_manifest(model_dir: Path) -> ModelManifest:
    """A ModelManifest built from *model_dir*."""
    signer = ModelSigner()
    return signer.create_manifest(
        model_dir=str(model_dir),
        model_name="test-model",
        model_version="1.2.3",
        framework="pytorch",
        author="test-author",
        description="A test model",
    )


# ---------------------------------------------------------------------------
# Signed-manifest fixtures (one per algorithm)
# ---------------------------------------------------------------------------


@pytest.fixture()
def ed25519_signed_manifest(
    model_manifest: ModelManifest,
    ed25519_keypair: tuple[bytes, bytes],
) -> SignedManifest:
    """A SignedManifest produced with the Ed25519 key."""
    private_pem, _ = ed25519_keypair
    signer = ModelSigner()
    return signer.sign_manifest(
        model_manifest, private_pem, signer_id="test@example.com"
    )


@pytest.fixture()
def ecdsa_signed_manifest(
    model_manifest: ModelManifest,
    ecdsa_p256_keypair: tuple[bytes, bytes],
) -> SignedManifest:
    """A SignedManifest produced with the ECDSA P-256 key."""
    private_pem, _ = ecdsa_p256_keypair
    signer = ModelSigner()
    return signer.sign_manifest(
        model_manifest, private_pem, signer_id="ecdsa-signer@example.com"
    )


# ---------------------------------------------------------------------------
# TrustedPublisher fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def trusted_publisher_ed25519(ed25519_keypair: tuple[bytes, bytes]) -> TrustedPublisher:
    """A TrustedPublisher whose public key matches the session Ed25519 pair."""
    _, public_pem = ed25519_keypair
    return TrustedPublisher(
        publisher_id="test@example.com",
        name="Test Publisher",
        public_key=base64.b64encode(public_pem).decode("ascii"),
        trusted_since=datetime(2024, 1, 1, tzinfo=UTC),
    )


@pytest.fixture()
def trusted_publisher_ecdsa(
    ecdsa_p256_keypair: tuple[bytes, bytes],
) -> TrustedPublisher:
    """A TrustedPublisher whose public key matches the session ECDSA pair."""
    _, public_pem = ecdsa_p256_keypair
    return TrustedPublisher(
        publisher_id="ecdsa-signer@example.com",
        name="ECDSA Test Publisher",
        public_key=base64.b64encode(public_pem).decode("ascii"),
        trusted_since=datetime(2024, 1, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# On-disk key fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def saved_ed25519_keys(
    tmp_path: Path,
    ed25519_keypair: tuple[bytes, bytes],
    key_manager: KeyManager,
) -> tuple[Path, Path]:
    """Write the Ed25519 key pair to tmp_path; return (private, public) Paths."""
    keys_dir = tmp_path / "keys"
    private_pem, public_pem = ed25519_keypair
    key_manager.save_keypair(private_pem, public_pem, str(keys_dir))
    return keys_dir / "private.pem", keys_dir / "public.pem"
