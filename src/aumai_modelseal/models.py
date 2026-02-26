"""Pydantic models for aumai-modelseal."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SignatureAlgorithm(str, Enum):
    """Asymmetric signing algorithm choices."""

    ed25519 = "ed25519"
    ecdsa_p256 = "ecdsa_p256"


class FileEntry(BaseModel):
    """Metadata and integrity hash for a single file in a model artifact."""

    path: str
    size_bytes: int = Field(ge=0)
    sha256_hash: str = Field(min_length=64, max_length=64)


class ModelManifest(BaseModel):
    """Human-readable + machine-verifiable description of a model artifact."""

    model_name: str
    model_version: str
    framework: str
    files: list[FileEntry] = Field(default_factory=list)
    total_size_bytes: int = Field(ge=0)
    created_at: datetime
    author: str
    description: str = ""


class Signature(BaseModel):
    """Cryptographic signature over a serialised :class:`ModelManifest`."""

    algorithm: SignatureAlgorithm
    public_key: str  # Base-64 encoded DER/raw public key bytes
    signature_hex: str
    signed_at: datetime
    signer_id: str


class SignedManifest(BaseModel):
    """Bundle that pairs a manifest with its detached signature."""

    manifest: ModelManifest
    signature: Signature


class VerificationResult(BaseModel):
    """Outcome of a signature or file-integrity verification attempt."""

    valid: bool
    manifest: ModelManifest | None = None
    signer_id: str | None = None
    error: str | None = None


class TrustedPublisher(BaseModel):
    """A publisher whose signing key has been added to the trust registry."""

    publisher_id: str
    name: str
    public_key: str  # Base-64 encoded
    trusted_since: datetime


__all__ = [
    "FileEntry",
    "ModelManifest",
    "Signature",
    "SignatureAlgorithm",
    "SignedManifest",
    "TrustedPublisher",
    "VerificationResult",
]
