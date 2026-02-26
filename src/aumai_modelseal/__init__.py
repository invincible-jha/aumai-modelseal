"""aumai-modelseal: Cryptographic signing and verification for ML model artifacts."""

from aumai_modelseal.core import KeyManager, ModelSigner, ModelVerifier
from aumai_modelseal.models import (
    FileEntry,
    ModelManifest,
    Signature,
    SignatureAlgorithm,
    SignedManifest,
    TrustedPublisher,
    VerificationResult,
)
from aumai_modelseal.registry import PublisherRegistry

__version__ = "0.1.0"

__all__ = [
    "FileEntry",
    "KeyManager",
    "ModelManifest",
    "ModelSigner",
    "ModelVerifier",
    "PublisherRegistry",
    "Signature",
    "SignatureAlgorithm",
    "SignedManifest",
    "TrustedPublisher",
    "VerificationResult",
]
