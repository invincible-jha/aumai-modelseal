"""Signing and verification logic for ML model artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aumai_modelseal.models import (
    FileEntry,
    ModelManifest,
    Signature,
    SignatureAlgorithm,
    SignedManifest,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256_file(file_path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of *file_path*."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _canonical_manifest_bytes(manifest: ModelManifest) -> bytes:
    """Deterministic JSON serialisation of the manifest for signing."""
    data = manifest.model_dump(mode="json")
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------

class KeyManager:
    """Generate, persist, and load asymmetric key pairs."""

    def generate_keypair(
        self, algorithm: SignatureAlgorithm
    ) -> tuple[bytes, bytes]:
        """Generate a fresh key pair.

        Returns:
            A tuple of ``(private_key_bytes, public_key_bytes)`` in PEM format.
        """
        if algorithm == SignatureAlgorithm.ed25519:
            private_key = Ed25519PrivateKey.generate()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            ec_private_key = ec.generate_private_key(ec.SECP256R1())
            private_pem = ec_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = ec_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return private_pem, public_pem

    def save_keypair(
        self, private_key: bytes, public_key: bytes, path: str
    ) -> None:
        """Write the PEM-encoded key pair to *path*/private.pem and *path*/public.pem.

        The output directory is created if it does not exist.  The private key
        file is written with mode 0o600 on POSIX systems.
        """
        out_dir = Path(path)
        out_dir.mkdir(parents=True, exist_ok=True)

        private_file = out_dir / "private.pem"
        public_file = out_dir / "public.pem"

        private_file.write_bytes(private_key)
        public_file.write_bytes(public_key)

        # Restrict private key permissions on POSIX
        try:
            os.chmod(private_file, 0o600)
        except NotImplementedError:
            pass  # Windows — skip chmod

    def load_private_key(self, path: str) -> bytes:
        """Read and return raw PEM bytes from *path*."""
        return Path(path).read_bytes()

    def load_public_key(self, path: str) -> bytes:
        """Read and return raw PEM bytes from *path*."""
        return Path(path).read_bytes()


# ---------------------------------------------------------------------------
# ModelSigner
# ---------------------------------------------------------------------------

class ModelSigner:
    """Create manifests and sign them with a private key."""

    def create_manifest(
        self,
        model_dir: str,
        model_name: str = "",
        model_version: str = "0.0.0",
        framework: str = "unknown",
        author: str = "",
        description: str = "",
    ) -> ModelManifest:
        """Walk *model_dir* recursively and build a :class:`ModelManifest`.

        Every file is hashed with SHA-256.  Directories themselves are not
        included in the file list.
        """
        root = Path(model_dir)
        if not root.is_dir():
            raise ValueError(f"model_dir does not exist or is not a directory: {model_dir}")

        entries: list[FileEntry] = []
        total_bytes: int = 0

        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            relative = file_path.relative_to(root).as_posix()
            size = file_path.stat().st_size
            sha256 = _sha256_file(file_path)
            entries.append(FileEntry(path=relative, size_bytes=size, sha256_hash=sha256))
            total_bytes += size

        return ModelManifest(
            model_name=model_name or root.name,
            model_version=model_version,
            framework=framework,
            files=entries,
            total_size_bytes=total_bytes,
            created_at=datetime.now(tz=UTC),
            author=author,
            description=description,
        )

    def sign_manifest(
        self,
        manifest: ModelManifest,
        private_key_bytes: bytes,
        signer_id: str,
    ) -> SignedManifest:
        """Sign *manifest* with *private_key_bytes* (PEM).

        Returns:
            A :class:`SignedManifest` containing the original manifest and the
            detached :class:`Signature`.
        """
        payload = _canonical_manifest_bytes(manifest)

        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

        if isinstance(private_key, Ed25519PrivateKey):
            algorithm = SignatureAlgorithm.ed25519
            raw_sig = private_key.sign(payload)
            pub_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif isinstance(private_key, EllipticCurvePrivateKey):
            algorithm = SignatureAlgorithm.ecdsa_p256
            raw_sig = private_key.sign(payload, ECDSA(hashes.SHA256()))
            pub_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise ValueError(
                f"Unsupported key type: {type(private_key).__name__}. "
                "Only Ed25519 and ECDSA P-256 are supported."
            )

        public_key_b64 = base64.b64encode(pub_key_bytes).decode("ascii")
        signature_hex = raw_sig.hex()

        sig = Signature(
            algorithm=algorithm,
            public_key=public_key_b64,
            signature_hex=signature_hex,
            signed_at=datetime.now(tz=UTC),
            signer_id=signer_id,
        )
        return SignedManifest(manifest=manifest, signature=sig)


# ---------------------------------------------------------------------------
# ModelVerifier
# ---------------------------------------------------------------------------

class ModelVerifier:
    """Verify cryptographic signatures and on-disk file integrity."""

    def verify_manifest(
        self,
        signed_manifest: SignedManifest,
        public_key_bytes: bytes,
    ) -> VerificationResult:
        """Verify that the manifest was signed with the key matching *public_key_bytes*.

        Args:
            signed_manifest: The :class:`SignedManifest` to verify.
            public_key_bytes: PEM-encoded public key to verify against.

        Returns:
            A :class:`VerificationResult` indicating success or the error.
        """
        sig = signed_manifest.signature
        manifest = signed_manifest.manifest

        payload = _canonical_manifest_bytes(manifest)
        raw_sig = bytes.fromhex(sig.signature_hex)

        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
        except Exception as exc:
            return VerificationResult(
                valid=False, error=f"Failed to load public key: {exc}"
            )

        try:
            if isinstance(public_key, Ed25519PublicKey):
                public_key.verify(raw_sig, payload)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(raw_sig, payload, ECDSA(hashes.SHA256()))
            else:
                return VerificationResult(
                    valid=False,
                    error=f"Unsupported public key type: {type(public_key).__name__}",
                )
        except Exception as exc:
            return VerificationResult(
                valid=False, error=f"Signature verification failed: {exc}"
            )

        return VerificationResult(
            valid=True,
            manifest=manifest,
            signer_id=sig.signer_id,
        )

    def verify_files(
        self,
        model_dir: str,
        manifest: ModelManifest,
    ) -> list[tuple[str, bool]]:
        """Verify each file in *manifest* against its recorded SHA-256 hash.

        Args:
            model_dir: Root directory where the model files reside.
            manifest: The manifest describing expected files and hashes.

        Returns:
            A list of ``(relative_path, is_valid)`` tuples.  Missing files are
            reported as ``False``.
        """
        root = Path(model_dir)
        results: list[tuple[str, bool]] = []

        for entry in manifest.files:
            file_path = root / entry.path
            if not file_path.exists():
                results.append((entry.path, False))
                continue
            actual_hash = _sha256_file(file_path)
            results.append((entry.path, actual_hash == entry.sha256_hash))

        return results


__all__ = [
    "KeyManager",
    "ModelSigner",
    "ModelVerifier",
]
