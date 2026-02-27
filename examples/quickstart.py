"""aumai-modelseal quickstart — working demonstrations of all major features.

Run this file directly to verify your installation and see all features in action:

    python examples/quickstart.py

Each demo function is self-contained and creates temporary files in the system
temp directory, cleaning up after itself.
"""

from __future__ import annotations

import base64
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from aumai_modelseal import (
    KeyManager,
    ModelSigner,
    ModelVerifier,
    PublisherRegistry,
    SignatureAlgorithm,
    SignedManifest,
    TrustedPublisher,
)


# ---------------------------------------------------------------------------
# Demo 1 — Ed25519 key generation, signing, and verification
# ---------------------------------------------------------------------------

def demo_sign_and_verify_ed25519() -> None:
    """Demonstrate the full sign-verify lifecycle with Ed25519 (the default)."""

    print("\n=== Demo 1: Ed25519 Sign & Verify ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Create a mock model directory with two files
        model_dir = tmp / "my-model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps({"architecture": "transformer", "vocab_size": 32000}),
            encoding="utf-8",
        )
        (model_dir / "weights.bin").write_bytes(b"\x00" * 1024)

        # Generate a key pair
        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)
        keys_dir = tmp / "keys"
        km.save_keypair(private_pem, public_pem, str(keys_dir))
        print(f"  Key pair written to: {keys_dir}/")

        # Build a manifest from the model directory
        signer = ModelSigner()
        manifest = signer.create_manifest(
            model_dir=str(model_dir),
            model_name="demo-transformer",
            model_version="1.0.0",
            framework="pytorch",
            author="Demo Author",
            description="A demo model for quickstart.",
        )
        print(f"  Manifest built: {len(manifest.files)} files, "
              f"{manifest.total_size_bytes:,} bytes total")

        # Sign the manifest
        private_key_bytes = km.load_private_key(str(keys_dir / "private.pem"))
        signed = signer.sign_manifest(
            manifest=manifest,
            private_key_bytes=private_key_bytes,
            signer_id="demo@aumai.dev",
        )
        print(f"  Signed by: {signed.signature.signer_id} "
              f"({signed.signature.algorithm.value})")

        # Persist the signed manifest
        manifest_path = tmp / "signed_manifest.json"
        manifest_path.write_text(signed.model_dump_json(indent=2), encoding="utf-8")

        # Verify the signature
        verifier = ModelVerifier()
        public_key_bytes = km.load_public_key(str(keys_dir / "public.pem"))
        result = verifier.verify_manifest(signed, public_key_bytes)
        print(f"  Signature valid: {result.valid}")
        assert result.valid, f"Unexpected failure: {result.error}"

        # Verify on-disk file hashes
        file_results = verifier.verify_files(str(model_dir), manifest)
        for path, ok in file_results:
            print(f"  File {'OK  ' if ok else 'FAIL'}: {path}")
        assert all(ok for _, ok in file_results), "File verification failed"

        print("  Demo 1 passed.")


# ---------------------------------------------------------------------------
# Demo 2 — ECDSA P-256 signing
# ---------------------------------------------------------------------------

def demo_ecdsa_signing() -> None:
    """Demonstrate signing and verification with ECDSA P-256."""

    print("\n=== Demo 2: ECDSA P-256 Signing ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Single-file model
        model_dir = tmp / "ecdsa-model"
        model_dir.mkdir()
        (model_dir / "model.onnx").write_bytes(b"\x00" * 512)

        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ecdsa_p256)
        keys_dir = tmp / "ecdsa-keys"
        km.save_keypair(private_pem, public_pem, str(keys_dir))
        print(f"  ECDSA P-256 keys written to: {keys_dir}/")

        signer = ModelSigner()
        manifest = signer.create_manifest(
            model_dir=str(model_dir),
            model_name="onnx-export",
            model_version="0.5.0",
            framework="onnx",
        )

        private_key_bytes = km.load_private_key(str(keys_dir / "private.pem"))
        signed = signer.sign_manifest(manifest, private_key_bytes, signer_id="hsm@myorg.com")
        print(f"  Algorithm used: {signed.signature.algorithm.value}")

        verifier = ModelVerifier()
        public_key_bytes = km.load_public_key(str(keys_dir / "public.pem"))
        result = verifier.verify_manifest(signed, public_key_bytes)
        print(f"  Signature valid: {result.valid}")
        assert result.valid, f"Unexpected failure: {result.error}"

        print("  Demo 2 passed.")


# ---------------------------------------------------------------------------
# Demo 3 — Tamper detection
# ---------------------------------------------------------------------------

def demo_tamper_detection() -> None:
    """Show that modifying a file after signing is detected by verify_files."""

    print("\n=== Demo 3: Tamper Detection ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        model_dir = tmp / "model"
        model_dir.mkdir()
        config_file = model_dir / "config.json"
        config_file.write_text('{"vocab_size": 32000}', encoding="utf-8")
        (model_dir / "weights.bin").write_bytes(b"\x00" * 256)

        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)
        keys_dir = tmp / "keys"
        km.save_keypair(private_pem, public_pem, str(keys_dir))

        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        private_key_bytes = km.load_private_key(str(keys_dir / "private.pem"))
        signed = signer.sign_manifest(manifest, private_key_bytes, signer_id="alice@aumai.dev")

        # Simulate tampering by appending to a file
        config_file.write_text('{"vocab_size": 99999}', encoding="utf-8")
        print("  config.json modified (simulated tamper)")

        # Signature on the manifest should still pass (manifest not changed)
        verifier = ModelVerifier()
        public_key_bytes = km.load_public_key(str(keys_dir / "public.pem"))
        sig_result = verifier.verify_manifest(signed, public_key_bytes)
        print(f"  Signature valid: {sig_result.valid}  (expected True — manifest unchanged)")
        assert sig_result.valid

        # File hash check should detect the tampered file
        file_results = verifier.verify_files(str(model_dir), manifest)
        failed = [path for path, ok in file_results if not ok]
        print(f"  Failed file hash checks: {failed}  (expected ['config.json'])")
        assert "config.json" in failed, f"Expected tamper not detected: {failed}"

        print("  Demo 3 passed.")


# ---------------------------------------------------------------------------
# Demo 4 — Passphrase-protected keys
# ---------------------------------------------------------------------------

def demo_passphrase_protected_keys() -> None:
    """Demonstrate encrypted private key generation and use."""

    print("\n=== Demo 4: Passphrase-Protected Keys ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        model_dir = tmp / "model"
        model_dir.mkdir()
        (model_dir / "tokenizer.json").write_bytes(b"x" * 128)

        passphrase = b"v3ry-s3cr3t"

        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(
            SignatureAlgorithm.ed25519,
            passphrase=passphrase,
        )
        keys_dir = tmp / "protected-keys"
        km.save_keypair(private_pem, public_pem, str(keys_dir))
        print("  Passphrase-protected key pair generated.")

        # Must supply the passphrase to load the private key
        private_key_bytes = km.load_private_key(
            str(keys_dir / "private.pem"),
            password=passphrase,
        )
        print("  Private key loaded successfully with correct passphrase.")

        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        # Must also supply password to sign_manifest
        signed = signer.sign_manifest(
            manifest=manifest,
            private_key_bytes=private_key_bytes,
            signer_id="protected@aumai.dev",
            password=passphrase,
        )

        verifier = ModelVerifier()
        public_key_bytes = km.load_public_key(str(keys_dir / "public.pem"))
        result = verifier.verify_manifest(signed, public_key_bytes)
        print(f"  Signature valid: {result.valid}")
        assert result.valid

        print("  Demo 4 passed.")


# ---------------------------------------------------------------------------
# Demo 5 — Trusted publisher registry
# ---------------------------------------------------------------------------

def demo_publisher_registry() -> None:
    """Demonstrate the PublisherRegistry for multi-publisher verification."""

    print("\n=== Demo 5: Publisher Registry ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        model_dir = tmp / "model"
        model_dir.mkdir()
        (model_dir / "weights.bin").write_bytes(b"\xff" * 64)

        # Publisher generates and signs
        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)
        keys_dir = tmp / "keys"
        km.save_keypair(private_pem, public_pem, str(keys_dir))

        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir), model_name="registry-demo")
        private_key_bytes = km.load_private_key(str(keys_dir / "private.pem"))
        signed = signer.sign_manifest(manifest, private_key_bytes, signer_id="alice@aumai.dev")

        # Consumer sets up a registry and registers the publisher
        registry_path = str(tmp / "registry.json")
        registry = PublisherRegistry(registry_path=registry_path)

        publisher = TrustedPublisher(
            publisher_id="alice@aumai.dev",
            name="Alice (Research Lab)",
            public_key=base64.b64encode(public_pem).decode(),
            trusted_since=datetime.now(tz=UTC),
        )
        registry.add_publisher(publisher)
        print(f"  Registered publishers: {[p.publisher_id for p in registry.list_publishers()]}")

        # Verify against registry — no need to specify the public key manually
        result = registry.verify_against_registry(signed)
        print(f"  Registry verification valid: {result.valid}")
        assert result.valid

        # Try with an unknown signer
        unknown_signed = SignedManifest(
            manifest=signed.manifest,
            signature=signed.signature.model_copy(update={"signer_id": "unknown@attacker.com"}),
        )
        result2 = registry.verify_against_registry(unknown_signed)
        print(f"  Unknown signer rejected: {not result2.valid}  (error: {result2.error})")
        assert not result2.valid

        print("  Demo 5 passed.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all quickstart demos in sequence."""
    print("aumai-modelseal quickstart demos")
    print("=" * 45)

    demo_sign_and_verify_ed25519()
    demo_ecdsa_signing()
    demo_tamper_detection()
    demo_passphrase_protected_keys()
    demo_publisher_registry()

    print("\n" + "=" * 45)
    print("All demos completed successfully.")


if __name__ == "__main__":
    main()
