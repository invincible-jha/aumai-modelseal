"""Tests for aumai_modelseal.core — KeyManager, ModelSigner, ModelVerifier."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from aumai_modelseal.core import KeyManager, ModelSigner, ModelVerifier, _sha256_file
from aumai_modelseal.models import (
    ModelManifest,
    SignatureAlgorithm,
    SignedManifest,
)

# ===========================================================================
# KeyManager
# ===========================================================================


class TestKeyManagerGenerate:
    def test_ed25519_returns_pem_bytes(self, key_manager: KeyManager) -> None:
        private_pem, public_pem = key_manager.generate_keypair(
            SignatureAlgorithm.ed25519
        )
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_ecdsa_p256_returns_pem_bytes(self, key_manager: KeyManager) -> None:
        private_pem, public_pem = key_manager.generate_keypair(
            SignatureAlgorithm.ecdsa_p256
        )
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_ed25519_private_key_is_loadable(
        self, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _ = ed25519_keypair
        key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(key, ed25519.Ed25519PrivateKey)

    def test_ecdsa_private_key_is_loadable(
        self, ecdsa_p256_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _ = ecdsa_p256_keypair
        key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_ed25519_public_key_is_loadable(
        self, ed25519_keypair: tuple[bytes, bytes]
    ) -> None:
        _, public_pem = ed25519_keypair
        key = serialization.load_pem_public_key(public_pem)
        assert isinstance(key, ed25519.Ed25519PublicKey)

    def test_ecdsa_public_key_is_loadable(
        self, ecdsa_p256_keypair: tuple[bytes, bytes]
    ) -> None:
        _, public_pem = ecdsa_p256_keypair
        key = serialization.load_pem_public_key(public_pem)
        assert isinstance(key, ec.EllipticCurvePublicKey)

    def test_each_call_generates_distinct_key(self, key_manager: KeyManager) -> None:
        priv1, _ = key_manager.generate_keypair(SignatureAlgorithm.ed25519)
        priv2, _ = key_manager.generate_keypair(SignatureAlgorithm.ed25519)
        assert priv1 != priv2

    def test_ecdsa_each_call_distinct(self, key_manager: KeyManager) -> None:
        priv1, _ = key_manager.generate_keypair(SignatureAlgorithm.ecdsa_p256)
        priv2, _ = key_manager.generate_keypair(SignatureAlgorithm.ecdsa_p256)
        assert priv1 != priv2


class TestKeyManagerPersistence:
    def test_save_creates_private_and_public_pem(
        self,
        tmp_path: Path,
        ed25519_keypair: tuple[bytes, bytes],
        key_manager: KeyManager,
    ) -> None:
        private_pem, public_pem = ed25519_keypair
        keys_dir = str(tmp_path / "keys")
        key_manager.save_keypair(private_pem, public_pem, keys_dir)

        assert (tmp_path / "keys" / "private.pem").exists()
        assert (tmp_path / "keys" / "public.pem").exists()

    def test_save_creates_parent_directory(
        self,
        tmp_path: Path,
        ed25519_keypair: tuple[bytes, bytes],
        key_manager: KeyManager,
    ) -> None:
        private_pem, public_pem = ed25519_keypair
        nested_dir = str(tmp_path / "deep" / "nested" / "keys")
        key_manager.save_keypair(private_pem, public_pem, nested_dir)
        assert (Path(nested_dir) / "private.pem").exists()

    def test_load_private_key_round_trip(
        self,
        saved_ed25519_keys: tuple[Path, Path],
        ed25519_keypair: tuple[bytes, bytes],
        key_manager: KeyManager,
    ) -> None:
        private_path, _ = saved_ed25519_keys
        original_private, _ = ed25519_keypair
        loaded = key_manager.load_private_key(str(private_path))
        assert loaded == original_private

    def test_load_public_key_round_trip(
        self,
        saved_ed25519_keys: tuple[Path, Path],
        ed25519_keypair: tuple[bytes, bytes],
        key_manager: KeyManager,
    ) -> None:
        _, public_path = saved_ed25519_keys
        _, original_public = ed25519_keypair
        loaded = key_manager.load_public_key(str(public_path))
        assert loaded == original_public

    def test_load_private_key_missing_file_raises(
        self, key_manager: KeyManager
    ) -> None:
        with pytest.raises((FileNotFoundError, OSError)):
            key_manager.load_private_key("/nonexistent/path/private.pem")

    def test_load_public_key_missing_file_raises(
        self, key_manager: KeyManager
    ) -> None:
        with pytest.raises((FileNotFoundError, OSError)):
            key_manager.load_public_key("/nonexistent/path/public.pem")

    def test_saved_content_matches_original(
        self,
        tmp_path: Path,
        ecdsa_p256_keypair: tuple[bytes, bytes],
        key_manager: KeyManager,
    ) -> None:
        private_pem, public_pem = ecdsa_p256_keypair
        key_manager.save_keypair(private_pem, public_pem, str(tmp_path / "k"))
        assert (tmp_path / "k" / "private.pem").read_bytes() == private_pem
        assert (tmp_path / "k" / "public.pem").read_bytes() == public_pem


# ===========================================================================
# Internal helpers
# ===========================================================================


class TestSha256File:
    def test_known_digest(self, tmp_path: Path) -> None:
        import hashlib

        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        assert _sha256_file(f) == expected

    def test_empty_file_digest(self, tmp_path: Path) -> None:
        import hashlib

        expected = hashlib.sha256(b"").hexdigest()
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert _sha256_file(f) == expected

    def test_different_content_gives_different_digest(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.bin"
        f2 = tmp_path / "b.bin"
        f1.write_bytes(b"content-a")
        f2.write_bytes(b"content-b")
        assert _sha256_file(f1) != _sha256_file(f2)


# ===========================================================================
# ModelSigner.create_manifest
# ===========================================================================


class TestModelSignerCreateManifest:
    def test_returns_model_manifest(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        assert isinstance(manifest, ModelManifest)

    def test_file_count_matches_directory(self, model_dir: Path) -> None:
        # model_dir fixture has 3 files: model.bin, config.json, subdir/weights.bin
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        assert len(manifest.files) == 3

    def test_files_are_sorted_by_path(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        paths = [entry.path for entry in manifest.files]
        assert paths == sorted(paths)

    def test_file_sizes_are_correct(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        size_map = {entry.path: entry.size_bytes for entry in manifest.files}
        assert size_map["model.bin"] == 256
        assert size_map["subdir/weights.bin"] == 128

    def test_total_size_is_sum_of_file_sizes(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        computed_total = sum(entry.size_bytes for entry in manifest.files)
        assert manifest.total_size_bytes == computed_total

    def test_sha256_hashes_are_64_chars(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        for entry in manifest.files:
            assert len(entry.sha256_hash) == 64

    def test_custom_model_name_used(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir), model_name="my-custom-model")
        assert manifest.model_name == "my-custom-model"

    def test_default_model_name_is_dir_name(self, tmp_path: Path) -> None:
        named_dir = tmp_path / "gpt2-small"
        named_dir.mkdir()
        (named_dir / "a.bin").write_bytes(b"x")
        signer = ModelSigner()
        manifest = signer.create_manifest(str(named_dir))
        assert manifest.model_name == "gpt2-small"

    def test_custom_version_and_framework(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(
            str(model_dir), model_version="2.0.1", framework="tensorflow"
        )
        assert manifest.model_version == "2.0.1"
        assert manifest.framework == "tensorflow"

    def test_author_and_description_stored(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(
            str(model_dir), author="Dr Smith", description="Research model"
        )
        assert manifest.author == "Dr Smith"
        assert manifest.description == "Research model"

    def test_empty_directory_produces_no_files(self, empty_model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(empty_model_dir))
        assert manifest.files == []
        assert manifest.total_size_bytes == 0

    def test_nonexistent_dir_raises_value_error(self) -> None:
        signer = ModelSigner()
        with pytest.raises(ValueError, match="model_dir does not exist"):
            signer.create_manifest("/nonexistent/path/that/does/not/exist")

    def test_file_as_model_dir_raises_value_error(self, tmp_path: Path) -> None:
        a_file = tmp_path / "not_a_dir.txt"
        a_file.write_text("hello")
        signer = ModelSigner()
        with pytest.raises(ValueError, match="model_dir does not exist"):
            signer.create_manifest(str(a_file))

    def test_paths_use_forward_slashes(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        for entry in manifest.files:
            assert "\\" not in entry.path

    def test_created_at_is_timezone_aware(self, model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        assert manifest.created_at.tzinfo is not None

    def test_single_file_model(self, single_file_model_dir: Path) -> None:
        signer = ModelSigner()
        manifest = signer.create_manifest(str(single_file_model_dir))
        assert len(manifest.files) == 1
        assert manifest.files[0].path == "model.pt"


# ===========================================================================
# ModelSigner.sign_manifest
# ===========================================================================


class TestModelSignerSignManifest:
    def test_sign_ed25519_returns_signed_manifest(
        self,
        model_manifest: ModelManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        private_pem, _ = ed25519_keypair
        signer = ModelSigner()
        signed = signer.sign_manifest(
            model_manifest, private_pem, signer_id="alice@example.com"
        )
        assert isinstance(signed, SignedManifest)

    def test_sign_ecdsa_returns_signed_manifest(
        self,
        model_manifest: ModelManifest,
        ecdsa_p256_keypair: tuple[bytes, bytes],
    ) -> None:
        private_pem, _ = ecdsa_p256_keypair
        signer = ModelSigner()
        signed = signer.sign_manifest(
            model_manifest, private_pem, signer_id="bob@example.com"
        )
        assert isinstance(signed, SignedManifest)

    def test_ed25519_algorithm_recorded(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        assert ed25519_signed_manifest.signature.algorithm == SignatureAlgorithm.ed25519

    def test_ecdsa_algorithm_recorded(
        self,
        ecdsa_signed_manifest: SignedManifest,
    ) -> None:
        assert (
            ecdsa_signed_manifest.signature.algorithm == SignatureAlgorithm.ecdsa_p256
        )

    def test_signer_id_stored_in_signature(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        assert ed25519_signed_manifest.signature.signer_id == "test@example.com"

    def test_manifest_preserved_in_signed_bundle(
        self,
        model_manifest: ModelManifest,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        assert ed25519_signed_manifest.manifest.model_name == model_manifest.model_name
        assert ed25519_signed_manifest.manifest.files == model_manifest.files

    def test_signature_hex_is_non_empty(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        assert len(ed25519_signed_manifest.signature.signature_hex) > 0

    def test_public_key_in_signature_is_base64(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        # Must be valid base64 — should not raise
        decoded = base64.b64decode(ed25519_signed_manifest.signature.public_key)
        assert len(decoded) > 0

    def test_signed_at_is_timezone_aware(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        assert ed25519_signed_manifest.signature.signed_at.tzinfo is not None

    def test_unsupported_key_type_raises(
        self,
        model_manifest: ModelManifest,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        signer = ModelSigner()
        with pytest.raises(ValueError, match="Unsupported key type"):
            signer.sign_manifest(model_manifest, rsa_private_pem, signer_id="x")

    def test_two_ed25519_signatures_on_same_manifest_differ(
        self,
        model_manifest: ModelManifest,
    ) -> None:
        """Ed25519 signatures are deterministic only for the same key+message."""
        km = KeyManager()
        priv1, _ = km.generate_keypair(SignatureAlgorithm.ed25519)
        priv2, _ = km.generate_keypair(SignatureAlgorithm.ed25519)
        signer = ModelSigner()
        s1 = signer.sign_manifest(model_manifest, priv1, signer_id="a")
        s2 = signer.sign_manifest(model_manifest, priv2, signer_id="b")
        assert s1.signature.signature_hex != s2.signature.signature_hex

    def test_ecdsa_signature_hex_parseable_as_bytes(
        self,
        ecdsa_signed_manifest: SignedManifest,
    ) -> None:
        raw = bytes.fromhex(ecdsa_signed_manifest.signature.signature_hex)
        assert len(raw) > 0


# ===========================================================================
# ModelVerifier.verify_manifest
# ===========================================================================


class TestModelVerifierVerifyManifest:
    def test_ed25519_valid_signature(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, public_pem)
        assert result.valid is True
        assert result.error is None

    def test_ecdsa_valid_signature(
        self,
        ecdsa_signed_manifest: SignedManifest,
        ecdsa_p256_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ecdsa_p256_keypair
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ecdsa_signed_manifest, public_pem)
        assert result.valid is True

    def test_valid_result_contains_signer_id(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, public_pem)
        assert result.signer_id == "test@example.com"

    def test_valid_result_contains_manifest(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, public_pem)
        assert result.manifest is not None
        assert result.manifest.model_name == "test-model"

    def test_wrong_public_key_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
        key_manager: KeyManager,
    ) -> None:
        # Generate a completely different key pair
        _, wrong_public_pem = key_manager.generate_keypair(SignatureAlgorithm.ed25519)
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, wrong_public_pem)
        assert result.valid is False
        assert result.error is not None

    def test_ecdsa_wrong_public_key_fails(
        self,
        ecdsa_signed_manifest: SignedManifest,
        key_manager: KeyManager,
    ) -> None:
        _, wrong_public_pem = key_manager.generate_keypair(
            SignatureAlgorithm.ecdsa_p256
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ecdsa_signed_manifest, wrong_public_pem)
        assert result.valid is False

    def test_tampered_signature_hex_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        # Flip a character in the hex string to corrupt the signature
        original_hex = ed25519_signed_manifest.signature.signature_hex
        tampered_hex = ("0" if original_hex[0] != "0" else "1") + original_hex[1:]
        tampered_sig = ed25519_signed_manifest.signature.model_copy(
            update={"signature_hex": tampered_hex}
        )
        tampered = SignedManifest(
            manifest=ed25519_signed_manifest.manifest, signature=tampered_sig
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(tampered, public_pem)
        assert result.valid is False

    def test_tampered_manifest_model_name_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        tampered_manifest = ed25519_signed_manifest.manifest.model_copy(
            update={"model_name": "hacked-model"}
        )
        tampered = SignedManifest(
            manifest=tampered_manifest, signature=ed25519_signed_manifest.signature
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(tampered, public_pem)
        assert result.valid is False

    def test_tampered_manifest_file_hash_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        _, public_pem = ed25519_keypair
        original_files = ed25519_signed_manifest.manifest.files
        # Replace first file entry's hash with garbage
        tampered_entry = original_files[0].model_copy(update={"sha256_hash": "f" * 64})
        tampered_files = [tampered_entry] + original_files[1:]
        tampered_manifest = ed25519_signed_manifest.manifest.model_copy(
            update={"files": tampered_files}
        )
        tampered = SignedManifest(
            manifest=tampered_manifest, signature=ed25519_signed_manifest.signature
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(tampered, public_pem)
        assert result.valid is False

    def test_invalid_pem_public_key_returns_invalid(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        verifier = ModelVerifier()
        result = verifier.verify_manifest(
            ed25519_signed_manifest, b"not-valid-pem-at-all"
        )
        assert result.valid is False
        assert result.error is not None
        assert "Failed to load public key" in result.error

    def test_wrong_algorithm_key_fails(
        self,
        ed25519_signed_manifest: SignedManifest,
        ecdsa_p256_keypair: tuple[bytes, bytes],
    ) -> None:
        # Try to verify an Ed25519 signature with an ECDSA public key
        _, ecdsa_public_pem = ecdsa_p256_keypair
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, ecdsa_public_pem)
        assert result.valid is False

    def test_cross_algorithm_signing_fails_verification(
        self,
        ed25519_keypair: tuple[bytes, bytes],
        ecdsa_p256_keypair: tuple[bytes, bytes],
        model_manifest: ModelManifest,
    ) -> None:
        """Sign with Ed25519, verify with ECDSA public key — must fail."""
        ed_priv, _ = ed25519_keypair
        _, ecdsa_pub = ecdsa_p256_keypair
        signer = ModelSigner()
        signed = signer.sign_manifest(model_manifest, ed_priv, signer_id="x")
        verifier = ModelVerifier()
        result = verifier.verify_manifest(signed, ecdsa_pub)
        assert result.valid is False

    def test_unsupported_public_key_type_returns_invalid(
        self,
        ed25519_signed_manifest: SignedManifest,
    ) -> None:
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_public_pem = rsa_key.public_key().public_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(ed25519_signed_manifest, rsa_public_pem)
        assert result.valid is False
        assert result.error is not None


# ===========================================================================
# ModelVerifier.verify_files
# ===========================================================================


class TestModelVerifierVerifyFiles:
    def test_all_files_valid_after_signing(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        assert all(ok for _, ok in results)

    def test_returns_one_result_per_manifest_file(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        assert len(results) == len(model_manifest.files)

    def test_tampered_file_detected(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        # Overwrite a file with different content
        (model_dir / "model.bin").write_bytes(b"\x00" * 256)
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        result_map = dict(results)
        assert result_map["model.bin"] is False

    def test_missing_file_reported_as_false(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        (model_dir / "model.bin").unlink()
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        result_map = dict(results)
        assert result_map["model.bin"] is False

    def test_unchanged_files_still_valid_after_one_tampered(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        # Tamper only model.bin; config.json and subdir/weights.bin should still pass
        (model_dir / "model.bin").write_bytes(b"tampered")
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        result_map = dict(results)
        assert result_map.get("config.json") is True
        assert result_map.get("subdir/weights.bin") is True

    def test_empty_manifest_returns_empty_list(
        self,
        model_dir: Path,
    ) -> None:
        from datetime import UTC, datetime

        empty_manifest = ModelManifest(
            model_name="x",
            model_version="1.0",
            framework="none",
            files=[],
            total_size_bytes=0,
            created_at=datetime.now(tz=UTC),
            author="",
        )
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), empty_manifest)
        assert results == []

    def test_relative_paths_in_results_match_manifest(
        self,
        model_dir: Path,
        model_manifest: ModelManifest,
    ) -> None:
        verifier = ModelVerifier()
        results = verifier.verify_files(str(model_dir), model_manifest)
        result_paths = {path for path, _ in results}
        manifest_paths = {entry.path for entry in model_manifest.files}
        assert result_paths == manifest_paths


# ===========================================================================
# Round-trip integration
# ===========================================================================


_BOTH_ALGOS = [SignatureAlgorithm.ed25519, SignatureAlgorithm.ecdsa_p256]


class TestSignVerifyRoundTrip:
    @pytest.mark.parametrize("algorithm", _BOTH_ALGOS)
    def test_sign_then_verify_succeeds(
        self,
        model_dir: Path,
        algorithm: SignatureAlgorithm,
    ) -> None:
        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(algorithm)
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir), model_name="rt-model")
        signed = signer.sign_manifest(
            manifest, private_pem, signer_id="roundtrip@test.com"
        )

        verifier = ModelVerifier()
        result = verifier.verify_manifest(signed, public_pem)

        assert result.valid is True
        assert result.signer_id == "roundtrip@test.com"

    @pytest.mark.parametrize("algorithm", _BOTH_ALGOS)
    def test_json_serialise_deserialise_round_trip(
        self,
        model_dir: Path,
        algorithm: SignatureAlgorithm,
    ) -> None:
        km = KeyManager()
        private_pem, public_pem = km.generate_keypair(algorithm)
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        signed = signer.sign_manifest(manifest, private_pem, signer_id="json@test.com")

        # Serialise → deserialise → verify
        json_str = signed.model_dump_json()
        restored = SignedManifest.model_validate_json(json_str)

        verifier = ModelVerifier()
        result = verifier.verify_manifest(restored, public_pem)
        assert result.valid is True

    def test_manifest_written_to_disk_and_loaded(
        self,
        tmp_path: Path,
        model_dir: Path,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        private_pem, public_pem = ed25519_keypair
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        signed = signer.sign_manifest(manifest, private_pem, signer_id="disk@test.com")

        manifest_file = tmp_path / "signed_manifest.json"
        manifest_file.write_text(signed.model_dump_json(indent=2), encoding="utf-8")

        restored = SignedManifest.model_validate_json(
            manifest_file.read_text(encoding="utf-8")
        )
        verifier = ModelVerifier()
        result = verifier.verify_manifest(restored, public_pem)
        assert result.valid is True

    def test_full_pipeline_sign_verify_files(
        self,
        model_dir: Path,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        private_pem, public_pem = ed25519_keypair
        signer = ModelSigner()
        manifest = signer.create_manifest(str(model_dir))
        signed = signer.sign_manifest(
            manifest, private_pem, signer_id="pipeline@test.com"
        )

        verifier = ModelVerifier()
        sig_result = verifier.verify_manifest(signed, public_pem)
        assert sig_result.valid is True

        file_results = verifier.verify_files(str(model_dir), signed.manifest)
        assert all(ok for _, ok in file_results)

    def test_canonical_json_is_deterministic(
        self,
        model_manifest: ModelManifest,
    ) -> None:
        from aumai_modelseal.core import _canonical_manifest_bytes

        b1 = _canonical_manifest_bytes(model_manifest)
        b2 = _canonical_manifest_bytes(model_manifest)
        assert b1 == b2

    def test_canonical_json_changes_when_manifest_changes(
        self,
        model_manifest: ModelManifest,
    ) -> None:
        from aumai_modelseal.core import _canonical_manifest_bytes

        original_bytes = _canonical_manifest_bytes(model_manifest)
        modified = model_manifest.model_copy(update={"model_name": "different-name"})
        modified_bytes = _canonical_manifest_bytes(modified)
        assert original_bytes != modified_bytes

    def test_canonical_json_is_valid_json(
        self,
        model_manifest: ModelManifest,
    ) -> None:
        from aumai_modelseal.core import _canonical_manifest_bytes

        raw = _canonical_manifest_bytes(model_manifest)
        parsed = json.loads(raw)
        assert parsed["model_name"] == model_manifest.model_name

    def test_public_key_embedded_in_signature_verifies(
        self,
        model_manifest: ModelManifest,
        ed25519_keypair: tuple[bytes, bytes],
    ) -> None:
        """The public key stored inside the signature should verify the manifest."""
        private_pem, _ = ed25519_keypair
        signer = ModelSigner()
        signed = signer.sign_manifest(
            model_manifest, private_pem, signer_id="self@test.com"
        )

        # Extract the public key that was embedded in the signature
        embedded_pub_pem = base64.b64decode(signed.signature.public_key)
        verifier = ModelVerifier()
        result = verifier.verify_manifest(signed, embedded_pub_pem)
        assert result.valid is True
