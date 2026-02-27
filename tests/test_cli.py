"""Tests for aumai_modelseal.cli — Click command group."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from aumai_modelseal.cli import main
from aumai_modelseal.core import KeyManager
from aumai_modelseal.models import SignatureAlgorithm

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_keys(
    tmp_path: Path,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ed25519,
) -> tuple[Path, Path]:
    """Generate a key pair, write to tmp_path/keys/. Return (private, public) paths."""
    km = KeyManager()
    private_pem, public_pem = km.generate_keypair(algorithm)
    km.save_keypair(private_pem, public_pem, str(tmp_path / "keys"))
    return tmp_path / "keys" / "private.pem", tmp_path / "keys" / "public.pem"


def _make_model_dir(tmp_path: Path) -> Path:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "weights.bin").write_bytes(bytes(range(64)))
    (model_dir / "config.json").write_text('{"layers": 2}', encoding="utf-8")
    return model_dir


# ===========================================================================
# Global --version flag
# ===========================================================================


class TestCliVersion:
    def test_version_flag_exits_zero(self) -> None:
        runner = CliRunner()
        with patch("importlib.metadata.version", return_value="0.1.0"):
            result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_reports_0_1_0(self) -> None:
        runner = CliRunner()
        with patch("importlib.metadata.version", return_value="0.1.0"):
            result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output

    def test_help_flag_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0

    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        for cmd in ("keygen", "sign", "verify", "inspect"):
            assert cmd in result.output


# ===========================================================================
# keygen command
# ===========================================================================


class TestKeygenCommand:
    def test_keygen_ed25519_default_exits_zero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["keygen", "--output", str(tmp_path / "keys")])
        assert result.exit_code == 0

    def test_keygen_creates_private_pem(self, tmp_path: Path) -> None:
        runner = CliRunner()
        keys_dir = tmp_path / "out"
        runner.invoke(main, ["keygen", "--output", str(keys_dir)])
        assert (keys_dir / "private.pem").exists()

    def test_keygen_creates_public_pem(self, tmp_path: Path) -> None:
        runner = CliRunner()
        keys_dir = tmp_path / "out"
        runner.invoke(main, ["keygen", "--output", str(keys_dir)])
        assert (keys_dir / "public.pem").exists()

    def test_keygen_output_mentions_algorithm(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["keygen", "--output", str(tmp_path / "keys"), "--algorithm", "ed25519"],
        )
        assert "ed25519" in result.output

    def test_keygen_ecdsa_p256_exits_zero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        keys_dir = tmp_path / "ecdsa_keys"
        result = runner.invoke(
            main,
            ["keygen", "--output", str(keys_dir), "--algorithm", "ecdsa_p256"],
        )
        assert result.exit_code == 0

    def test_keygen_ecdsa_creates_valid_pem(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives import serialization

        runner = CliRunner()
        keys_dir = tmp_path / "ecdsa_keys"
        runner.invoke(
            main,
            ["keygen", "--output", str(keys_dir), "--algorithm", "ecdsa_p256"],
        )
        private_pem = (keys_dir / "private.pem").read_bytes()
        # Should load without error
        serialization.load_pem_private_key(private_pem, password=None)

    def test_keygen_output_message_includes_paths(self, tmp_path: Path) -> None:
        runner = CliRunner()
        keys_dir = tmp_path / "mykeys"
        result = runner.invoke(main, ["keygen", "--output", str(keys_dir)])
        assert "private.pem" in result.output
        assert "public.pem" in result.output

    def test_keygen_invalid_algorithm_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["keygen", "--output", str(tmp_path / "keys"), "--algorithm", "rsa4096"],
        )
        assert result.exit_code != 0


# ===========================================================================
# sign command
# ===========================================================================


class TestSignCommand:
    def test_sign_exits_zero(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_sign_creates_signed_manifest_json(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
            ],
        )
        assert (model_dir / "signed_manifest.json").exists()

    def test_sign_default_output_is_valid_json(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
            ],
        )
        raw = (model_dir / "signed_manifest.json").read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert "manifest" in parsed
        assert "signature" in parsed

    def test_sign_custom_output_path(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        out_file = tmp_path / "my_manifest.json"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
                "--output", str(out_file),
            ],
        )
        assert out_file.exists()

    def test_sign_output_shows_signer_id(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "cli-test@corp.com",
            ],
        )
        assert "cli-test@corp.com" in result.output

    def test_sign_with_model_name_override(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
                "--model-name", "custom-model-name",
            ],
        )
        manifest_text = (model_dir / "signed_manifest.json").read_text(encoding="utf-8")
        raw = json.loads(manifest_text)
        assert raw["manifest"]["model_name"] == "custom-model-name"

    def test_sign_with_version_and_framework(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "test@example.com",
                "--model-version", "3.1.4",
                "--framework", "jax",
            ],
        )
        manifest_text = (model_dir / "signed_manifest.json").read_text(encoding="utf-8")
        raw = json.loads(manifest_text)
        assert raw["manifest"]["model_version"] == "3.1.4"
        assert raw["manifest"]["framework"] == "jax"

    def test_sign_nonexistent_model_dir_exits_nonzero(self, tmp_path: Path) -> None:
        private_key, _ = _write_keys(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sign",
                "--model-dir", "/totally/nonexistent/path",
                "--key", str(private_key),
                "--signer-id", "test@example.com",
            ],
        )
        assert result.exit_code != 0

    def test_sign_nonexistent_key_exits_nonzero(self, tmp_path: Path) -> None:
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", "/nonexistent/private.pem",
                "--signer-id", "test@example.com",
            ],
        )
        assert result.exit_code != 0

    def test_sign_missing_required_options_shows_error(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["sign"])
        assert result.exit_code != 0


# ===========================================================================
# verify command
# ===========================================================================


class TestVerifyCommand:
    def _sign_model(self, tmp_path: Path) -> tuple[Path, Path]:
        """Sign a model and return (manifest_path, public_key_path)."""
        private_key, public_key = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "verify-test@example.com",
            ],
        )
        return model_dir / "signed_manifest.json", public_key

    def test_verify_valid_signature_exits_zero(self, tmp_path: Path) -> None:
        manifest_path, public_key = self._sign_model(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["verify", "--manifest", str(manifest_path), "--key", str(public_key)],
        )
        assert result.exit_code == 0

    def test_verify_valid_shows_valid_message(self, tmp_path: Path) -> None:
        manifest_path, public_key = self._sign_model(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["verify", "--manifest", str(manifest_path), "--key", str(public_key)],
        )
        assert "VALID" in result.output

    def test_verify_shows_signer_id(self, tmp_path: Path) -> None:
        manifest_path, public_key = self._sign_model(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["verify", "--manifest", str(manifest_path), "--key", str(public_key)],
        )
        assert "verify-test@example.com" in result.output

    def test_verify_wrong_key_exits_2(self, tmp_path: Path) -> None:
        manifest_path, _ = self._sign_model(tmp_path)
        # Generate a fresh unrelated key pair
        km = KeyManager()
        _, wrong_pub = km.generate_keypair(SignatureAlgorithm.ed25519)
        wrong_pub_path = tmp_path / "wrong_public.pem"
        wrong_pub_path.write_bytes(wrong_pub)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["verify", "--manifest", str(manifest_path), "--key", str(wrong_pub_path)],
        )
        assert result.exit_code == 2

    def test_verify_wrong_key_shows_invalid_message(self, tmp_path: Path) -> None:
        manifest_path, _ = self._sign_model(tmp_path)
        km = KeyManager()
        _, wrong_pub = km.generate_keypair(SignatureAlgorithm.ed25519)
        wrong_pub_path = tmp_path / "wrong_public.pem"
        wrong_pub_path.write_bytes(wrong_pub)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["verify", "--manifest", str(manifest_path), "--key", str(wrong_pub_path)],
        )
        assert "INVALID" in result.output

    def test_verify_with_model_dir_exits_zero(self, tmp_path: Path) -> None:
        private_key, public_key = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "files-test@example.com",
            ],
        )
        manifest_path = model_dir / "signed_manifest.json"
        result = runner.invoke(
            main,
            [
                "verify",
                "--manifest", str(manifest_path),
                "--key", str(public_key),
                "--model-dir", str(model_dir),
            ],
        )
        assert result.exit_code == 0

    def test_verify_with_model_dir_shows_file_ok(self, tmp_path: Path) -> None:
        private_key, public_key = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "files-test@example.com",
            ],
        )
        manifest_path = model_dir / "signed_manifest.json"
        result = runner.invoke(
            main,
            [
                "verify",
                "--manifest", str(manifest_path),
                "--key", str(public_key),
                "--model-dir", str(model_dir),
            ],
        )
        assert "OK" in result.output

    def test_verify_tampered_file_exits_2(self, tmp_path: Path) -> None:
        private_key, public_key = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "tamper@example.com",
            ],
        )
        # Tamper with the file after signing
        (model_dir / "weights.bin").write_bytes(b"TAMPERED!")
        manifest_path = model_dir / "signed_manifest.json"
        result = runner.invoke(
            main,
            [
                "verify",
                "--manifest", str(manifest_path),
                "--key", str(public_key),
                "--model-dir", str(model_dir),
            ],
        )
        assert result.exit_code == 2

    def test_verify_missing_manifest_exits_nonzero(self, tmp_path: Path) -> None:
        _, public_key = _write_keys(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "verify",
                "--manifest", str(tmp_path / "nonexistent.json"),
                "--key", str(public_key),
            ],
        )
        assert result.exit_code != 0

    def test_verify_missing_required_options_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["verify"])
        assert result.exit_code != 0


# ===========================================================================
# inspect command
# ===========================================================================


class TestInspectCommand:
    def _create_signed_manifest_file(self, tmp_path: Path) -> Path:
        private_key, _ = _write_keys(tmp_path)
        model_dir = _make_model_dir(tmp_path)
        runner = CliRunner()
        out_file = tmp_path / "manifest.json"
        runner.invoke(
            main,
            [
                "sign",
                "--model-dir", str(model_dir),
                "--key", str(private_key),
                "--signer-id", "inspector@example.com",
                "--output", str(out_file),
                "--model-name", "inspect-model",
                "--model-version", "9.9.9",
                "--framework", "keras",
            ],
        )
        return out_file

    def test_inspect_exits_zero(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert result.exit_code == 0

    def test_inspect_shows_model_name(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "inspect-model" in result.output

    def test_inspect_shows_version(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "9.9.9" in result.output

    def test_inspect_shows_framework(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "keras" in result.output

    def test_inspect_shows_signer_id(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "inspector@example.com" in result.output

    def test_inspect_shows_algorithm(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "ed25519" in result.output

    def test_inspect_json_output_flag(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main, ["inspect", "--manifest", str(manifest_file), "--json-output"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "manifest" in parsed
        assert "signature" in parsed

    def test_inspect_json_output_model_name_correct(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main, ["inspect", "--manifest", str(manifest_file), "--json-output"]
        )
        parsed = json.loads(result.output)
        assert parsed["manifest"]["model_name"] == "inspect-model"

    def test_inspect_missing_manifest_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["inspect", "--manifest", str(tmp_path / "does_not_exist.json")]
        )
        assert result.exit_code != 0

    def test_inspect_shows_file_list(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        # The model has weights.bin and config.json
        assert "weights.bin" in result.output or "config.json" in result.output

    def test_inspect_shows_total_size(self, tmp_path: Path) -> None:
        manifest_file = self._create_signed_manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--manifest", str(manifest_file)])
        assert "Total Size" in result.output or "bytes" in result.output
