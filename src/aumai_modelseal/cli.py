"""CLI entry point for aumai-modelseal."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from aumai_modelseal.core import KeyManager, ModelSigner, ModelVerifier
from aumai_modelseal.models import (
    SignatureAlgorithm,
    SignedManifest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_signed_manifest(path: str) -> SignedManifest:
    raw = Path(path).read_text(encoding="utf-8")
    return SignedManifest.model_validate_json(raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def main() -> None:
    """AumAI ModelSeal — cryptographic signing for ML model artifacts."""


@main.command("keygen")
@click.option(
    "--output",
    default="keys",
    show_default=True,
    metavar="DIR",
    help="Directory to write private.pem and public.pem.",
)
@click.option(
    "--algorithm",
    type=click.Choice(["ed25519", "ecdsa_p256"], case_sensitive=False),
    default="ed25519",
    show_default=True,
    help="Signing algorithm.",
)
def keygen_command(output: str, algorithm: str) -> None:
    """Generate an asymmetric key pair for model signing."""
    algo = SignatureAlgorithm(algorithm)
    km = KeyManager()
    private_pem, public_pem = km.generate_keypair(algo)
    km.save_keypair(private_pem, public_pem, output)
    click.echo(f"Key pair ({algo.value}) written to '{output}/'")
    click.echo(f"  Private: {output}/private.pem")
    click.echo(f"  Public : {output}/public.pem")


@main.command("sign")
@click.option(
    "--model-dir",
    required=True,
    metavar="DIR",
    help="Directory containing model files.",
)
@click.option(
    "--key",
    required=True,
    metavar="PATH",
    help="Path to private PEM key file.",
)
@click.option(
    "--signer-id",
    required=True,
    metavar="ID",
    help="Signer identity string (e.g. email).",
)
@click.option(
    "--model-name",
    default=None,
    help="Override model name (defaults to directory name).",
)
@click.option("--model-version", default="0.0.0", show_default=True)
@click.option("--framework", default="unknown", show_default=True)
@click.option("--author", default="", help="Author name.")
@click.option(
    "--output",
    default=None,
    metavar="PATH",
    help=(
        "Output path for signed manifest JSON "
        "(default: <model-dir>/signed_manifest.json)."
    ),
)
def sign_command(
    model_dir: str,
    key: str,
    signer_id: str,
    model_name: str | None,
    model_version: str,
    framework: str,
    author: str,
    output: str | None,
) -> None:
    """Sign a model directory and write the signed manifest to disk."""
    signer = ModelSigner()
    km = KeyManager()

    try:
        private_key = km.load_private_key(key)
        manifest = signer.create_manifest(
            model_dir=model_dir,
            model_name=model_name or "",
            model_version=model_version,
            framework=framework,
            author=author,
        )
        signed = signer.sign_manifest(manifest, private_key, signer_id)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    out_path = Path(output) if output else Path(model_dir) / "signed_manifest.json"
    out_path.write_text(signed.model_dump_json(indent=2), encoding="utf-8")

    click.echo(f"Signed manifest written to: {out_path}")
    click.echo(f"  Files    : {len(manifest.files)}")
    click.echo(f"  Total    : {manifest.total_size_bytes:,} bytes")
    click.echo(f"  Signer   : {signer_id}")
    click.echo(f"  Algorithm: {signed.signature.algorithm.value}")


@main.command("verify")
@click.option(
    "--manifest",
    "manifest_path",
    required=True,
    metavar="PATH",
    help="Path to signed manifest JSON.",
)
@click.option(
    "--key",
    required=True,
    metavar="PATH",
    help="Path to public PEM key file.",
)
@click.option(
    "--model-dir",
    default=None,
    metavar="DIR",
    help="If supplied, also verify on-disk file hashes.",
)
def verify_command(manifest_path: str, key: str, model_dir: str | None) -> None:
    """Verify the cryptographic signature of a signed manifest."""
    verifier = ModelVerifier()
    km = KeyManager()

    try:
        signed = _load_signed_manifest(manifest_path)
        public_key = km.load_public_key(key)
        result = verifier.verify_manifest(signed, public_key)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if result.valid:
        click.echo("Signature: VALID")
        click.echo(f"  Signer   : {result.signer_id}")
        if result.manifest:
            model_name = result.manifest.model_name
            model_version = result.manifest.model_version
            click.echo(f"  Model    : {model_name} v{model_version}")
    else:
        click.echo(f"Signature: INVALID — {result.error}")
        sys.exit(2)

    if model_dir is not None and result.manifest is not None:
        click.echo("\nVerifying on-disk file hashes...")
        file_results = verifier.verify_files(model_dir, result.manifest)
        all_ok = True
        for file_path, ok in file_results:
            status = "OK" if ok else "FAIL"
            click.echo(f"  [{status}] {file_path}")
            if not ok:
                all_ok = False
        if all_ok:
            click.echo("All files verified successfully.")
        else:
            click.echo("One or more files failed verification.", err=True)
            sys.exit(2)


@main.command("inspect")
@click.option(
    "--manifest",
    "manifest_path",
    required=True,
    metavar="PATH",
    help="Path to signed manifest JSON.",
)
@click.option("--json-output", is_flag=True, help="Emit raw JSON.")
def inspect_command(manifest_path: str, json_output: bool) -> None:
    """Display the contents of a signed manifest."""
    try:
        signed = _load_signed_manifest(manifest_path)
    except Exception as exc:
        click.echo(f"Error loading manifest: {exc}", err=True)
        sys.exit(1)

    if json_output:
        click.echo(signed.model_dump_json(indent=2))
        return

    m = signed.manifest
    s = signed.signature
    click.echo(f"Model Name   : {m.model_name}")
    click.echo(f"Version      : {m.model_version}")
    click.echo(f"Framework    : {m.framework}")
    click.echo(f"Author       : {m.author}")
    click.echo(f"Created      : {m.created_at.isoformat()}")
    click.echo(f"Total Size   : {m.total_size_bytes:,} bytes")
    click.echo(f"Files        : {len(m.files)}")
    click.echo(f"\nSigner       : {s.signer_id}")
    click.echo(f"Algorithm    : {s.algorithm.value}")
    click.echo(f"Signed At    : {s.signed_at.isoformat()}")
    click.echo("\nFiles in manifest:")
    for entry in m.files:
        sha_prefix = entry.sha256_hash[:16]
        click.echo(
            f"  {entry.path}  ({entry.size_bytes:,} bytes)  sha256:{sha_prefix}..."
        )


if __name__ == "__main__":
    main()
