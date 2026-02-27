# Getting Started with aumai-modelseal

This guide walks you from a fresh install through your first signed and verified
model artifact, then shows the most common patterns for real-world workflows.

---

## Prerequisites

- **Python 3.11 or later**
- A POSIX or Windows shell (the CLI works on both)
- A directory containing at least one ML model file to sign

Optional but recommended for YAML config support:

```bash
pip install pyyaml
```

---

## Installation

### From PyPI (recommended)

```bash
pip install aumai-modelseal
```

Verify the install:

```bash
aumai-modelseal --version
# aumai-modelseal, version 0.1.0
```

### From source

```bash
git clone https://github.com/aumai/aumai-modelseal.git
cd aumai-modelseal
pip install -e .
```

### Development mode (with test dependencies)

```bash
git clone https://github.com/aumai/aumai-modelseal.git
cd aumai-modelseal
pip install -e ".[dev]"
make lint test
```

---

## Your First Signed Model

This tutorial signs a local model directory, verifies the signature, and demonstrates
that tampering is detected. It takes about five minutes.

### Step 1 — Prepare a model directory

If you do not have a model directory handy, create a minimal stand-in:

```bash
mkdir -p ./demo-model
echo '{"architecture": "transformer", "vocab_size": 32000}' > ./demo-model/config.json
dd if=/dev/urandom bs=1024 count=1024 of=./demo-model/weights.bin 2>/dev/null
echo "Step 1 complete — demo-model/ created."
```

### Step 2 — Generate a signing key pair

```bash
aumai-modelseal keygen --output ./demo-keys
```

Output:

```
Key pair (ed25519) written to 'demo-keys/'
  Private: demo-keys/private.pem
  Public : demo-keys/public.pem
```

Keep `private.pem` secret. Distribute `public.pem` to anyone who needs to verify
your models.

### Step 3 — Sign the model

```bash
aumai-modelseal sign \
  --model-dir ./demo-model \
  --key ./demo-keys/private.pem \
  --signer-id you@example.com \
  --model-name "demo-transformer" \
  --model-version "0.1.0" \
  --framework "pytorch"
```

Output:

```
Signed manifest written to: demo-model/signed_manifest.json
  Files    : 2
  Total    : 1,049,648 bytes
  Signer   : you@example.com
  Algorithm: ed25519
```

The file `demo-model/signed_manifest.json` is the signed manifest. It contains
a complete inventory of every file with its SHA-256 hash, plus the cryptographic
signature. You can inspect it at any time:

```bash
aumai-modelseal inspect --manifest ./demo-model/signed_manifest.json
```

### Step 4 — Verify the signature and files

```bash
aumai-modelseal verify \
  --manifest ./demo-model/signed_manifest.json \
  --key ./demo-keys/public.pem \
  --model-dir ./demo-model
```

Expected output:

```
Signature: VALID
  Signer   : you@example.com
  Model    : demo-transformer v0.1.0
Verifying on-disk file hashes...
  [OK] config.json
  [OK] weights.bin
All files verified successfully.
```

### Step 5 — Verify that tampering is detected

Modify one of the model files to simulate tampering:

```bash
echo "TAMPERED" >> ./demo-model/config.json
aumai-modelseal verify \
  --manifest ./demo-model/signed_manifest.json \
  --key ./demo-keys/public.pem \
  --model-dir ./demo-model
```

Expected output:

```
Signature: VALID
  Signer   : you@example.com
  Model    : demo-transformer v0.1.0
Verifying on-disk file hashes...
  [FAIL] config.json
  [OK] weights.bin
One or more files failed verification.
```

The signature is still valid (it covers the original manifest), but the on-disk
hash check catches the modification. This is the intended two-step verification
model: the signature proves who published the manifest; the file hashes prove the
files have not changed since.

---

## Common Patterns

### Pattern 1 — CI/CD pipeline signing

Sign a model as part of a release pipeline. The private key is loaded from an
environment variable or secrets manager.

```python
import os
from aumai_modelseal import KeyManager, ModelSigner

private_key_pem = os.environ["MODEL_SIGNING_KEY"].encode("utf-8")
signer_id = os.environ.get("SIGNER_ID", "ci@myorg.com")

km = KeyManager()
# Validate the key immediately (fast-fail)
km.load_private_key.__func__  # KeyManager.load_private_key validates on load

from cryptography.hazmat.primitives import serialization
serialization.load_pem_private_key(private_key_pem, password=None)

signer = ModelSigner()
manifest = signer.create_manifest(
    model_dir="./dist/model",
    model_name="production-v3",
    model_version=os.environ["MODEL_VERSION"],
    framework="transformers",
    author="ML Platform CI",
)
signed = signer.sign_manifest(manifest, private_key_pem, signer_id=signer_id)

with open("./dist/signed_manifest.json", "w", encoding="utf-8") as f:
    f.write(signed.model_dump_json(indent=2))

print(f"Signed {len(manifest.files)} files ({manifest.total_size_bytes:,} bytes)")
```

### Pattern 2 — Verify at model load time

Gate model loading behind a signature check. Fail fast if the model is untrusted.

```python
import sys
from aumai_modelseal import KeyManager, ModelVerifier, SignedManifest

TRUSTED_PUBLIC_KEY_PATH = "/etc/aumai/trusted_key.pem"
MODEL_DIR = "/opt/models/production-v3"
MANIFEST_PATH = f"{MODEL_DIR}/signed_manifest.json"

km = KeyManager()
verifier = ModelVerifier()

with open(MANIFEST_PATH, encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())

public_key_bytes = km.load_public_key(TRUSTED_PUBLIC_KEY_PATH)
result = verifier.verify_manifest(signed, public_key_bytes)

if not result.valid:
    print(f"FATAL: Model signature invalid — {result.error}", file=sys.stderr)
    sys.exit(1)

# Optional: also verify every file on disk
file_results = verifier.verify_files(MODEL_DIR, signed.manifest)
failed = [path for path, ok in file_results if not ok]
if failed:
    print(f"FATAL: {len(failed)} file(s) failed hash check: {failed}", file=sys.stderr)
    sys.exit(1)

print(f"Model verified. Proceeding to load {result.manifest.model_name}.")
# ... your model loading code here
```

### Pattern 3 — Maintain a trusted publisher registry

Use the registry when you receive models from multiple known publishers and want to
verify each one against its registered public key without passing the key explicitly.

```python
import base64
from datetime import UTC, datetime
from aumai_modelseal import PublisherRegistry, TrustedPublisher, SignedManifest

registry = PublisherRegistry(registry_path="./registry.json")

# One-time registration of each publisher
for publisher_id, key_path, display_name in [
    ("alice@myorg.com", "./keys/alice_public.pem", "Alice — Research"),
    ("ci@myorg.com", "./keys/ci_public.pem", "CI Pipeline"),
]:
    public_pem = open(key_path, "rb").read()
    registry.add_publisher(TrustedPublisher(
        publisher_id=publisher_id,
        name=display_name,
        public_key=base64.b64encode(public_pem).decode(),
        trusted_since=datetime.now(tz=UTC),
    ))

# At verification time — no need to look up the right key manually
with open("./received_model/signed_manifest.json", encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())

result = registry.verify_against_registry(signed)
print("Valid:", result.valid)
if not result.valid:
    print("Reason:", result.error)
```

### Pattern 4 — Inspect a manifest programmatically

Parse and query a manifest without performing verification.

```python
from aumai_modelseal import SignedManifest

with open("./signed_manifest.json", encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())

m = signed.manifest
print(f"Model: {m.model_name} v{m.model_version} ({m.framework})")
print(f"Author: {m.author}")
print(f"Created: {m.created_at.isoformat()}")
print(f"Files: {len(m.files)}, Total: {m.total_size_bytes:,} bytes")
print(f"Signer: {signed.signature.signer_id}")
print(f"Algorithm: {signed.signature.algorithm.value}")

for entry in m.files:
    print(f"  {entry.path}  {entry.size_bytes:,}B  sha256:{entry.sha256_hash[:16]}...")
```

### Pattern 5 — ECDSA P-256 for HSM environments

If your organisation uses a hardware security module (HSM) that supports NIST P-256
but not Edwards curves, use `ecdsa_p256` throughout.

```bash
aumai-modelseal keygen --algorithm ecdsa_p256 --output ./hsm-keys
aumai-modelseal sign \
  --model-dir ./my-model \
  --key ./hsm-keys/private.pem \
  --signer-id hsm@myorg.com

# Verification is identical — the algorithm is auto-detected from the manifest
aumai-modelseal verify \
  --manifest ./my-model/signed_manifest.json \
  --key ./hsm-keys/public.pem
```

---

## Troubleshooting FAQ

**Q: `aumai-modelseal: command not found` after `pip install`**

A: The script is installed to the Python environment's `bin/` directory. Make sure
your active virtualenv's `bin/` is on your `PATH`, or prefix with `python -m`:

```bash
python -m aumai_modelseal.cli --help
```

**Q: `Error: Failed to load public key: Could not deserialize key data`**

A: You passed the private key path to `--key` in the `verify` command. The `verify`
command requires the **public** key.

**Q: Signature is VALID but file verification reports FAIL**

A: This is the intended behaviour. The signature proves the manifest has not been
altered since it was signed. File verification is a separate step that checks whether
the on-disk files still match what was recorded in the manifest. A valid signature
with failing file hashes means the files were modified after signing.

**Q: `ValueError: model_dir does not exist or is not a directory`**

A: The path passed to `--model-dir` does not exist or is a file, not a directory.
Check the path and ensure the directory exists before signing.

**Q: The manifest JSON contains a `created_at` timestamp — will two runs produce
different manifests?**

A: Yes. The `created_at` field is set to the current UTC time when
`ModelSigner.create_manifest` is called, so the manifest will differ between runs
even if the files have not changed. This means signatures are not reproducible across
invocations. If you need deterministic manifests for content-addressed storage, set
`created_at` explicitly by constructing the `ModelManifest` directly and passing it
to `sign_manifest`.

**Q: Can I add files to the model directory after signing?**

A: The signature covers the manifest, which lists exactly the files present at sign
time. Adding files does not invalidate the signature, but those new files will not be
listed in the manifest and will not be covered by file-integrity verification. If you
need the new files to be covered, re-sign.

**Q: `KeyError: Publisher not found` from `PublisherRegistry.remove_publisher`**

A: The `publisher_id` you passed is not in the registry. List registered publishers
with `registry.list_publishers()` to find the correct ID.
