# API Reference — aumai-modelseal

Complete reference for every public class, function, and Pydantic model in
`aumai-modelseal`. All classes are importable from the top-level package:

```python
from aumai_modelseal import (
    KeyManager, ModelSigner, ModelVerifier, PublisherRegistry,
    FileEntry, ModelManifest, Signature, SignatureAlgorithm,
    SignedManifest, TrustedPublisher, VerificationResult,
)
```

---

## Enumerations

### `SignatureAlgorithm`

```python
class SignatureAlgorithm(str, Enum):
    ed25519   = "ed25519"
    ecdsa_p256 = "ecdsa_p256"
```

Asymmetric signing algorithm choices passed to `KeyManager.generate_keypair`.

| Member | Value | Notes |
|---|---|---|
| `ed25519` | `"ed25519"` | Edwards-curve DSA; default; 64-byte signatures |
| `ecdsa_p256` | `"ecdsa_p256"` | ECDSA over NIST P-256 with SHA-256 |

---

## Pydantic Models

All models are Pydantic `BaseModel` subclasses. Use `.model_dump_json()` to serialise
and `.model_validate_json()` to deserialise.

---

### `FileEntry`

```python
class FileEntry(BaseModel):
    path: str
    size_bytes: int          # Field(ge=0)
    sha256_hash: str         # Field(min_length=64, max_length=64)
```

Metadata and integrity hash for a single file inside a model artifact.

| Field | Type | Constraints | Description |
|---|---|---|---|
| `path` | `str` | — | Relative POSIX path from the model root (e.g. `"weights/model.safetensors"`) |
| `size_bytes` | `int` | `>= 0` | File size in bytes at sign time |
| `sha256_hash` | `str` | exactly 64 hex chars | Lowercase hex-encoded SHA-256 digest |

**Example:**

```python
from aumai_modelseal import FileEntry

entry = FileEntry(
    path="config.json",
    size_bytes=512,
    sha256_hash="a" * 64,
)
print(entry.model_dump_json())
```

---

### `ModelManifest`

```python
class ModelManifest(BaseModel):
    model_name: str
    model_version: str
    framework: str
    files: list[FileEntry]       # default_factory=list
    total_size_bytes: int        # Field(ge=0)
    created_at: datetime
    author: str
    description: str             # default ""
```

Human-readable and machine-verifiable description of a model artifact. This is the
object that is serialised and cryptographically signed.

| Field | Type | Description |
|---|---|---|
| `model_name` | `str` | Name of the model; defaults to the directory name when built via `ModelSigner.create_manifest` |
| `model_version` | `str` | Semver or arbitrary version string |
| `framework` | `str` | ML framework (e.g. `"pytorch"`, `"jax"`, `"transformers"`) |
| `files` | `list[FileEntry]` | All files in the artifact, sorted by path |
| `total_size_bytes` | `int` | Sum of all file sizes |
| `created_at` | `datetime` | UTC timestamp when the manifest was created |
| `author` | `str` | Author or organisation that produced the model |
| `description` | `str` | Free-form description |

---

### `Signature`

```python
class Signature(BaseModel):
    algorithm: SignatureAlgorithm
    public_key: str      # Base64-encoded PEM bytes
    signature_hex: str   # Lowercase hex-encoded raw signature bytes
    signed_at: datetime
    signer_id: str
```

Cryptographic signature over a serialised `ModelManifest`. Stored detached from the
manifest weights so that the manifest and signature can be distributed together.

| Field | Type | Description |
|---|---|---|
| `algorithm` | `SignatureAlgorithm` | Algorithm used to produce the signature |
| `public_key` | `str` | Base64-encoded PEM public key bytes (for self-contained verification) |
| `signature_hex` | `str` | Hex-encoded raw signature bytes |
| `signed_at` | `datetime` | UTC timestamp when the signature was created |
| `signer_id` | `str` | Arbitrary identity string for the signing entity |

---

### `SignedManifest`

```python
class SignedManifest(BaseModel):
    manifest: ModelManifest
    signature: Signature
```

Bundle that pairs a manifest with its detached signature. This is the top-level
document written to disk by `ModelSigner.sign_manifest` and read by
`ModelVerifier.verify_manifest`.

| Field | Type | Description |
|---|---|---|
| `manifest` | `ModelManifest` | The complete file inventory |
| `signature` | `Signature` | The cryptographic signature over the manifest |

**Serialise to disk:**

```python
with open("signed_manifest.json", "w", encoding="utf-8") as f:
    f.write(signed.model_dump_json(indent=2))
```

**Deserialise from disk:**

```python
from aumai_modelseal import SignedManifest

with open("signed_manifest.json", encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())
```

---

### `VerificationResult`

```python
class VerificationResult(BaseModel):
    valid: bool
    manifest: ModelManifest | None = None
    signer_id: str | None = None
    error: str | None = None
```

Outcome of a signature verification attempt. Never raises on cryptographic failure;
failures are encoded as `valid=False` with a descriptive `error` string.

| Field | Type | Description |
|---|---|---|
| `valid` | `bool` | `True` if the signature verified successfully |
| `manifest` | `ModelManifest \| None` | The manifest, if verification succeeded |
| `signer_id` | `str \| None` | The signer identity, if verification succeeded |
| `error` | `str \| None` | Human-readable error description if `valid=False` |

---

### `TrustedPublisher`

```python
class TrustedPublisher(BaseModel):
    publisher_id: str
    name: str
    public_key: str      # Base64-encoded PEM bytes
    trusted_since: datetime
```

A publisher whose public key has been registered in the `PublisherRegistry`.

| Field | Type | Description |
|---|---|---|
| `publisher_id` | `str` | Unique identifier (typically an email or org ID) |
| `name` | `str` | Human-readable display name |
| `public_key` | `str` | Base64-encoded PEM public key bytes |
| `trusted_since` | `datetime` | UTC timestamp of registration |

---

## Classes

### `KeyManager`

```python
class KeyManager:
    def generate_keypair(
        self,
        algorithm: SignatureAlgorithm,
        passphrase: bytes | None = None,
    ) -> tuple[bytes, bytes]: ...

    def save_keypair(
        self,
        private_key: bytes,
        public_key: bytes,
        path: str,
    ) -> None: ...

    def load_private_key(
        self,
        path: str,
        password: bytes | None = None,
    ) -> bytes: ...

    def load_public_key(self, path: str) -> bytes: ...
```

Generates, saves, and loads asymmetric key pairs in PEM format.

---

#### `KeyManager.generate_keypair`

```python
def generate_keypair(
    self,
    algorithm: SignatureAlgorithm,
    passphrase: bytes | None = None,
) -> tuple[bytes, bytes]
```

Generate a fresh asymmetric key pair.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `algorithm` | `SignatureAlgorithm` | `SignatureAlgorithm.ed25519` or `SignatureAlgorithm.ecdsa_p256` |
| `passphrase` | `bytes \| None` | Optional passphrase to encrypt the private key PEM at rest |

**Returns:** `(private_key_pem_bytes, public_key_pem_bytes)` — both in PEM format,
ready for `save_keypair` or direct use.

**Example:**

```python
from aumai_modelseal import KeyManager, SignatureAlgorithm

km = KeyManager()
private_pem, public_pem = km.generate_keypair(SignatureAlgorithm.ed25519)
encrypted_priv, pub = km.generate_keypair(
    SignatureAlgorithm.ed25519,
    passphrase=b"hunter2",
)
```

---

#### `KeyManager.save_keypair`

```python
def save_keypair(
    self,
    private_key: bytes,
    public_key: bytes,
    path: str,
) -> None
```

Write the PEM-encoded key pair to `{path}/private.pem` and `{path}/public.pem`.

The output directory is created recursively if it does not exist. On POSIX systems,
`private.pem` is written with mode `0o600` (owner read/write only).

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `private_key` | `bytes` | PEM bytes for the private key |
| `public_key` | `bytes` | PEM bytes for the public key |
| `path` | `str` | Directory path (created if absent) |

**Example:**

```python
km.save_keypair(private_pem, public_pem, path="./my-keys")
# Creates: ./my-keys/private.pem (mode 0o600) and ./my-keys/public.pem
```

---

#### `KeyManager.load_private_key`

```python
def load_private_key(
    self,
    path: str,
    password: bytes | None = None,
) -> bytes
```

Read and validate a PEM private key from `path`. The key is eagerly loaded and
decrypted with `password` to produce a clear error at load time rather than later
at sign time.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `path` | `str` | Filesystem path to the PEM private key file |
| `password` | `bytes \| None` | Passphrase for encrypted keys; `None` for unencrypted |

**Returns:** Raw PEM bytes of the private key.

**Raises:** `ValueError` from the underlying cryptography library if the password is
wrong or the file is not a valid PEM key.

---

#### `KeyManager.load_public_key`

```python
def load_public_key(self, path: str) -> bytes
```

Read raw PEM bytes from `path`. No parsing is performed.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `path` | `str` | Filesystem path to the PEM public key file |

**Returns:** Raw PEM bytes.

---

### `ModelSigner`

```python
class ModelSigner:
    def create_manifest(
        self,
        model_dir: str,
        model_name: str = "",
        model_version: str = "0.0.0",
        framework: str = "unknown",
        author: str = "",
        description: str = "",
    ) -> ModelManifest: ...

    def sign_manifest(
        self,
        manifest: ModelManifest,
        private_key_bytes: bytes,
        signer_id: str,
        password: bytes | None = None,
    ) -> SignedManifest: ...
```

Creates manifests from model directories and signs them with a private key.

---

#### `ModelSigner.create_manifest`

```python
def create_manifest(
    self,
    model_dir: str,
    model_name: str = "",
    model_version: str = "0.0.0",
    framework: str = "unknown",
    author: str = "",
    description: str = "",
) -> ModelManifest
```

Walk `model_dir` recursively and build a `ModelManifest`. Every file is hashed with
SHA-256 in 64 KB chunks. Files are sorted by path for determinism. Directories
themselves are not included in the file list.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `model_dir` | `str` | required | Root directory of the model artifact |
| `model_name` | `str` | `""` | Model name; defaults to the directory basename |
| `model_version` | `str` | `"0.0.0"` | Version string |
| `framework` | `str` | `"unknown"` | ML framework name |
| `author` | `str` | `""` | Author or team |
| `description` | `str` | `""` | Free-form description |

**Returns:** `ModelManifest` with `created_at` set to the current UTC time.

**Raises:** `ValueError` if `model_dir` does not exist or is not a directory.

**Example:**

```python
from aumai_modelseal import ModelSigner

signer = ModelSigner()
manifest = signer.create_manifest(
    model_dir="./my-model",
    model_name="sentiment-classifier",
    model_version="2.0.0",
    framework="transformers",
    author="Research Team",
)
print(f"Hashed {len(manifest.files)} files, {manifest.total_size_bytes:,} bytes total")
```

---

#### `ModelSigner.sign_manifest`

```python
def sign_manifest(
    self,
    manifest: ModelManifest,
    private_key_bytes: bytes,
    signer_id: str,
    password: bytes | None = None,
) -> SignedManifest
```

Serialise `manifest` to canonical JSON, sign the bytes with the private key, and
return a `SignedManifest` containing the manifest and the detached `Signature`.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `manifest` | `ModelManifest` | The manifest to sign |
| `private_key_bytes` | `bytes` | PEM-encoded private key (from `KeyManager.load_private_key`) |
| `signer_id` | `str` | Identity string stored in the signature (e.g. email, CI pipeline name) |
| `password` | `bytes \| None` | Passphrase if the private key is encrypted; `None` otherwise |

**Returns:** `SignedManifest` with `signature.algorithm` auto-detected from the key type.

**Raises:** `ValueError` if the key type is not Ed25519 or ECDSA P-256.

**Example:**

```python
from aumai_modelseal import KeyManager, ModelSigner

km = KeyManager()
signer = ModelSigner()

private_key_bytes = km.load_private_key("./keys/private.pem")
manifest = signer.create_manifest("./my-model")
signed = signer.sign_manifest(manifest, private_key_bytes, signer_id="ci@myorg.com")

with open("signed_manifest.json", "w", encoding="utf-8") as f:
    f.write(signed.model_dump_json(indent=2))
```

---

### `ModelVerifier`

```python
class ModelVerifier:
    def verify_manifest(
        self,
        signed_manifest: SignedManifest,
        public_key_bytes: bytes,
    ) -> VerificationResult: ...

    def verify_files(
        self,
        model_dir: str,
        manifest: ModelManifest,
    ) -> list[tuple[str, bool]]: ...
```

Verifies cryptographic signatures and on-disk file integrity.

---

#### `ModelVerifier.verify_manifest`

```python
def verify_manifest(
    self,
    signed_manifest: SignedManifest,
    public_key_bytes: bytes,
) -> VerificationResult
```

Verify that `signed_manifest` was signed with the private key corresponding to
`public_key_bytes`. Never raises on cryptographic failure — failures are returned
as `VerificationResult(valid=False, error=...)`.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `signed_manifest` | `SignedManifest` | The signed manifest to verify |
| `public_key_bytes` | `bytes` | PEM-encoded public key to verify against |

**Returns:** `VerificationResult`. Check `result.valid` before using other fields.

**Example:**

```python
from aumai_modelseal import KeyManager, ModelVerifier, SignedManifest

km = KeyManager()
verifier = ModelVerifier()

with open("signed_manifest.json", encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())

public_key_bytes = km.load_public_key("./keys/public.pem")
result = verifier.verify_manifest(signed, public_key_bytes)

if result.valid:
    print(f"OK — signed by {result.signer_id}")
else:
    print(f"FAIL — {result.error}")
```

---

#### `ModelVerifier.verify_files`

```python
def verify_files(
    self,
    model_dir: str,
    manifest: ModelManifest,
) -> list[tuple[str, bool]]
```

Verify each file listed in `manifest` by re-hashing it and comparing against the
stored SHA-256. Missing files are reported as `False`.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `model_dir` | `str` | Root directory where the model files reside |
| `manifest` | `ModelManifest` | The manifest describing expected files and hashes |

**Returns:** List of `(relative_path, is_valid)` tuples, in manifest order.

**Example:**

```python
file_results = verifier.verify_files("./my-model", signed.manifest)
for path, ok in file_results:
    print(f"{'OK  ' if ok else 'FAIL'}: {path}")

all_ok = all(ok for _, ok in file_results)
```

---

### `PublisherRegistry`

```python
class PublisherRegistry:
    def __init__(self, registry_path: str | None = None) -> None: ...

    def add_publisher(self, publisher: TrustedPublisher) -> None: ...
    def remove_publisher(self, publisher_id: str) -> None: ...
    def get_publisher(self, publisher_id: str) -> TrustedPublisher | None: ...
    def list_publishers(self) -> list[TrustedPublisher]: ...

    def verify_against_registry(
        self, signed_manifest: SignedManifest
    ) -> VerificationResult: ...
```

Manages a set of trusted publishers and verifies manifests against their registered
public keys. Optionally persists to a JSON file.

---

#### `PublisherRegistry.__init__`

```python
def __init__(self, registry_path: str | None = None) -> None
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `registry_path` | `str \| None` | Path to a JSON file for persistence. If the file exists, publishers are loaded immediately. Pass `None` for an in-memory-only registry |

---

#### `PublisherRegistry.add_publisher`

```python
def add_publisher(self, publisher: TrustedPublisher) -> None
```

Add or replace a trusted publisher entry. Immediately persists to disk if a
`registry_path` was provided.

---

#### `PublisherRegistry.remove_publisher`

```python
def remove_publisher(self, publisher_id: str) -> None
```

Remove a publisher from the trust registry.

**Raises:** `KeyError` if `publisher_id` is not in the registry.

---

#### `PublisherRegistry.get_publisher`

```python
def get_publisher(self, publisher_id: str) -> TrustedPublisher | None
```

Return the `TrustedPublisher` for `publisher_id`, or `None` if not registered.

---

#### `PublisherRegistry.list_publishers`

```python
def list_publishers(self) -> list[TrustedPublisher]
```

Return a list of all registered `TrustedPublisher` instances.

---

#### `PublisherRegistry.verify_against_registry`

```python
def verify_against_registry(
    self, signed_manifest: SignedManifest
) -> VerificationResult
```

Verify `signed_manifest` against the public key of the matching trusted publisher.
The signer identity in `signed_manifest.signature.signer_id` must correspond to a
registered publisher.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `signed_manifest` | `SignedManifest` | The manifest to verify |

**Returns:** `VerificationResult`. If the signer is unknown, `valid=False` with an
informative error message.

**Example:**

```python
from aumai_modelseal import PublisherRegistry, SignedManifest

registry = PublisherRegistry(registry_path="./registry.json")

with open("signed_manifest.json", encoding="utf-8") as f:
    signed = SignedManifest.model_validate_json(f.read())

result = registry.verify_against_registry(signed)
print(result.valid, result.error)
```

---

## Internal Functions (non-public)

The following functions are internal implementation details. They are documented here
for contributors.

### `_sha256_file(file_path: Path) -> str`

Return the lowercase hex-encoded SHA-256 digest of `file_path`, read in 64 KB chunks.

### `_canonical_manifest_bytes(manifest: ModelManifest) -> bytes`

Serialise `manifest` to a deterministic JSON byte string with `sort_keys=True` and
no extra whitespace. This is the payload that is cryptographically signed.
