# Design Document: Post-Copy DB Verification

## Overview

Add SHA-256 post-copy verification to all OscalStore database seeding paths, extract shared hash-reading logic into a helper, and remove the brittle hardcoded-count test.

## Architecture

The change is scoped to `OscalStore` in `oscal_store.py` and one test class in `test_build_oscal_db.py`. No new modules or public API changes.

### Component Changes

#### 1. New static method: `_get_expected_db_hash()`

Extracts the hashes.json parsing logic currently duplicated in `_verify_bundled_db()` into a reusable helper.

```python
@staticmethod
def _get_expected_db_hash() -> str | None:
    """Read the expected SHA-256 hash for oscal_store.db from hashes.json.

    Returns:
        The expected hex digest string, or None if hashes.json is
        missing, malformed, or lacks an entry for oscal_store.db.
    """
    if not BUNDLED_HASHES_PATH.exists():
        logger.warning(
            "hashes.json not found at %s; cannot verify DB",
            BUNDLED_HASHES_PATH,
        )
        return None

    try:
        manifest = json.loads(BUNDLED_HASHES_PATH.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read hashes.json: %s", exc)
        return None

    expected = manifest.get("file_hashes", {}).get("oscal_store.db")
    if not expected:
        logger.warning("No hash entry for oscal_store.db in hashes.json")
    return expected
```

#### 2. New static method: `_verify_file_hash()`

Computes SHA-256 of a file and compares against the expected hash. Raises `RuntimeError` on mismatch and cleans up the file.

```python
@staticmethod
def _verify_file_hash(file_path: Path, expected_hash: str) -> None:
    """Verify a file's SHA-256 matches the expected hash.

    Args:
        file_path: Path to the file to verify.
        expected_hash: Expected SHA-256 hex digest.

    Raises:
        RuntimeError: If the hash does not match.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    actual_hash = h.hexdigest()
    if actual_hash != expected_hash:
        file_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Post-copy integrity check failed for {file_path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )
```

#### 3. Refactored `_verify_bundled_db()`

Rewritten to use `_get_expected_db_hash()` and `_verify_file_hash()` internally, preserving the same return type (`bool`) and behavior.

```python
@staticmethod
def _verify_bundled_db() -> bool:
    """Verify the bundled DB SHA-256 against the hash in hashes.json."""
    if not BUNDLED_DB_PATH.exists():
        return False

    expected_hash = OscalStore._get_expected_db_hash()
    if not expected_hash:
        return False

    h = hashlib.sha256()
    try:
        with open(BUNDLED_DB_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError as exc:
        logger.warning("Failed to read bundled DB for hashing: %s", exc)
        return False

    actual_hash = h.hexdigest()
    if actual_hash != expected_hash:
        logger.warning(
            "Bundled DB integrity check failed: expected %s, got %s",
            expected_hash,
            actual_hash,
        )
        return False

    logger.info("Bundled DB integrity verified")
    return True
```

Note: `_verify_bundled_db` does NOT call `_verify_file_hash` directly because it must not delete the bundled DB on mismatch (it's a read-only package asset) and must return `bool` rather than raise. It shares only the hash-reading helper.

#### 4. Modified `_resolve_persistent()`

After `shutil.copy2`, call `_verify_file_hash()` on the copied file. If it raises `RuntimeError`, the error propagates up (fatal).

```python
def _resolve_persistent(self, db_path: str) -> str:
    p = Path(db_path)
    if p.exists():
        self._db_mode = "persistent"
        logger.info("Opening existing persistent DB at %s", db_path)
        return db_path

    if self._seed_from_bundled:
        if BUNDLED_DB_PATH.exists() and self._verify_bundled_db():
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(BUNDLED_DB_PATH, p)
            except OSError:
                logger.warning(
                    "Failed to copy bundled DB to %s; creating fresh DB",
                    db_path,
                )
            else:
                # Verify the copy's integrity
                expected_hash = self._get_expected_db_hash()
                if expected_hash:
                    self._verify_file_hash(p, expected_hash)
                self._db_mode = "persistent"
                logger.info(
                    "Seeded persistent DB from bundled DB at %s", db_path
                )
                return db_path

    p.parent.mkdir(parents=True, exist_ok=True)
    self._db_mode = "persistent"
    logger.info("Creating new persistent DB at %s", db_path)
    return db_path
```

#### 5. Modified `_copy_bundled_to_temp()`

Same pattern: after `shutil.copy2`, verify the copy.

```python
def _copy_bundled_to_temp(self) -> str:
    self._temp_dir = tempfile.TemporaryDirectory(prefix="oscal_store_")
    dest = Path(self._temp_dir.name) / "oscal_store.db"
    try:
        shutil.copy2(BUNDLED_DB_PATH, dest)
    except OSError:
        logger.warning(
            "Failed to copy bundled DB; falling back to ephemeral"
        )
        return self._create_ephemeral()

    expected_hash = self._get_expected_db_hash()
    if expected_hash:
        self._verify_file_hash(dest, expected_hash)
    self._db_mode = "bundled"
    logger.info("Copied bundled DB to temp location %s", dest)
    return str(dest)
```

### Test Changes

#### Remove `test_new_path_with_bundled_db_seeds`

Delete the entire method from `TestPreservationDefaultSeeding`. Update the class docstring to remove the reference to Requirement 3.1 and the hardcoded count test.

#### Update class docstring

```python
class TestPreservationDefaultSeeding:
    """Preservation: default OscalStore seeding behavior unchanged.

    **Validates: Requirements 3.2, 3.3, 3.4**

    These tests capture the existing correct behavior that must not regress
    when the bugfix is applied. They MUST PASS on unfixed code.
    """
```

## Error Handling

- `_verify_file_hash()` raises `RuntimeError` on hash mismatch — this is intentionally fatal. Without an intact database, the server cannot perform as expected.
- `_verify_file_hash()` calls `file_path.unlink(missing_ok=True)` before raising to clean up the corrupted copy.
- If `_get_expected_db_hash()` returns `None` (missing manifest), the post-copy verification is skipped. The pre-copy `_verify_bundled_db()` check would have already caught this case and prevented the copy.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Hash mismatch raises RuntimeError and removes file

*For any* file path and any pair of (expected_hash, actual_hash) where expected_hash differs from actual_hash, calling `_verify_file_hash` on that file SHALL raise a `RuntimeError` whose message contains both the expected hash and the actual hash and the file path, AND the file SHALL not exist after the error is raised.

**Validates: Requirements 1.3, 1.4**
