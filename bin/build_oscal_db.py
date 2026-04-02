#!/usr/bin/env python3
"""
Build script for the bundled OSCAL SQLite database.

Scans the bundled content directories (component_definitions/ and oscal_docs/),
eagerly indexes all documents (full parse + child element extraction + FTS
population), computes a SHA-256 hash of the resulting DB, and updates the
appropriate hashes.json manifest.

Usage:
    hatch run python bin/build_oscal_db.py

The resulting ``oscal_store.db`` is placed at
``src/mcp_server_for_oscal/oscal_store.db`` and is intended to be shipped
with the package for instant startup.

Requirements: 10.1, 10.2, 10.3, 10.4
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Resolve paths relative to the repository root
REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "src" / "mcp_server_for_oscal"
DB_PATH = PACKAGE_DIR / "oscal_store.db"
COMPONENT_DEFS_DIR = REPO_ROOT / "data" / "component_definitions"
OSCAL_DOCS_DIR = REPO_ROOT / "data" / "oscal_docs"
HASHES_FILE = PACKAGE_DIR / "hashes.json"


def compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def update_hashes_json(db_hash: str) -> None:
    """Update (or create) the hashes.json manifest with the DB hash.

    Follows the same pattern as ``bin/update_hashes.py`` — the manifest
    contains a ``commit`` key and a ``file_hashes`` dict.
    """
    manifest: dict = {}
    if HASHES_FILE.exists():
        try:
            manifest = json.loads(HASHES_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            logger.warning("Could not read existing %s; creating new", HASHES_FILE)

    if "file_hashes" not in manifest:
        manifest["file_hashes"] = {}
    if "commit" not in manifest:
        manifest["commit"] = ""

    manifest["file_hashes"]["oscal_store.db"] = db_hash

    HASHES_FILE.write_text(json.dumps(manifest, indent=2) + "\n")
    logger.info("Updated %s with oscal_store.db hash", HASHES_FILE)


def build_db(
    db_path: Path | None = None,
    component_defs_dir: Path | None = None,
    oscal_docs_dir: Path | None = None,
) -> dict:
    """Build the bundled OSCAL database.

    Args:
        db_path: Where to write the SQLite DB. Defaults to the package
            location ``src/mcp_server_for_oscal/oscal_store.db``.
        component_defs_dir: Directory containing bundled component
            definitions. Defaults to the package ``component_definitions/``.
        oscal_docs_dir: Directory containing other bundled OSCAL docs.
            Defaults to the package ``oscal_docs/``.

    Returns:
        A stats dict with keys: ``docs_indexed``, ``children``,
        ``db_size_bytes``, ``db_hash``.
    """
    # Lazy import so the module can be imported without triggering
    # OscalStore side-effects (important for testing).
    from mcp_server_for_oscal.tools.oscal_store import OscalStore

    db_path = db_path or DB_PATH
    component_defs_dir = component_defs_dir or COMPONENT_DEFS_DIR
    oscal_docs_dir = oscal_docs_dir or OSCAL_DOCS_DIR

    # Remove existing DB so we get a clean build (idempotency)
    if db_path.exists():
        os.remove(db_path)
        logger.info("Removed existing DB at %s", db_path)

    # Initialize store with explicit db_path
    store = OscalStore(db_path=str(db_path), cache_size=200, seed_from_bundled=False)

    # --- Scan directories ---
    total_scanned = 0
    if component_defs_dir.exists():
        n = store.scan_directory(component_defs_dir)
        logger.info("Scanned component_definitions/: %d document(s)", n)
        total_scanned += n
    else:
        logger.info("component_definitions/ not found, skipping")

    if oscal_docs_dir.exists():
        n = store.scan_directory(oscal_docs_dir)
        logger.info("Scanned oscal_docs/: %d document(s)", n)
        total_scanned += n
    else:
        logger.info("oscal_docs/ not found, skipping")

    # --- Eagerly index every document ---
    rows = store._conn.execute("SELECT id FROM documents").fetchall()
    for row in rows:
        store._ensure_indexed(row["id"])

    # --- Gather stats ---
    doc_count = store._conn.execute(
        "SELECT COUNT(*) AS cnt FROM documents"
    ).fetchone()["cnt"]
    child_count = store._conn.execute(
        "SELECT COUNT(*) AS cnt FROM child_elements"
    ).fetchone()["cnt"]

    store.close()

    db_size = db_path.stat().st_size

    stats = {
        "docs_indexed": doc_count,
        "children": child_count,
        "db_size_bytes": db_size,
        "db_hash": "",
    }

    logger.info(
        "Build complete — %d document(s), %d child element(s), DB size %s",
        doc_count,
        child_count,
        _human_size(db_size),
    )

    return stats


def _human_size(nbytes: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"


def main() -> None:
    """Entry point for the build script."""
    logger.info("Building bundled OSCAL database at %s", DB_PATH)

    stats = build_db()

    # Compute hash and update manifest
    db_hash = compute_sha256(DB_PATH)
    stats["db_hash"] = db_hash
    logger.info("SHA-256: %s", db_hash)

    update_hashes_json(db_hash)

    logger.info(
        "Done — %d docs, %d children, %s",
        stats["docs_indexed"],
        stats["children"],
        _human_size(stats["db_size_bytes"]),
    )


if __name__ == "__main__":
    main()
