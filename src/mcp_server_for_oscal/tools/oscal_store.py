"""
SQLite-backed store for all OSCAL model types.

Replaces the in-memory ComponentDefinitionStore with a scalable store
that supports all eight OSCAL model types, lazy loading, FTS5 search,
pagination, and three database modes (bundled, persistent, ephemeral).
"""

import functools
import importlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import OSCALModelType, ROOT_KEY_TO_MODEL_TYPE

logger = logging.getLogger(__name__)

# Path to the pre-built DB shipped with the package
BUNDLED_DB_PATH = Path(__file__).parent.parent / "oscal_store.db"

# Maps each OSCAL model type to the child element types it can contain.
CHILD_ELEMENT_TYPES: dict[OSCALModelType, tuple[str, ...]] = {
    OSCALModelType.COMPONENT_DEFINITION: ("component", "capability"),
    OSCALModelType.CATALOG: ("control", "group"),
    OSCALModelType.PROFILE: ("import", "modify"),
    OSCALModelType.SYSTEM_SECURITY_PLAN: (
        "control-implementation",
        "system-component",
    ),
    OSCALModelType.ASSESSMENT_PLAN: ("task", "activity"),
    OSCALModelType.ASSESSMENT_RESULTS: ("result", "finding"),
    OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: ("poam-item",),
    OSCALModelType.MAPPING: ("mapping",),
}

# Maps OSCALModelType to (trestle module, class name) for validation.
TRESTLE_MODEL_MAP: dict[OSCALModelType, tuple[str, str]] = {
    OSCALModelType.CATALOG: ("trestle.oscal.catalog", "Catalog"),
    OSCALModelType.PROFILE: ("trestle.oscal.profile", "Profile"),
    OSCALModelType.COMPONENT_DEFINITION: (
        "trestle.oscal.component",
        "ComponentDefinition",
    ),
    OSCALModelType.SYSTEM_SECURITY_PLAN: (
        "trestle.oscal.ssp",
        "SystemSecurityPlan",
    ),
    OSCALModelType.ASSESSMENT_PLAN: (
        "trestle.oscal.assessment_plan",
        "AssessmentPlan",
    ),
    OSCALModelType.ASSESSMENT_RESULTS: (
        "trestle.oscal.assessment_results",
        "AssessmentResults",
    ),
    OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: (
        "trestle.oscal.poam",
        "PlanOfActionAndMilestones",
    ),
    # mapping-collection has no trestle model until OSCAL > 1.2.0
}


class OscalStore:
    """SQLite-backed store for all OSCAL model types."""

    def __init__(
        self,
        db_path: str | None = None,
        cache_size: int = 100,
    ) -> None:
        """Initialize the store, resolving database mode.

        Resolution order:
        1. If db_path is set and file exists -> open persistent DB
        2. If db_path is set and file missing -> copy bundled DB (if exists)
           or create new
        3. If db_path is None and bundled DB exists -> copy to temp,
           verify integrity
        4. If db_path is None and no bundled DB -> create ephemeral in temp dir

        Args:
            db_path: Path to SQLite database file. None = auto-resolve.
                     When None, falls back to config.oscal_store_db_path if set.
            cache_size: Max number of parsed Trestle models to cache.

        Raises:
            RuntimeError: If the database cannot be created or opened.
        """
        self._cache_size = cache_size
        self._db_mode: str = ""  # "bundled", "persistent", or "ephemeral"
        self._temp_dir: tempfile.TemporaryDirectory | None = None
        self._cached_parse = self._build_cached_parse()

        resolved_path = self._resolve_db_path(db_path)
        self._db_path: str = resolved_path

        try:
            self._conn = sqlite3.connect(resolved_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise RuntimeError(
                f"Cannot open SQLite database at {resolved_path}: {exc}"
            ) from exc

        self._init_schema()
        logger.info(
            "OscalStore initialized in %s mode at %s",
            self._db_mode,
            resolved_path,
        )

    # ------------------------------------------------------------------
    # Database mode resolution
    # ------------------------------------------------------------------

    def _resolve_db_path(self, db_path: str | None) -> str:
        """Resolve the database file path based on configuration.

        Returns the resolved path string and sets ``self._db_mode``.
        """
        # Use explicit argument first, then fall back to config
        effective_path = db_path
        if effective_path is None:
            cfg_path = getattr(config, "oscal_store_db_path", "")
            if cfg_path:
                effective_path = cfg_path

        if effective_path:
            return self._resolve_persistent(effective_path)
        return self._resolve_auto()

    def _resolve_persistent(self, db_path: str) -> str:
        """Resolve when an explicit DB path is provided."""
        p = Path(db_path)
        if p.exists():
            self._db_mode = "persistent"
            logger.info("Opening existing persistent DB at %s", db_path)
            return db_path

        # DB file doesn't exist yet — seed from bundled if available
        if BUNDLED_DB_PATH.exists():
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(BUNDLED_DB_PATH, p)
                self._db_mode = "persistent"
                logger.info(
                    "Seeded persistent DB from bundled DB at %s", db_path
                )
                return db_path
            except OSError:
                logger.warning(
                    "Failed to copy bundled DB to %s; creating fresh DB",
                    db_path,
                )

        # Create a new empty persistent DB
        p.parent.mkdir(parents=True, exist_ok=True)
        self._db_mode = "persistent"
        logger.info("Creating new persistent DB at %s", db_path)
        return db_path

    def _resolve_auto(self) -> str:
        """Resolve when no explicit DB path is configured."""
        if BUNDLED_DB_PATH.exists():
            return self._copy_bundled_to_temp()

        # No bundled DB — create ephemeral
        return self._create_ephemeral()

    def _copy_bundled_to_temp(self) -> str:
        """Copy the bundled DB to a temporary directory."""
        self._temp_dir = tempfile.TemporaryDirectory(
            prefix="oscal_store_"
        )
        dest = Path(self._temp_dir.name) / "oscal_store.db"
        try:
            shutil.copy2(BUNDLED_DB_PATH, dest)
            self._db_mode = "bundled"
            logger.info("Copied bundled DB to temp location %s", dest)
            return str(dest)
        except OSError:
            logger.warning(
                "Failed to copy bundled DB; falling back to ephemeral"
            )
            return self._create_ephemeral()

    def _create_ephemeral(self) -> str:
        """Create an ephemeral DB in a temporary directory."""
        if self._temp_dir is None:
            self._temp_dir = tempfile.TemporaryDirectory(
                prefix="oscal_store_"
            )
        dest = Path(self._temp_dir.name) / "oscal_store.db"
        self._db_mode = "ephemeral"
        logger.info("Creating ephemeral DB at %s", dest)
        return str(dest)

    # ------------------------------------------------------------------
    # Schema initialization
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create all required tables, indexes, and FTS virtual table.

        Uses ``CREATE … IF NOT EXISTS`` so it is safe to call on an
        existing database.
        """
        cur = self._conn.cursor()
        try:
            # -- documents table --
            cur.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid        TEXT    NOT NULL UNIQUE,
                    title       TEXT    NOT NULL,
                    model_type  TEXT    NOT NULL,
                    file_path   TEXT    NOT NULL UNIQUE,
                    file_size   INTEGER NOT NULL,
                    file_mtime  REAL    NOT NULL,
                    raw_json    TEXT    NOT NULL,
                    indexed     INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
                )
            """)

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_uuid "
                "ON documents(uuid)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_title "
                "ON documents(title COLLATE NOCASE)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_model_type "
                "ON documents(model_type)"
            )

            # -- child_elements table --
            cur.execute("""
                CREATE TABLE IF NOT EXISTS child_elements (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid            TEXT    NOT NULL,
                    title           TEXT    NOT NULL,
                    element_type    TEXT    NOT NULL,
                    parent_doc_id   INTEGER NOT NULL
                                    REFERENCES documents(id) ON DELETE CASCADE,
                    description     TEXT,
                    raw_json        TEXT,
                    UNIQUE(uuid, parent_doc_id)
                )
            """)

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_child_uuid "
                "ON child_elements(uuid)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_child_title "
                "ON child_elements(title COLLATE NOCASE)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_child_type "
                "ON child_elements(element_type)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_child_parent "
                "ON child_elements(parent_doc_id)"
            )

            # -- FTS5 virtual table --
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS fts_index USING fts5(
                    entity_type,
                    entity_id,
                    title,
                    description,
                    model_type,
                    content=''
                )
            """)

            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise RuntimeError(
                f"Failed to initialize database schema: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    @property
    def db_mode(self) -> str:
        """Return the resolved database mode."""
        return self._db_mode

    @property
    def db_path(self) -> str:
        """Return the resolved database file path."""
        return self._db_path

    def close(self) -> None:
        """Close the database connection and clean up temp resources."""
        if self._conn:
            self._conn.close()
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    # ------------------------------------------------------------------
    # LRU-cached model parsing
    # ------------------------------------------------------------------

    def get_parsed_model(self, doc_id: int) -> object:
        """Get a fully parsed Trestle model for a document, using LRU cache.

        Fetches ``raw_json`` and ``model_type`` from SQLite, then delegates
        to an instance-level LRU-cached parser so repeated accesses for the
        same ``doc_id`` are served from cache.

        The cache key includes ``doc_id`` and ``raw_json``, so when a file
        is re-ingested with new content the stale entry is naturally
        bypassed.

        Args:
            doc_id: The integer primary key of the document row.

        Returns:
            A parsed Trestle Pydantic model instance.

        Raises:
            ValueError: If no document exists for *doc_id* or the model
                type has no Trestle mapping.
            RuntimeError: If parsing fails.
        """
        row = self._conn.execute(
            "SELECT raw_json, model_type FROM documents WHERE id = ?",
            (doc_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"No document found with id {doc_id}")

        raw_json: str = row["raw_json"]
        model_type_str: str = row["model_type"]

        return self._cached_parse(doc_id, raw_json, model_type_str)

    @staticmethod
    def _do_parse(raw_json: str, model_type_str: str) -> object:
        """Parse *raw_json* into the Trestle model for *model_type_str*.

        This is the actual parsing logic, separated from caching so it
        can be tested independently.
        """
        try:
            model_type = OSCALModelType(model_type_str)
        except ValueError as exc:
            raise ValueError(
                f"Unknown model type '{model_type_str}'"
            ) from exc

        if model_type not in TRESTLE_MODEL_MAP:
            raise ValueError(
                f"No Trestle model mapping for type '{model_type_str}'"
            )

        module_name, class_name = TRESTLE_MODEL_MAP[model_type]
        try:
            mod = importlib.import_module(module_name)
            model_class = getattr(mod, class_name)
        except (ImportError, AttributeError) as exc:
            raise RuntimeError(
                f"Cannot load Trestle model {module_name}.{class_name}: {exc}"
            ) from exc

        data = json.loads(raw_json)
        root_data = data.get(model_type.value, data)

        try:
            return model_class.parse_obj(root_data)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to parse document as {class_name}: {exc}"
            ) from exc

    def _build_cached_parse(self) -> "functools._lru_cache_wrapper":
        """Build an LRU-cached wrapper around ``_do_parse``.

        The wrapper signature is ``(doc_id, raw_json, model_type_str)``
        so that *doc_id* + *raw_json* together form the effective cache
        key.  When a document is re-ingested with new content the
        *raw_json* argument changes, causing a cache miss.
        """

        @functools.lru_cache(maxsize=self._cache_size)
        def _cached_parse(
            doc_id: int, raw_json: str, model_type_str: str
        ) -> object:
            return OscalStore._do_parse(raw_json, model_type_str)

        return _cached_parse

    # ------------------------------------------------------------------
    # Model type detection
    # ------------------------------------------------------------------

    def _detect_model_type(self, file_path: Path) -> OSCALModelType | None:
        """Read only the first root key from a JSON file to detect model type.

        Opens the file, parses the JSON, and checks if the first (or any)
        root key maps to a known OSCAL model type via ROOT_KEY_TO_MODEL_TYPE.

        Args:
            file_path: Path to the JSON file.

        Returns:
            The detected OSCALModelType, or None if no known root key found.
        """
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Cannot read/parse %s: %s", file_path, exc)
            return None

        if not isinstance(data, dict):
            return None

        for key in data:
            if key in ROOT_KEY_TO_MODEL_TYPE:
                return ROOT_KEY_TO_MODEL_TYPE[key]
        return None

    def _detect_model_type_from_data(
        self, data: dict
    ) -> OSCALModelType | None:
        """Detect model type from already-parsed JSON data.

        Args:
            data: Parsed JSON dict.

        Returns:
            The detected OSCALModelType, or None if no known root key found.
        """
        if not isinstance(data, dict):
            return None
        for key in data:
            if key in ROOT_KEY_TO_MODEL_TYPE:
                return ROOT_KEY_TO_MODEL_TYPE[key]
        return None

    # ------------------------------------------------------------------
    # Trestle validation
    # ------------------------------------------------------------------

    def _validate_with_trestle(
        self, data: dict, model_type: OSCALModelType
    ) -> bool:
        """Validate document data using the corresponding Trestle model.

        Args:
            data: The full parsed JSON dict (with root key).
            model_type: The detected OSCAL model type.

        Returns:
            True if validation succeeds, False otherwise.
        """
        if model_type not in TRESTLE_MODEL_MAP:
            # No trestle model available (e.g. mapping-collection)
            # Accept without validation
            return True

        module_name, class_name = TRESTLE_MODEL_MAP[model_type]
        try:
            mod = importlib.import_module(module_name)
            model_class = getattr(mod, class_name)
            root_data = data.get(model_type.value, data)
            model_class.parse_obj(root_data)
            return True
        except Exception as exc:
            logger.warning(
                "Trestle validation failed for %s document: %s",
                model_type.value,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Directory scanning
    # ------------------------------------------------------------------

    def scan_directory(
        self,
        directory: Path,
        model_type_filter: OSCALModelType | None = None,
    ) -> int:
        """Scan a directory for OSCAL JSON files, extracting metadata only.

        Walks the directory tree for ``.json`` and ``.zip`` files.  For each
        file, extracts metadata (UUID, title, model_type, file_path,
        file_size, file_mtime, raw_json) and UPSERTs into the ``documents``
        table with ``indexed=0``.

        Change detection: files whose mtime **and** size match the stored
        values are skipped.

        Args:
            directory: Root directory to scan.
            model_type_filter: When set, only ingest documents of this type.

        Returns:
            Number of new or updated files ingested.
        """
        if not directory.exists():
            logger.info(
                "Directory does not exist, skipping: %s", directory
            )
            return 0

        if not directory.is_dir():
            logger.info("Path is not a directory, skipping: %s", directory)
            return 0

        count = 0

        # Process .json files
        json_files = list(directory.rglob("**/*.json"))
        for json_file in json_files:
            if json_file.name == "hashes.json":
                continue
            result = self._process_json_file(json_file, model_type_filter)
            if result:
                count += 1

        # Process .zip files
        zip_files = list(directory.rglob("**/*.zip"))
        for zip_file in zip_files:
            count += self._process_zip_file(zip_file, model_type_filter)

        if count == 0:
            logger.info(
                "No new or updated OSCAL documents found in %s", directory
            )
        else:
            logger.info(
                "Ingested %d new/updated document(s) from %s",
                count,
                directory,
            )

        return count

    def _file_unchanged(
        self, file_path: str, file_size: int, file_mtime: float
    ) -> bool:
        """Check if a file's mtime and size match the stored values."""
        row = self._conn.execute(
            "SELECT file_size, file_mtime FROM documents WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        if row is None:
            return False
        return row["file_size"] == file_size and row["file_mtime"] == file_mtime

    def _extract_metadata(
        self, data: dict, model_type: OSCALModelType
    ) -> tuple[str, str] | None:
        """Extract UUID and title from parsed OSCAL JSON data.

        Args:
            data: Full parsed JSON dict (with root key).
            model_type: The detected model type.

        Returns:
            (uuid, title) tuple, or None if extraction fails.
        """
        root_data = data.get(model_type.value, data)
        uuid = root_data.get("uuid")
        title = None
        metadata = root_data.get("metadata")
        if isinstance(metadata, dict):
            title = metadata.get("title")

        if not uuid or not title:
            return None
        return (str(uuid), str(title))

    def _upsert_document(
        self,
        uuid: str,
        title: str,
        model_type: str,
        file_path: str,
        file_size: int,
        file_mtime: float,
        raw_json: str,
    ) -> bool:
        """UPSERT a document row into the documents table.

        Returns True on success, False on failure.
        """
        try:
            self._conn.execute(
                """
                INSERT INTO documents
                    (uuid, title, model_type, file_path, file_size,
                     file_mtime, raw_json, indexed, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, datetime('now'))
                ON CONFLICT(uuid) DO UPDATE SET
                    title = excluded.title,
                    model_type = excluded.model_type,
                    file_path = excluded.file_path,
                    file_size = excluded.file_size,
                    file_mtime = excluded.file_mtime,
                    raw_json = excluded.raw_json,
                    indexed = 0,
                    updated_at = datetime('now')
                """,
                (uuid, title, model_type, file_path, file_size, file_mtime, raw_json),
            )
            self._conn.commit()
            return True
        except sqlite3.Error as exc:
            logger.error("Failed to upsert document %s: %s", uuid, exc)
            self._conn.rollback()
            return False

    def _process_json_file(
        self,
        json_file: Path,
        model_type_filter: OSCALModelType | None,
    ) -> bool:
        """Process a single JSON file for ingestion.

        Returns True if the file was ingested (new or updated).
        """
        file_path_str = str(json_file)
        try:
            stat = json_file.stat()
        except OSError as exc:
            logger.debug("Cannot stat %s: %s", json_file, exc)
            return False

        file_size = stat.st_size
        file_mtime = stat.st_mtime

        # Change detection
        if self._file_unchanged(file_path_str, file_size, file_mtime):
            return False

        # Detect model type
        model_type = self._detect_model_type(json_file)
        if model_type is None:
            logger.debug("No OSCAL root key found in %s", json_file)
            return False

        # Apply filter
        if model_type_filter is not None and model_type != model_type_filter:
            return False

        # Read full JSON
        try:
            with open(json_file) as f:
                raw_json = f.read()
            data = json.loads(raw_json)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Cannot read %s: %s", json_file, exc)
            return False

        # Validate with Trestle
        if not self._validate_with_trestle(data, model_type):
            logger.warning(
                "Skipping invalid document: %s", json_file
            )
            return False

        # Extract metadata
        meta = self._extract_metadata(data, model_type)
        if meta is None:
            logger.debug(
                "Cannot extract UUID/title from %s", json_file
            )
            return False

        uuid, title = meta
        return self._upsert_document(
            uuid, title, model_type.value, file_path_str,
            file_size, file_mtime, raw_json,
        )

    def _process_zip_file(
        self,
        zip_path: Path,
        model_type_filter: OSCALModelType | None,
    ) -> int:
        """Process a zip file containing OSCAL JSON documents.

        Returns the number of documents ingested from the zip.
        """
        count = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for inner_name in zf.namelist():
                    if not inner_name.endswith(".json"):
                        continue
                    # Use zip_path/inner_name as the canonical file_path
                    file_path_str = zip_path.joinpath(inner_name).as_posix()

                    # For zip entries, use the zip file's stat for mtime/size
                    try:
                        zip_stat = zip_path.stat()
                    except OSError:
                        continue

                    try:
                        with zf.open(inner_name) as inner_f:
                            raw_bytes = inner_f.read()
                    except (KeyError, OSError) as exc:
                        logger.debug(
                            "Cannot read %s from %s: %s",
                            inner_name, zip_path, exc,
                        )
                        continue

                    raw_json = raw_bytes.decode("utf-8", errors="replace")
                    file_size = len(raw_bytes)
                    file_mtime = zip_stat.st_mtime

                    # Change detection
                    if self._file_unchanged(
                        file_path_str, file_size, file_mtime
                    ):
                        continue

                    try:
                        data = json.loads(raw_json)
                    except json.JSONDecodeError as exc:
                        logger.debug(
                            "Invalid JSON in %s/%s: %s",
                            zip_path, inner_name, exc,
                        )
                        continue

                    model_type = self._detect_model_type_from_data(data)
                    if model_type is None:
                        continue

                    if (
                        model_type_filter is not None
                        and model_type != model_type_filter
                    ):
                        continue

                    # Validate with Trestle
                    if not self._validate_with_trestle(data, model_type):
                        logger.warning(
                            "Skipping invalid document in zip: %s/%s",
                            zip_path, inner_name,
                        )
                        continue

                    meta = self._extract_metadata(data, model_type)
                    if meta is None:
                        continue

                    uuid, title = meta
                    if self._upsert_document(
                        uuid, title, model_type.value, file_path_str,
                        file_size, file_mtime, raw_json,
                    ):
                        count += 1

        except zipfile.BadZipFile as exc:
            logger.debug("Bad zip file %s: %s", zip_path, exc)
        except OSError as exc:
            logger.debug("Cannot open zip %s: %s", zip_path, exc)

        return count
