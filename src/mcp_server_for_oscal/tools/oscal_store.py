"""
SQLite-backed store for all OSCAL model types.

Replaces the in-memory ComponentDefinitionStore with a scalable store
that supports all eight OSCAL model types, lazy loading, FTS5 search,
pagination, and three database modes (bundled, persistent, ephemeral).
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import OSCALModelType, ROOT_KEY_TO_MODEL_TYPE

logger = logging.getLogger(__name__)

# Path to the pre-built DB shipped with the package
BUNDLED_DB_PATH = Path(__file__).parent.parent / "oscal_store.db"

# Path to the package-level hashes.json manifest (written by build_oscal_db.py)
BUNDLED_HASHES_PATH = Path(__file__).parent.parent / "hashes.json"

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
    OSCALModelType.MAPPING: (
        "trestle.oscal.mapping",
        "MappingCollection",
    ),
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

        # DB file doesn't exist yet — seed from bundled if available and valid
        if BUNDLED_DB_PATH.exists() and self._verify_bundled_db():
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
            if self._verify_bundled_db():
                return self._copy_bundled_to_temp()
            logger.warning(
                "Bundled DB failed integrity check; "
                "falling back to ephemeral DB"
            )
            return self._create_ephemeral()

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

    @staticmethod
    def _verify_bundled_db() -> bool:
        """Verify the bundled DB SHA-256 against the hash in hashes.json.

        Reuses the same integrity verification pattern as
        ``verify_package_integrity`` in ``utils.py``, but operates on a
        single file rather than a whole directory.

        Returns:
            True if the bundled DB exists and its hash matches the
            recorded value in hashes.json.  False if the DB is missing,
            hashes.json is missing/malformed, or the hash does not match.
        """
        if not BUNDLED_DB_PATH.exists():
            return False

        if not BUNDLED_HASHES_PATH.exists():
            logger.warning(
                "hashes.json not found at %s; cannot verify bundled DB",
                BUNDLED_HASHES_PATH,
            )
            return False

        try:
            manifest = json.loads(BUNDLED_HASHES_PATH.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read hashes.json: %s", exc)
            return False

        file_hashes = manifest.get("file_hashes", {})
        expected_hash = file_hashes.get("oscal_store.db")
        if not expected_hash:
            logger.warning(
                "No hash entry for oscal_store.db in hashes.json"
            )
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
                "Bundled DB integrity check failed: "
                "expected %s, got %s",
                expected_hash,
                actual_hash,
            )
            return False

        logger.info("Bundled DB integrity verified")
        return True

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
                    model_type
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
    # Lazy indexing
    # ------------------------------------------------------------------

    def _ensure_indexed(self, doc_id: int) -> None:
        """Ensure a document's child elements are indexed.

        Checks the ``indexed`` flag on the document row.  If already 1,
        returns immediately (no-op).  Otherwise, parses the document via
        the LRU cache, extracts child elements, inserts them into the
        ``child_elements`` and ``fts_index`` tables, and sets
        ``indexed=1``.

        Args:
            doc_id: The integer primary key of the document row.

        Raises:
            ValueError: If no document exists for *doc_id*.
            RuntimeError: If parsing or extraction fails.
        """
        row = self._conn.execute(
            "SELECT indexed, model_type, title, uuid FROM documents WHERE id = ?",
            (doc_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"No document found with id {doc_id}")

        if row["indexed"]:
            return

        model_type_str = row["model_type"]
        try:
            model_type = OSCALModelType(model_type_str)
        except ValueError:
            logger.warning(
                "Unknown model type '%s' for doc %d; skipping indexing",
                model_type_str,
                doc_id,
            )
            return

        # Parse the full Trestle model (uses LRU cache)
        parsed_model = self.get_parsed_model(doc_id)

        # Extract child elements
        children = self._extract_child_elements(model_type, parsed_model)

        try:
            cur = self._conn.cursor()

            # Remove any stale child elements for this doc
            cur.execute(
                "DELETE FROM child_elements WHERE parent_doc_id = ?",
                (doc_id,),
            )

            for child in children:
                cur.execute(
                    """
                    INSERT OR REPLACE INTO child_elements
                        (uuid, title, element_type, parent_doc_id,
                         description, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        child["uuid"],
                        child["title"],
                        child["element_type"],
                        doc_id,
                        child.get("description"),
                        child.get("raw_json"),
                    ),
                )

                # Insert FTS entry for the child element
                child_id = cur.lastrowid
                cur.execute(
                    """
                    INSERT INTO fts_index
                        (entity_type, entity_id, title, description, model_type)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "child_element",
                        str(child_id),
                        child["title"],
                        child.get("description", ""),
                        model_type_str,
                    ),
                )

            # Insert FTS entry for the document itself
            cur.execute(
                """
                INSERT INTO fts_index
                    (entity_type, entity_id, title, description, model_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "document",
                    str(doc_id),
                    row["title"],
                    "",
                    model_type_str,
                ),
            )

            # Mark as indexed
            cur.execute(
                "UPDATE documents SET indexed = 1 WHERE id = ?",
                (doc_id,),
            )

            self._conn.commit()
            logger.debug(
                "Indexed doc %d (%s): %d child elements",
                doc_id,
                model_type_str,
                len(children),
            )
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise RuntimeError(
                f"Failed to index document {doc_id}: {exc}"
            ) from exc

    def _extract_child_elements(
        self,
        model_type: OSCALModelType,
        parsed_model: object,
    ) -> list[dict]:
        """Extract child element metadata from a parsed Trestle model.

        Each returned dict has keys: uuid, title, element_type,
        description (optional), raw_json (optional).

        Args:
            model_type: The OSCAL model type of the document.
            parsed_model: A parsed Trestle Pydantic model instance.

        Returns:
            A list of child element dicts.
        """
        children: list[dict] = []

        if model_type == OSCALModelType.COMPONENT_DEFINITION:
            # components
            for comp in getattr(parsed_model, "components", None) or []:
                children.append(self._child_dict(
                    uuid=str(comp.uuid),
                    title=str(comp.title),
                    element_type="component",
                    description=str(comp.description) if comp.description else None,
                    obj=comp,
                ))
            # capabilities
            for cap in getattr(parsed_model, "capabilities", None) or []:
                children.append(self._child_dict(
                    uuid=str(cap.uuid),
                    title=str(cap.name),
                    element_type="capability",
                    description=str(cap.description) if cap.description else None,
                    obj=cap,
                ))

        elif model_type == OSCALModelType.CATALOG:
            # controls (top-level)
            for ctrl in getattr(parsed_model, "controls", None) or []:
                children.append(self._child_dict(
                    uuid=str(ctrl.id),
                    title=str(ctrl.title),
                    element_type="control",
                    description=None,
                    obj=ctrl,
                ))
            # groups
            for grp in getattr(parsed_model, "groups", None) or []:
                children.append(self._child_dict(
                    uuid=str(grp.id),
                    title=str(grp.title),
                    element_type="group",
                    description=None,
                    obj=grp,
                ))

        elif model_type == OSCALModelType.PROFILE:
            # imports
            for idx, imp in enumerate(
                getattr(parsed_model, "imports", None) or []
            ):
                href = str(getattr(imp, "href", ""))
                children.append(self._child_dict(
                    uuid=f"import-{idx}",
                    title=href or f"import-{idx}",
                    element_type="import",
                    description=href,
                    obj=imp,
                ))
            # modify
            modify = getattr(parsed_model, "modify", None)
            if modify is not None:
                children.append(self._child_dict(
                    uuid="modify",
                    title="modify",
                    element_type="modify",
                    description=None,
                    obj=modify,
                ))

        elif model_type == OSCALModelType.SYSTEM_SECURITY_PLAN:
            # control-implementation
            ctrl_impl = getattr(parsed_model, "control_implementation", None)
            if ctrl_impl is not None:
                desc = (
                    str(ctrl_impl.description)
                    if ctrl_impl.description
                    else None
                )
                children.append(self._child_dict(
                    uuid="control-implementation",
                    title="control-implementation",
                    element_type="control-implementation",
                    description=desc,
                    obj=ctrl_impl,
                ))
            # system-components from system_implementation
            sys_impl = getattr(parsed_model, "system_implementation", None)
            if sys_impl is not None:
                for comp in getattr(sys_impl, "components", None) or []:
                    children.append(self._child_dict(
                        uuid=str(comp.uuid),
                        title=str(comp.title),
                        element_type="system-component",
                        description=(
                            str(comp.description)
                            if comp.description
                            else None
                        ),
                        obj=comp,
                    ))

        elif model_type == OSCALModelType.ASSESSMENT_PLAN:
            # tasks
            for task in getattr(parsed_model, "tasks", None) or []:
                children.append(self._child_dict(
                    uuid=str(task.uuid),
                    title=str(task.title),
                    element_type="task",
                    description=(
                        str(task.description)
                        if task.description
                        else None
                    ),
                    obj=task,
                ))
            # activities from local_definitions
            local_defs = getattr(parsed_model, "local_definitions", None)
            if local_defs is not None:
                for act in getattr(local_defs, "activities", None) or []:
                    children.append(self._child_dict(
                        uuid=str(act.uuid),
                        title=str(act.title) if act.title else str(act.uuid),
                        element_type="activity",
                        description=(
                            str(act.description)
                            if act.description
                            else None
                        ),
                        obj=act,
                    ))

        elif model_type == OSCALModelType.ASSESSMENT_RESULTS:
            # results
            for result in getattr(parsed_model, "results", None) or []:
                children.append(self._child_dict(
                    uuid=str(result.uuid),
                    title=str(result.title),
                    element_type="result",
                    description=(
                        str(result.description)
                        if result.description
                        else None
                    ),
                    obj=result,
                ))
                # findings within each result
                for finding in getattr(result, "findings", None) or []:
                    children.append(self._child_dict(
                        uuid=str(finding.uuid),
                        title=str(finding.title),
                        element_type="finding",
                        description=(
                            str(finding.description)
                            if finding.description
                            else None
                        ),
                        obj=finding,
                    ))

        elif model_type == OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES:
            # poam-items
            for item in getattr(parsed_model, "poam_items", None) or []:
                children.append(self._child_dict(
                    uuid=str(item.uuid),
                    title=str(item.title),
                    element_type="poam-item",
                    description=(
                        str(item.description)
                        if item.description
                        else None
                    ),
                    obj=item,
                ))

        elif model_type == OSCALModelType.MAPPING:
            # mappings
            mappings = getattr(parsed_model, "mappings", None)
            if mappings is not None:
                # mappings can be a single Mapping or a list
                if not isinstance(mappings, list):
                    mappings = [mappings]
                for m in mappings:
                    title = str(
                        getattr(m, "matching_rationale", None) or m.uuid
                    )
                    children.append(self._child_dict(
                        uuid=str(m.uuid),
                        title=title,
                        element_type="mapping",
                        description=None,
                        obj=m,
                    ))

        return children

    @staticmethod
    def _child_dict(
        uuid: str,
        title: str,
        element_type: str,
        description: str | None,
        obj: object,
    ) -> dict:
        """Build a child element dict, serializing the object to JSON."""
        raw_json: str | None = None
        try:
            json_method = getattr(obj, "json", None)
            if json_method is not None:
                raw_json = json_method(exclude_none=True, by_alias=True)
        except Exception:
            logger.debug(
                "Could not serialize %s child to JSON", element_type
            )
        return {
            "uuid": uuid,
            "title": title,
            "element_type": element_type,
            "description": description,
            "raw_json": raw_json,
        }

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def query(
        self,
        ctx: object | None = None,
        oscal_model_type: OSCALModelType | None = None,
        query_type: str = "all",
        query_value: str | None = None,
        offset: int = 0,
        limit: int = 10,
    ) -> dict:
        """Unified query across all OSCAL model types.

        Args:
            ctx: MCP server context (unused, kept for interface compat).
            oscal_model_type: Scope to a specific model type, or None for all.
            query_type: ``"all"`` (paginated scan), ``"by_uuid"`` (index
                lookup), ``"by_title"`` (case-insensitive exact then FTS
                fallback), or ``"by_type"`` (filter on model_type column).
            query_value: Required for by_uuid, by_title, by_type.
            offset: Zero-based pagination offset.
            limit: Maximum number of items to return.

        Returns:
            Page_Response dict with keys: items, total, offset, limit, hasMore.

        Raises:
            ValueError: If query_value is missing when required.
        """
        if query_type in ("by_uuid", "by_title", "by_type") and not query_value:
            raise ValueError(
                f"query_value is required for query_type '{query_type}'"
            )

        if query_type == "by_uuid":
            # query_value validated above; cast for type checker
            return self._query_by_uuid(query_value, oscal_model_type, offset, limit)  # type: ignore[arg-type]
        elif query_type == "by_title":
            return self._query_by_title(query_value, oscal_model_type, offset, limit)  # type: ignore[arg-type]
        elif query_type == "by_type":
            return self._query_by_type(query_value, oscal_model_type, offset, limit)  # type: ignore[arg-type]
        else:
            # "all" — paginated scan
            return self._query_all(oscal_model_type, offset, limit)

    def _query_by_uuid(
        self,
        uuid_value: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Direct index lookup on documents.uuid."""
        where = "WHERE d.uuid = ?"
        params: list = [uuid_value]
        if oscal_model_type is not None:
            where += " AND d.model_type = ?"
            params.append(oscal_model_type.value)

        total = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM documents d {where}", params  # nosec B608
        ).fetchone()["cnt"]

        rows = self._conn.execute(
            f"SELECT d.id, d.uuid, d.title, d.model_type, d.file_path, d.file_size "  # nosec B608
            f"FROM documents d {where} ORDER BY d.id LIMIT ? OFFSET ?",  # nosec B608
            params + [limit, offset],
        ).fetchall()

        items = self._build_query_items(rows)
        return self._page_response(items, total, offset, limit)

    def _query_by_title(
        self,
        title_value: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Case-insensitive exact match first, FTS fallback."""
        # Phase 1: exact case-insensitive match
        where = "WHERE d.title = ? COLLATE NOCASE"
        params: list = [title_value]
        if oscal_model_type is not None:
            where += " AND d.model_type = ?"
            params.append(oscal_model_type.value)

        total = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM documents d {where}", params  # nosec B608
        ).fetchone()["cnt"]

        if total > 0:
            rows = self._conn.execute(
                f"SELECT d.id, d.uuid, d.title, d.model_type, d.file_path, d.file_size "  # nosec B608
                f"FROM documents d {where} ORDER BY d.id LIMIT ? OFFSET ?",  # nosec B608
                params + [limit, offset],
            ).fetchall()
            items = self._build_query_items(rows)
            return self._page_response(items, total, offset, limit)

        # Phase 2: FTS fallback
        return self._query_by_title_fts(title_value, oscal_model_type, offset, limit)

    def _query_by_title_fts(
        self,
        title_value: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """FTS fallback for title search."""
        try:
            fts_where = "WHERE fts_index MATCH ?"
            fts_params: list = [f"entity_type:document {title_value}"]
            if oscal_model_type is not None:
                fts_params = [
                    f"entity_type:document model_type:{oscal_model_type.value} {title_value}"
                ]

            fts_ids = self._conn.execute(
                f"SELECT CAST(f.entity_id AS INTEGER) as doc_id "  # nosec B608
                f"FROM fts_index f {fts_where}",  # nosec B608
                fts_params,
            ).fetchall()
            doc_ids = [r["doc_id"] for r in fts_ids]
        except sqlite3.OperationalError:
            # Bad FTS syntax — fall back to LIKE
            like_where = "WHERE d.title LIKE ?"
            like_params: list = [f"%{title_value}%"]
            if oscal_model_type is not None:
                like_where += " AND d.model_type = ?"
                like_params.append(oscal_model_type.value)

            like_rows = self._conn.execute(
                f"SELECT d.id FROM documents d {like_where}",  # nosec B608
                like_params,
            ).fetchall()
            doc_ids = [r["id"] for r in like_rows]

        if not doc_ids:
            return self._page_response([], 0, offset, limit)

        total = len(doc_ids)
        paged_ids = doc_ids[offset : offset + limit]
        if not paged_ids:
            return self._page_response([], total, offset, limit)

        placeholders = ",".join("?" for _ in paged_ids)
        rows = self._conn.execute(
            f"SELECT d.id, d.uuid, d.title, d.model_type, d.file_path, d.file_size "  # nosec B608
            f"FROM documents d WHERE d.id IN ({placeholders}) ORDER BY d.id",  # nosec B608
            paged_ids,
        ).fetchall()

        items = self._build_query_items(rows)
        return self._page_response(items, total, offset, limit)

    def _query_by_type(
        self,
        type_value: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Filter on model_type column."""
        where = "WHERE d.model_type = ?"
        params: list = [type_value]
        if oscal_model_type is not None:
            # Both filters apply — type_value from query_value and
            # oscal_model_type from the parameter. They may overlap.
            where += " AND d.model_type = ?"
            params.append(oscal_model_type.value)

        total = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM documents d {where}", params  # nosec B608
        ).fetchone()["cnt"]

        rows = self._conn.execute(
            f"SELECT d.id, d.uuid, d.title, d.model_type, d.file_path, d.file_size "  # nosec B608
            f"FROM documents d {where} ORDER BY d.id LIMIT ? OFFSET ?",  # nosec B608
            params + [limit, offset],
        ).fetchall()

        items = self._build_query_items(rows)
        return self._page_response(items, total, offset, limit)

    def _query_all(
        self,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Paginated scan of all documents."""
        where = ""
        params: list = []
        if oscal_model_type is not None:
            where = "WHERE d.model_type = ?"
            params.append(oscal_model_type.value)

        total = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM documents d {where}", params  # nosec B608
        ).fetchone()["cnt"]

        rows = self._conn.execute(
            f"SELECT d.id, d.uuid, d.title, d.model_type, d.file_path, d.file_size "  # nosec B608
            f"FROM documents d {where} ORDER BY d.id LIMIT ? OFFSET ?",  # nosec B608
            params + [limit, offset],
        ).fetchall()

        items = self._build_query_items(rows)
        return self._page_response(items, total, offset, limit)

    def _build_query_items(self, rows: list) -> list[dict]:
        """Build item dicts from document rows, triggering _ensure_indexed."""
        items = []
        for row in rows:
            doc_id = row["id"]
            self._ensure_indexed(doc_id)

            # Fetch child elements for this document
            children = self._conn.execute(
                "SELECT uuid, title, element_type, description "
                "FROM child_elements WHERE parent_doc_id = ? "
                "ORDER BY element_type, title",
                (doc_id,),
            ).fetchall()

            child_list = [
                {
                    "uuid": c["uuid"],
                    "title": c["title"],
                    "element_type": c["element_type"],
                    "description": c["description"],
                }
                for c in children
            ]

            items.append({
                "uuid": row["uuid"],
                "title": row["title"],
                "model_type": row["model_type"],
                "file_path": row["file_path"],
                "sizeInBytes": row["file_size"],
                "children": child_list,
            })
        return items

    @staticmethod
    def _page_response(
        items: list[dict], total: int, offset: int, limit: int
    ) -> dict:
        """Build a Page_Response dict."""
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "hasMore": offset + limit < total,
        }

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

    # ------------------------------------------------------------------
    # List / query API
    # ------------------------------------------------------------------

    def list_documents(
        self,
        ctx: object | None = None,
        oscal_model_type: OSCALModelType | None = None,
        offset: int = 0,
        limit: int = 10,
    ) -> dict:
        """List document summaries (UUID, title, model_type, child_count, sizeInBytes).

        Reads directly from SQLite — no full document loading.
        Triggers ``_ensure_indexed()`` for documents in the result page so
        that ``child_count`` is accurate.

        Args:
            ctx: Optional MCP context (unused, kept for interface consistency).
            oscal_model_type: Filter to a specific model type, or None for all.
            offset: Pagination offset (0-based).
            limit: Maximum number of items to return.

        Returns:
            Page_Response dict with keys: items, total, offset, limit, hasMore.
        """
        # Build WHERE clause
        where_clauses: list[str] = []
        params: list = []
        if oscal_model_type is not None:
            where_clauses.append("d.model_type = ?")
            params.append(oscal_model_type.value)

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Get total count
        total_row = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM documents d {where_sql}",  # nosec B608
            params,
        ).fetchone()
        total = total_row["cnt"]

        # Get the page of documents
        page_params = params + [limit, offset]
        rows = self._conn.execute(
            f"""
            SELECT d.id, d.uuid, d.title, d.model_type, d.file_size, d.indexed
            FROM documents d
            {where_sql}
            ORDER BY d.title COLLATE NOCASE, d.uuid
            LIMIT ? OFFSET ?
            """,  # nosec B608
            page_params,
        ).fetchall()

        # Ensure indexing for documents in this page so child_count is accurate
        for row in rows:
            if not row["indexed"]:
                try:
                    self._ensure_indexed(row["id"])
                except Exception:
                    logger.warning(
                        "Failed to index doc %d for list_documents",
                        row["id"],
                    )

        # Build items with child_count via subquery per document
        items: list[dict] = []
        for row in rows:
            child_count_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM child_elements WHERE parent_doc_id = ?",
                (row["id"],),
            ).fetchone()
            items.append({
                "uuid": row["uuid"],
                "title": row["title"],
                "model_type": row["model_type"],
                "childCount": child_count_row["cnt"],
                "sizeInBytes": row["file_size"],
            })

        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "hasMore": offset + limit < total,
        }

    def text_search(
        self,
        query_text: str,
        oscal_model_type: OSCALModelType | None = None,
        offset: int = 0,
        limit: int = 10,
    ) -> dict:
        """FTS5 full-text search across documents and child elements.

        Queries the ``fts_index`` FTS5 virtual table using ``MATCH`` syntax.
        Results are ranked by relevance (using FTS5 ``rank``).  When the
        query text contains invalid FTS5 syntax, catches
        ``sqlite3.OperationalError`` and falls back to a ``LIKE`` query on
        the ``title`` and ``description`` columns.

        Supports optional ``oscal_model_type`` scoping so that only entities
        of the specified model type appear in results.

        Args:
            query_text: The search string.
            oscal_model_type: Scope results to a specific model type, or
                None for all types.
            offset: Pagination offset (0-based).
            limit: Maximum number of items to return.

        Returns:
            Page_Response dict with keys: items, total, offset, limit, hasMore.
            Each item contains: entity_type, entity_id, title, description,
            model_type.
        """
        if not query_text or not query_text.strip():
            return {
                "items": [],
                "total": 0,
                "offset": offset,
                "limit": limit,
                "hasMore": False,
            }

        try:
            return self._fts_search(
                query_text, oscal_model_type, offset, limit
            )
        except sqlite3.OperationalError:
            logger.warning(
                "FTS MATCH failed for query '%s'; falling back to LIKE",
                query_text,
            )
            return self._like_search(
                query_text, oscal_model_type, offset, limit
            )

    def _fts_search(
        self,
        query_text: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Execute an FTS5 MATCH search on fts_index.

        May raise ``sqlite3.OperationalError`` on bad FTS syntax.
        """
        where_clauses = ["fts_index MATCH ?"]
        params: list = [query_text]

        if oscal_model_type is not None:
            where_clauses.append("model_type = ?")
            params.append(oscal_model_type.value)

        where_sql = " AND ".join(where_clauses)

        # Total count
        total_row = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM fts_index WHERE {where_sql}",  # nosec B608
            params,
        ).fetchone()
        total = total_row["cnt"]

        # Paginated results ranked by relevance
        page_params = params + [limit, offset]
        rows = self._conn.execute(
            f"""
            SELECT entity_type, entity_id, title, description, model_type,
                   rank
            FROM fts_index
            WHERE {where_sql}
            ORDER BY rank
            LIMIT ? OFFSET ?
            """,  # nosec B608
            page_params,
        ).fetchall()

        items = [
            {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "title": row["title"],
                "description": row["description"],
                "model_type": row["model_type"],
            }
            for row in rows
        ]

        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "hasMore": offset + limit < total,
        }

    def _like_search(
        self,
        query_text: str,
        oscal_model_type: OSCALModelType | None,
        offset: int,
        limit: int,
    ) -> dict:
        """Fallback LIKE search on fts_index title and description columns."""
        like_pattern = f"%{query_text}%"
        where_clauses = ["(title LIKE ? OR description LIKE ?)"]
        params: list = [like_pattern, like_pattern]

        if oscal_model_type is not None:
            where_clauses.append("model_type = ?")
            params.append(oscal_model_type.value)

        where_sql = " AND ".join(where_clauses)

        # Total count
        total_row = self._conn.execute(
            f"SELECT COUNT(*) as cnt FROM fts_index WHERE {where_sql}",  # nosec B608
            params,
        ).fetchone()
        total = total_row["cnt"]

        # Paginated results
        page_params = params + [limit, offset]
        rows = self._conn.execute(
            f"""
            SELECT entity_type, entity_id, title, description, model_type
            FROM fts_index
            WHERE {where_sql}
            ORDER BY title
            LIMIT ? OFFSET ?
            """,  # nosec B608
            page_params,
        ).fetchall()

        items = [
            {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "title": row["title"],
                "description": row["description"],
                "model_type": row["model_type"],
            }
            for row in rows
        ]

        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "hasMore": offset + limit < total,
        }

    def list_child_elements(
        self,
        ctx: object | None = None,
        parent_doc_uuid: str | None = None,
        element_type: str | None = None,
        offset: int = 0,
        limit: int = 10,
    ) -> dict:
        """List child element summaries with parent document info.

        Triggers ``_ensure_indexed()`` for relevant parent documents so
        that child elements are available.

        Args:
            ctx: Optional MCP context (unused, kept for interface consistency).
            parent_doc_uuid: Filter to children of a specific parent document.
            element_type: Filter to a specific child element type.
            offset: Pagination offset (0-based).
            limit: Maximum number of items to return.

        Returns:
            Page_Response dict with keys: items, total, offset, limit, hasMore.
        """
        # Ensure indexing for relevant parent documents
        if parent_doc_uuid is not None:
            doc_row = self._conn.execute(
                "SELECT id, indexed FROM documents WHERE uuid = ?",
                (parent_doc_uuid,),
            ).fetchone()
            if doc_row is not None and not doc_row["indexed"]:
                try:
                    self._ensure_indexed(doc_row["id"])
                except Exception:
                    logger.warning(
                        "Failed to index doc %s for list_child_elements",
                        parent_doc_uuid,
                    )
        else:
            # Ensure all unindexed documents are indexed
            unindexed = self._conn.execute(
                "SELECT id FROM documents WHERE indexed = 0"
            ).fetchall()
            for row in unindexed:
                try:
                    self._ensure_indexed(row["id"])
                except Exception:
                    logger.warning(
                        "Failed to index doc %d for list_child_elements",
                        row["id"],
                    )

        # Build WHERE clause
        where_clauses: list[str] = []
        params: list = []
        if parent_doc_uuid is not None:
            where_clauses.append("d.uuid = ?")
            params.append(parent_doc_uuid)
        if element_type is not None:
            where_clauses.append("ce.element_type = ?")
            params.append(element_type)

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Get total count
        total_row = self._conn.execute(
            f"""
            SELECT COUNT(*) as cnt
            FROM child_elements ce
            JOIN documents d ON ce.parent_doc_id = d.id
            {where_sql}
            """,  # nosec B608
            params,
        ).fetchone()
        total = total_row["cnt"]

        # Get the page
        page_params = params + [limit, offset]
        rows = self._conn.execute(
            f"""
            SELECT ce.uuid, ce.title, ce.element_type, ce.description,
                   d.title AS parent_title, d.uuid AS parent_uuid
            FROM child_elements ce
            JOIN documents d ON ce.parent_doc_id = d.id
            {where_sql}
            ORDER BY ce.title COLLATE NOCASE, ce.uuid
            LIMIT ? OFFSET ?
            """,  # nosec B608
            page_params,
        ).fetchall()

        items: list[dict] = []
        for row in rows:
            items.append({
                "uuid": row["uuid"],
                "title": row["title"],
                "element_type": row["element_type"],
                "description": row["description"],
                "parentDocumentTitle": row["parent_title"],
                "parentDocumentUuid": row["parent_uuid"],
            })

        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "hasMore": offset + limit < total,
        }

    # ------------------------------------------------------------------
    # Backward-compatible external loading
    # ------------------------------------------------------------------

    def load_external_component_definition(
        self, source: str, ctx: object | None = None,
    ) -> None:
        """Load an OSCAL Component Definition from a local zip or remote URI.

        Backward-compatible method that mirrors the legacy
        ``ComponentDefinitionStore.load_external_component_definition``
        behavior.

        For local zip files, extracts and ingests all JSON entries.
        For remote URIs, fetches the JSON, validates, and ingests.

        Args:
            source: URI to the Component Definition JSON file or zip archive.
            ctx: Optional MCP context for error reporting.

        Raises:
            ValueError: If remote URIs are not allowed, validation fails,
                or the source is a directory.
        """
        import requests as _requests
        from mcp_server_for_oscal.tools.utils import try_notify_client_error

        def _notify(msg: str) -> None:
            try_notify_client_error(msg, ctx)  # type: ignore[arg-type]

        uri = urlparse(source)

        if uri.scheme in ("", "file"):
            lf = Path(source)
            if lf.is_dir():
                raise ValueError(
                    "URI must point to a zip file or JSON component definition"
                )
            if lf.is_file() and lf.name.endswith("zip"):
                self._process_zip_file(
                    lf, OSCALModelType.COMPONENT_DEFINITION
                )
            return

        if not config.allow_remote_uris:
            msg = (
                f"Remote URI loading is not enabled. "
                f"Set OSCAL_ALLOW_REMOTE_URIS=true to enable. Source: {source}"
            )
            logger.error(msg)
            _notify(msg)
            raise ValueError(msg)

        logger.debug(
            "Fetching remote Component Definition from: %s", source
        )

        try:
            response = _requests.get(source, timeout=config.request_timeout)
            response.raise_for_status()

            data = response.json()
            if "component-definition" not in data:
                data = {"component-definition": data}

            model_type = self._detect_model_type_from_data(data)
            if model_type != OSCALModelType.COMPONENT_DEFINITION:
                raise ValueError(
                    "Remote document is not a Component Definition"
                )

            if not self._validate_with_trestle(data, model_type):
                raise ValueError(
                    "Remote Component Definition failed validation"
                )

            meta = self._extract_metadata(data, model_type)
            if meta is None:
                raise ValueError(
                    "Cannot extract UUID/title from remote document"
                )

            uuid_val, title = meta
            raw_json = json.dumps(data)
            self._upsert_document(
                uuid_val,
                title,
                model_type.value,
                source,
                len(raw_json),
                0.0,
                raw_json,
            )
            logger.info(
                "Successfully loaded remote component definition from: %s",
                source,
            )

        except _requests.Timeout as e:
            msg = (
                f"Request timeout while fetching remote URI "
                f"(timeout={config.request_timeout}s): {source}"
            )
            logger.exception(msg)
            _notify(msg)
            raise ValueError(msg) from e

        except _requests.RequestException as e:
            msg = f"Failed to fetch remote Component Definition: {e}"
            logger.exception(msg)
            _notify(msg)
            raise ValueError(msg) from e

        except json.JSONDecodeError as e:
            msg = f"Failed to parse remote Component Definition JSON: {e}"
            logger.exception(msg)
            _notify(msg)
            raise ValueError(msg) from e

        except ValueError:
            raise

        except Exception as e:
            msg = (
                "Failed to load or validate remote "
                f"Component Definition: {e}"
            )
            logger.exception(msg)
            _notify(msg)
            raise ValueError(msg) from e
