"""
Tools for loading and querying OSCAL Component Definition documents.

OSCAL Component Definitions follow a hierarchy:
  Component Definition  →  Capability  →  Component

A Component Definition is the top-level document. It contains Capabilities
(groupings that describe higher-level security functions) and Components
(leaf-level items such as services, software, or regions). Queries in this
module prioritize Capabilities over Components to reflect that hierarchy.
"""
from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp.server import Context
from strands import tool
from trestle.oscal.component import Capability, ComponentDefinition, DefinedComponent

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import (
    OSCALModelType,
    paginate,
    safe_log_mcp,
    try_notify_client_error,
)

if TYPE_CHECKING:
    from mcp_server_for_oscal.tools.oscal_store import OscalStore

logger = logging.getLogger(__name__)


class ComponentDefinitionStore:
    """In-memory store that loads, indexes, and queries OSCAL Component Definitions."""

    def __init__(self) -> None:
        self._cdefs_by_path: dict[str, ComponentDefinition] = {}
        self._cdefs_by_uuid: dict[str, ComponentDefinition] = {}
        self._cdefs_by_title: dict[str, ComponentDefinition] = {}
        self._components_by_uuid: dict[str, DefinedComponent] = {}
        self._components_by_title: dict[str, DefinedComponent] = {}
        self._components_to_cdef_by_uuid: dict[str, str] = {}
        self._capabilities_by_uuid: dict[str, Capability] = {}
        self._capabilities_by_name: dict[str, Capability] = {}
        self._capabilities_to_cdef_by_uuid: dict[str, str] = {}

        self._stats: dict[str, int] = {
            "loaded_files": 0,
            "processed_zip_files": 0,
            "zip_file_contents": 0,
            "processed_json_files": 0,
            "component_definitions_indexed": 0,
            "components_indexed": 0,
            "processed_external_files": 0,
            "capabilities_indexed": 0,
        }

    def _reset(self) -> None:
        """Clear all indexed data and reset stats."""
        self._cdefs_by_path.clear()
        self._cdefs_by_title.clear()
        self._cdefs_by_uuid.clear()
        self._components_by_title.clear()
        self._components_by_uuid.clear()
        self._components_to_cdef_by_uuid.clear()
        self._capabilities_by_uuid.clear()
        self._capabilities_by_name.clear()
        self._capabilities_to_cdef_by_uuid.clear()
        self._stats.update(dict.fromkeys(self._stats, 0))

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_external_component_definition(self, source: str, ctx: Context | None) -> None:
        """
        Load and validate an OSCAL Component Definition from a URI.

        The URI can be local or remote and may refer to a zip file that contains
        Component Definitions.  Remote URIs are only fetched when
        ``config.allow_remote_uris`` is True.

        Args:
            source: URI to the Component Definition JSON file or zip archive.
            ctx: MCP server context for error reporting.

        Raises:
            ValueError: If remote URIs are not allowed or validation fails.
            requests.RequestException: If HTTP request fails.
        """
        uri = urlparse(source)

        if uri.scheme in ("", "file"):
            lf = Path(source)
            if lf.is_dir():
                raise ValueError("URI must point to a zip file or JSON component definition")
            if lf.is_file() and lf.name.endswith("zip"):
                self._handle_zip_file(Path(source))
                self._stats["processed_external_files"] += 1
            return

        if not config.allow_remote_uris:
            msg = (
                f"Remote URI loading is not enabled. "
                f"Set OSCAL_ALLOW_REMOTE_URIS=true to enable. Source: {source}"
            )
            logger.error(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)

        logger.debug("Fetching remote Component Definition from: %s", source)

        try:
            response = requests.get(source, timeout=config.request_timeout)
            response.raise_for_status()

            data = response.json()
            if "component-definition" in data:
                data = data["component-definition"]

            component_def = ComponentDefinition.parse_obj(data)
            self._index_components(component_def, source)
            self._stats["processed_external_files"] += 1
            logger.info("Successfully loaded and validated remote component definition from: %s", source)
            logger.debug(self._stats)

        except requests.Timeout as e:
            msg = f"Request timeout while fetching remote URI (timeout={config.request_timeout}s): {source}"
            logger.exception(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg) from e

        except requests.RequestException as e:
            msg = f"Failed to fetch remote Component Definition: {e}"
            logger.exception(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg) from e

        except json.JSONDecodeError as e:
            msg = f"Failed to parse remote Component Definition JSON: {e}"
            logger.exception(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg) from e

        except Exception as e:
            msg = f"Failed to load or validate remote Component Definition: {e}"
            logger.exception(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg) from e

    def load_from_directory(self, directory_path: Path | None = None) -> dict[str, ComponentDefinition]:
        """
        Recursively scan a directory for Component Definition files and load them.

        Searches for all ``.json`` and ``.zip`` files in the directory tree.
        Successfully loaded definitions are indexed for efficient querying.

        Args:
            directory_path: Directory to scan.  Defaults to
                ``config.component_definitions_dir`` when *None*.  Passing an
                explicit path resets all previously loaded data first.

        Returns:
            Dictionary mapping file paths to ``ComponentDefinition`` instances.
        """
        if directory_path is None:
            directory_path = Path(__file__).parent.parent / config.component_definitions_dir
        else:
            self._reset()

        if not directory_path.exists():
            logger.warning("Component definitions directory does not exist: %s", directory_path)
            return {}

        if not directory_path.is_dir():
            logger.warning("Component definitions path is not a directory: %s", directory_path)
            return {}

        self._process_zip_files(directory_path)
        self._process_json_files(directory_path)

        logger.info(self._stats)
        return self._cdefs_by_path

    # ------------------------------------------------------------------
    # Private helpers – file processing
    # ------------------------------------------------------------------

    def _process_zip_files(self, directory_path: Path) -> None:
        logger.info("Scanning directory for Component Definitions: %s", directory_path)
        zip_files = list(directory_path.rglob("**/*.zip"))
        if zip_files:
            logger.debug("found %s zip files.", len(zip_files))
            for zf in zip_files:
                # if any(zf.name in key for key in self._cdefs_by_path):
                #     continue
                self._handle_zip_file(zf)
                self._stats["processed_zip_files"] += 1

    def _handle_zip_file(self, zf: Path) -> None:
        with zipfile.ZipFile(zf, "r") as zip_file:
            file_list = zip_file.namelist()
            self._stats["zip_file_contents"] += len(file_list)
            logger.debug("zip manifest includes %s files", len(file_list))
            for innerfile in file_list:
                innerfile_path = zf.joinpath(innerfile).as_posix()
                if innerfile_path in self._cdefs_by_path:
                    logger.info("Reprocessing Component Definition file %s", innerfile_path)
                #     continue
                if not innerfile.endswith("json"):
                    continue
                with zip_file.open(innerfile) as f:
                    data = json.load(f)
                    self._index_components(
                        cast("ComponentDefinition", ComponentDefinition.parse_obj(data["component-definition"])),
                        innerfile_path,
                    )
                    self._stats["loaded_files"] += 1

    def _process_json_files(self, directory_path: Path) -> None:
        json_files = list(directory_path.rglob("**/*.json"))
        logger.debug("Found %d JSON files to process", len(json_files))

        for json_file in json_files:
            if json_file.name == "hashes.json":
                logger.debug("Skipping hashes.json file")
                continue
            try:
                relative_path = str(json_file.relative_to(directory_path))
                if relative_path in self._cdefs_by_path:
                    logger.info("Reprocessing Component Definition file %s", relative_path)
                #     continue
                component_def = cast("ComponentDefinition", ComponentDefinition.oscal_read(json_file))
                self._stats["processed_json_files"] += 1
                if component_def is None:
                    logger.debug("Skipping file (oscal_read returned None): %s", json_file)
                    continue
                self._index_components(component_def, relative_path)
                self._stats["loaded_files"] += 1
            except Exception as e:
                logger.debug("Skipping file (not a valid Component Definition): %s - %s", json_file, e)
                continue

    def _index_components(self, cdef: ComponentDefinition, path: str) -> None:
        """Index a ComponentDefinition and its child Components for efficient querying."""
        try:
            self._cdefs_by_path[path] = cdef

            if cdef.uuid in self._cdefs_by_uuid:
                logger.info(
                    "Replacing existing Component Definition %s (%s) in index with content from %s",
                    cdef.uuid, cdef.metadata.title, path,
                )

            self._cdefs_by_uuid[cdef.uuid] = cdef
            # lowercase to eliminate case sensitivity
            self._cdefs_by_title[cdef.metadata.title.lower()] = cdef
            self._stats["component_definitions_indexed"] += 1
            logger.debug("Successfully loaded Component Definition: %s", path)

            if cdef.capabilities:
                for cap in cdef.capabilities:
                    guid = str(cap.uuid)
                    self._capabilities_by_uuid[guid] = cap
                    # lowercase to eliminate case sensitivity
                    self._capabilities_by_name[cap.name.lower()] = cap
                    self._capabilities_to_cdef_by_uuid[guid] = str(cdef.uuid)
                    self._stats["capabilities_indexed"] += 1

            if cdef.components:
                for c in cdef.components:
                    guid = str(c.uuid)
                    if guid in self._components_by_uuid:
                        logger.info(
                            "Replacing existing Component %s (%s) in index with content from %s",
                            c.uuid, c.title, cdef.metadata.title,
                        )
                    self._components_by_uuid[guid] = c
                    # lowercase to eliminate case sensitivity
                    self._components_by_title[c.title.lower()] = c
                    self._components_to_cdef_by_uuid[guid] = str(cdef.uuid)
                    self._stats["components_indexed"] += 1
                    logger.debug("Component %s added to index", c.title)
        except:
            logger.exception("Failed to index component %s from %s", cdef.metadata.title, path)
            raise

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @staticmethod
    def find_component_by_prop_value(
        components: list[DefinedComponent], value: str,
    ) -> DefinedComponent | None:
        """Find a component by searching property values."""
        for component in components:
            if component.props:
                for prop in component.props:
                    if prop.value == value:
                        return component
        return None

    @staticmethod
    def filter_components_by_type(
        components: list[DefinedComponent], component_type: str,
    ) -> list[DefinedComponent]:
        """Filter components by their type field."""
        return [c for c in components if c.type == component_type]

    # ------------------------------------------------------------------
    # Public query API
    # ------------------------------------------------------------------

    def query(
        self,
        ctx: Context | None,
        component_definition_filter: str | None = None,
        query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
        query_value: str | None = None,
        return_format: Literal["raw"] = "raw",
    ) -> dict[str, Any]:
        """
        Query loaded Component Definitions to extract component information.

        Args:
            ctx: MCP server context for error reporting.
            component_definition_filter: Optional UUID or title to limit the search.
            query_type: ``"all"``, ``"by_uuid"``, ``"by_title"``, or ``"by_type"``.
            query_value: Value to search for (required except for ``"all"``).
            return_format: Currently only ``"raw"`` is supported.

        Returns:
            A dict with ``components``, ``total_count``, ``query_type``,
            ``component_definitions_searched``, and ``filtered_by``.
        """
        if query_value:
            query_value = query_value.strip()

        logger.debug(
            "query(component_definition_filter: %s, query_type: %s, query_value: %s, return_format: %s)",
            component_definition_filter, query_type, query_value, return_format,
        )

        if query_type in ["by_uuid", "by_title", "by_type"] and not query_value:
            msg = f"query_value is required when query_type is '{query_type}'"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)

        if not self._cdefs_by_path:
            msg = "No Component Definitions loaded"
            logger.warning(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)

        # Resolve the set of component definitions to search
        comp_defs_searched = self._resolve_comp_defs(component_definition_filter, ctx)
        if component_definition_filter and not comp_defs_searched:
            # we should only get here if a component_definition_filter was provided and nothing matched
            return {
                "components": [],
                "total_count": 0,
                "query_type": query_type,
                "component_definitions_searched": len(comp_defs_searched),
                "filtered_by": component_definition_filter,
            }

        try:
            cape: Capability = None # type: ignore[assignment]
            foundit: bool = False
            if query_type == "by_title":
                qvl = query_value.lower() # type: ignore[union-attr]
                if qvl in _store._capabilities_by_name:
                    logger.debug("capability query by title: %s", qvl)
                    cape = _store._capabilities_by_name[qvl]
            elif query_type == "by_uuid" and query_value in _store._capabilities_by_uuid:
                logger.debug("capability query by uuid: %s", query_value)
                cape = _store._capabilities_by_uuid[query_value]

            if cape and component_definition_filter:
                logger.debug("found a capability. now filtering to match component_definition_filter %s", component_definition_filter)
                parent_cdef_uuid = _store._capabilities_to_cdef_by_uuid[cape.uuid]
                for cd in comp_defs_searched:
                    if cd.uuid == parent_cdef_uuid:
                        foundit = True
                        logger.debug("Capability parent %s in filtered list of cdefs", cd.uuid)
                        break
            elif cape:
                foundit = True

            if foundit:
                logger.debug("Returning capability")
                return {
                    "capability": cape.oscal_dict(),
                    "component_count": len(cape.incorporates_components) if cape.incorporates_components else 0,
                    "query_type": query_type,
                    "component_definitions_searched": len(comp_defs_searched),
                    "filtered_by": component_definition_filter,
                }
        except:
            logger.exception("Failure while searching capabilities")

        # Build filtered component indexes
        filtered_by_uuid, filtered_by_title = self._build_filtered_indexes(comp_defs_searched)

        logger.debug("%s components in filtered index", len(filtered_by_uuid))

        if not filtered_by_uuid:
            logger.warning("No components found in the Component Definition(s)")
            return {
                "components": [],
                "total_count": 0,
                "query_type": query_type,
                "component_definitions_searched": len(comp_defs_searched),
                "filtered_by": component_definition_filter,
            }

        selected = self._select_components(
            query_type, query_value, filtered_by_uuid, filtered_by_title, ctx,
        )

        formatted = [c.dict(exclude_none=True) for c in selected if c]

        return {
            "components": formatted if formatted else [],
            "total_count": len(formatted),
            "query_type": query_type,
            "component_definitions_searched": len(comp_defs_searched),
            "filtered_by": component_definition_filter,
        }

    def list_component_definitions(self, ctx: Context | None) -> list[dict]:
        """Return summary info for every loaded Component Definition."""
        if not self._cdefs_by_title:
            msg = "No Component Definitions loaded"
            try_notify_client_error(msg, ctx)
            raise RuntimeError(msg)

        rv = []
        for cd in self._cdefs_by_title.values():
            component_count = len(cd.components) if cd.components else 0
            imported_cdef_count = len(cd.import_component_definitions) if cd.import_component_definitions else 0
            rv.append({
                "uuid": cd.uuid,
                "title": cd.metadata.title,
                "componentCount": component_count,
                "importedComponentDefinitionsCount": imported_cdef_count,
                "sizeInBytes": len(cd.oscal_serialize_json_bytes()),
            })
        return rv

    def list_components(self, ctx: Context | None) -> list[dict]:
        """Return summary info for every loaded Component."""
        if not self._components_by_title:
            msg = "No Components loaded"
            try_notify_client_error(msg, ctx)
            raise RuntimeError(msg)

        rv = []
        for cd in self._components_by_title.values():
            parent = self._cdefs_by_uuid[self._components_to_cdef_by_uuid[str(cd.uuid)]]
            rv.append({
                "uuid": cd.uuid,
                "title": cd.title,
                "parentComponentDefinitionTitle": parent.metadata.title,
                "parentComponentDefinitionUuid": parent.uuid,
                "sizeInBytes": len(cd.oscal_serialize_json_bytes()),
            })
        return rv

    def list_capabilities(self, ctx: Context | None) -> list[dict]:
        # no errors in case there are no capabilities, as they are not required
        rv = []
        for cap in self._capabilities_by_uuid.values():
            parent = self._cdefs_by_uuid[self._capabilities_to_cdef_by_uuid[str(cap.uuid)]]
            rv.append({
                "uuid": cap.uuid,
                "name": cap.name,
                "parentComponentDefinitionTitle": parent.metadata.title,
                "parentComponentDefinitionUuid": parent.uuid,
                "sizeInBytes": len(cap.oscal_serialize_json_bytes()),
            })
        return rv

    # ------------------------------------------------------------------
    # Private query helpers
    # ------------------------------------------------------------------

    def _resolve_comp_defs(
        self, filter_value: str | None, ctx: Context | None,
    ) -> list[ComponentDefinition]:
        """Resolve which ComponentDefinitions to search based on an optional filter."""
        if not filter_value:
            return list(self._cdefs_by_path.values())

        if filter_value in self._cdefs_by_uuid:
            logger.info("Filtered to Component Definition with UUID: %s", filter_value)
            return [self._cdefs_by_uuid[filter_value]]

        # lowercase to avoid case sensitivity issues
        fvl = filter_value.lower()
        if fvl in self._cdefs_by_title:
            logger.info("Filtered to Component Definition with title: %s", filter_value)
            return [self._cdefs_by_title[fvl]]

        msg = f"No Component Definition found with UUID or title matching: `{filter_value}`."
        logger.debug(msg)
        safe_log_mcp(msg+" Try again without a filter or lookup the filter value with the tool list_component_definitions.", ctx, "info")
        return []
        # raise ValueError(msg)

    @staticmethod
    def _build_filtered_indexes(
        comp_defs: list[ComponentDefinition],
    ) -> tuple[dict[str, DefinedComponent], dict[str, DefinedComponent]]:
        by_uuid: dict[str, DefinedComponent] = {}
        by_title: dict[str, DefinedComponent] = {}
        for comp_def in comp_defs:
            if comp_def.components:
                for c in comp_def.components:
                    by_uuid[str(c.uuid)] = c
                    by_title[c.title.lower()] = c
        return by_uuid, by_title

    def _select_components(
        self,
        query_type: str,
        query_value: str | None,
        by_uuid: dict[str, DefinedComponent],
        by_title: dict[str, DefinedComponent],
        ctx: Context | None,
    ) -> list[DefinedComponent]:
        """Select components based on query_type and query_value."""
        if query_type == "all":
            return list(by_uuid.values())

        if query_type == "by_uuid":
            if query_value is None:
                msg = "query_value is required for by_uuid query type"
                try_notify_client_error(msg, ctx)
                logger.error(msg)
                raise ValueError(msg)
            component = by_uuid.get(query_value)
            if not component:
                msg = f"Component with UUID '{query_value}' not found"
                # try_notify_client_error(msg, ctx)
                logger.debug(msg)
                # raise ValueError(msg)
            return [component] #type: ignore[list-item]

        if query_type == "by_title":
            if query_value is None:
                msg = "query_value is required for by_title query type"
                try_notify_client_error(msg, ctx)
                logger.error(msg)
                raise ValueError(msg)
            component = by_title.get(query_value.lower())
            if not component:
                logger.debug("fallback to prop search; no component found with title: %s", query_value)
                component = self.find_component_by_prop_value(list(by_uuid.values()), query_value)
            if not component:
                msg = f"Component with title or prop value '{query_value}' not found"
                # try_notify_client_error(msg, ctx)
                logger.debug(msg)
                # raise ValueError(msg)
            return [component] #type: ignore[list-item]

        if query_type == "by_type":
            if query_value is None:
                msg = "query_value is required for by_type query type"
                try_notify_client_error(msg, ctx)
                logger.error(msg)
                raise ValueError(msg)
            selected = self.filter_components_by_type(list(by_uuid.values()), query_value)
            if not selected:
                msg = f"No components with type '{query_value}' found"
                # try_notify_client_error(msg, ctx)
                logger.debug(msg)
                # raise ValueError(msg)
            return selected

        msg = f"Invalid query_type: {query_type}"
        try_notify_client_error(msg, ctx)
        logger.error(msg)
        raise ValueError(msg)


# ------------------------------------------------------------------
# Module-level singleton & backward-compatible aliases
# ------------------------------------------------------------------

_store = ComponentDefinitionStore()

# Expose for tests and other modules that import the private loader directly
_load_component_definitions_from_directory = _store.load_from_directory

# OscalStore singleton — when set, MCP tool wrappers delegate to it
# instead of the legacy ComponentDefinitionStore.
_oscal_store: OscalStore | None = None


def init_store(store: OscalStore) -> None:
    """Set the module-level OscalStore singleton.

    When set, the MCP tool wrappers delegate to the OscalStore
    instead of the legacy ComponentDefinitionStore.

    Args:
        store: An initialized OscalStore instance.
    """
    global _oscal_store  # noqa: PLW0603
    _oscal_store = store


# ------------------------------------------------------------------
# MCP tool wrappers (thin delegates to the singleton store)
# ------------------------------------------------------------------


@tool()
def query_component_definition(
    ctx: Context | None = None,
    component_definition_filter: str | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    return_format: Literal["raw"] = "raw",
    offset: int = 0,
    limit: int = 10,
) -> dict[str, Any]:
    """
    Query OSCAL Component Definition documents to find Capabilities and Components.

    OSCAL Component Definitions follow a hierarchy: a Component Definition contains
    Capabilities and Components. A Capability groups related Components and describes
    a higher-level security function. This tool reflects that hierarchy — when a
    query matches a Capability (by title or UUID), the Capability is returned
    directly, including its list of incorporated Components. Only when no matching
    Capability is found does the search fall through to individual Components.

    Prefer querying by Capability name/UUID when exploring what a Component
    Definition offers. Query by Component only when you need details about a
    specific service, software, region, or similar leaf-level element.

    Use the companion tools to discover valid query filters:
      - list_capabilities()  — lists all Capability UUIDs and names
      - list_components()    — lists all Component UUIDs and titles
      - list_component_definitions() — lists all Component Definition UUIDs and titles

    If you need details about the Component Definition schema, use the tool get_oscal_schema.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        component_definition_filter: Optional UUID or metadata.title of a Component
            Definition to narrow the search scope. Case-insensitive for titles.
            If omitted, all loaded Component Definitions are searched.
        query_type: Type of query to perform:
            - "all": Return all components in the definition(s). Intended for use
              with a component_definition_filter. Results may be large. For a
              lightweight summary, use list_components() instead.
            - "by_uuid": Find a Capability or Component by UUID (requires query_value).
              Capabilities are checked first.
            - "by_title": Find a Capability by name or a Component by title
              (requires query_value). Capabilities are checked first; if no
              Capability matches, Components are searched with a fallback to
              property-value matching.
            - "by_type": Filter Components by type (requires query_value).
              Does not apply to Capabilities.
        query_value: The value to search for. Required for by_uuid, by_title,
            and by_type queries.
        return_format: Response format. Currently only "raw" is supported, returning
            complete OSCAL objects as JSON.
        offset: Zero-based pagination offset (default 0).
        limit: Maximum items to return, 1-100 (default 10).

    Returns:
        dict: When a Capability matches, the response contains:
            - capability: Full OSCAL Capability object as JSON
            - component_count: Number of Components the Capability incorporates
            - offset, limit, total, hasMore: Pagination metadata
              (always 0, 1, 1, False for single-capability results)
            - query_type, component_definitions_searched, filtered_by

        When Components are returned instead, the response contains:
            - components: Paginated list of OSCAL Component objects as JSON
            - total_count: Total number of matching Components across all pages
            - offset, limit, hasMore: Pagination metadata
            - query_type, component_definitions_searched, filtered_by

    Raises:
        ValueError: If required query parameters are missing or no data is loaded.
    """
    if _oscal_store is not None:
        return _oscal_store_query_component_definition(
            ctx=ctx,
            component_definition_filter=component_definition_filter,
            query_type=query_type,
            query_value=query_value,
            return_format=return_format,
            offset=offset,
            limit=limit,
        )
    result = _store.query(
        ctx=ctx,
        component_definition_filter=component_definition_filter,
        query_type=query_type,
        query_value=query_value,
        return_format=return_format,
    )
    if "capability" in result:
        result["offset"] = 0
        result["limit"] = 1
        result["total"] = 1
        result["hasMore"] = False
        return result
    return _paginate_component_response(result, offset, limit)


@tool()
def list_component_definitions(
    ctx: Context | None = None, offset: int = 0, limit: int = 10
) -> dict:
    """List loaded Component Definitions with summary metadata.

    A Component Definition is the top-level OSCAL document that contains
    Capabilities and Components. Use this tool to discover available
    definitions and obtain UUIDs or titles for use as the
    component_definition_filter in query_component_definition().

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        offset: Zero-based index of the first item to return (default 0).
        limit: Maximum number of items to return, 1-100 (default 10).

    Returns:
        dict: Page_Response with keys ``items``, ``total``, ``offset``,
            ``limit``, ``hasMore``. Each item in ``items`` has keys:
            uuid, title, componentCount, importedComponentDefinitionsCount,
            sizeInBytes.
    """
    if _oscal_store is not None:
        return _oscal_store_list_component_definitions(ctx, offset, limit)
    items = _store.list_component_definitions(ctx)
    return paginate(items, offset, limit)


@tool()
def list_components(
    ctx: Context | None = None, offset: int = 0, limit: int = 10
) -> dict:
    """List loaded Components with summary metadata.

    Components are leaf-level elements within a Component Definition that
    represent individual services, software, regions, or similar items.
    A Component may belong to one or more Capabilities. Use this tool to
    discover Component UUIDs and titles for targeted queries via
    query_component_definition().

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        offset: Zero-based index of the first item to return (default 0).
        limit: Maximum number of items to return, 1-100 (default 10).

    Returns:
        dict: Page_Response with keys ``items``, ``total``, ``offset``,
            ``limit``, ``hasMore``. Each item in ``items`` has keys:
            uuid, title, parentComponentDefinitionTitle,
            parentComponentDefinitionUuid, sizeInBytes.
    """
    if _oscal_store is not None:
        return _oscal_store_list_components(ctx, offset, limit)
    items = _store.list_components(ctx)
    return paginate(items, offset, limit)

@tool()
def list_capabilities(
    ctx: Context | None = None, offset: int = 0, limit: int = 10
) -> dict:
    """List loaded Capabilities with summary metadata.

    Capabilities sit above Components but are optional in the OSCAL hierarchy.
    Each Capability groups related Components and describes a collection
    or higher-level offering. Start here when exploring what a Component
    Definition provides — then drill into individual Components as needed.

    Use the returned UUIDs or names as query_value in
    query_component_definition() to retrieve full Capability details.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        offset: Zero-based index of the first item to return (default 0).
        limit: Maximum number of items to return, 1-100 (default 10).

    Returns:
        dict: Page_Response with keys ``items``, ``total``, ``offset``,
            ``limit``, ``hasMore``. Each item in ``items`` has keys:
            uuid, name, parentComponentDefinitionTitle,
            parentComponentDefinitionUuid, sizeInBytes.
    """
    if _oscal_store is not None:
        return _oscal_store_list_capabilities(ctx, offset, limit)
    items = _store.list_capabilities(ctx)
    return paginate(items, offset, limit)

@tool()
def get_capability(ctx: Context | None = None, uuid: str = "") -> dict | None:
    """Retrieve a single Capability by UUID, returning its full OSCAL representation.

    A Capability groups related Components and may include control
    implementations, description, and a list of incorporated Components.
    Use list_capabilities() to discover available UUIDs.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        uuid: UUID of the Capability to retrieve.

    Returns:
        dict | None: Full OSCAL Capability object as a dict, or None if the
            UUID is not found.
    """
    if _oscal_store is not None:
        return _oscal_store_get_capability(ctx, uuid)
    return _store._capabilities_by_uuid[uuid].dict() if uuid in _store._capabilities_by_uuid else None

_store.load_from_directory()


# ------------------------------------------------------------------
# Pagination helper
# ------------------------------------------------------------------


def _paginate_component_response(
    result: dict[str, Any], offset: int, limit: int
) -> dict[str, Any]:
    """Apply pagination to a component query response.

    Takes a response dict (with ``components`` and ``total_count`` keys)
    and slices the ``components`` list using :func:`paginate`, merging
    the pagination metadata back into the response.

    Args:
        result: Component query response containing a ``components`` list.
        offset: Zero-based index of the first item to return.
        limit: Maximum number of items to return (1-100).

    Returns:
        The same *result* dict, mutated in place, with ``components``
        replaced by the paginated slice and ``offset``, ``limit``,
        ``total_count``, and ``hasMore`` keys set.
    """
    components = result.get("components", [])
    page = paginate(components, offset, limit)
    result["components"] = page["items"]
    result["total_count"] = page["total"]
    result["offset"] = page["offset"]
    result["limit"] = page["limit"]
    result["hasMore"] = page["hasMore"]
    return result


# ------------------------------------------------------------------
# OscalStore delegation helpers
# ------------------------------------------------------------------


def _oscal_store_query_component_definition(
    ctx: Context | None,
    component_definition_filter: str | None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"],
    query_value: str | None,
    return_format: Literal["raw"],
    offset: int = 0,
    limit: int = 10,
) -> dict[str, Any]:
    """Delegate query_component_definition to OscalStore.

    Translates the legacy ComponentDefinitionStore query interface into
    OscalStore.query() calls while preserving the exact return format.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    if query_value:
        query_value = query_value.strip()

    if query_type in ("by_uuid", "by_title", "by_type") and not query_value:
        msg = f"query_value is required when query_type is '{query_type}'"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    # Count total component definitions for the response
    cd_list = _oscal_store.list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
        offset=0,
        limit=100,
    )
    total_cdefs = cd_list["total"]

    if total_cdefs == 0:
        msg = "No Component Definitions loaded"
        logger.warning(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    # Determine which component definitions to search
    cdefs_searched = total_cdefs
    if component_definition_filter:
        # Try to find the specific cdef by UUID or title
        filter_result = _oscal_store.query(
            ctx=ctx,
            oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
            query_type="by_uuid",
            query_value=component_definition_filter,
            offset=0,
            limit=1,
        )
        if filter_result["total"] == 0:
            # Try by title
            filter_result = _oscal_store.query(
                ctx=ctx,
                oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
                query_type="by_title",
                query_value=component_definition_filter,
                offset=0,
                limit=1,
            )
        if filter_result["total"] == 0:
            msg = (
                f"No Component Definition found with UUID or title "
                f"matching: `{component_definition_filter}`."
            )
            logger.debug(msg)
            safe_log_mcp(
                msg + " Try again without a filter or lookup the filter "
                "value with the tool list_component_definitions.",
                ctx,
                "info",
            )
            return {
                "components": [],
                "total_count": 0,
                "query_type": query_type,
                "component_definitions_searched": 0,
                "filtered_by": component_definition_filter,
                "offset": offset,
                "limit": limit,
                "hasMore": False,
            }
        cdefs_searched = filter_result["total"]

    # Check capabilities first (by_title or by_uuid)
    if query_type in ("by_title", "by_uuid") and query_value:
        cap_result = _oscal_store_find_capability(
            ctx, query_type, query_value, component_definition_filter,
        )
        if cap_result is not None:
            cap_result["component_definitions_searched"] = cdefs_searched
            cap_result["offset"] = 0
            cap_result["limit"] = 1
            cap_result["total"] = 1
            cap_result["hasMore"] = False
            return cap_result

    # Fall through to component search via the legacy store
    # The OscalStore query returns documents, not components.
    # For backward compat, we delegate to the legacy store which
    # has the full component-level query logic.
    result = _store.query(
        ctx=ctx,
        component_definition_filter=component_definition_filter,
        query_type=query_type,
        query_value=query_value,
        return_format=return_format,
    )
    return _paginate_component_response(result, offset, limit)


def _oscal_store_find_capability(
    ctx: Context | None,
    query_type: str,
    query_value: str,
    component_definition_filter: str | None,
) -> dict[str, Any] | None:
    """Try to find a capability via OscalStore.

    Returns the capability response dict if found, or None to fall through
    to component search.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    # Search for capability as a child element
    cap_result = _oscal_store.list_child_elements(
        ctx=ctx,
        element_type="capability",
        offset=0,
        limit=100,
    )

    if cap_result["total"] == 0:
        return None

    # Find matching capability
    matched_cap = None
    for cap_item in cap_result["items"]:
        if query_type == "by_uuid" and cap_item["uuid"] == query_value:
            matched_cap = cap_item
            break
        if query_type == "by_title" and cap_item["title"].lower() == query_value.lower():
            matched_cap = cap_item
            break

    if matched_cap is None:
        return None

    # If there's a component_definition_filter, verify the parent matches
    if component_definition_filter:
        parent_uuid = matched_cap.get("parentDocumentUuid", "")
        parent_title = matched_cap.get("parentDocumentTitle", "")
        if (
            parent_uuid != component_definition_filter
            and parent_title.lower() != component_definition_filter.lower()
        ):
            return None

    # Retrieve the full capability data from the store's child_elements
    # by querying the parent document by UUID
    cap_uuid = matched_cap["uuid"]
    parent_doc_uuid = matched_cap.get("parentDocumentUuid", "")

    # Get the full capability JSON from the OscalStore
    cap_query = _oscal_store.query(
        ctx=ctx,
        oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
        query_type="by_uuid",
        query_value=parent_doc_uuid,
        offset=0,
        limit=1,
    )

    if cap_query["total"] == 0:
        return None

    # Parse the parent document to get the full capability object
    doc_item = cap_query["items"][0]
    doc_id_row = _oscal_store._conn.execute(
        "SELECT id FROM documents WHERE uuid = ?",
        (parent_doc_uuid,),
    ).fetchone()
    if doc_id_row is None:
        return None

    parsed_model = _oscal_store.get_parsed_model(doc_id_row["id"])
    for cap in getattr(parsed_model, "capabilities", None) or []:
        if str(cap.uuid) == cap_uuid:
            return {
                "capability": cap.oscal_dict(),
                "component_count": (
                    len(cap.incorporates_components)
                    if cap.incorporates_components
                    else 0
                ),
                "query_type": query_type,
                "component_definitions_searched": 0,  # filled by caller
                "filtered_by": component_definition_filter,
            }

    return None


def _oscal_store_list_component_definitions(
    ctx: Context | None, offset: int, limit: int,
) -> dict:
    """Delegate list_component_definitions to OscalStore.

    Preserves the exact return format: Page_Response with items containing
    uuid, title, componentCount, importedComponentDefinitionsCount, sizeInBytes.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    result = _oscal_store.list_documents(
        ctx=ctx,
        oscal_model_type=OSCALModelType.COMPONENT_DEFINITION,
        offset=offset,
        limit=limit,
    )

    if result["total"] == 0:
        msg = "No Component Definitions loaded"
        try_notify_client_error(msg, ctx)
        raise RuntimeError(msg)

    # Transform items to match legacy format
    items = []
    for item in result["items"]:
        items.append({
            "uuid": item["uuid"],
            "title": item["title"],
            "componentCount": item.get("childCount", 0),
            "importedComponentDefinitionsCount": 0,
            "sizeInBytes": item.get("sizeInBytes", 0),
        })

    return {
        "items": items,
        "total": result["total"],
        "offset": result["offset"],
        "limit": result["limit"],
        "hasMore": result["hasMore"],
    }


def _oscal_store_list_components(
    ctx: Context | None, offset: int, limit: int,
) -> dict:
    """Delegate list_components to OscalStore.

    Preserves the exact return format: Page_Response with items containing
    uuid, title, parentComponentDefinitionTitle,
    parentComponentDefinitionUuid, sizeInBytes.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    result = _oscal_store.list_child_elements(
        ctx=ctx,
        element_type="component",
        offset=offset,
        limit=limit,
    )

    if result["total"] == 0:
        msg = "No Components loaded"
        try_notify_client_error(msg, ctx)
        raise RuntimeError(msg)

    # Transform items to match legacy format
    items = []
    for item in result["items"]:
        items.append({
            "uuid": item["uuid"],
            "title": item["title"],
            "parentComponentDefinitionTitle": item.get(
                "parentDocumentTitle", ""
            ),
            "parentComponentDefinitionUuid": item.get(
                "parentDocumentUuid", ""
            ),
            "sizeInBytes": 0,  # Not available from child_elements
        })

    return {
        "items": items,
        "total": result["total"],
        "offset": result["offset"],
        "limit": result["limit"],
        "hasMore": result["hasMore"],
    }


def _oscal_store_list_capabilities(
    ctx: Context | None, offset: int, limit: int,
) -> dict:
    """Delegate list_capabilities to OscalStore.

    Preserves the exact return format: Page_Response with items containing
    uuid, name, parentComponentDefinitionTitle,
    parentComponentDefinitionUuid, sizeInBytes.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    result = _oscal_store.list_child_elements(
        ctx=ctx,
        element_type="capability",
        offset=offset,
        limit=limit,
    )

    # Capabilities are optional — return empty list if none found
    items = []
    for item in result["items"]:
        items.append({
            "uuid": item["uuid"],
            "name": item["title"],
            "parentComponentDefinitionTitle": item.get(
                "parentDocumentTitle", ""
            ),
            "parentComponentDefinitionUuid": item.get(
                "parentDocumentUuid", ""
            ),
            "sizeInBytes": 0,  # Not available from child_elements
        })

    return {
        "items": items,
        "total": result["total"],
        "offset": result["offset"],
        "limit": result["limit"],
        "hasMore": result["hasMore"],
    }


def _oscal_store_get_capability(
    ctx: Context | None, uuid: str,
) -> dict | None:
    """Delegate get_capability to OscalStore.

    Returns the full OSCAL Capability dict, or None if not found.
    """
    if _oscal_store is None:  # pragma: no cover
        raise RuntimeError("OscalStore not initialised")

    if not uuid:
        return None

    # Search for the capability by UUID in child_elements
    result = _oscal_store.list_child_elements(
        ctx=ctx,
        element_type="capability",
        offset=0,
        limit=100,
    )

    for item in result["items"]:
        if item["uuid"] == uuid:
            # Found it — get the full capability from the parsed model
            parent_uuid = item.get("parentDocumentUuid", "")
            doc_row = _oscal_store._conn.execute(
                "SELECT id FROM documents WHERE uuid = ?",
                (parent_uuid,),
            ).fetchone()
            if doc_row is None:
                return None

            parsed_model = _oscal_store.get_parsed_model(doc_row["id"])
            for cap in getattr(parsed_model, "capabilities", None) or []:
                if str(cap.uuid) == uuid:
                    return cap.dict()

    return None
