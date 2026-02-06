"""
Tool for querying OSCAL Component Definition documents.
"""

import json
import logging
from pathlib import Path
from typing import Any, Literal, cast, List

import requests
from mcp.server.fastmcp.server import Context
from strands import tool
from trestle.oscal.component import ComponentDefinition, DefinedComponent

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import try_notify_client_error

logger = logging.getLogger(__name__)
logger.setLevel(config.log_level)

_cdefs_by_path: dict[str, ComponentDefinition] = {}
_cdefs_by_uuid: dict[str, ComponentDefinition] = {}
_cdefs_by_title: dict[str, ComponentDefinition] = {}
_components_by_uuid: dict[str, DefinedComponent] = {}
_components_by_title: dict[str, DefinedComponent] = {}

def _load_remote_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a remote URI.

    Only works when allow_remote_uris is configured to True. Fetches the JSON
    content via HTTP and validates it using trestle's parse_obj method.

    Args:
        source: Remote URI to the Component Definition JSON file
        ctx: MCP server context for error reporting

    Returns:
        ComponentDefinition: Validated Pydantic model instance

    Raises:
        ValueError: If remote URIs are not allowed or validation fails
        requests.RequestException: If HTTP request fails
    """
    # Check if remote URIs are allowed
    if not config.allow_remote_uris:
        msg = (
            f"Remote URI loading is not enabled. "
            f"Set OSCAL_ALLOW_REMOTE_URIS=true to enable. Source: {source}"
        )
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    logger.info("Fetching remote Component Definition from: %s", source)

    try:
        # Fetch the remote content with timeout
        response = requests.get(source, timeout=config.request_timeout)
        response.raise_for_status()

        # Parse JSON and extract the component-definition wrapper if present
        data = response.json()
        if "component-definition" in data:
            data = data["component-definition"]

        # Use trestle's parse_obj for validation and model instantiation
        component_def = ComponentDefinition.parse_obj(data)

        logger.info("Successfully loaded and validated remote component definition from: %s", source)
        return component_def

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


def load_component_definitions_from_directory(directory_path: Path) -> dict[str, ComponentDefinition]:
    """
    Recursively scan a directory for Component Definition files and load them.

    Searches for all .json files in the directory and subdirectories, attempts to
    load them as OSCAL Component Definitions using trestle's oscal_read method,
    and stores successfully loaded definitions in a dictionary keyed by file path.

    Args:
        directory_path: Path to the directory to scan for Component Definition files

    Returns:
        dict: Dictionary mapping file paths (as strings) to ComponentDefinition instances.
              Only successfully loaded and validated Component Definitions are included.

    Note:
        - Invalid files are logged but do not stop the loading process
        - Files that don't contain valid Component Definitions are skipped
        - The function logs successful loads and any errors encountered
        - Uses trestle's ComponentDefinition.oscal_read which properly handles
          the OSCAL wrapper format ({"component-definition": {...}})
    """
    if not directory_path:
        # Load all Component Definitions from the configured directory
        directory_path = Path(__file__).parent.parent / config.component_definitions_dir 

    component_definitions: dict[str, ComponentDefinition] = {}

    if not directory_path.exists():
        logger.warning("Component definitions directory does not exist: %s", directory_path)
        return component_definitions

    if not directory_path.is_dir():
        logger.warning("Component definitions path is not a directory: %s", directory_path)
        return component_definitions

    logger.info("Scanning directory for Component Definitions: %s", directory_path)

    # Recursively find all .json files
    json_files = list(directory_path.rglob("**/*.json"))
    logger.info("Found %d JSON files to process", len(json_files))

    global _cdefs_by_path
    global _cdefs_by_title
    global _cdefs_by_uuid

    for json_file in json_files:
        # ignore the hash manifest we use for content validation
        if json_file.name == "hashes.json":
            continue
        try:
            relative_path = str(json_file.relative_to(directory_path))
            if relative_path in _cdefs_by_path.keys():
                continue
            # Use trestle's oscal_read to properly load and validate OSCAL files
            # This method automatically handles the OSCAL wrapper format
            component_def = cast(ComponentDefinition, ComponentDefinition.oscal_read(json_file))

            if component_def is None:
                logger.debug("Skipping file (oscal_read returned None): %s", json_file)
                continue

            # Store with relative path as key
            component_definitions[relative_path] = component_def
            _cdefs_by_uuid[component_def.uuid] = component_def
            _cdefs_by_title[component_def.metadata.title] = component_def
            logger.info("Successfully loaded Component Definition: %s", relative_path)

            global _components_by_uuid
            global _components_by_title
            if component_def.components:
                for c in component_def.components:
                    _components_by_uuid[str(c.uuid)] = c
                    _components_by_title[c.title] = c
                    logger.debug("Component %s added to index", c.title)
        except Exception as e:
            # Log but don't fail - file might not be a Component Definition
            logger.debug("Skipping file (not a valid Component Definition): %s - %s", json_file, e)
            continue

    logger.info("Successfully loaded %d Component Definitions from directory", len(component_definitions))
    
    return component_definitions





# def find_component_by_uuid(components: list[DefinedComponent], uuid: str) -> DefinedComponent | None:
#     """
#     Find a component by its UUID.

#     Performs an exact match on the component's UUID field.

#     Args:
#         components: List of DefinedComponent Pydantic model instances
#         uuid: UUID string to search for

#     Returns:
#         DefinedComponent if found, None otherwise
#     """
#     for component in components:
#         if str(component.uuid) == uuid:
#             return component
#     return None


# def find_component_by_title(components: list[DefinedComponent], title: str) -> DefinedComponent | None:
#     """
#     Find a component by its title.

#     Performs an exact match on the component's title field.

#     Args:
#         components: List of DefinedComponent Pydantic model instances
#         title: Title string to search for

#     Returns:
#         DefinedComponent if found, None otherwise
#     """
#     for component in components:
#         if component.title == title:
#             return component
#     return None


def find_component_by_prop_value(components: list[DefinedComponent], value: str) -> DefinedComponent | None:
    """
    Find a component by searching prop values.

    Searches through all prop values for an exact match. This is a fallback
    when title search fails.

    Args:
        components: List of DefinedComponent Pydantic model instances
        value: Value string to search for in props

    Returns:
        DefinedComponent if found, None otherwise
    """
    for component in components:
        if component.props:
            # Search through all prop values for this component
            for prop in component.props:
                if prop.value == value:
                    return component
    return None


def filter_components_by_type(components: list[DefinedComponent], component_type: str) -> list[DefinedComponent]:
    """
    Filter components by type.

    Returns all components where the type field matches the query value.

    Args:
        components: List of DefinedComponent Pydantic model instances
        component_type: Type string to filter by

    Returns:
        List of DefinedComponent instances matching the type
    """
    return [component for component in components if component.type == component_type]









@tool()
def query_component_definition(
    ctx: Context,
    component_definition_filter: str | None = None,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    return_format: Literal["raw"] = "raw",
) -> dict[str, Any]:
    """
    Query OSCAL Component Definition documents to extract component information about services, software, regions, etc. Use this tool to get details about the names, IDs, availability, security features, controls, and more associated with a Component.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        component_definition_filter: Optional UUID or title from Component Definition metadata
            to limit the search to a specific Component Definition. If not provided, searches
            across all Component Definitions in the configured directory.
        query_type: Type of query to perform:
            - "all": Return all components in the definition(s). USE 'all' AS A LAST RESORT. RESULT SET WILL BE VERY, VERY LARGE.
            - "by_uuid": Find component by UUID (requires query_value)
            - "by_title": Find component by title with prop fallback (requires query_value)
            - "by_type": Filter components by type (requires query_value)
        query_value: Value to search for (required for by_uuid, by_title, by_type)
        return_format: Format of returned component data. Currently only "raw" is supported,
            which returns complete OSCAL Component objects. This parameter is kept for
            future extensibility.

    Returns:
        dict: ComponentQueryResponse containing:
            - components: List of complete OSCAL Component objects as JSON
            - total_count: Number of components returned
            - query_type: The query type used
            - component_definitions_searched: Number of Component Definitions searched
            - filtered_by: The filter value used (if any)

    Raises:
        ValueError: If query parameters are invalid or component not found
        Exception: If document loading, parsing, or validation fails
    """
    if query_value:
        query_value = query_value.strip()

    logger.debug(
        "query_component_definition(component_definition_filter: %s, query_type: %s, query_value: %s, return_format: %s)",
        component_definition_filter,
        query_type,
        query_value,
        return_format,
    )

    # Validate query parameters
    if query_type in ["by_uuid", "by_title", "by_type"] and not query_value:
        msg = f"query_value is required when query_type is '{query_type}'"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    global _cdefs_by_path
    global _cdefs_by_uuid
    global _cdefs_by_title
    global _components_by_uuid
    global _components_by_title

    # Load all Component Definitions from the configured directory
    comp_defs_dir = Path(__file__).parent.parent / config.component_definitions_dir
    try:
        _cdefs_by_path.update(load_component_definitions_from_directory(comp_defs_dir))
    except Exception as e:
        msg = f"Failed to load Component Definitions from directory: {e!s}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise

    if not _cdefs_by_path:
        msg = f"No Component Definitions found in directory: {comp_defs_dir}"
        logger.warning(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    # Filter to specific Component Definition if filter is provided
    comp_defs_searched: dict[str, ComponentDefinition] = {}
    if component_definition_filter:
        # Try to match by UUID first
        if component_definition_filter in _cdefs_by_uuid:
            comp_def = _cdefs_by_uuid[component_definition_filter]
            # Find the path for this component definition
            for path, cd in _cdefs_by_path.items():
                if cd.uuid == comp_def.uuid:
                    comp_defs_searched[path] = comp_def
                    logger.info("Filtered to Component Definition with UUID: %s", component_definition_filter)
                    break
        # Try to match by title
        elif component_definition_filter in _cdefs_by_title:
            comp_def = _cdefs_by_title[component_definition_filter]
            # Find the path for this component definition
            for path, cd in _cdefs_by_path.items():
                if cd.metadata.title == comp_def.metadata.title:
                    comp_defs_searched[path] = comp_def
                    logger.info("Filtered to Component Definition with title: %s", component_definition_filter)
                    break

        if not comp_defs_searched:
            msg = f"No Component Definition found with UUID or title matching: {component_definition_filter}"
            logger.warning(msg)
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
    else:
        comp_defs_searched = _cdefs_by_path

    # Build component indexes from filtered component definitions only
    filtered_components_by_uuid: dict[str, DefinedComponent] = {}
    filtered_components_by_title: dict[str, DefinedComponent] = {}

    for comp_def in comp_defs_searched.values():
        if comp_def.components:
            for c in comp_def.components:
                filtered_components_by_uuid[str(c.uuid)] = c
                filtered_components_by_title[c.title] = c

    logger.debug("%s components in filtered index", len(filtered_components_by_uuid))

    if not filtered_components_by_uuid:
        logger.warning("No components found in the Component Definition(s)")
        return {
            "components": [],
            "total_count": 0,
            "query_type": query_type,
            "component_definitions_searched": len(comp_defs_searched),
            "filtered_by": component_definition_filter,
        }

    # Filter/query components based on query_type
    if query_type == "all":
        selected_components = list(filtered_components_by_uuid.values())
    elif query_type == "by_uuid":
        if query_value is None:
            msg = "query_value is required for by_uuid query type"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
        component = filtered_components_by_uuid.get(query_value)
        if not component:
            msg = f"Component with UUID '{query_value}' not found"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
        selected_components = [component]
    elif query_type == "by_title":
        if query_value is None:
            msg = "query_value is required for by_title query type"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
        # Try exact title match first
        component = filtered_components_by_title.get(query_value)
        # if title not found, try again without spaces
        if not component:
            component = filtered_components_by_title.get(query_value.replace(" ", ""))

        # Fallback to prop value search if title not found
        if not component:
            logger.debug("fallback to prop search; no component found with title: %s", query_value)
            component = find_component_by_prop_value(list(filtered_components_by_uuid.values()), query_value)
        if not component:
            msg = f"Component with title or prop value '{query_value}' not found"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
        selected_components = [component]
    elif query_type == "by_type":
        if query_value is None:
            msg = "query_value is required for by_type query type"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
        selected_components = filter_components_by_type(list(filtered_components_by_uuid.values()), query_value)
        if not selected_components:
            msg = f"No components with type '{query_value}' found"
            try_notify_client_error(msg, ctx)
            logger.error(msg)
            raise ValueError(msg)
    else:
        msg = f"Invalid query_type: {query_type}"
        try_notify_client_error(msg, ctx)
        logger.error(msg)
        raise ValueError(msg)

    # Format the components - always use raw format (full OSCAL Component objects)
    formatted_components = []
    for component in selected_components:
        # Always return full Component as JSON OSCAL object using component.dict()
        component_data = component.dict(exclude_none=True)
        formatted_components.append(component_data)

    # Return the query response

    r = {
        "components": formatted_components,
        "total_count": len(formatted_components),
        "query_type": query_type,
        "component_definitions_searched": len(comp_defs_searched),
        "filtered_by": component_definition_filter,
    }
    # logger.debug(r)
    return r

@tool()
def list_component_definitions(ctx: Context) -> List[dict]:
    """Use this tool to get a list of all loaded Component Definitions including the UUID, title, and component-count of each.
    
    Args:
        ctx: MCP server context (injected automatically by MCP server)
    
    Returns:
        List[dict]: List of dictionaries containing uuid, title, and componentCount for each Component Definition
    """
    global _cdefs_by_title
    if not _cdefs_by_title:
        load_component_definitions_from_directory(None)
        logger.debug(_cdefs_by_title.keys())
    
    rv = []
    for cd in _cdefs_by_title.values():
        component_count = len(cd.components) if cd.components else 0
        imported_cdef_count = len(cd.import_component_definitions) if cd.import_component_definitions else 0
        rv.append({
            "uuid": cd.uuid,
            "title": cd.metadata.title,
            "componentCount": component_count,
            "importedComponentDefinitions": imported_cdef_count
        })

    return rv