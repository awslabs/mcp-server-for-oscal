"""
Tool for querying OSCAL Component Definition documents.
"""
import json
import logging
from pathlib import Path
from typing import Any, Literal, cast

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
_components_to_cdef_by_uuid: dict[str, str] = {}

_stats: dict[str, int] = {
    "loaded_files": 0,
    "processed_zip_files": 0,
    "zip_file_contents": 0,
    "processed_json_files": 0,
    "component_definitions_indexed": 0,
    "components_indexed": 0
}

def _load_external_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definitions from a URI. The URI can be local or remote and may refer to a zip file that contains Component Definitions. 

    Only works when `config.allow_remote_uris` is to True. Fetches the JSON
    content via HTTP and validates it using trestle's ComponentDefinition.parse_obj method.

    Args:
        source: Remote URI to the Component Definition JSON file
        ctx: MCP server context for error reporting

    Returns:
        ComponentDefinition: Validated trestle ComponentDefinition Pydantic model instance

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


def _load_component_definitions_from_directory(directory_path: Path | None = None) -> dict[str, ComponentDefinition]:
    """
    Recursively scan a directory for Component Definition files and load them.
    
    This function is called when this module is initialized. No need to call
    directly unless you want to load new files after initialization. 

    Searches for all .json and .zip files in the directory and subdirectories. For each file:
    - JSON files: Attempts to load as OSCAL Component Definitions using trestle's oscal_read
    - ZIP files: Extracts and processes contained JSON files
    
    Successfully loaded definitions are stored in the global _cdefs_by_path dictionary and
    indexed in _cdefs_by_uuid and _cdefs_by_title for efficient querying.

    Args:
        directory_path: Path to the directory to scan for Component Definition files. 
                       Defaults to `config.component_definitions_dir` if None. If you pass a value
                       for directory_path, all existing Component Definitions and Components will be 
                       cleared from memory before the directory is processed.

    Returns:
        dict[str, ComponentDefinition]: Dictionary mapping file paths (as strings) to 
                                       ComponentDefinition instances. This is stored in 
                                       the global _cdefs_by_path variable. Only successfully 
                                       loaded and validated Component Definitions are included.

    Note:
        - Invalid files are logged but do not stop the loading process
        - Files that don't contain valid Component Definitions are skipped
        - The function logs successful loads and any errors encountered
        - Uses trestle's ComponentDefinition.oscal_read which properly handles
          the OSCAL wrapper format ({"component-definition": {...}})
        - Updates global _stats dictionary with loading statistics
    """
    global _stats

    if directory_path is None:
        # Load all Component Definitions from the configured directory
        directory_path = Path(__file__).parent.parent / config.component_definitions_dir
    else:
        _cdefs_by_path.clear()
        _cdefs_by_title.clear()
        _cdefs_by_uuid.clear()
        _components_by_title.clear()
        _components_by_uuid.clear()
        _components_to_cdef_by_uuid.clear()

    component_definitions: dict[str, ComponentDefinition] = {}

    if not directory_path.exists():
        logger.warning("Component definitions directory does not exist: %s", directory_path)
        return component_definitions

    if not directory_path.is_dir():
        logger.warning("Component definitions path is not a directory: %s", directory_path)
        return component_definitions
    # logger.info("Loaded %d Component Definitions from directory; index contains", len(component_definitions))
    logger.info(_stats)

    _process_zip_files(directory_path)
    _process_json_files(directory_path)

    return _cdefs_by_path

def _process_zip_files(directory_path: Path) -> None:
    global _stats

    logger.info("Scanning directory for Component Definitions: %s", directory_path)

    zip_files = list(directory_path.rglob("**/*.zip"))
    if zip_files:
        logger.debug("found %s zip files.", len(zip_files))
        import zipfile
        # loop through all discovered zip files
        for zf in zip_files:
            if any(zf.name in key for key in _cdefs_by_path):
                continue # we've already processed this zip file
            _stats["processed_zip_files"] += 1
            with zipfile.ZipFile(zf, 'r') as zip_file:
                file_list = zip_file.namelist()
                _stats["zip_file_contents"] += len(file_list)
                logger.debug("zip manifest includes %s files", len(file_list))
                for innerfile in file_list:
                    innerfile_path = zf.joinpath(innerfile).as_posix()
                    if innerfile_path in _cdefs_by_path:
                        continue # we've already processed this inner file
                    if not innerfile.endswith("json"):
                        continue # this also prevents errors when zip contains subdirectories
                    with zip_file.open(innerfile) as f:
                        data = json.load(f)
                        _index_components(cast(ComponentDefinition, ComponentDefinition.parse_obj(data["component-definition"])), innerfile_path)
                        _stats["loaded_files"] += 1

def _process_json_files(directory_path: Path) -> None:

    global _stats
    # Recursively find all .json files
    json_files = list(directory_path.rglob("**/*.json"))
    logger.debug("Found %d JSON files to process", len(json_files))

    for json_file in json_files:
        # ignore the hash manifest we use for content validation
        if json_file.name == "hashes.json":
            logger.debug("Skipping hashes.json file")
            continue
        try:
            relative_path = str(json_file.relative_to(directory_path))
            if relative_path in _cdefs_by_path:
                continue # we've already loaded this file
            # Use trestle's oscal_read to properly load and validate OSCAL files
            # This method automatically handles the OSCAL wrapper format
            component_def = cast(ComponentDefinition, ComponentDefinition.oscal_read(json_file))
            _stats["processed_json_files"]
            if component_def is None:
                logger.debug("Skipping file (oscal_read returned None): %s", json_file)
                continue

            _index_components(component_def, relative_path)
            _stats["loaded_files"] += 1

        except Exception as e:
            # Log but don't fail - file might not be a Component Definition
            logger.debug("Skipping file (not a valid Component Definition): %s - %s", json_file, e)
            continue


def _index_components(cdef: ComponentDefinition, path: str) -> None:
    """
    Index a ComponentDefinition and its child Components for efficient querying.
    
    Adds the ComponentDefinition and its DefinedComponents to various global dictionaries:
    - _cdefs_by_uuid: Maps ComponentDefinition UUIDs to instances
    - _cdefs_by_title: Maps ComponentDefinition titles to instances
    - _components_by_uuid: Maps Component UUIDs to (component, parent_cdef) tuples
    - _components_by_title: Maps Component titles to (component, parent_cdef) tuples
    
    Args:
        cdef: ComponentDefinition instance to index
        path: File path where the ComponentDefinition was loaded from
        
    Note:
        - Updates global _stats dictionary with indexing counts
        - Called automatically by _load_component_definitions_from_directory
    """
    global _cdefs_by_path
    global _cdefs_by_title
    global _cdefs_by_uuid
    global _components_by_uuid
    global _components_by_title
    global _components_to_cdef_by_uuid
    global _stats

    try:
        # Store with relative path as key
        _cdefs_by_path[path] = cdef
        _cdefs_by_uuid[cdef.uuid] = cdef
        _cdefs_by_title[cdef.metadata.title] = cdef
        _stats["component_definitions_indexed"] +=1
        logger.info("Successfully loaded Component Definition: %s", path)


        if cdef.components:
            for c in cdef.components:
                _components_by_uuid[str(c.uuid)] = c
                _components_by_title[c.title] = c
                _components_to_cdef_by_uuid[str(c.uuid)] = str(cdef.uuid)
                _stats["components_indexed"] +=1
                logger.debug("Component %s added to index", c.title)
    except:
        logger.exception("Failed to index component %s from %s", cdef.metadata.title, path)
        raise



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
    Find a component by searching property values.

    Searches through all property values in each component's props list for an exact match.
    This is used as a fallback when title-based search fails in by_title queries.

    Args:
        components: List of DefinedComponent Pydantic model instances to search
        value: Value string to search for in component properties

    Returns:
        DefinedComponent: First component with a matching property value, or None if not found
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
    Filter components by their type field.

    Returns all components where the type field exactly matches the specified component_type.

    Args:
        components: List of DefinedComponent Pydantic model instances to filter
        component_type: Type string to match against component.type field

    Returns:
        list[DefinedComponent]: List of components with matching type field
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
    Query OSCAL Component Definition documents to extract component information about services, software, regions, etc. Use this tool to get details about the names, IDs, availability, security features, controls, and more associated with a Component. If needed, use the tools list_components() or list_component_definitions() to get summary information including titles and UUIDs that can be used as query filters.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        component_definition_filter: Optional UUID or metadata.title from Component Definition 
            to limit the search to a specific Component Definition. If not provided, searches
            across all loaded Component Definitions.
        query_type: Type of query to perform:
            - "all": Return all components in the definition(s). This is intended for use only with a component_definition_filter. Results will be large and may overflow context window. If you just need a summary of all available components, use the list_components() tool instead.
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


    if not _cdefs_by_path:
        msg = "No Component Definitions loaded"
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
def list_component_definitions(ctx: Context) -> list[dict]:
    """Use this tool to get a list of all loaded Component Definitions including the UUID, title, component-count, imported component-definition-count, and size of each.

    Args:
        ctx: MCP server context (injected automatically by MCP server)

    Returns:
        List[dict]: List of dictionaries containing uuid, title, componentCount, and importedComponentDefinitionsCount, for each Component Definition
    """
    global _cdefs_by_title
    if not _cdefs_by_title:
        msg = "No Component Definitions loaded"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)
        # logger.debug(_cdefs_by_title.keys())

    rv = []

    for cd in _cdefs_by_title.values():
        component_count = len(cd.components) if cd.components else 0
        imported_cdef_count = len(cd.import_component_definitions) if cd.import_component_definitions else 0
        rv.append({
            "uuid": cd.uuid,
            "title": cd.metadata.title,
            "componentCount": component_count,
            "importedComponentDefinitionsCount": imported_cdef_count,
            "sizeInBytes": len(cd.oscal_serialize_json_bytes())
        })

    return rv


@tool()
def list_components(ctx: Context) -> list[dict]:
    """Use this tool to get a list of all loaded Components including for each its UUID, title, and parent Component Definition's UUID and title.

    Args:
        ctx: MCP server context (injected automatically by MCP server)

    Returns:
        List[dict]: List of dictionaries containing for each Component: uuid, title, and parent's UUID and title
    """
    global _components_by_title
    global _components_to_cdef_by_uuid

    if not _components_by_title:
        msg = "No Components loaded"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)
        # logger.debug(_components_by_title.keys())

    rv = []
    for cd in _components_by_title.values():
        rv.append({
            "uuid": cd.uuid,
            "title": cd.title,
            "parentComponentDefinitionTitle": _cdefs_by_uuid[_components_to_cdef_by_uuid[str(cd.uuid)]].metadata.title,
            "parentComponentDefinitionUuid": _cdefs_by_uuid[_components_to_cdef_by_uuid[str(cd.uuid)]].uuid,
            "sizeInBytes": len(cd.oscal_serialize_json_bytes())
        })

    return rv

_load_component_definitions_from_directory()
