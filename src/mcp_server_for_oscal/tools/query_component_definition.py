"""
Tool for querying OSCAL Component Definition documents.
"""

import json
import logging
from pathlib import Path
from typing import Any, Literal

import requests
from mcp.server.fastmcp.server import Context
from strands import tool
from trestle.oscal.component import ComponentDefinition, DefinedComponent

from mcp_server_for_oscal.config import config
from mcp_server_for_oscal.tools.utils import try_notify_client_error

logger = logging.getLogger(__name__)



def load_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a local file path or remote URI.

    Uses Pydantic's built-in parsing methods for automatic validation.
    Remote URI loading is only supported when explicitly configured via allow_remote_uris setting.

    Args:
        source: Local file path or remote URI to the Component Definition JSON file
        ctx: MCP server context for error reporting

    Returns:
        ComponentDefinition: Validated Pydantic model instance

    Raises:
        FileNotFoundError: If the source file does not exist
        ValueError: If the file cannot be parsed, fails validation, or remote URIs are not allowed
        requests.RequestException: If remote URI fetching fails
    """
    logger.debug("Loading component definition from: %s", source)

    # Check if source is a remote URI
    is_remote = source.startswith("http://") or source.startswith("https://")

    if is_remote:
        return _load_remote_component_definition(source, ctx)

    return _load_local_component_definition(source, ctx)


def _load_local_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a local file path.

    Args:
        source: Local file path to the Component Definition JSON file
        ctx: MCP server context for error reporting

    Returns:
        ComponentDefinition: Validated Pydantic model instance

    Raises:
        FileNotFoundError: If the source file does not exist
        ValueError: If the file cannot be parsed or fails validation
    """
    source_path = Path(source)

    try:
        # Load and parse JSON, then extract the component-definition wrapper
        with open(source_path) as f:
            data = json.load(f)

        # Extract the component-definition wrapper if present
        if "component-definition" in data:
            component_def = ComponentDefinition(**data["component-definition"])
        else:
            component_def = ComponentDefinition(**data)

        logger.info("Successfully loaded and validated component definition from: %s", source)
        return component_def

    except FileNotFoundError as e:
        msg = f"Component Definition file not found: {source}"
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise FileNotFoundError(msg) from e

    except IsADirectoryError as e:
        msg = f"Source path is not a file: {source}"
        logger.error(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e

    except json.JSONDecodeError as e:
        msg = f"Failed to parse Component Definition JSON: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e

    except Exception as e:
        msg = f"Failed to load or validate Component Definition: {e}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise ValueError(msg) from e


def _load_remote_component_definition(source: str, ctx: Context) -> ComponentDefinition:
    """
    Load and validate an OSCAL Component Definition from a remote URI.

    Only works when allow_remote_uris is configured to True. Fetches the JSON
    content via HTTP and validates it using Pydantic.

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
            component_def = ComponentDefinition(**data["component-definition"])
        else:
            component_def = ComponentDefinition(**data)

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


def extract_component_summary(component: DefinedComponent) -> dict[str, Any]:
    """
    Extract summary information from a DefinedComponent.

    Extracts the required fields (UUID, title, description, type, purpose) and
    handles optional fields (responsible_roles, protocols) from a compliance-trestle
    DefinedComponent Pydantic model.

    Args:
        component: DefinedComponent Pydantic model instance

    Returns:
        dict: Summary dictionary with component information including:
            - uuid: Component UUID
            - title: Component title
            - description: Component description
            - type: Component type
            - purpose: Component purpose
            - responsible_roles: List of responsible role IDs (optional)
            - protocols: List of protocol UUIDs (optional)
    """
    summary = {
        "uuid": str(component.uuid),
        "title": component.title,
        "description": component.description,
        "type": component.type,
        "purpose": component.purpose,
    }

    # Handle optional fields
    if component.responsible_roles:
        summary["responsible_roles"] = [role.role_id for role in component.responsible_roles]

    if component.protocols:
        summary["protocols"] = [str(protocol.uuid) for protocol in component.protocols]

    return summary


def find_component_by_uuid(components: list[Any], uuid: str) -> Any | None:
    """
    Find a component by its UUID.

    Performs an exact match on the component's UUID field.

    Args:
        components: List of DefinedComponent Pydantic model instances
        uuid: UUID string to search for

    Returns:
        DefinedComponent if found, None otherwise
    """
    for component in components:
        if str(component.uuid) == uuid:
            return component
    return None


def find_component_by_title(components: list[Any], title: str) -> Any | None:
    """
    Find a component by its title.

    Performs an exact match on the component's title field.

    Args:
        components: List of DefinedComponent Pydantic model instances
        title: Title string to search for

    Returns:
        DefinedComponent if found, None otherwise
    """
    for component in components:
        if component.title == title:
            return component
    return None


def find_component_by_prop_value(components: list[DefinedComponent], value: str) -> Any | None:
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


def filter_components_by_type(components: list[DefinedComponent], component_type: str) -> list[Any]:
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


def resolve_links_and_props(component: DefinedComponent, ctx: Context, resolve_uris: bool = False, visited_uris: set[str] | None = None, current_depth: int = 0) -> dict[str, Any]:
    """
    Resolve and process Link and Prop objects from a component.

    Extracts name-value pairs from props and href from links according to
    OSCAL extension patterns. Optionally fetches and processes referenced URIs
    when requested.

    Args:
        component: DefinedComponent Pydantic model instance
        ctx: MCP server context for error reporting
        resolve_uris: Whether to fetch and process URI references
        visited_uris: Set of already visited URIs to prevent circular references
        current_depth: Current depth of URI resolution

    Returns:
        Dictionary containing resolved props and links information
    """
    result: dict[str, Any] = {
        "props": [],
        "links": []
    }

    # Extract props (name-value pairs)
    if component.props:
        for prop in component.props:
            prop_data = {
                "name": prop.name,
                "value": prop.value
            }
            # Include optional fields if present
            if prop.ns:
                prop_data["ns"] = prop.ns
            if prop.class_:
                prop_data["class"] = prop.class_
            if prop.remarks:
                prop_data["remarks"] = prop.remarks

            result["props"].append(prop_data)

    # Extract links (href references)
    if component.links:
        for link in component.links:
            link_data: dict[str, Any] = {
                "href": link.href
            }
            # Include optional fields if present
            if link.rel:
                link_data["rel"] = str(link.rel)
            if link.text:
                link_data["text"] = link.text

            # Optionally resolve URI references
            if resolve_uris and link.href:
                resolved_content = _resolve_uri_reference(
                    link.href,
                    ctx,
                    visited_uris or set(),
                    current_depth
                )
                if resolved_content:
                    link_data["resolved_content"] = resolved_content

            result["links"].append(link_data)

    return result


def extract_control_implementations(component: DefinedComponent) -> list[dict[str, Any]]:
    """
    Extract control implementation information from a DefinedComponent.

    Extracts control implementations including implemented requirements with their
    UUIDs, control IDs, descriptions, and implementation statements from a
    compliance-trestle DefinedComponent Pydantic model.

    Args:
        component: DefinedComponent Pydantic model instance

    Returns:
        list: List of control implementation dictionaries, each containing:
            - uuid: Control implementation UUID
            - source: Source reference for the control implementation
            - description: Description of the control implementation (required)
            - implemented_requirements: List of implemented requirement dictionaries with:
                - uuid: Requirement UUID
                - control_id: Control identifier
                - description: Requirement description (required)
                - statements: List of implementation statement dictionaries with:
                    - statement_id: Statement identifier
                    - uuid: Statement UUID
                    - description: Statement description (required)
    """
    control_implementations: list[dict[str, Any]] = []

    # Check if component has control implementations
    if not hasattr(component, 'control_implementations') or not component.control_implementations:
        return control_implementations

    # Process each control implementation
    for ctrl_impl in component.control_implementations:
        impl_data: dict[str, Any] = {
            "uuid": str(ctrl_impl.uuid),
            "source": ctrl_impl.source,
            "description": ctrl_impl.description,  # Required field
        }

        # Process implemented requirements
        implemented_requirements = []
        if hasattr(ctrl_impl, 'implemented_requirements') and ctrl_impl.implemented_requirements:
            for req in ctrl_impl.implemented_requirements:
                req_data = {
                    "uuid": str(req.uuid),
                    "control_id": req.control_id,
                    "description": req.description,  # Required field
                }

                # Process implementation statements
                statements = []
                if hasattr(req, 'statements') and req.statements:
                    for stmt in req.statements:
                        stmt_data = {
                            "statement_id": stmt.statement_id,
                            "uuid": str(stmt.uuid),
                            "description": stmt.description,  # Required field
                        }
                        statements.append(stmt_data)

                if statements:
                    req_data["statements"] = statements

                implemented_requirements.append(req_data)

        if implemented_requirements:
            impl_data["implemented_requirements"] = implemented_requirements

        control_implementations.append(impl_data)

    return control_implementations


def _resolve_uri_reference(uri: str, ctx: Context, visited_uris: set[str], current_depth: int) -> dict[str, Any] | None:
    """
    Fetch and process a URI reference.

    Tracks visited URIs to prevent circular references and respects max_uri_depth
    configuration to limit recursion depth.

    Args:
        uri: The URI to resolve
        ctx: MCP server context for error reporting
        visited_uris: Set of already visited URIs to prevent circular references
        current_depth: Current depth of URI resolution

    Returns:
        Dictionary containing resolved URI content, or None if resolution fails
    """
    # Check if we've exceeded max depth
    if current_depth >= config.max_uri_depth:
        logger.warning("Maximum URI resolution depth (%d) reached for URI: %s", config.max_uri_depth, uri)
        return {
            "error": f"Maximum URI resolution depth ({config.max_uri_depth}) reached",
            "uri": uri
        }

    # Check for circular references
    if uri in visited_uris:
        logger.warning("Circular reference detected for URI: %s", uri)
        return {
            "error": "Circular reference detected",
            "uri": uri
        }

    # Add to visited set
    visited_uris.add(uri)

    # Check if remote URIs are allowed
    is_remote = uri.startswith("http://") or uri.startswith("https://")
    if is_remote and not config.allow_remote_uris:
        logger.warning("Remote URI resolution is not enabled: %s", uri)
        return {
            "error": "Remote URI resolution is not enabled",
            "uri": uri
        }

    try:
        if is_remote:
            # Fetch remote URI
            logger.debug("Fetching remote URI: %s (depth: %d)", uri, current_depth)
            response = requests.get(uri, timeout=config.request_timeout)
            response.raise_for_status()

            # Try to parse as JSON
            try:
                content = response.json()
                return {
                    "uri": uri,
                    "content": content,
                    "content_type": "json",
                    "depth": current_depth
                }
            except json.JSONDecodeError:
                # Return as text if not JSON
                return {
                    "uri": uri,
                    "content": response.text,
                    "content_type": "text",
                    "depth": current_depth
                }
        else:
            # Handle local file references
            logger.debug("Resolving local URI: %s (depth: %d)", uri, current_depth)
            local_path = Path(uri)

            if not local_path.exists():
                logger.warning("Local URI file not found: %s", uri)
                return {
                    "error": "File not found",
                    "uri": uri
                }

            # Read local file
            with open(local_path) as f:
                content_str = f.read()

            # Try to parse as JSON
            try:
                content = json.loads(content_str)
                return {
                    "uri": uri,
                    "content": content,
                    "content_type": "json",
                    "depth": current_depth
                }
            except json.JSONDecodeError:
                # Return as text if not JSON
                return {
                    "uri": uri,
                    "content": content_str,
                    "content_type": "text",
                    "depth": current_depth
                }

    except requests.RequestException as e:
        logger.error("Failed to fetch remote URI %s: %s", uri, e)
        return {
            "error": f"Failed to fetch URI: {e}",
            "uri": uri
        }
    except OSError as e:
        logger.error("Failed to read local URI %s: %s", uri, e)
        return {
            "error": f"Failed to read file: {e}",
            "uri": uri
        }
    except Exception as e:
        logger.error("Unexpected error resolving URI %s: %s", uri, e)
        return {
            "error": f"Unexpected error: {e}",
            "uri": uri
        }



@tool
def query_component_definition(
    ctx: Context,
    source: str,
    query_type: Literal["all", "by_uuid", "by_title", "by_type"] = "all",
    query_value: str | None = None,
    return_format: Literal["raw"] = "raw",
    resolve_uris: bool = False,
) -> dict[str, Any]:
    """
    Query an OSCAL Component Definition document to extract component information.

    This tool loads and parses OSCAL Component Definition documents from local files
    or remote URIs (when configured), validates them against the OSCAL schema, and
    extracts component information based on the specified query parameters.

    The tool returns full OSCAL Component objects as JSON, preserving all fields and
    structure from the original OSCAL Component Definition schema.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        source: Path to local Component Definition file or remote URI
        query_type: Type of query to perform:
            - "all": Return all components in the definition
            - "by_uuid": Find component by UUID (requires query_value)
            - "by_title": Find component by title with prop fallback (requires query_value)
            - "by_type": Filter components by type (requires query_value)
        query_value: Value to search for (required for by_uuid, by_title, by_type)
        return_format: Format of returned component data. Currently only "raw" is supported,
            which returns complete OSCAL Component objects. This parameter is kept for
            future extensibility.
        resolve_uris: Whether to resolve and process URI references in components

    Returns:
        dict: ComponentQueryResponse containing:
            - components: List of complete OSCAL Component objects as JSON
            - total_count: Number of components returned
            - query_type: The query type used
            - source: The source file/URI queried

    Raises:
        ValueError: If query parameters are invalid or component not found
        Exception: If document loading, parsing, or validation fails
    """
    logger.debug(
        "query_component_definition(source: %s, query_type: %s, query_value: %s, return_format: %s, resolve_uris: %s)",
        source,
        query_type,
        query_value,
        return_format,
        resolve_uris,
    )

    # Validate query parameters
    if query_type in ["by_uuid", "by_title", "by_type"] and not query_value:
        msg = f"query_value is required when query_type is '{query_type}'"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    # Load and validate the Component Definition document
    try:
        comp_def = load_component_definition(source, ctx)
    except Exception as e:
        msg = f"Failed to load or parse Component Definition from {source}: {e!s}"
        logger.exception(msg)
        try_notify_client_error(msg, ctx)
        raise

    # Get all components from the definition
    if not comp_def.components:
        logger.warning("Component Definition has no components")
        return {
            "components": [],
            "total_count": 0,
            "query_type": query_type,
            "source": source,
        }

    components = comp_def.components

    # Filter/query components based on query_type
    if query_type == "all":
        selected_components = components
    elif query_type == "by_uuid":
        if query_value is None:
            msg = "query_value is required for by_uuid query type"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
        component = find_component_by_uuid(components, query_value)
        if not component:
            msg = f"Component with UUID '{query_value}' not found in {source}"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
        selected_components = [component]
    elif query_type == "by_title":
        if query_value is None:
            msg = "query_value is required for by_title query type"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
        # Try exact title match first
        component = find_component_by_title(components, query_value)
        # Fallback to prop value search if title not found
        if not component:
            component = find_component_by_prop_value(components, query_value)
        if not component:
            msg = f"Component with title or prop value '{query_value}' not found in {source}"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
        selected_components = [component]
    elif query_type == "by_type":
        if query_value is None:
            msg = "query_value is required for by_type query type"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
        selected_components = filter_components_by_type(components, query_value)
        if not selected_components:
            msg = f"No components with type '{query_value}' found in {source}"
            try_notify_client_error(msg, ctx)
            raise ValueError(msg)
    else:
        msg = f"Invalid query_type: {query_type}"
        try_notify_client_error(msg, ctx)
        raise ValueError(msg)

    # Format the components - always use raw format (full OSCAL Component objects)
    formatted_components = []
    for component in selected_components:
        # Always return full Component as JSON OSCAL object using component.dict()
        component_data = component.dict(exclude_none=True)
        formatted_components.append(component_data)

    # Return the query response
    return {
        "components": formatted_components,
        "total_count": len(formatted_components),
        "query_type": query_type,
        "source": source,
    }
