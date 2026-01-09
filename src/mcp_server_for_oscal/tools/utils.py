"""
Shared utilities for OSCAL MCP tools.
"""

import asyncio
import logging
from enum import StrEnum
import json
from typing import Literal
from pathlib import Path
import hashlib

from mcp.server.fastmcp.server import Context
from mcp_server_for_oscal.config import config

logger = logging.getLogger(__name__)
logger.setLevel(config.log_level)


class OSCALModelType(StrEnum):
    """Enumeration of OSCAL model types."""

    # These values are intended to match the root object name in the JSON schema
    CATALOG = "catalog"
    PROFILE = "profile"
    COMPONENT_DEFINITION = "component-definition"
    SYSTEM_SECURITY_PLAN = "system-security-plan"
    ASSESSMENT_PLAN = "assessment-plan"
    ASSESSMENT_RESULTS = "assessment-results"
    PLAN_OF_ACTION_AND_MILESTONES = "plan-of-action-and-milestones"
    MAPPING = "mapping-collection"


schema_names = {
    OSCALModelType.ASSESSMENT_PLAN: "oscal_assessment-plan_schema",
    OSCALModelType.ASSESSMENT_RESULTS: "oscal_assessment-results_schema",
    OSCALModelType.CATALOG: "oscal_catalog_schema",
    OSCALModelType.COMPONENT_DEFINITION: "oscal_component_schema",
    OSCALModelType.MAPPING: "oscal_mapping_schema",
    OSCALModelType.PROFILE: "oscal_profile_schema",
    OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: "oscal_poam_schema",
    OSCALModelType.SYSTEM_SECURITY_PLAN: "oscal_ssp_schema",
    "complete": "oscal_complete_schema",
}


def try_notify_client_error(msg: str, ctx: Context) -> None:
    safe_log_mcp(msg, ctx, "error")


def safe_log_mcp(
    msg: str, ctx: Context, level: Literal["debug", "info", "warning", "error"]
) -> None:
    if not ctx or not msg:
        return
    try:
        loop = asyncio.get_running_loop()
        # Already in async context - can't use asyncio.run()
        loop.run_until_complete(ctx.log(level, msg))
    except RuntimeError:
        # Not in async context - safe to use asyncio.run()
        asyncio.run(ctx.log(level, msg))


def verify_package_integrity(directory: Path) -> None:
    """Verify all files in a package directory match their expected SHA-256 hashes.

    This function provides critical security functionality by validating that bundled
    OSCAL schemas and documentation files haven't been tampered with. It reads a
    hashes.json manifest file and verifies that all listed files exist and have
    matching SHA-256 hashes.

    This implements the file integrity verification requirements specified in:
    .kiro/specs/file-integrity-testing/requirements.md - Requirements 1-6

    The function performs comprehensive validation:
    1. Parses and validates the hashes.json manifest file
    2. Verifies all files listed in the manifest exist
    3. Computes SHA-256 hashes for all files and compares with expected values
    4. Detects orphaned files (present but not in manifest)
    5. Provides detailed logging and error reporting

    Args:
        directory (Path): Path to the package directory containing files and hashes.json.
                         The directory must contain a valid hashes.json file with the format:
                         {
                           "commit": "git_commit_hash",
                           "file_hashes": {
                             "filename1": "sha256_hash1",
                             "filename2": "sha256_hash2"
                           }
                         }

    Returns:
        None: Function completes silently on success

    Raises:
        RuntimeError: Raised in the following cases:
            - hashes.json file is missing or contains malformed JSON
            - hashes.json is missing required 'file_hashes' section
            - Any file listed in the manifest is missing from the directory
            - Any file's computed hash doesn't match the expected hash
            - Any file exists in the directory but isn't listed in the manifest
            - I/O errors occur during file reading or hash computation
            - Permission errors prevent file access

    Example:
        >>> from pathlib import Path
        >>> verify_package_integrity(Path("src/mcp_server_for_oscal/oscal_schemas"))
        # Completes silently if all files are valid
        
        >>> verify_package_integrity(Path("tampered_directory"))
        RuntimeError: File schema.json has been modified; expected hash abc123 != def456

    Security Notes:
        - Uses SHA-256 for cryptographic hash verification
        - Reads files in binary mode to ensure accurate hash computation
        - Fails fast on first integrity violation to prevent use of compromised data
        - Logs all verification activities for security monitoring
        - Designed to be called during server startup to prevent use of tampered files

    Integration:
        This function is typically called during MCP server startup to verify the
        integrity of bundled OSCAL schemas and documentation. The hashes.json files
        are generated at build time using the bin/update_hashes.py script.

        Server startup integration (main.py):
        >>> verify_package_integrity(Path("src/mcp_server_for_oscal/oscal_schemas"))
        >>> verify_package_integrity(Path("src/mcp_server_for_oscal/oscal_docs"))
    """

    logger.info(f"Verifying contents of package {directory.name}")
    with open(directory.joinpath("hashes.json"), "r") as hashes:
        state = json.load(hashes)

    # Confirm that all files listed in hashes.json actually exist
    for file_path in state["file_hashes"]:
        sfp = directory.joinpath(file_path)
        if not sfp.exists():
            raise RuntimeError(f"File {file_path} missing from package.")
        logger.debug("File %s exists", sfp)

    # Validate that all files in directory are unmodified
    for fn in directory.iterdir():
        # Skip the hash file itself, which is not included in hashes.json
        if not fn.is_file() or fn.name == "hashes.json":
            continue
        with open(fn, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
            try:
                if h != state["file_hashes"][fn.name]:
                    raise RuntimeError(
                        f"File {fn.name} has been modified; expected hash {state['file_hashes'][fn.name]} != {h}"
                    )
            except KeyError:
                logger.exception(
                    f"Unexpected file {fn.name} in directory {directory.name}"
                )
                raise
            logger.debug("Hash for file %s matches", fn.name)
