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
    "complete": "oscal_complete_schema"
}

def try_notify_client_error(msg: str, ctx: Context) -> None:
    safe_log_mcp(msg, ctx, "error")

def safe_log_mcp(msg: str, ctx: Context, level: Literal['debug', 'info', 'warning', 'error']) -> None:
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
    """Verify all files match captured state from build time"""

    logger.info(f"Verifying contents of package {directory.name}")
    with open(directory.joinpath('hashes.json'), 'r') as hashes:
        state = json.load(hashes)
    
    # Confirm that all files listed in hashes.json actually exist
    for file_path in state['file_hashes']:
        sfp = directory.joinpath(file_path)
        if not sfp.exists():
            raise RuntimeError(f"File {file_path} missing from package.")
        logger.debug("File %s exists", sfp)

    # Validate that all files in directory are unmodified
    for fn in directory.iterdir():
        # Skip the hash file itself, which is not included in hashes.json
        if not fn.is_file() or fn.name == 'hashes.json':
            continue
        with open(fn, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
            if h != state['file_hashes'][fn.name]:
                raise RuntimeError(f"File {fn.name} has been modified; expected hash {state['file_hashes'][fn.name]} != {h}")
            logger.debug("Hash for file %s matches", fn.name)
            