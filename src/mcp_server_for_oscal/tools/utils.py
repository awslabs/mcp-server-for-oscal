"""
Shared utilities for OSCAL MCP tools.
"""

# import os.path
import logging

# from typing import Any
from enum import StrEnum

logger = logging.getLogger(__name__)


class OSCALModelType(StrEnum):
    """Enumeration of OSCAL model types."""

    CATALOG = "catalog"
    PROFILE = "profile"
    COMPONENT_DEFINITION = "component-definition"
    SYSTEM_SECURITY_PLAN = "system-security-plan"
    ASSESSMENT_PLAN = "assessment-plan"
    ASSESSMENT_RESULTS = "assessment-results"
    PLAN_OF_ACTION_AND_MILESTONES = "plan-of-action-and-milestones"
    MAPPING = "mapping-collection"
