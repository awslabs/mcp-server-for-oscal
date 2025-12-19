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
