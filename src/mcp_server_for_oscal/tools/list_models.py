"""
Tool for listing available OSCAL model types.
"""

from strands import tool

from mcp_server_for_oscal.tools.utils import OSCALModelType


@tool
def list_oscal_models() -> dict:
    """
    List all available OSCAL model types with descriptions.

    Returns:
        dict: Formatted list of OSCAL models with descriptions, layers, and status
    """
    models = {
        OSCALModelType.CATALOG: {
            "description": "A structured set of controls and control enhancements",
            "layer": "Control",
            "status": "GA",
        },
        OSCALModelType.PROFILE: {
            "description": "A baseline or overlay that selects and customizes controls from catalogs",
            "layer": "Control",
            "status": "GA",
        },
        OSCALModelType.MAPPING: {
            "description": "Describes how a collection of security controls relates to another collection of controls",
            "layer": "Control",
            "status": "GA",
        },
        OSCALModelType.COMPONENT_DEFINITION: {
            "description": "Describes how components implement controls",
            "layer": "Implementation",
            "status": "GA",
        },
        OSCALModelType.SYSTEM_SECURITY_PLAN: {
            "description": "Documents how a system implements required controls",
            "layer": "Implementation",
            "status": "GA",
        },
        OSCALModelType.ASSESSMENT_PLAN: {
            "description": "Defines how controls will be assessed",
            "layer": "Assessment",
            "status": "GA",
        },
        OSCALModelType.ASSESSMENT_RESULTS: {
            "description": "Documents the results of control assessments",
            "layer": "Assessment",
            "status": "GA",
        },
        OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: {
            "description": "Documents remediation plans for identified issues",
            "layer": "Assessment",
            "status": "GA",
        },
    }

    return models
