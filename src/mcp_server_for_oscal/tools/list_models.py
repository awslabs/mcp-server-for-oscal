"""
Tool for listing available OSCAL model types.
"""

from strands import tool

from mcp_server_for_oscal.tools.utils import OSCALModelType


@tool
def list_oscal_models() -> dict:
    """
    List all available OSCAL model types with metadata.

    Returns:
        dict: List of OSCAL models where the key is model's name as used 
            in the schema, and value is an object that includes description,
            layer, formal and short names, and release status.
    """
    models = {
        OSCALModelType.CATALOG: {
            "description": "A structured set of controls and control enhancements",
            "layer": "Control",
            "formalName": "Catalog",
            "shortName": "catalog",
            "status": "GA",
        },
        OSCALModelType.PROFILE: {
            "description": "A baseline or overlay that selects and customizes controls from catalogs",
            "layer": "Control",
            "formalName": "Profile",
            "shortName": "profile",
            "status": "GA",
        },
        OSCALModelType.MAPPING: {
            "description": "Describes how a collection of security controls relates to another collection of controls",
            "layer": "Control",
            "formalName": "Mapping Collection",
            "shortName": "mapping",
            "status": "GA",
        },
        OSCALModelType.COMPONENT_DEFINITION: {
            "description": "Describes how components implement controls",
            "layer": "Implementation",
            "formalName": "Component Definition",
            "shortName": "component",
            "status": "GA",
        },
        OSCALModelType.SYSTEM_SECURITY_PLAN: {
            "description": "Documents how a system implements required controls",
            "layer": "Implementation",
            "formalName": "System Security Plan (SSP)",
            "shortName": "SSP",
            "status": "GA",
        },
        OSCALModelType.ASSESSMENT_PLAN: {
            "description": "Defines how controls will be assessed",
            "layer": "Assessment",
            "formalName": "Security Assessment Plan (SAP)",
            "shortName": "AP",
            "status": "GA",
        },
        OSCALModelType.ASSESSMENT_RESULTS: {
            "description": "Documents the results of control assessments",
            "layer": "Assessment",
            "formalName": "Security Assessment Results (SAR)",
            "shortName": "AR",
            "status": "GA",
        },
        OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: {
            "description": "Documents remediation plans for identified issues",
            "layer": "Assessment",
            "formalName": "Plan of Action and Milestones (POA&M)",
            "shortName": "POAM",
            "status": "GA",
        },
    }

    return models
