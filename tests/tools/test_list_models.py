"""
Tests for the list_models tool.
"""

from mcp_server_for_oscal.tools.list_models import list_oscal_models
from mcp_server_for_oscal.tools.utils import OSCALModelType


class TestListModels:
    """Test cases for the list_oscal_models tool."""

    def test_list_oscal_models_returns_dict(self):
        """Test that list_oscal_models returns a dictionary."""
        result = list_oscal_models()
        assert isinstance(result, dict)

    def test_list_oscal_models_contains_all_model_types(self):
        """Test that all OSCAL model types are included in the result."""
        result = list_oscal_models()

        # Verify all enum values are present as keys
        for model_type in OSCALModelType:
            assert model_type in result, f"Model type {model_type} not found in result"

    def test_list_oscal_models_structure(self):
        """Test that each model entry has the expected structure."""
        result = list_oscal_models()

        required_fields = ["description", "layer", "status"]

        for model_name, model_info in result.items():
            assert isinstance(model_info, dict), (
                f"Model info for {model_name} is not a dict"
            )

            for field in required_fields:
                assert field in model_info, f"Field {field} missing from {model_name}"
                assert isinstance(model_info[field], str), (
                    f"Field {field} in {model_name} is not a string"
                )
                assert model_info[field].strip(), (
                    f"Field {field} in {model_name} is empty"
                )

    def test_list_oscal_models_catalog_details(self):
        """Test specific details for the catalog model."""
        result = list_oscal_models()

        catalog = result[OSCALModelType.CATALOG]
        assert (
            catalog["description"]
            == "A structured set of controls and control enhancements"
        )
        assert catalog["layer"] == "Control"
        assert catalog["status"] == "GA"

    def test_list_oscal_models_profile_details(self):
        """Test specific details for the profile model."""
        result = list_oscal_models()

        profile = result[OSCALModelType.PROFILE]
        assert (
            profile["description"]
            == "A baseline or overlay that selects and customizes controls from catalogs"
        )
        assert profile["layer"] == "Control"
        assert profile["status"] == "GA"

    def test_list_oscal_models_component_definition_details(self):
        """Test specific details for the component-definition model."""
        result = list_oscal_models()

        component_def = result[OSCALModelType.COMPONENT_DEFINITION]
        assert (
            component_def["description"]
            == "Describes how components implement controls"
        )
        assert component_def["layer"] == "Implementation"
        assert component_def["status"] == "GA"

    def test_list_oscal_models_ssp_details(self):
        """Test specific details for the system-security-plan model."""
        result = list_oscal_models()

        ssp = result[OSCALModelType.SYSTEM_SECURITY_PLAN]
        assert (
            ssp["description"] == "Documents how a system implements required controls"
        )
        assert ssp["layer"] == "Implementation"
        assert ssp["status"] == "GA"

    def test_list_oscal_models_assessment_plan_details(self):
        """Test specific details for the assessment-plan model."""
        result = list_oscal_models()

        assessment_plan = result[OSCALModelType.ASSESSMENT_PLAN]
        assert assessment_plan["description"] == "Defines how controls will be assessed"
        assert assessment_plan["layer"] == "Assessment"
        assert assessment_plan["status"] == "GA"

    def test_list_oscal_models_assessment_results_details(self):
        """Test specific details for the assessment-results model."""
        result = list_oscal_models()

        assessment_results = result[OSCALModelType.ASSESSMENT_RESULTS]
        assert (
            assessment_results["description"]
            == "Documents the results of control assessments"
        )
        assert assessment_results["layer"] == "Assessment"
        assert assessment_results["status"] == "GA"

    def test_list_oscal_models_poam_details(self):
        """Test specific details for the plan-of-action-and-milestones model."""
        result = list_oscal_models()

        poam = result[OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES]
        assert (
            poam["description"] == "Documents remediation plans for identified issues"
        )
        assert poam["layer"] == "Assessment"
        assert poam["status"] == "GA"

    def test_list_oscal_models_mapping_details(self):
        """Test specific details for the mapping-collection model."""
        result = list_oscal_models()

        mapping = result[OSCALModelType.MAPPING]
        assert (
            mapping["description"]
            == "Describes how a collection of security controls relates to another collection of controls"
        )
        assert mapping["layer"] == "Control"
        assert mapping["status"] == "GA"

    def test_list_oscal_models_layers(self):
        """Test that models are correctly categorized by layer."""
        result = list_oscal_models()

        control_layer_models = [
            OSCALModelType.CATALOG,
            OSCALModelType.PROFILE,
            OSCALModelType.MAPPING,
        ]

        implementation_layer_models = [
            OSCALModelType.COMPONENT_DEFINITION,
            OSCALModelType.SYSTEM_SECURITY_PLAN,
        ]

        assessment_layer_models = [
            OSCALModelType.ASSESSMENT_PLAN,
            OSCALModelType.ASSESSMENT_RESULTS,
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
        ]

        # Verify Control layer models
        for model in control_layer_models:
            assert result[model]["layer"] == "Control", (
                f"Model {model} should be in Control layer"
            )

        # Verify Implementation layer models
        for model in implementation_layer_models:
            assert result[model]["layer"] == "Implementation", (
                f"Model {model} should be in Implementation layer"
            )

        # Verify Assessment layer models
        for model in assessment_layer_models:
            assert result[model]["layer"] == "Assessment", (
                f"Model {model} should be in Assessment layer"
            )

    def test_list_oscal_models_status_values(self):
        """Test that all status values are valid."""
        result = list_oscal_models()

        valid_statuses = ["GA", "PROTOTYPE"]

        for model_name, model_info in result.items():
            status = model_info["status"]
            assert status in valid_statuses, (
                f"Model {model_name} has invalid status: {status}"
            )

    def test_list_oscal_models_ga_status_models(self):
        """Test that expected models have GA status."""
        result = list_oscal_models()

        ga_models = [
            OSCALModelType.CATALOG,
            OSCALModelType.COMPONENT_DEFINITION,
            OSCALModelType.SYSTEM_SECURITY_PLAN,
            OSCALModelType.ASSESSMENT_PLAN,
            OSCALModelType.ASSESSMENT_RESULTS,
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
            OSCALModelType.PROFILE,
            OSCALModelType.MAPPING,
        ]

        for model in ga_models:
            assert result[model]["status"] == "GA", (
                f"Model {model} should have GA status"
            )

    def test_list_oscal_models_prototype_status_models(self):
        """Test that expected models have Prototype status."""
        result = list_oscal_models()

        prototype_models = []

        for model in prototype_models:
            assert result[model]["status"] == "PROTOTYPE", (
                f"Model {model} should have Prototype status"
            )

    def test_list_oscal_models_consistent_calls(self):
        """Test that multiple calls return consistent results."""
        result1 = list_oscal_models()
        result2 = list_oscal_models()

        assert result1 == result2, "Multiple calls should return identical results"

    def test_list_oscal_models_no_empty_descriptions(self):
        """Test that no model has an empty description."""
        result = list_oscal_models()

        for model_name, model_info in result.items():
            description = model_info["description"]
            assert description and description.strip(), (
                f"Model {model_name} has empty description"
            )
            assert len(description) > 10, (
                f"Model {model_name} has very short description: {description}"
            )

    def test_list_oscal_models_description_content(self):
        """Test that descriptions contain meaningful content."""
        result = list_oscal_models()

        # Check that descriptions contain relevant keywords
        expected_keywords = {
            OSCALModelType.CATALOG: ["controls", "control"],
            OSCALModelType.PROFILE: ["baseline", "selects", "controls"],
            OSCALModelType.COMPONENT_DEFINITION: [
                "components",
                "implement",
                "controls",
            ],
            OSCALModelType.SYSTEM_SECURITY_PLAN: ["system", "implements", "controls"],
            OSCALModelType.ASSESSMENT_PLAN: ["controls", "assessed"],
            OSCALModelType.ASSESSMENT_RESULTS: ["results", "assessments"],
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: ["remediation", "plans"],
            OSCALModelType.MAPPING: ["collection", "controls", "relates"],
        }

        for model_name, keywords in expected_keywords.items():
            description = result[model_name]["description"].lower()
            found_keywords = [kw for kw in keywords if kw in description]
            assert found_keywords, (
                f"Model {model_name} description should contain at least one of {keywords}"
            )

    def test_list_oscal_models_count(self):
        """Test that the expected number of models are returned."""
        result = list_oscal_models()

        # Should match the number of enum values
        expected_count = len(OSCALModelType)
        actual_count = len(result)

        assert actual_count == expected_count, (
            f"Expected {expected_count} models, got {actual_count}"
        )
