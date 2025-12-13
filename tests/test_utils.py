"""
Tests for the utils module.
"""

from mcp_server_for_oscal.tools.utils import OSCALModelType


class TestOSCALModelType:
    """Test cases for the OSCALModelType enum."""

    def test_oscal_model_type_is_str_enum(self):
        """Test that OSCALModelType is a string enum."""
        # Test that enum values are strings
        for model_type in OSCALModelType:
            assert isinstance(model_type.value, str)
            assert isinstance(model_type, str)

    def test_oscal_model_type_values(self):
        """Test that all expected OSCAL model types are defined."""
        expected_values = {
            "catalog",
            "profile",
            "component-definition",
            "system-security-plan",
            "assessment-plan",
            "assessment-results",
            "plan-of-action-and-milestones",
            "mapping-collection"
        }

        actual_values = {model_type.value for model_type in OSCALModelType}
        assert actual_values == expected_values

    def test_oscal_model_type_catalog(self):
        """Test the CATALOG model type."""
        assert OSCALModelType.CATALOG == "catalog"
        assert OSCALModelType.CATALOG.value == "catalog"

    def test_oscal_model_type_profile(self):
        """Test the PROFILE model type."""
        assert OSCALModelType.PROFILE == "profile"
        assert OSCALModelType.PROFILE.value == "profile"

    def test_oscal_model_type_component_definition(self):
        """Test the COMPONENT_DEFINITION model type."""
        assert OSCALModelType.COMPONENT_DEFINITION == "component-definition"
        assert OSCALModelType.COMPONENT_DEFINITION.value == "component-definition"

    def test_oscal_model_type_system_security_plan(self):
        """Test the SYSTEM_SECURITY_PLAN model type."""
        assert OSCALModelType.SYSTEM_SECURITY_PLAN == "system-security-plan"
        assert OSCALModelType.SYSTEM_SECURITY_PLAN.value == "system-security-plan"

    def test_oscal_model_type_assessment_plan(self):
        """Test the ASSESSMENT_PLAN model type."""
        assert OSCALModelType.ASSESSMENT_PLAN == "assessment-plan"
        assert OSCALModelType.ASSESSMENT_PLAN.value == "assessment-plan"

    def test_oscal_model_type_assessment_results(self):
        """Test the ASSESSMENT_RESULTS model type."""
        assert OSCALModelType.ASSESSMENT_RESULTS == "assessment-results"
        assert OSCALModelType.ASSESSMENT_RESULTS.value == "assessment-results"

    def test_oscal_model_type_plan_of_action_and_milestones(self):
        """Test the PLAN_OF_ACTION_AND_MILESTONES model type."""
        assert OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES == "plan-of-action-and-milestones"
        assert OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES.value == "plan-of-action-and-milestones"

    def test_oscal_model_type_mapping(self):
        """Test the MAPPING model type."""
        assert OSCALModelType.MAPPING == "mapping-collection"
        assert OSCALModelType.MAPPING.value == "mapping-collection"

    def test_oscal_model_type_iteration(self):
        """Test that we can iterate over all model types."""
        model_types = list(OSCALModelType)
        assert len(model_types) == 8  # Update if more model types are added

        # Verify all expected types are present
        expected_types = [
            OSCALModelType.CATALOG,
            OSCALModelType.PROFILE,
            OSCALModelType.COMPONENT_DEFINITION,
            OSCALModelType.SYSTEM_SECURITY_PLAN,
            OSCALModelType.ASSESSMENT_PLAN,
            OSCALModelType.ASSESSMENT_RESULTS,
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
            OSCALModelType.MAPPING
        ]

        for expected_type in expected_types:
            assert expected_type in model_types

    def test_oscal_model_type_membership(self):
        """Test membership testing with the enum."""
        # Test valid values
        assert "catalog" in OSCALModelType.__members__.values()
        assert "profile" in OSCALModelType.__members__.values()
        assert "component-definition" in OSCALModelType.__members__.values()

        # Test invalid values
        assert "invalid-model" not in OSCALModelType.__members__.values()
        assert "unknown" not in OSCALModelType.__members__.values()

    def test_oscal_model_type_string_comparison(self):
        """Test that enum values can be compared with strings."""
        assert OSCALModelType.CATALOG == "catalog"
        assert OSCALModelType.PROFILE == "profile"
        assert OSCALModelType.COMPONENT_DEFINITION == "component-definition"

        # Test inequality
        assert OSCALModelType.CATALOG != "profile"
        assert OSCALModelType.CATALOG != "invalid"

    def test_oscal_model_type_case_sensitivity(self):
        """Test that enum values are case sensitive."""
        assert OSCALModelType.CATALOG != "CATALOG"
        assert OSCALModelType.CATALOG != "Catalog"
        assert OSCALModelType.PROFILE != "PROFILE"

    def test_oscal_model_type_hyphenation(self):
        """Test that multi-word model types use hyphens."""
        multi_word_types = [
            OSCALModelType.COMPONENT_DEFINITION,
            OSCALModelType.SYSTEM_SECURITY_PLAN,
            OSCALModelType.ASSESSMENT_PLAN,
            OSCALModelType.ASSESSMENT_RESULTS,
            OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES,
            OSCALModelType.MAPPING
        ]

        for model_type in multi_word_types:
            assert "-" in model_type.value, f"Multi-word type {model_type} should contain hyphens"

    def test_oscal_model_type_no_spaces(self):
        """Test that no model type values contain spaces."""
        for model_type in OSCALModelType:
            assert " " not in model_type.value, f"Model type {model_type} should not contain spaces"

    def test_oscal_model_type_lowercase(self):
        """Test that all model type values are lowercase."""
        for model_type in OSCALModelType:
            assert model_type.value.islower(), f"Model type {model_type} should be lowercase"

    def test_oscal_model_type_unique_values(self):
        """Test that all model type values are unique."""
        values = [model_type.value for model_type in OSCALModelType]
        unique_values = set(values)
        assert len(values) == len(unique_values), "All model type values should be unique"

    def test_oscal_model_type_repr(self):
        """Test the string representation of enum values."""
        # Test that the enum can be converted to string
        catalog_str = str(OSCALModelType.CATALOG)
        assert catalog_str == "catalog"

        profile_str = str(OSCALModelType.PROFILE)
        assert profile_str == "profile"

    def test_oscal_model_type_in_collections(self):
        """Test that enum values work properly in collections."""
        # Test in list
        model_list = [OSCALModelType.CATALOG, OSCALModelType.PROFILE]
        assert OSCALModelType.CATALOG in model_list
        assert OSCALModelType.COMPONENT_DEFINITION not in model_list

        # Test in set
        model_set = {OSCALModelType.CATALOG, OSCALModelType.PROFILE}
        assert OSCALModelType.CATALOG in model_set
        assert OSCALModelType.COMPONENT_DEFINITION not in model_set

        # Test in dict keys
        model_dict = {OSCALModelType.CATALOG: "catalog_data"}
        assert OSCALModelType.CATALOG in model_dict
        assert model_dict[OSCALModelType.CATALOG] == "catalog_data"

    def test_oscal_model_type_sorting(self):
        """Test that enum values can be sorted."""
        model_types = list(OSCALModelType)
        sorted_types = sorted(model_types)

        # Should be sorted alphabetically by value
        expected_order = sorted([mt.value for mt in model_types])
        actual_order = [mt.value for mt in sorted_types]

        assert actual_order == expected_order
