# OSCAL Schemas Directory

This directory contains OSCAL (Open Security Controls Assessment Language) schema files that define the structure and validation rules for OSCAL documents. These schemas are used by the MCP server to provide accurate schema information and validation capabilities for OSCAL models.

## Contents

This directory contains schema files for the following OSCAL model types:

### Core OSCAL Models

- **`oscal_catalog_schema.*`** - Catalog model schemas
  - Defines the structure for security control catalogs (e.g., NIST SP 800-53)
  - Contains control definitions, parameters, and guidance

- **`oscal_profile_schema.*`** - Profile model schemas  
  - Defines tailored sets of controls selected from catalogs
  - Includes control customizations and parameter settings

- **`oscal_component_schema.*`** - Component Definition model schemas
  - Defines system components and their implemented controls
  - Maps controls to specific technical implementations

- **`oscal_ssp_schema.*`** - System Security Plan (SSP) model schemas
  - Defines complete system security documentation
  - Links system components to control implementations

### Assessment Models

- **`oscal_assessment-plan_schema.*`** - Assessment Plan model schemas
  - Defines security assessment planning and methodology
  - Specifies assessment objectives and procedures

- **`oscal_assessment-results_schema.*`** - Assessment Results model schemas
  - Defines security assessment findings and results
  - Contains compliance status and evidence

- **`oscal_poam_schema.*`** - Plan of Action and Milestones (POA&M) model schemas
  - Defines remediation tracking for security findings
  - Contains timelines and responsible parties for fixes

### Comprehensive Schema

- **`oscal_complete_schema.*`** - Complete OSCAL schema
  - Unified schema containing all OSCAL model definitions
  - Useful for tools that work with multiple OSCAL model types

## File Formats

Each OSCAL model is provided in two schema formats:

- **`.json`** - JSON Schema files (JSON Schema Draft 7)
  - Used for validating OSCAL documents in JSON format
  - Provides programmatic validation capabilities

- **`.xsd`** - XML Schema Definition files  
  - Used for validating OSCAL documents in XML format
  - Provides XML-specific validation and tooling support

## How Schema Files Are Populated

The schema files in this directory are automatically downloaded and updated using the `bin/update-oscal-schemas.sh` script:

1. **Source**: Schemas are downloaded from the official NIST OSCAL GitHub repository
2. **Version**: OSCAL version 1.2.0 as of the last update to this README. Determined by value of variable `CURRENT_RELEASE_VERSION` in the script. 
3. **Update Process**: 
   ```bash
   # Run from project root
   ./bin/update-oscal-schemas.sh
   ```
4. **Automation**: The script downloads the official OSCAL release package and extracts only the schema files (.json and .xsd)

## Usage in MCP Server

These schemas are used by the MCP server in several ways:

### Schema Validation
- Validate OSCAL documents against their corresponding schemas
- Ensure document structure compliance with OSCAL standards
- Provide validation feedback for malformed documents

### Tool Support  
- Enable IDE integration with schema-aware editing
- Support auto-completion and validation in development tools
- Provide accurate type information for OSCAL models

### Model Information
- Serve schema definitions through MCP tools like `get_schema`
- List available OSCAL model types via `list_models`  
- Support documentation queries about OSCAL structure

### API Integration
- Validate API requests and responses against OSCAL schemas
- Ensure data consistency across OSCAL-based workflows
- Support programmatic document generation and manipulation

## Updating Schemas

To update to a newer version of OSCAL schemas:

1. **Edit the update script**: Modify `CURRENT_RELEASE_VERSION` in `bin/update-oscal-schemas.sh` to point to the desired OSCAL version
2. **Run the update**: Execute `./bin/update-oscal-schemas.sh` from the project root
3. **Test compatibility**: Verify that existing functionality works with the new schemas
4. **Update documentation**: Update version references in code and documentation as needed

## Related Documentation

- [OSCAL Official Website](https://pages.nist.gov/OSCAL/)
- [OSCAL GitHub Repository](https://github.com/usnistgov/OSCAL)
- [OSCAL Model Documentation](https://pages.nist.gov/OSCAL/concepts/layer/)
- [OSCAL Schema Documentation](https://pages.nist.gov/OSCAL/concepts/validation/)
