---
inclusion: always
---

# Compliance-Trestle Integration Guidelines

## Overview

This project leverages the `compliance-trestle` library (imported as `trestle`) for OSCAL processing. Always prefer trestle's built-in capabilities over custom implementations.

## Core Trestle Capabilities to Use

### 1. OSCAL Pydantic Models
- Use `trestle.oscal.*` models for all OSCAL data structures
- Available models include: `catalog`, `profile`, `component`, `ssp`, `assessment_plan`, `assessment_results`, `poam`
- These models provide type safety, validation, and IDE support

### 2. OSCAL Validation
- Trestle models automatically validate OSCAL structure on instantiation
- Use model validation instead of writing custom validation logic

### 3. JSON Serialization/Deserialization
- Use trestle's built-in methods for reading/writing OSCAL JSON files
- Models support `.json()` for serialization and `.parse_obj()` for deserialization
- Trestle handles OSCAL-specific formatting requirements

### 4. File I/O Operations
- Use `trestle.common.file_utils` for OSCAL file operations
- Use `trestle.common.load_validate` for loading and validating OSCAL files

## Implementation Workflow

1. **Before writing OSCAL code**: Search trestle's API for existing functionality
2. **Check these modules first**:
   - `trestle.oscal.*` - OSCAL model definitions
   - `trestle.common.*` - Common utilities and helpers
   - `trestle.core.*` - Core processing functions
3. **If trestle lacks needed functionality**:
   - Document what you searched for
   - Explain why trestle's existing capabilities don't fit
   - Proceed with custom implementation
4. **When uncertain**: Ask for clarification about trestle usage before implementing

## Anti-Patterns to Avoid

- Don't manually parse OSCAL JSON - use trestle models
- Don't write custom OSCAL validation - use model validation
- Don't create custom OSCAL type definitions - use trestle.oscal models
- Don't implement OSCAL file I/O from scratch - use trestle utilities

## Example Usage Patterns

```python
# Good: Using trestle models
from trestle.oscal import component

comp_def = component.ComponentDefinition.parse_file('component.json')

# Good: Using trestle validation
try:
    comp = component.Component(**data)
except ValidationError as e:
    # Handle validation errors
    pass

# Good: Using trestle serialization
json_str = comp_def.json(exclude_none=True, by_alias=True, indent=2)
```