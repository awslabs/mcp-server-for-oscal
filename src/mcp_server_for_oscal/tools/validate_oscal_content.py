"""
Tool for validating OSCAL content through a multi-level validation pipeline.
"""

import importlib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp.server import Context
from strands import tool

from mcp_server_for_oscal.tools.utils import (
    OSCALModelType,
    ROOT_KEY_TO_MODEL_TYPE,
    load_oscal_json_schema,
    try_notify_client_error,
)

logger = logging.getLogger(__name__)

MAX_ERRORS_PER_LEVEL = 20

# Maps OSCALModelType to (trestle module, class name) for Level 3 validation.
_TRESTLE_MODEL_MAP: dict[OSCALModelType, tuple[str, str]] = {
    OSCALModelType.CATALOG: ("trestle.oscal.catalog", "Catalog"),
    OSCALModelType.PROFILE: ("trestle.oscal.profile", "Profile"),
    OSCALModelType.COMPONENT_DEFINITION: ("trestle.oscal.component", "ComponentDefinition"),
    OSCALModelType.SYSTEM_SECURITY_PLAN: ("trestle.oscal.ssp", "SystemSecurityPlan"),
    OSCALModelType.ASSESSMENT_PLAN: ("trestle.oscal.assessment_plan", "AssessmentPlan"),
    OSCALModelType.ASSESSMENT_RESULTS: ("trestle.oscal.assessment_results", "AssessmentResults"),
    OSCALModelType.PLAN_OF_ACTION_AND_MILESTONES: ("trestle.oscal.poam", "PlanOfActionAndMilestones"),
    # mapping-collection has no trestle model
}


def _make_level(
    level: str,
    valid: bool = True,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    skipped: bool = False,
    skip_reason: str | None = None,
) -> dict[str, Any]:
    """Create a validation level result dict."""
    return {
        "level": level,
        "valid": valid,
        "errors": errors or [],
        "warnings": warnings or [],
        "skipped": skipped,
        "skip_reason": skip_reason,
    }


def _detect_model_type(data: dict) -> OSCALModelType | None:
    """Detect the OSCAL model type from a parsed JSON document's root keys."""
    for key in data:
        if key == "$schema":
            continue
        if key in ROOT_KEY_TO_MODEL_TYPE:
            return ROOT_KEY_TO_MODEL_TYPE[key]
    return None


def _validate_well_formedness(content: str) -> tuple[dict, dict | None]:
    """Level 1: Check that content is valid JSON and a dict.

    Returns:
        (level_result, parsed_data_or_None)
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError) as exc:
        return _make_level("well_formedness", valid=False, errors=[str(exc)]), None

    if not isinstance(data, dict):
        return _make_level(
            "well_formedness",
            valid=False,
            errors=[f"Expected a JSON object at root, got {type(data).__name__}"],
        ), None

    return _make_level("well_formedness"), data


def _validate_json_schema(data: dict, model_type: OSCALModelType) -> dict:
    """Level 2: Validate against the bundled NIST OSCAL JSON schema."""
    import jsonschema

    try:
        schema = load_oscal_json_schema(model_type)
    except Exception as exc:
        return _make_level(
            "json_schema",
            valid=False,
            errors=[f"Failed to load schema for {model_type}: {exc}"],
        )

    validator = jsonschema.Draft7Validator(schema)
    raw_errors = list(validator.iter_errors(data))

    if not raw_errors:
        return _make_level("json_schema")

    errors = [e.message for e in raw_errors[:MAX_ERRORS_PER_LEVEL]]
    warnings = []
    if len(raw_errors) > MAX_ERRORS_PER_LEVEL:
        warnings.append(
            f"Showing {MAX_ERRORS_PER_LEVEL} of {len(raw_errors)} errors"
        )

    return _make_level("json_schema", valid=False, errors=errors, warnings=warnings)


def _validate_trestle(data: dict, model_type: OSCALModelType) -> dict:
    """Level 3: Semantic validation using trestle Pydantic models."""
    mapping = _TRESTLE_MODEL_MAP.get(model_type)
    if mapping is None:
        return _make_level(
            "trestle",
            skipped=True,
            skip_reason=f"trestle does not support model type '{model_type}'",
        )

    module_path, class_name = mapping

    try:
        mod = importlib.import_module(module_path)
        model_cls = getattr(mod, class_name)
    except Exception as exc:
        return _make_level(
            "trestle",
            valid=False,
            errors=[f"Failed to load trestle model: {exc}"],
        )

    # The OSCAL doc has a root key wrapping the actual model data
    inner = data.get(model_type.value, data)

    try:
        model_cls(**inner)
    except Exception as exc:
        error_str = str(exc)
        # Pydantic ValidationError can be very long; truncate per-error lines
        error_lines = error_str.split("\n")
        errors = error_lines[:MAX_ERRORS_PER_LEVEL]
        warnings = []
        if len(error_lines) > MAX_ERRORS_PER_LEVEL:
            warnings.append(
                f"Showing {MAX_ERRORS_PER_LEVEL} of {len(error_lines)} error lines"
            )
        return _make_level("trestle", valid=False, errors=errors, warnings=warnings)

    return _make_level("trestle")


def _validate_oscal_cli(content: str, model_type: OSCALModelType) -> dict:
    """Level 4: Full NIST validation via oscal-cli if available."""
    oscal_cli = shutil.which("oscal-cli")
    if oscal_cli is None:
        return _make_level(
            "oscal_cli",
            skipped=True,
            skip_reason="oscal-cli not found in PATH",
        )

    tmp_file = None
    try:
        tmp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        tmp_file.write(content)
        tmp_file.close()

        result = subprocess.run(
            [oscal_cli, "validate", tmp_file.name],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            return _make_level("oscal_cli")

        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        output = stderr or stdout or "Validation failed with no output"
        error_lines = output.split("\n")
        errors = error_lines[:MAX_ERRORS_PER_LEVEL]
        warnings = []
        if len(error_lines) > MAX_ERRORS_PER_LEVEL:
            warnings.append(
                f"Showing {MAX_ERRORS_PER_LEVEL} of {len(error_lines)} error lines"
            )
        return _make_level("oscal_cli", valid=False, errors=errors, warnings=warnings)

    except subprocess.TimeoutExpired:
        return _make_level(
            "oscal_cli",
            valid=False,
            errors=["oscal-cli validation timed out after 60 seconds"],
        )
    except Exception as exc:
        return _make_level(
            "oscal_cli",
            valid=False,
            errors=[f"oscal-cli execution error: {exc}"],
        )
    finally:
        if tmp_file is not None:
            Path(tmp_file.name).unlink(missing_ok=True)


@tool
def validate_oscal_content(
    ctx: Context,
    content: str,
    model_type: str | None = None,
) -> dict:
    """
    Validate OSCAL JSON content through a multi-level validation pipeline.

    Runs up to four validation levels in sequence:
      1. Well-formedness - Is it valid JSON and a JSON object?
      2. JSON Schema - Does it conform to the NIST OSCAL JSON schema?
      3. Trestle - Semantic checks via compliance-trestle Pydantic models
      4. oscal-cli - Full NIST validation if oscal-cli is installed

    If Level 1 fails, Levels 2-4 are skipped. If oscal-cli is not installed,
    Level 4 is gracefully skipped. The overall result is valid only when all
    non-skipped levels pass.

    Args:
        ctx: MCP server context (injected automatically by MCP server)
        content: OSCAL JSON content as a string
        model_type: Optional OSCAL model type (e.g. "catalog", "profile").
            If omitted, the model type is auto-detected from the root key.

    Returns:
        dict: Structured validation results with per-level detail
    """
    logger.debug("validate_oscal_content(model_type=%s, content_length=%d)", model_type, len(content))

    levels: list[dict] = []

    # -- Level 1: Well-formedness --
    wf_result, parsed = _validate_well_formedness(content)
    levels.append(wf_result)

    if parsed is None:
        # JSON is not parseable; skip remaining levels
        for lvl in ("json_schema", "trestle", "oscal_cli"):
            levels.append(
                _make_level(lvl, skipped=True, skip_reason="Skipped due to well-formedness failure")
            )
        return {"valid": False, "model_type": model_type, "levels": levels}

    # -- Detect or validate model type --
    detected = _detect_model_type(parsed)

    if model_type is not None:
        # Validate provided model_type
        try:
            resolved_type = OSCALModelType(model_type)
        except ValueError:
            msg = f"Invalid model_type: '{model_type}'. Use list_oscal_models to see valid types."
            try_notify_client_error(msg, ctx)
            return {"valid": False, "model_type": model_type, "levels": levels, "error": msg}
    elif detected is not None:
        resolved_type = detected
    else:
        root_keys = [k for k in parsed if k != "$schema"]
        msg = f"Cannot detect OSCAL model type from root keys: {root_keys}"
        try_notify_client_error(msg, ctx)
        return {"valid": False, "model_type": None, "levels": levels, "error": msg}

    model_type_str = resolved_type.value

    # -- Level 2: JSON Schema --
    levels.append(_validate_json_schema(parsed, resolved_type))

    # -- Level 3: Trestle --
    levels.append(_validate_trestle(parsed, resolved_type))

    # -- Level 4: oscal-cli --
    levels.append(_validate_oscal_cli(content, resolved_type))

    # -- Overall validity --
    overall_valid = all(
        lvl["valid"] for lvl in levels if not lvl["skipped"]
    )

    return {"valid": overall_valid, "model_type": model_type_str, "levels": levels}
