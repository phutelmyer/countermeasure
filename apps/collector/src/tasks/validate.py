"""
Validation tasks for Celery.
"""

import asyncio
import re
from typing import Any, Dict, List

import yaml
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.db.session import async_session_maker
from src.schedulers.celery_app import app


logger = get_logger(__name__)


@app.task
def validate_all_rules(
    tenant_id: str = None,
    detection_ids: List[str] = None,
    validation_types: List[str] = None
):
    """
    Celery task to validate all detection rules in the database.

    Args:
        tenant_id: Specific tenant to validate (optional)
        detection_ids: Specific detection IDs to validate (optional)
        validation_types: Types of validation to perform (optional)
    """
    logger.info("Starting rule validation task")

    # Use asyncio to run the async validation function
    result = asyncio.run(_validate_rules_async(tenant_id, detection_ids, validation_types))
    return result


async def _validate_rules_async(
    tenant_id: str = None,
    detection_ids: List[str] = None,
    validation_types: List[str] = None
) -> Dict[str, Any]:
    """
    Async implementation of rule validation.
    """
    try:
        async with async_session_maker() as db:
            # Import here to avoid circular imports
            from src.db.models import Detection

            validated_count = 0
            failed_count = 0
            warnings_count = 0
            validation_results = []

            # Build query for detections to validate
            query = select(Detection)

            if tenant_id:
                query = query.where(Detection.tenant_id == tenant_id)

            if detection_ids:
                query = query.where(Detection.id.in_(detection_ids))

            # Limit to prevent overwhelming the system
            query = query.limit(1000)

            result = await db.execute(query)
            detections = result.scalars().all()

            logger.info(f"Found {len(detections)} detections to validate")

            for detection in detections:
                try:
                    # Perform validation based on rule format
                    validation_result = await _validate_detection(detection, validation_types)

                    # Update detection validation status
                    if validation_result["status"] == "valid":
                        validated_count += 1
                        detection.validation_status = "valid"
                    elif validation_result["status"] == "warning":
                        warnings_count += 1
                        detection.validation_status = "warning"
                    else:
                        failed_count += 1
                        detection.validation_status = "invalid"

                    # Store validation results
                    detection.validation_errors = validation_result.get("errors", [])
                    detection.validation_warnings = validation_result.get("warnings", [])

                    validation_results.append({
                        "detection_id": str(detection.id),
                        "name": detection.name,
                        "status": validation_result["status"],
                        "errors": validation_result.get("errors", []),
                        "warnings": validation_result.get("warnings", [])
                    })

                    await db.commit()

                except Exception as e:
                    logger.error(f"Failed to validate detection {detection.id}: {e}")
                    failed_count += 1
                    await db.rollback()

            logger.info(f"Validation complete: {validated_count} valid, {warnings_count} warnings, {failed_count} invalid")

            return {
                "status": "completed",
                "valid_count": validated_count,
                "warning_count": warnings_count,
                "invalid_count": failed_count,
                "total_processed": len(detections),
                "results": validation_results[:10]  # Limit results for response size
            }

    except Exception as e:
        logger.error(f"Rule validation task failed: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }


async def _validate_detection(detection, validation_types: List[str] = None) -> Dict[str, Any]:
    """Validate a single detection rule."""
    errors = []
    warnings = []

    try:
        # Basic field validation
        if not validation_types or "fields" in validation_types:
            field_errors, field_warnings = _validate_required_fields(detection)
            errors.extend(field_errors)
            warnings.extend(field_warnings)

        # Rule content validation based on format
        if not validation_types or "syntax" in validation_types:
            if detection.rule_format and detection.rule_content:
                if detection.rule_format.lower() == "sigma":
                    syntax_errors, syntax_warnings = _validate_sigma_syntax(detection.rule_content)
                elif detection.rule_format.lower() == "yara":
                    syntax_errors, syntax_warnings = _validate_yara_syntax(detection.rule_content)
                elif detection.rule_format.lower() == "suricata":
                    syntax_errors, syntax_warnings = _validate_suricata_syntax(detection.rule_content)
                else:
                    syntax_errors, syntax_warnings = [], [f"Unknown rule format: {detection.rule_format}"]

                errors.extend(syntax_errors)
                warnings.extend(syntax_warnings)

        # Metadata validation
        if not validation_types or "metadata" in validation_types:
            meta_errors, meta_warnings = _validate_metadata(detection)
            errors.extend(meta_errors)
            warnings.extend(meta_warnings)

        # Performance impact assessment
        if not validation_types or "performance" in validation_types:
            perf_warnings = _assess_performance_impact(detection)
            warnings.extend(perf_warnings)

        # Determine overall status
        if errors:
            status = "invalid"
        elif warnings:
            status = "warning"
        else:
            status = "valid"

        return {
            "status": status,
            "errors": errors,
            "warnings": warnings
        }

    except Exception as e:
        return {
            "status": "invalid",
            "errors": [f"Validation failed: {e}"],
            "warnings": []
        }


def _validate_required_fields(detection) -> tuple[List[str], List[str]]:
    """Validate required fields are present and valid."""
    errors = []
    warnings = []

    # Required fields
    if not detection.name or len(detection.name.strip()) == 0:
        errors.append("Detection name is required")

    if not detection.rule_content or len(detection.rule_content.strip()) == 0:
        errors.append("Rule content is required")

    if not detection.rule_format:
        errors.append("Rule format is required")

    # Recommended fields
    if not detection.description:
        warnings.append("Description is recommended for better documentation")

    if not detection.author:
        warnings.append("Author field is recommended for attribution")

    if not detection.platforms or len(detection.platforms) == 0:
        warnings.append("Platform specification is recommended")

    if not detection.data_sources or len(detection.data_sources) == 0:
        warnings.append("Data source specification is recommended")

    # Field format validation
    if detection.confidence_score is not None:
        if not (0.0 <= detection.confidence_score <= 1.0):
            errors.append("Confidence score must be between 0.0 and 1.0")

    return errors, warnings


def _validate_sigma_syntax(rule_content: str) -> tuple[List[str], List[str]]:
    """Validate SIGMA rule syntax."""
    errors = []
    warnings = []

    try:
        # Parse YAML
        try:
            rule_data = yaml.safe_load(rule_content)
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML syntax: {e}")
            return errors, warnings

        # Check required SIGMA fields
        required_fields = ["title", "detection", "level"]
        for field in required_fields:
            if field not in rule_data:
                errors.append(f"Missing required SIGMA field: {field}")

        # Check detection structure
        if "detection" in rule_data:
            detection = rule_data["detection"]
            if not isinstance(detection, dict):
                errors.append("Detection field must be a dictionary")
            else:
                if "condition" not in detection:
                    errors.append("Detection must have a condition field")

                # Check for at least one selection
                has_selection = any(key.startswith("selection") for key in detection.keys())
                if not has_selection:
                    warnings.append("Detection should have at least one selection")

        # Check level field
        if "level" in rule_data:
            valid_levels = ["info", "low", "medium", "high", "critical"]
            if rule_data["level"] not in valid_levels:
                errors.append(f"Invalid level. Must be one of: {', '.join(valid_levels)}")

        # Check for recommended fields
        recommended_fields = ["description", "author", "logsource"]
        for field in recommended_fields:
            if field not in rule_data:
                warnings.append(f"Recommended SIGMA field missing: {field}")

        # Validate logsource
        if "logsource" in rule_data:
            logsource = rule_data["logsource"]
            if isinstance(logsource, dict):
                if not any(key in logsource for key in ["product", "service", "category"]):
                    warnings.append("Logsource should specify product, service, or category")

    except Exception as e:
        errors.append(f"SIGMA validation error: {e}")

    return errors, warnings


def _validate_yara_syntax(rule_content: str) -> tuple[List[str], List[str]]:
    """Validate YARA rule syntax (basic)."""
    errors = []
    warnings = []

    try:
        # Basic YARA syntax checks
        if not rule_content.strip().startswith("rule "):
            errors.append("YARA rule must start with 'rule' keyword")

        # Check for rule name
        rule_match = re.search(r"rule\s+(\w+)", rule_content)
        if not rule_match:
            errors.append("YARA rule must have a valid rule name")

        # Check for required sections
        if "{" not in rule_content or "}" not in rule_content:
            errors.append("YARA rule must have opening and closing braces")

        # Check for strings or condition section
        has_strings = "strings:" in rule_content
        has_condition = "condition:" in rule_content

        if not has_condition:
            errors.append("YARA rule must have a condition section")

        if has_strings:
            # Validate string definitions
            string_matches = re.findall(r'\$\w+\s*=', rule_content)
            if not string_matches:
                warnings.append("Strings section declared but no strings defined")

        # Check for basic syntax errors
        brace_count = rule_content.count("{") - rule_content.count("}")
        if brace_count != 0:
            errors.append("Mismatched braces in YARA rule")

    except Exception as e:
        errors.append(f"YARA validation error: {e}")

    return errors, warnings


def _validate_suricata_syntax(rule_content: str) -> tuple[List[str], List[str]]:
    """Validate Suricata rule syntax (basic)."""
    errors = []
    warnings = []

    try:
        # Basic Suricata rule format: action protocol src_ip src_port -> dst_ip dst_port (options)
        rule_pattern = r'^(alert|drop|reject|pass)\s+\w+\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s+\('

        if not re.match(rule_pattern, rule_content.strip()):
            errors.append("Invalid Suricata rule format")

        # Check for required components
        if not rule_content.strip().startswith(("alert", "drop", "reject", "pass")):
            errors.append("Suricata rule must start with valid action (alert, drop, reject, pass)")

        if "->" not in rule_content:
            errors.append("Suricata rule must contain direction indicator (->) ")

        if not (rule_content.count("(") == rule_content.count(")")):
            errors.append("Mismatched parentheses in Suricata rule")

        # Check for recommended options
        if "msg:" not in rule_content:
            warnings.append("Suricata rule should have a msg option")

        if "sid:" not in rule_content:
            errors.append("Suricata rule must have a sid option")

        if "rev:" not in rule_content:
            warnings.append("Suricata rule should have a rev option")

    except Exception as e:
        errors.append(f"Suricata validation error: {e}")

    return errors, warnings


def _validate_metadata(detection) -> tuple[List[str], List[str]]:
    """Validate detection metadata."""
    errors = []
    warnings = []

    # Validate MITRE technique IDs format
    if detection.mitre_technique_ids:
        for technique_id in detection.mitre_technique_ids:
            if not re.match(r'^T\d{4}(\.\d{3})?$', technique_id):
                warnings.append(f"Invalid MITRE technique ID format: {technique_id}")

    # Validate platforms
    if detection.platforms:
        valid_platforms = ["Windows", "Linux", "macOS", "Unix", "Android", "iOS"]
        for platform in detection.platforms:
            if platform not in valid_platforms:
                warnings.append(f"Non-standard platform: {platform}")

    # Validate data sources
    if detection.data_sources:
        common_sources = [
            "Process Creation", "Network Connection", "File Monitoring",
            "Windows Registry", "DNS", "HTTP", "Image Load", "WMI"
        ]
        for source in detection.data_sources:
            if source not in common_sources:
                warnings.append(f"Non-standard data source: {source}")

    return errors, warnings


def _assess_performance_impact(detection) -> List[str]:
    """Assess potential performance impact of the detection rule."""
    warnings = []

    if not detection.rule_content:
        return warnings

    rule_content = detection.rule_content.lower()

    # Check for potentially expensive operations
    expensive_patterns = [
        ("regex", "Regular expressions can be expensive"),
        ("contains.*contains", "Multiple contains operations may impact performance"),
        (".*.*", "Wildcard patterns can be expensive"),
        ("all of", "Universal quantifiers may impact performance"),
    ]

    for pattern, warning in expensive_patterns:
        if pattern in rule_content:
            warnings.append(warning)

    # Check rule complexity
    line_count = len(detection.rule_content.split("\n"))
    if line_count > 100:
        warnings.append("Very long rule may impact performance")

    # Check for broad matching criteria
    if detection.rule_format and detection.rule_format.lower() == "sigma":
        if "selection:" in rule_content and "all" in rule_content:
            warnings.append("Broad selection criteria may generate false positives")

    return warnings


@app.task
def validate_sigma_rule(rule_content: str, rule_name: str = "Anonymous Rule"):
    """
    Celery task to validate a single SIGMA rule.

    Args:
        rule_content: SIGMA rule YAML content
        rule_name: Name for the rule (for logging)
    """
    logger.info(f"Starting SIGMA rule validation for: {rule_name}")

    try:
        # Validate SIGMA syntax
        errors, warnings = _validate_sigma_syntax(rule_content)

        # Assess performance impact
        performance_warnings = []
        if rule_content:
            rule_lower = rule_content.lower()
            if ".*" in rule_lower:
                performance_warnings.append("Wildcard patterns can be expensive")
            if rule_lower.count("contains") > 3:
                performance_warnings.append("Multiple contains operations may impact performance")
            if len(rule_content.split("\n")) > 50:
                performance_warnings.append("Long rule may impact performance")

        warnings.extend(performance_warnings)

        # Determine overall status
        if errors:
            status = "invalid"
        elif warnings:
            status = "warning"
        else:
            status = "valid"

        return {
            "status": status,
            "rule_name": rule_name,
            "errors": errors,
            "warnings": warnings,
            "error_count": len(errors),
            "warning_count": len(warnings)
        }

    except Exception as e:
        logger.error(f"SIGMA rule validation failed for {rule_name}: {e}")
        return {
            "status": "failed",
            "rule_name": rule_name,
            "errors": [f"Validation failed: {e}"],
            "warnings": [],
            "error_count": 1,
            "warning_count": 0
        }
