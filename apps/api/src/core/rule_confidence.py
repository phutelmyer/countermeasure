"""
Rule confidence scoring implementation.
"""

from typing import List
from src.db.models import Detection


def calculate_rule_confidence_score(detection: Detection) -> float:
    """
    Calculate rule quality score based on multiple factors.

    Args:
        detection: Detection instance

    Returns:
        float: Confidence score between 0.0 and 1.0
    """
    factors = []

    # Completeness (30% weight)
    completeness_fields = [
        detection.description,
        detection.author,
        detection.source_url
    ]
    completeness = sum(1 for field in completeness_fields if field) / len(completeness_fields)
    factors.append(completeness * 0.3)

    # MITRE mapping (25% weight)
    mitre_score = min(1.0, len(detection.mitre_techniques) / 3.0)
    factors.append(mitre_score * 0.25)

    # Categorization (20% weight)
    category_score = min(1.0, len(detection.categories) / 2.0)
    factors.append(category_score * 0.2)

    # Community validation and status (25% weight)
    status_scores = {
        "active": 1.0,
        "testing": 0.7,
        "draft": 0.3,
        "deprecated": 0.1
    }
    validation_score = status_scores.get(detection.status, 0.5)
    factors.append(validation_score * 0.25)

    return min(1.0, sum(factors))


def calculate_rule_content_quality(rule_content: str, rule_format: str) -> float:
    """
    Calculate rule content quality based on format-specific criteria.

    Args:
        rule_content: The rule content string
        rule_format: The rule format (yara, sigma, etc.)

    Returns:
        float: Quality score between 0.0 and 1.0
    """
    if not rule_content or not rule_content.strip():
        return 0.0

    content_length = len(rule_content.strip())

    # Base score from content length
    if content_length < 50:
        length_score = 0.2
    elif content_length < 200:
        length_score = 0.5
    elif content_length < 1000:
        length_score = 0.8
    else:
        length_score = 1.0

    # Format-specific quality checks
    format_score = 0.5  # Default score

    if rule_format.lower() == "yara":
        format_score = _calculate_yara_quality(rule_content)
    elif rule_format.lower() == "sigma":
        format_score = _calculate_sigma_quality(rule_content)
    elif rule_format.lower() in ["suricata", "snort"]:
        format_score = _calculate_network_rule_quality(rule_content)

    return (length_score * 0.4) + (format_score * 0.6)


def _calculate_yara_quality(content: str) -> float:
    """Calculate quality score for YARA rules."""
    score = 0.0

    # Check for rule structure
    if "rule " in content:
        score += 0.3
    if "{" in content and "}" in content:
        score += 0.2
    if "condition:" in content:
        score += 0.3
    if "strings:" in content or "$" in content:
        score += 0.2

    return min(1.0, score)


def _calculate_sigma_quality(content: str) -> float:
    """Calculate quality score for Sigma rules."""
    score = 0.0

    # Check for required Sigma fields
    required_fields = ["title:", "detection:", "condition:"]
    for field in required_fields:
        if field in content.lower():
            score += 0.25

    # Check for optional but valuable fields
    optional_fields = ["author:", "level:", "references:", "tags:"]
    for field in optional_fields:
        if field in content.lower():
            score += 0.0625  # 0.25 / 4

    return min(1.0, score)


def _calculate_network_rule_quality(content: str) -> float:
    """Calculate quality score for network rules (Suricata/Snort)."""
    score = 0.0

    # Check for basic rule structure
    if any(action in content for action in ["alert", "drop", "reject", "pass"]):
        score += 0.3
    if "msg:" in content:
        score += 0.2
    if "sid:" in content:
        score += 0.2
    if "rev:" in content:
        score += 0.1
    if "classtype:" in content:
        score += 0.1
    if "reference:" in content:
        score += 0.1

    return min(1.0, score)


def validate_rule_format(rule_content: str, rule_format: str) -> tuple[bool, List[str]]:
    """
    Validate rule content for format-specific syntax.

    Args:
        rule_content: The rule content string
        rule_format: The rule format

    Returns:
        tuple: (is_valid, list_of_errors)
    """
    errors = []

    if not rule_content or not rule_content.strip():
        errors.append("Rule content cannot be empty")
        return False, errors

    if rule_format.lower() == "yara":
        errors.extend(_validate_yara_syntax(rule_content))
    elif rule_format.lower() == "sigma":
        errors.extend(_validate_sigma_syntax(rule_content))
    elif rule_format.lower() in ["suricata", "snort"]:
        errors.extend(_validate_network_rule_syntax(rule_content))

    return len(errors) == 0, errors


def _validate_yara_syntax(content: str) -> List[str]:
    """Validate YARA rule syntax."""
    errors = []

    if "rule " not in content:
        errors.append("YARA rule must contain 'rule' keyword")

    if not ('{' in content and '}' in content):
        errors.append("YARA rule must have opening and closing braces")

    if "condition:" not in content:
        errors.append("YARA rule must have a condition section")

    return errors


def _validate_sigma_syntax(content: str) -> List[str]:
    """Validate Sigma rule syntax."""
    errors = []

    required_fields = ["title:", "detection:", "condition:"]
    for field in required_fields:
        if field not in content.lower():
            errors.append(f"Sigma rule must contain '{field}' field")

    return errors


def _validate_network_rule_syntax(content: str) -> List[str]:
    """Validate network rule syntax."""
    errors = []

    if not any(action in content for action in ["alert", "drop", "reject", "pass"]):
        errors.append("Network rule must start with an action (alert, drop, reject, pass)")

    if "msg:" not in content:
        errors.append("Network rule should contain 'msg:' field")

    if "sid:" not in content:
        errors.append("Network rule should contain 'sid:' field")

    return errors