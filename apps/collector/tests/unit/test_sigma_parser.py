"""
Unit tests for SIGMA parser functionality.
"""

import pytest
from unittest.mock import patch, Mock
from pathlib import Path

from src.collectors.detection.sigma_parser import SigmaParser
from src.schemas.detection import DetectionCreate


class SigmaParsingError(Exception):
    """Mock SIGMA parsing error for testing."""
    pass


class TestSigmaParser:
    """Test suite for SIGMA parser."""

    @pytest.fixture
    def parser(self):
        """Create a SigmaParser instance."""
        return SigmaParser()

    @pytest.fixture
    def sample_sigma_rule(self):
        """Sample SIGMA rule content."""
        return """
title: Test SIGMA Rule
id: 12345678-1234-5678-9012-123456789012
description: A test rule for unit testing
author: Test Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\\test.exe'
    condition: selection
falsepositives:
    - Test scenarios
level: medium
tags:
    - attack.execution
    - attack.t1059
"""

    @pytest.fixture
    def invalid_sigma_rule(self):
        """Invalid SIGMA rule content."""
        return """
title: Invalid Rule
# Missing required fields
detection:
    condition: selection
"""

    def test_parse_rule_success(self, parser, sample_sigma_rule):
        """Test successful SIGMA rule parsing."""
        result = parser.parse_rule(sample_sigma_rule, "test_rule.yml")

        assert isinstance(result, DetectionCreate)
        assert result.name == "Test SIGMA Rule"
        assert result.description == "A test rule for unit testing"
        assert result.author == "Test Author"
        assert result.rule_format == "sigma"
        assert result.rule_content == sample_sigma_rule.strip()
        assert "Windows" in result.platforms
        assert "Process Creation" in result.data_sources
        assert "Test scenarios" in result.false_positives

    def test_parse_rule_invalid_yaml(self, parser):
        """Test parsing invalid YAML content."""
        invalid_yaml = "title: Test\ninvalid: yaml: content: here"

        with pytest.raises(SigmaParsingError, match="Invalid YAML format"):
            parser.parse_rule(invalid_yaml, "invalid.yml")

    def test_parse_rule_missing_required_fields(self, parser, invalid_sigma_rule):
        """Test parsing rule missing required fields."""
        with pytest.raises(SigmaParsingError, match="Missing required field"):
            parser.parse_rule(invalid_sigma_rule, "invalid.yml")

    def test_extract_platforms_windows(self, parser):
        """Test platform extraction for Windows."""
        rule_data = {
            "logsource": {"product": "windows"},
            "tags": ["attack.execution"]
        }

        platforms = parser._extract_platforms(rule_data)
        assert "Windows" in platforms

    def test_extract_platforms_linux(self, parser):
        """Test platform extraction for Linux."""
        rule_data = {
            "logsource": {"product": "linux"},
            "tags": []
        }

        platforms = parser._extract_platforms(rule_data)
        assert "Linux" in platforms

    def test_extract_platforms_from_tags(self, parser):
        """Test platform extraction from tags."""
        rule_data = {
            "logsource": {"product": "unknown"},
            "tags": ["linux", "attack.execution"]
        }

        platforms = parser._extract_platforms(rule_data)
        assert "Linux" in platforms

    def test_extract_platforms_from_file_path(self, parser):
        """Test platform extraction from file path."""
        rule_data = {
            "logsource": {"product": "unknown"},
            "tags": []
        }

        platforms = parser._extract_platforms(rule_data, "/rules/windows/test.yml")
        assert "Windows" in platforms

    def test_extract_data_sources_process_creation(self, parser):
        """Test data source extraction for process creation."""
        rule_data = {
            "logsource": {"category": "process_creation"}
        }

        data_sources = parser._extract_data_sources(rule_data)
        assert "Process Creation" in data_sources

    def test_extract_data_sources_network(self, parser):
        """Test data source extraction for network connections."""
        rule_data = {
            "logsource": {"category": "network_connection"}
        }

        data_sources = parser._extract_data_sources(rule_data)
        assert "Network Connection" in data_sources

    def test_extract_data_sources_file_event(self, parser):
        """Test data source extraction for file events."""
        rule_data = {
            "logsource": {"category": "file_event"}
        }

        data_sources = parser._extract_data_sources(rule_data)
        assert "File Monitoring" in data_sources

    def test_extract_data_sources_unknown_category(self, parser):
        """Test data source extraction for unknown category."""
        rule_data = {
            "logsource": {"category": "unknown_category"}
        }

        data_sources = parser._extract_data_sources(rule_data)
        assert "Process Monitoring" in data_sources  # Default fallback

    def test_format_log_sources(self, parser):
        """Test log source formatting."""
        rule_data = {
            "logsource": {
                "product": "windows",
                "category": "process_creation",
                "service": "sysmon"
            }
        }

        log_sources = parser._format_log_sources(rule_data)
        expected = "product:windows | category:process_creation | service:sysmon"
        assert log_sources == expected

    def test_format_log_sources_minimal(self, parser):
        """Test log source formatting with minimal data."""
        rule_data = {
            "logsource": {
                "category": "process_creation"
            }
        }

        log_sources = parser._format_log_sources(rule_data)
        expected = "category:process_creation"
        assert log_sources == expected

    def test_validate_rule_data_success(self, parser):
        """Test successful rule validation."""
        rule_data = {
            "title": "Test Rule",
            "description": "Test description",
            "detection": {"condition": "selection"}
        }

        # Should not raise exception
        parser._validate_rule_data(rule_data)

    def test_validate_rule_data_missing_title(self, parser):
        """Test validation with missing title."""
        rule_data = {
            "description": "Test description",
            "detection": {"condition": "selection"}
        }

        with pytest.raises(SigmaParsingError, match="Missing required field: title"):
            parser._validate_rule_data(rule_data)

    def test_validate_rule_data_missing_detection(self, parser):
        """Test validation with missing detection."""
        rule_data = {
            "title": "Test Rule",
            "description": "Test description"
        }

        with pytest.raises(SigmaParsingError, match="Missing required field: detection"):
            parser._validate_rule_data(rule_data)

    @patch('yaml.safe_load')
    def test_parse_rule_yaml_error(self, mock_yaml_load, parser):
        """Test YAML parsing error handling."""
        mock_yaml_load.side_effect = Exception("YAML error")

        with pytest.raises(SigmaParsingError, match="Invalid YAML format"):
            parser.parse_rule("invalid yaml", "test.yml")

    def test_extract_false_positives(self, parser):
        """Test false positive extraction."""
        rule_data = {
            "falsepositives": [
                "Legitimate admin tools",
                "Automated testing"
            ]
        }

        false_positives = parser._extract_false_positives(rule_data)
        assert "Legitimate admin tools" in false_positives
        assert "Automated testing" in false_positives

    def test_extract_false_positives_empty(self, parser):
        """Test false positive extraction when none provided."""
        rule_data = {}

        false_positives = parser._extract_false_positives(rule_data)
        assert false_positives == []

    def test_parse_rule_with_complex_detection(self, parser):
        """Test parsing rule with complex detection logic."""
        complex_rule = """
title: Complex Detection Rule
id: 87654321-4321-8765-2109-876543210987
description: A complex rule with multiple conditions
author: Test Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        EventID: 1
        Image|endswith: '\\suspicious.exe'
    selection2:
        CommandLine|contains:
            - 'encoded'
            - 'obfuscated'
    condition: selection1 and selection2
level: high
"""

        result = parser.parse_rule(complex_rule, "complex_rule.yml")

        assert result.name == "Complex Detection Rule"
        assert result.description == "A complex rule with multiple conditions"
        assert "Windows" in result.platforms
        assert "Process Creation" in result.data_sources

    def test_determine_severity_mapping(self, parser):
        """Test severity level mapping."""
        # Test different levels
        assert parser._determine_severity({"level": "low"}) == "low"
        assert parser._determine_severity({"level": "medium"}) == "medium"
        assert parser._determine_severity({"level": "high"}) == "high"
        assert parser._determine_severity({"level": "critical"}) == "critical"

        # Test missing level (should default)
        assert parser._determine_severity({}) == "medium"

        # Test unknown level (should default)
        assert parser._determine_severity({"level": "unknown"}) == "medium"