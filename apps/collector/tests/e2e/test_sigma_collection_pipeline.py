"""
End-to-end tests for complete SIGMA collection pipeline.

Tests the entire workflow from Git clone through rule parsing,
validation, enrichment, and API submission.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.collectors.detection.sigma import SigmaCollector
from src.core.api_client import CountermeasureClient


class TestSigmaCollectionPipelineE2E:
    """End-to-end tests for SIGMA collection pipeline."""

    @pytest.mark.asyncio
    async def test_complete_sigma_collection_workflow(self):
        """Test complete SIGMA collection workflow from start to finish."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup: Create realistic SIGMA repository structure
            repo_dir = Path(temp_dir) / "sigma"
            repo_dir.mkdir()

            # Create realistic directory structure
            rules_dir = repo_dir / "rules"
            rules_dir.mkdir()

            windows_dir = rules_dir / "windows"
            windows_dir.mkdir()

            process_creation_dir = windows_dir / "process_creation"
            process_creation_dir.mkdir()

            network_dir = windows_dir / "network_connection"
            network_dir.mkdir()

            linux_dir = rules_dir / "linux"
            linux_dir.mkdir()

            # Create realistic SIGMA rules
            sigma_rules = [
                {
                    "path": process_creation_dir / "powershell_suspicious.yml",
                    "content": """
title: Suspicious PowerShell Command Line
id: e2e6dfa8-9138-46be-a5a8-5d62e9e8c8b9
description: Detects suspicious PowerShell command line patterns often used by attackers
author: Security Team
date: 2024/01/01
modified: 2024/01/01
status: experimental
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://docs.microsoft.com/en-us/powershell/
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection_powershell:
        EventID: 1
        Image|endswith: '\\powershell.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'FromBase64String'
            - 'WebClient'
            - 'IEX'
            - '-EncodedCommand'
            - '-WindowStyle Hidden'
    condition: selection_powershell and selection_suspicious
falsepositives:
    - Legitimate PowerShell scripts in enterprise environments
    - Administrative tools using PowerShell
    - Security tools and monitoring scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1071.001
    - sysmon
                    """
                },
                {
                    "path": network_dir / "suspicious_outbound.yml",
                    "content": """
title: Suspicious Outbound Network Connection
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
description: Detects suspicious outbound network connections to known bad domains
author: Threat Intelligence Team
date: 2024/01/01
status: stable
references:
    - https://attack.mitre.org/techniques/T1071/
logsource:
    category: network_connection
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Initiated: true
        DestinationPort:
            - 80
            - 443
            - 8080
    suspicious_domains:
        DestinationHostname|endswith:
            - '.tk'
            - '.ml'
            - '.ga'
            - '.cf'
        DestinationHostname|contains:
            - 'pastebin'
            - 'hastebin'
            - 'bit.ly'
    condition: selection and suspicious_domains
falsepositives:
    - Legitimate business connections to these domains
    - CDN services that might use suspicious TLDs
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
    - network
                    """
                },
                {
                    "path": linux_dir / "linux_persistence.yml",
                    "content": """
title: Linux Persistence via Crontab
id: 12345678-90ab-cdef-1234-567890abcdef
description: Detects attempts to establish persistence via crontab modifications
author: Linux Security Team
date: 2024/01/01
status: experimental
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/crontab'
            - '/systemctl'
        CommandLine|contains:
            - 'crontab -e'
            - 'crontab -l'
            - 'systemctl enable'
    condition: selection
falsepositives:
    - Legitimate system administration
    - Scheduled maintenance tasks
level: medium
tags:
    - attack.persistence
    - attack.t1053.003
    - linux
                    """
                },
                {
                    "path": process_creation_dir / "mimikatz_execution.yml",
                    "content": """
title: Mimikatz Execution
id: 98765432-10ab-cdef-9876-543210fedcba
description: Detects execution of Mimikatz credential dumping tool
author: Red Team Detection
date: 2024/01/01
status: stable
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection_image:
        EventID: 1
        Image|endswith: '\\mimikatz.exe'
    selection_commandline:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'privilege::debug'
            - 'lsadump::sam'
            - 'crypto::capi'
    condition: selection_image or selection_commandline
falsepositives:
    - Authorized penetration testing
    - Security research in isolated environments
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003.002
    - mimikatz
                    """
                },
                {
                    "path": process_creation_dir / "wmi_persistence.yml",
                    "content": """
title: WMI Event Subscription Persistence
id: fedcba09-8765-4321-0987-654321098765
description: Detects WMI event subscription for persistence
author: Windows Forensics Team
date: 2024/01/01
status: experimental
references:
    - https://attack.mitre.org/techniques/T1546/003/
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - '/namespace:'
            - 'create'
            - 'EventFilter'
            - 'EventConsumer'
            - 'FilterToConsumerBinding'
    condition: selection
falsepositives:
    - Legitimate system administration
    - Monitoring software setup
level: high
tags:
    - attack.persistence
    - attack.t1546.003
    - wmi
                    """
                }
            ]

            # Write all SIGMA rule files
            for rule_info in sigma_rules:
                rule_info["path"].write_text(rule_info["content"])

            # Create some non-SIGMA files that should be ignored
            (rules_dir / "README.md").write_text("# SIGMA Rules Repository")
            (rules_dir / "config.yml").write_text("version: 1.0")
            (process_creation_dir / "template.yml.example").write_text("# Template file")

            # Mock comprehensive API client
            class MockComprehensiveApiClient:
                def __init__(self):
                    self.login_attempts = 0
                    self.submitted_detections = []
                    self.submission_errors = []
                    self.is_authenticated = False

                async def login(self):
                    self.login_attempts += 1
                    if self.login_attempts <= 3:  # Allow retries
                        self.is_authenticated = True
                        return True
                    return False

                async def create_detection(self, detection_data):
                    if not self.is_authenticated:
                        raise Exception("Not authenticated")

                    # Simulate validation
                    if not detection_data.name or not detection_data.rule_yaml:
                        raise ValueError("Missing required fields")

                    # Simulate occasional API errors
                    if "WMI Event" in detection_data.name:
                        self.submission_errors.append("Temporary API error for WMI rule")
                        raise Exception("Temporary API error")

                    # Create successful response
                    detection_response = {
                        "id": f"det_{len(self.submitted_detections) + 1:04d}",
                        "name": detection_data.name,
                        "description": detection_data.description,
                        "rule_yaml": detection_data.rule_yaml,
                        "platforms": detection_data.platforms,
                        "data_sources": detection_data.data_sources,
                        "false_positives": getattr(detection_data, 'false_positives', []),
                        "log_sources": getattr(detection_data, 'log_sources', ''),
                        "tags": getattr(detection_data, 'tags', []),
                        "status": detection_data.status,
                        "visibility": detection_data.visibility,
                        "confidence_score": detection_data.confidence_score,
                        "tenant_id": "e2e_test_tenant",
                        "created_at": "2024-01-01T12:00:00Z",
                        "updated_at": "2024-01-01T12:00:00Z",
                        "actors": [],
                        "mitre_techniques": [],
                        "severity_id": 1
                    }

                    self.submitted_detections.append(detection_response)
                    return detection_response

                async def close(self):
                    pass

            # Configure collector for complete workflow
            config = {
                "api_url": "http://localhost:8000",
                "email": "e2e_test@example.com",
                "password": "E2ETestPassword123!",
                "repo_url": "https://github.com/SigmaHQ/sigma.git",  # Real repo URL
                "clone_dir": temp_dir,
                "limit": 50,  # Process up to 50 rules
                "batch_size": 3,  # Small batches for testing
                "include_patterns": ["*.yml", "*.yaml"],
                "exclude_patterns": ["*template*", "*example*"],
                "confidence_threshold": 0.5,
                "enable_enrichment": True,
                "validate_yaml": True,
                "continue_on_error": True,
            }

            collector = SigmaCollector(config)
            mock_client = MockComprehensiveApiClient()

            # Mock Git clone to use our prepared directory
            with patch.object(collector, '_clone_repository') as mock_clone:
                mock_clone.return_value = True

                # Mock file discovery to use our prepared files
                rule_files = [rule_info["path"] for rule_info in sigma_rules]
                with patch.object(collector, '_discover_sigma_files') as mock_discover:
                    mock_discover.return_value = rule_files

                    # Mock API client creation
                    with patch.object(collector, '_create_api_client') as mock_create_client:
                        mock_create_client.return_value = mock_client

                        # Execute complete workflow
                        start_time = asyncio.get_event_loop().time()
                        results = await collector.collect_and_submit()
                        end_time = asyncio.get_event_loop().time()

                        # Verify workflow results
                        assert results is not None

                        # Verify Git operations
                        mock_clone.assert_called_once()
                        mock_discover.assert_called_once()

                        # Verify API authentication
                        assert mock_client.login_attempts > 0
                        assert mock_client.is_authenticated

                        # Verify rule processing
                        # Should have processed 4 rules successfully (WMI rule failed)
                        assert len(mock_client.submitted_detections) >= 4

                        # Verify detection content
                        submitted_names = [d["name"] for d in mock_client.submitted_detections]
                        expected_names = [
                            "Suspicious PowerShell Command Line",
                            "Suspicious Outbound Network Connection",
                            "Linux Persistence via Crontab",
                            "Mimikatz Execution"
                        ]

                        for expected_name in expected_names:
                            assert expected_name in submitted_names

                        # Verify metadata extraction worked
                        powershell_detection = next(
                            d for d in mock_client.submitted_detections
                            if "PowerShell" in d["name"]
                        )

                        assert "Windows" in powershell_detection["platforms"]
                        assert "Process Creation" in powershell_detection["data_sources"]
                        assert len(powershell_detection["false_positives"]) > 0
                        assert len(powershell_detection["tags"]) > 0
                        assert powershell_detection["confidence_score"] > 0.0

                        # Verify Linux rule was processed correctly
                        linux_detection = next(
                            d for d in mock_client.submitted_detections
                            if "Linux" in d["name"]
                        )

                        assert "Linux" in linux_detection["platforms"]
                        assert linux_detection["log_sources"] != ""

                        # Verify error handling
                        assert len(mock_client.submission_errors) > 0  # WMI rule should have failed

                        # Verify performance
                        processing_time = end_time - start_time
                        assert processing_time < 10.0  # Should complete within 10 seconds

    @pytest.mark.asyncio
    async def test_real_sigma_repository_integration(self):
        """Test integration with real SIGMA repository (limited scope)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock API client for real repo testing
            class MockRealRepoClient:
                def __init__(self):
                    self.submitted_detections = []
                    self.parsing_errors = []

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    try:
                        # Validate detection data structure
                        assert hasattr(detection_data, 'name')
                        assert hasattr(detection_data, 'rule_yaml')
                        assert len(detection_data.name) > 0
                        assert len(detection_data.rule_yaml) > 0

                        detection_response = {
                            "id": f"real_det_{len(self.submitted_detections) + 1:04d}",
                            "name": detection_data.name,
                            "description": detection_data.description,
                            "platforms": detection_data.platforms,
                            "data_sources": detection_data.data_sources,
                            "status": detection_data.status,
                            "confidence_score": detection_data.confidence_score,
                            "tenant_id": "real_repo_test_tenant",
                            "created_at": "2024-01-01T12:00:00Z"
                        }

                        self.submitted_detections.append(detection_response)
                        return detection_response

                    except Exception as e:
                        self.parsing_errors.append(str(e))
                        raise

                async def close(self):
                    pass

            # Configure for real SIGMA repository
            config = {
                "api_url": "http://localhost:8000",
                "email": "real_test@example.com",
                "password": "RealTestPassword123!",
                "repo_url": "https://github.com/SigmaHQ/sigma.git",
                "clone_dir": temp_dir,
                "limit": 10,  # Limit to 10 rules for testing
                "batch_size": 5,
                "timeout": 300,  # 5 minute timeout for Git operations
                "validate_yaml": True,
                "continue_on_error": True,
            }

            collector = SigmaCollector(config)
            mock_client = MockRealRepoClient()

            # Mock API client creation
            with patch.object(collector, '_create_api_client') as mock_create_client:
                mock_create_client.return_value = mock_client

                try:
                    # Execute with real repository
                    results = await collector.collect_and_submit()

                    # If Git clone succeeded, verify results
                    if results is not None:
                        # Should have processed some rules
                        assert len(mock_client.submitted_detections) > 0

                        # Verify all submitted detections have valid structure
                        for detection in mock_client.submitted_detections:
                            assert "id" in detection
                            assert "name" in detection
                            assert len(detection["name"]) > 0
                            assert "platforms" in detection
                            assert isinstance(detection["platforms"], list)

                        # Verify error handling worked
                        # Some parsing errors are expected with real diverse rules
                        total_attempts = len(mock_client.submitted_detections) + len(mock_client.parsing_errors)
                        success_rate = len(mock_client.submitted_detections) / total_attempts if total_attempts > 0 else 0

                        # Should have reasonable success rate
                        assert success_rate >= 0.7  # At least 70% success rate

                except Exception as e:
                    # If Git clone fails (network issues), skip test
                    if "git" in str(e).lower() or "network" in str(e).lower():
                        pytest.skip(f"Git operation failed: {e}")
                    else:
                        raise

    @pytest.mark.asyncio
    async def test_pipeline_error_recovery(self):
        """Test pipeline error recovery and continuation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test repository with mix of valid/invalid files
            repo_dir = Path(temp_dir) / "sigma"
            repo_dir.mkdir()
            rules_dir = repo_dir / "rules"
            rules_dir.mkdir()

            # Create mix of files with various issues
            test_files = [
                {
                    "path": rules_dir / "valid_rule_1.yml",
                    "content": """
title: Valid Rule 1
description: This rule should process successfully
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
    condition: selection
level: medium
tags:
    - attack.execution
                    """,
                    "should_succeed": True
                },
                {
                    "path": rules_dir / "invalid_yaml.yml",
                    "content": """
title: Invalid YAML Rule
description: This rule has invalid YAML syntax
logsource:
    category: process_creation
detection:
    selection:
        EventID: 1
    condition: selection
level: [invalid_yaml_structure  # Missing closing bracket
                    """,
                    "should_succeed": False
                },
                {
                    "path": rules_dir / "missing_detection.yml",
                    "content": """
title: Missing Detection Field
description: This rule is missing the detection field
logsource:
    category: process_creation
    product: windows
level: medium
tags:
    - incomplete
                    """,
                    "should_succeed": False
                },
                {
                    "path": rules_dir / "valid_rule_2.yml",
                    "content": """
title: Valid Rule 2
description: Another rule that should succeed
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        EventID: 3
        DestinationPort: 443
    condition: selection
level: low
                    """,
                    "should_succeed": True
                },
                {
                    "path": rules_dir / "empty_file.yml",
                    "content": "",
                    "should_succeed": False
                },
                {
                    "path": rules_dir / "valid_rule_3.yml",
                    "content": """
title: Valid Rule 3
description: Final valid rule for testing
logsource:
    category: file_event
    product: linux
detection:
    selection:
        EventID: 11
        TargetFilename|contains: '/tmp/'
    condition: selection
level: high
                    """,
                    "should_succeed": True
                }
            ]

            # Write test files
            for file_info in test_files:
                file_info["path"].write_text(file_info["content"])

            # Mock API client that tracks successes and errors
            class MockErrorRecoveryClient:
                def __init__(self):
                    self.successful_submissions = []
                    self.failed_submissions = []
                    self.processing_errors = []

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    # Simulate API submission error for one specific rule
                    if "Valid Rule 2" in detection_data.name:
                        error_msg = "Simulated API submission error"
                        self.failed_submissions.append({
                            "name": detection_data.name,
                            "error": error_msg
                        })
                        raise Exception(error_msg)

                    # Successful submission
                    detection_response = {
                        "id": f"recovery_det_{len(self.successful_submissions) + 1:04d}",
                        "name": detection_data.name,
                        "description": detection_data.description,
                        "status": detection_data.status,
                        "confidence_score": detection_data.confidence_score,
                        "created_at": "2024-01-01T12:00:00Z"
                    }

                    self.successful_submissions.append(detection_response)
                    return detection_response

                async def close(self):
                    pass

            config = {
                "api_url": "http://localhost:8000",
                "email": "recovery_test@example.com",
                "password": "RecoveryTestPassword123!",
                "repo_url": "file://" + str(repo_dir),
                "clone_dir": temp_dir,
                "limit": 20,
                "batch_size": 2,
                "continue_on_error": True,  # Key setting for error recovery
                "validate_yaml": True,
                "skip_invalid_rules": True,
            }

            collector = SigmaCollector(config)
            mock_client = MockErrorRecoveryClient()

            # Track parsing errors at collector level
            original_parse = getattr(collector, '_parse_sigma_rule', None)
            parsing_errors = []

            def track_parsing_errors(file_path):
                try:
                    if original_parse:
                        return original_parse(file_path)
                    else:
                        # Simplified parsing for test
                        content = file_path.read_text()
                        if not content.strip():
                            raise ValueError("Empty file")
                        if "invalid_yaml_structure" in content:
                            raise ValueError("Invalid YAML syntax")
                        if "detection:" not in content:
                            raise ValueError("Missing detection field")
                        return content  # Simplified return
                except Exception as e:
                    parsing_errors.append({
                        "file": str(file_path),
                        "error": str(e)
                    })
                    raise

            # Mock Git clone and file discovery
            with patch.object(collector, '_clone_repository') as mock_clone:
                mock_clone.return_value = True

                with patch.object(collector, '_discover_sigma_files') as mock_discover:
                    mock_discover.return_value = [info["path"] for info in test_files]

                    with patch.object(collector, '_create_api_client') as mock_create_client:
                        mock_create_client.return_value = mock_client

                        if original_parse:
                            with patch.object(collector, '_parse_sigma_rule', track_parsing_errors):
                                results = await collector.collect_and_submit()
                        else:
                            results = await collector.collect_and_submit()

                        # Verify error recovery behavior
                        # Should have processed valid rules despite errors

                        # Count expected outcomes
                        expected_successful = len([f for f in test_files if f["should_succeed"]])
                        expected_parsing_errors = len([f for f in test_files if not f["should_succeed"]])

                        # Verify successful submissions
                        # Note: "Valid Rule 2" should fail at API level, so expect 2 successful
                        actual_successful = len(mock_client.successful_submissions)
                        assert actual_successful >= 2  # At least Valid Rule 1 and Valid Rule 3

                        # Verify that valid rules were processed
                        successful_names = [s["name"] for s in mock_client.successful_submissions]
                        assert "Valid Rule 1" in successful_names
                        assert "Valid Rule 3" in successful_names

                        # Verify API submission error was handled
                        assert len(mock_client.failed_submissions) >= 1
                        failed_names = [f["name"] for f in mock_client.failed_submissions]
                        assert "Valid Rule 2" in failed_names

                        # Verify parsing errors were tracked (if original_parse exists)
                        if original_parse and parsing_errors:
                            assert len(parsing_errors) >= expected_parsing_errors

                        # Verify the collector continued processing after errors
                        # Total processed should be close to total files
                        total_processed = (
                            len(mock_client.successful_submissions) +
                            len(mock_client.failed_submissions) +
                            len(parsing_errors)
                        )
                        assert total_processed >= len(test_files) - 2  # Allow for some tolerance

    @pytest.mark.asyncio
    async def test_pipeline_performance_with_large_dataset(self):
        """Test pipeline performance with larger dataset."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create large test dataset
            repo_dir = Path(temp_dir) / "sigma"
            repo_dir.mkdir()
            rules_dir = repo_dir / "rules"
            rules_dir.mkdir()

            # Create subdirectories
            for platform in ["windows", "linux", "macos"]:
                platform_dir = rules_dir / platform
                platform_dir.mkdir()

                for category in ["process_creation", "network", "file_event"]:
                    category_dir = platform_dir / category
                    category_dir.mkdir()

            # Generate many test rules
            num_rules = 50
            created_files = []

            for i in range(num_rules):
                platform = ["windows", "linux", "macos"][i % 3]
                category = ["process_creation", "network", "file_event"][i % 3]

                rule_content = f"""
title: Performance Test Rule {i + 1}
id: {i:08d}-1234-5678-9abc-def012345678
description: Generated rule {i + 1} for performance testing on {platform}
author: Performance Test Suite
date: 2024/01/01
status: experimental
logsource:
    category: {category}
    product: {platform}
detection:
    selection:
        EventID: {(i % 10) + 1}
        Field{i}: 'value_{i}'
    condition: selection
falsepositives:
    - Legitimate use case {i}
    - Testing scenario {i}
level: {["low", "medium", "high"][i % 3]}
tags:
    - attack.execution
    - attack.t10{i:02d}
    - performance_test
                """

                rule_file = rules_dir / platform / category / f"perf_rule_{i + 1:03d}.yml"
                rule_file.write_text(rule_content)
                created_files.append(rule_file)

            # Mock high-performance API client
            class MockPerformanceClient:
                def __init__(self):
                    self.submissions = []
                    self.start_time = None
                    self.submission_times = []

                async def login(self):
                    self.start_time = asyncio.get_event_loop().time()
                    return True

                async def create_detection(self, detection_data):
                    current_time = asyncio.get_event_loop().time()
                    self.submission_times.append(current_time - self.start_time)

                    # Simulate realistic API response time
                    await asyncio.sleep(0.01)  # 10ms simulated API latency

                    detection_response = {
                        "id": f"perf_det_{len(self.submissions) + 1:04d}",
                        "name": detection_data.name,
                        "platforms": detection_data.platforms,
                        "submission_order": len(self.submissions) + 1,
                        "submission_time": current_time - self.start_time
                    }

                    self.submissions.append(detection_response)
                    return detection_response

                async def close(self):
                    pass

            # Configure for performance testing
            config = {
                "api_url": "http://localhost:8000",
                "email": "perf_test@example.com",
                "password": "PerfTestPassword123!",
                "repo_url": "file://" + str(repo_dir),
                "clone_dir": temp_dir,
                "limit": num_rules,
                "batch_size": 10,  # Larger batches for performance
                "max_concurrent": 5,  # Enable concurrency
                "timeout": 30,
                "validate_yaml": True,
                "enable_caching": True,  # If supported
            }

            collector = SigmaCollector(config)
            mock_client = MockPerformanceClient()

            # Execute performance test
            with patch.object(collector, '_clone_repository') as mock_clone:
                mock_clone.return_value = True

                with patch.object(collector, '_discover_sigma_files') as mock_discover:
                    mock_discover.return_value = created_files

                    with patch.object(collector, '_create_api_client') as mock_create_client:
                        mock_create_client.return_value = mock_client

                        # Measure overall performance
                        start_time = asyncio.get_event_loop().time()
                        results = await collector.collect_and_submit()
                        end_time = asyncio.get_event_loop().time()

                        total_time = end_time - start_time

                        # Verify performance results
                        assert len(mock_client.submissions) == num_rules

                        # Performance assertions
                        # Should process rules faster than sequential API calls
                        theoretical_sequential_time = num_rules * 0.01  # 10ms per rule
                        assert total_time < theoretical_sequential_time * 2  # Allow for overhead

                        # Verify submission ordering and timing
                        submission_times = [s["submission_time"] for s in mock_client.submissions]

                        # Times should be generally increasing (allowing for concurrency)
                        # But not strictly sequential due to parallel processing
                        first_submission_time = submission_times[0]
                        last_submission_time = submission_times[-1]

                        # First submission should happen relatively quickly
                        assert first_submission_time < 1.0  # Within 1 second

                        # Total processing time should be reasonable
                        assert last_submission_time < 10.0  # Within 10 seconds

                        # Average time per rule should be reasonable
                        avg_time_per_rule = total_time / num_rules
                        assert avg_time_per_rule < 0.2  # Less than 200ms per rule on average

                        # Verify all rules were processed correctly
                        submitted_names = [s["name"] for s in mock_client.submissions]
                        expected_names = [f"Performance Test Rule {i + 1}" for i in range(num_rules)]

                        for expected_name in expected_names:
                            assert expected_name in submitted_names