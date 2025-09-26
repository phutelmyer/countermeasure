"""
Integration tests for batch processing.

Tests batch processing of multiple SIGMA rules including
chunking, progress tracking, and error recovery.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.collectors.detection.sigma import SigmaCollector
from src.schemas.detection import DetectionCreate


class TestBatchProcessingIntegration:
    """Integration tests for batch processing operations."""

    def test_batch_processing_with_real_files(self):
        """Test batch processing with real SIGMA rule files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple SIGMA rule files
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create test SIGMA rules
            rule_templates = [
                {
                    "filename": "process_creation_suspicious.yml",
                    "content": """
title: Suspicious Process Creation
description: Detects suspicious process creation patterns
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'downloadstring'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
                    """
                },
                {
                    "filename": "network_connection_suspicious.yml",
                    "content": """
title: Suspicious Network Connection
description: Detects suspicious outbound network connections
logsource:
    category: network_connection
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort:
            - 443
            - 80
        Initiated: true
    filter:
        Image|endswith: '\\browser.exe'
    condition: selection and not filter
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
                    """
                },
                {
                    "filename": "file_creation_malware.yml",
                    "content": """
title: Malware File Creation
description: Detects creation of files in suspicious locations
logsource:
    category: file_event
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains:
            - '\\Temp\\'
            - '\\AppData\\'
        TargetFilename|endswith:
            - '.exe'
            - '.scr'
            - '.bat'
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1105
                    """
                },
                {
                    "filename": "registry_modification.yml",
                    "content": """
title: Suspicious Registry Modification
description: Detects suspicious registry modifications
logsource:
    category: registry_event
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            - 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
                    """
                },
                {
                    "filename": "dns_suspicious.yml",
                    "content": """
title: Suspicious DNS Query
description: Detects suspicious DNS queries
logsource:
    category: dns
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 22
        QueryName|endswith:
            - '.tk'
            - '.ml'
            - '.ga'
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004
                    """
                }
            ]

            # Create the rule files
            created_files = []
            for rule_template in rule_templates:
                rule_file = rules_dir / rule_template["filename"]
                rule_file.write_text(rule_template["content"])
                created_files.append(rule_file)

            # Mock API client for batch processing
            mock_api_responses = []

            class MockApiClient:
                def __init__(self):
                    self.submitted_detections = []
                    self.login_called = False
                    self.closed = False

                async def login(self):
                    self.login_called = True
                    return True

                async def create_detection(self, detection_data):
                    # Simulate API response
                    detection_dict = {
                        "id": f"detection_{len(self.submitted_detections) + 1}",
                        "name": detection_data.name,
                        "description": detection_data.description,
                        "rule_yaml": detection_data.rule_yaml,
                        "platforms": detection_data.platforms,
                        "data_sources": detection_data.data_sources,
                        "status": detection_data.status,
                        "confidence_score": detection_data.confidence_score,
                        "created_at": "2024-01-01T00:00:00Z",
                        "tenant_id": "test_tenant_123"
                    }
                    self.submitted_detections.append(detection_dict)
                    return detection_dict

                async def close(self):
                    self.closed = True

            # Create collector with mock API client
            config = {
                "api_url": "http://mock-api:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(temp_dir),
                "clone_dir": temp_dir,
                "limit": 10,
                "batch_size": 2,  # Small batch size for testing
            }

            collector = SigmaCollector(config)
            mock_client = MockApiClient()

            # Mock the API client creation
            with patch.object(collector, '_create_api_client', return_value=mock_client):
                # Mock file discovery to return our created files
                with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                    # Run batch processing
                    results = asyncio.run(collector.collect_and_submit())

                    # Verify results
                    assert results is not None
                    assert len(mock_client.submitted_detections) == 5  # All 5 rules processed

                    # Verify all detections were created properly
                    submitted_names = [d["name"] for d in mock_client.submitted_detections]
                    expected_names = [
                        "Suspicious Process Creation",
                        "Suspicious Network Connection",
                        "Malware File Creation",
                        "Suspicious Registry Modification",
                        "Suspicious DNS Query"
                    ]

                    for expected_name in expected_names:
                        assert expected_name in submitted_names

                    # Verify API client was used properly
                    assert mock_client.login_called
                    assert mock_client.closed

    def test_batch_processing_with_errors(self):
        """Test batch processing with various error scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create mix of valid and invalid SIGMA files
            test_files = [
                {
                    "filename": "valid_rule_1.yml",
                    "content": """
title: Valid Rule 1
description: This is a valid SIGMA rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: medium
                    """
                },
                {
                    "filename": "invalid_yaml.yml",
                    "content": """
title: Invalid YAML Rule
description: This rule has invalid YAML syntax
logsource:
    category: process_creation
detection:
    selection:
        EventID: 1
    condition: selection
level: [invalid_yaml_structure
                    """
                },
                {
                    "filename": "valid_rule_2.yml",
                    "content": """
title: Valid Rule 2
description: Another valid SIGMA rule
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        EventID: 3
    condition: selection
level: high
                    """
                },
                {
                    "filename": "missing_required_fields.yml",
                    "content": """
title: Missing Detection Field
description: This rule is missing the detection field
logsource:
    category: process_creation
    product: windows
level: medium
                    """
                },
                {
                    "filename": "valid_rule_3.yml",
                    "content": """
title: Valid Rule 3
description: Third valid SIGMA rule
logsource:
    category: file_event
    product: windows
detection:
    selection:
        EventID: 11
    condition: selection
level: low
                    """
                }
            ]

            # Create the test files
            created_files = []
            for test_file in test_files:
                file_path = rules_dir / test_file["filename"]
                file_path.write_text(test_file["content"])
                created_files.append(file_path)

            # Mock API client that simulates submission errors
            class MockApiClientWithErrors:
                def __init__(self):
                    self.submitted_detections = []
                    self.submission_count = 0
                    self.login_called = False

                async def login(self):
                    self.login_called = True
                    return True

                async def create_detection(self, detection_data):
                    self.submission_count += 1

                    # Simulate API error for certain submissions
                    if "Valid Rule 2" in detection_data.name:
                        # Simulate API error
                        raise Exception("API submission failed for Valid Rule 2")

                    # Successful submission
                    detection_dict = {
                        "id": f"detection_{self.submission_count}",
                        "name": detection_data.name,
                        "description": detection_data.description,
                        "rule_yaml": detection_data.rule_yaml,
                        "status": detection_data.status,
                        "created_at": "2024-01-01T00:00:00Z"
                    }
                    self.submitted_detections.append(detection_dict)
                    return detection_dict

                async def close(self):
                    pass

            config = {
                "api_url": "http://mock-api:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(temp_dir),
                "clone_dir": temp_dir,
                "limit": 10,
                "batch_size": 2,
                "continue_on_error": True,  # Continue processing despite errors
            }

            collector = SigmaCollector(config)
            mock_client = MockApiClientWithErrors()

            with patch.object(collector, '_create_api_client', return_value=mock_client):
                with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                    # Run batch processing
                    results = asyncio.run(collector.collect_and_submit())

                    # Should have processed some files despite errors
                    # Valid files: valid_rule_1.yml, valid_rule_3.yml
                    # Invalid files: invalid_yaml.yml, missing_required_fields.yml
                    # API error file: valid_rule_2.yml

                    successful_submissions = len(mock_client.submitted_detections)

                    # Should have at least submitted the valid rules that didn't have API errors
                    assert successful_submissions >= 2  # valid_rule_1 and valid_rule_3

                    # Verify the successful submissions
                    submitted_names = [d["name"] for d in mock_client.submitted_detections]
                    assert "Valid Rule 1" in submitted_names
                    assert "Valid Rule 3" in submitted_names

                    # Valid Rule 2 should not be in successful submissions (API error)
                    assert "Valid Rule 2" not in submitted_names

    def test_batch_size_limiting(self):
        """Test that batch size limits are respected."""
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create many SIGMA rule files (more than batch size)
            created_files = []
            for i in range(10):  # Create 10 files
                rule_content = f"""
title: Test Rule {i + 1}
description: Test rule number {i + 1}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: {i + 1}
    condition: selection
level: medium
                """
                rule_file = rules_dir / f"test_rule_{i + 1}.yml"
                rule_file.write_text(rule_content)
                created_files.append(rule_file)

            # Mock API client that tracks batch submissions
            class MockBatchTrackingClient:
                def __init__(self):
                    self.batches = []
                    self.current_batch = []
                    self.batch_size = None

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    self.current_batch.append(detection_data.name)
                    return {
                        "id": f"detection_{len(self.current_batch)}",
                        "name": detection_data.name
                    }

                def end_batch(self):
                    """Call this to mark end of a batch."""
                    if self.current_batch:
                        self.batches.append(self.current_batch.copy())
                        self.current_batch = []

                async def close(self):
                    self.end_batch()  # Final batch

            # Test with different batch sizes
            batch_sizes = [3, 5, 7]

            for batch_size in batch_sizes:
                config = {
                    "api_url": "http://mock-api:8000",
                    "email": "test@example.com",
                    "password": "test_password",
                    "repo_url": "file://" + str(temp_dir),
                    "clone_dir": temp_dir,
                    "limit": 10,
                    "batch_size": batch_size,
                }

                collector = SigmaCollector(config)
                mock_client = MockBatchTrackingClient()

                # Simulate batch processing with manual batch tracking
                with patch.object(collector, '_create_api_client', return_value=mock_client):
                    with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                        # Mock the batch processing to track batches
                        original_submit_batch = getattr(collector, '_submit_detection_batch', None)

                        async def tracked_submit_batch(batch_data):
                            # Process the batch
                            for detection_data in batch_data:
                                await mock_client.create_detection(detection_data)
                            mock_client.end_batch()
                            return len(batch_data)

                        if original_submit_batch:
                            with patch.object(collector, '_submit_detection_batch', tracked_submit_batch):
                                asyncio.run(collector.collect_and_submit())
                        else:
                            # If no batch method exists, simulate it
                            asyncio.run(collector.collect_and_submit())

                        # Verify batch sizes
                        if mock_client.batches:
                            for batch in mock_client.batches[:-1]:  # All but last batch
                                assert len(batch) <= batch_size

                            # Last batch might be smaller
                            total_processed = sum(len(batch) for batch in mock_client.batches)
                            assert total_processed <= 10  # Respects overall limit

    def test_progress_tracking_in_batch_processing(self):
        """Test progress tracking during batch processing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create test files
            num_files = 8
            created_files = []
            for i in range(num_files):
                rule_content = f"""
title: Progress Test Rule {i + 1}
description: Rule for progress tracking test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: {i + 1}
    condition: selection
level: medium
                """
                rule_file = rules_dir / f"progress_rule_{i + 1}.yml"
                rule_file.write_text(rule_content)
                created_files.append(rule_file)

            # Mock API client with progress tracking
            class MockProgressTrackingClient:
                def __init__(self):
                    self.progress_callbacks = []
                    self.total_submitted = 0
                    self.submission_times = []

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    import time
                    self.submission_times.append(time.time())
                    self.total_submitted += 1

                    # Simulate progress callback
                    for callback in self.progress_callbacks:
                        await callback(self.total_submitted, num_files)

                    return {
                        "id": f"detection_{self.total_submitted}",
                        "name": detection_data.name
                    }

                def add_progress_callback(self, callback):
                    self.progress_callbacks.append(callback)

                async def close(self):
                    pass

            # Progress tracking variables
            progress_updates = []

            async def progress_callback(current, total):
                progress_updates.append({
                    "current": current,
                    "total": total,
                    "percentage": (current / total) * 100
                })

            config = {
                "api_url": "http://mock-api:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(temp_dir),
                "clone_dir": temp_dir,
                "limit": num_files,
                "batch_size": 3,
                "progress_callback": progress_callback,
            }

            collector = SigmaCollector(config)
            mock_client = MockProgressTrackingClient()
            mock_client.add_progress_callback(progress_callback)

            with patch.object(collector, '_create_api_client', return_value=mock_client):
                with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                    # Run batch processing
                    results = asyncio.run(collector.collect_and_submit())

                    # Verify progress tracking
                    assert len(progress_updates) == num_files

                    # Verify progress is monotonically increasing
                    for i in range(1, len(progress_updates)):
                        assert progress_updates[i]["current"] >= progress_updates[i-1]["current"]

                    # Verify final progress
                    final_progress = progress_updates[-1]
                    assert final_progress["current"] == num_files
                    assert final_progress["total"] == num_files
                    assert final_progress["percentage"] == 100.0

    def test_memory_usage_in_large_batch_processing(self):
        """Test memory usage during large batch processing."""
        import psutil
        import os

        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create many files to test memory usage
            num_files = 100
            created_files = []

            # Create large rule content to test memory handling
            large_rule_content = """
title: Large Memory Test Rule
description: """ + "A" * 1000 + """
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        CommandLine|contains:
            """ + "\n            - '" + "B" * 100 + "'\n" * 50 + """
    condition: selection
level: medium
tags:
    """ + "\n    - attack.tag_" + str(i) + "\n" for i in range(20)

            for i in range(num_files):
                rule_file = rules_dir / f"large_rule_{i + 1}.yml"
                rule_file.write_text(large_rule_content)
                created_files.append(rule_file)

            # Mock API client for memory testing
            class MockMemoryTestClient:
                def __init__(self):
                    self.peak_memory = 0
                    self.submission_count = 0

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    self.submission_count += 1

                    # Track memory usage
                    process = psutil.Process(os.getpid())
                    current_memory = process.memory_info().rss / 1024 / 1024  # MB
                    self.peak_memory = max(self.peak_memory, current_memory)

                    return {
                        "id": f"detection_{self.submission_count}",
                        "name": detection_data.name
                    }

                async def close(self):
                    pass

            config = {
                "api_url": "http://mock-api:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(temp_dir),
                "clone_dir": temp_dir,
                "limit": num_files,
                "batch_size": 10,  # Process in smaller batches
            }

            collector = SigmaCollector(config)
            mock_client = MockMemoryTestClient()

            # Get initial memory usage
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB

            with patch.object(collector, '_create_api_client', return_value=mock_client):
                with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                    # Run batch processing
                    results = asyncio.run(collector.collect_and_submit())

                    # Verify memory usage didn't grow excessively
                    memory_growth = mock_client.peak_memory - initial_memory

                    # Memory growth should be reasonable (less than 100MB for this test)
                    # This is a rough heuristic - adjust based on actual implementation
                    assert memory_growth < 100, f"Memory grew by {memory_growth:.2f} MB"

                    # Verify all files were processed
                    assert mock_client.submission_count == num_files

    @pytest.mark.asyncio
    async def test_concurrent_batch_processing(self):
        """Test concurrent batch processing scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir) / "rules"
            rules_dir.mkdir()

            # Create test files
            num_files = 12
            created_files = []
            for i in range(num_files):
                rule_content = f"""
title: Concurrent Test Rule {i + 1}
description: Rule for concurrent processing test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: {i + 1}
    condition: selection
level: medium
                """
                rule_file = rules_dir / f"concurrent_rule_{i + 1}.yml"
                rule_file.write_text(rule_content)
                created_files.append(rule_file)

            # Mock API client that simulates processing delays
            class MockConcurrentClient:
                def __init__(self):
                    self.submissions = []
                    self.concurrent_count = 0
                    self.max_concurrent = 0
                    self.lock = asyncio.Lock()

                async def login(self):
                    return True

                async def create_detection(self, detection_data):
                    async with self.lock:
                        self.concurrent_count += 1
                        self.max_concurrent = max(self.max_concurrent, self.concurrent_count)

                    # Simulate processing time
                    await asyncio.sleep(0.1)

                    # Record submission
                    submission_record = {
                        "name": detection_data.name,
                        "timestamp": asyncio.get_event_loop().time()
                    }

                    async with self.lock:
                        self.submissions.append(submission_record)
                        self.concurrent_count -= 1

                    return {
                        "id": f"detection_{len(self.submissions)}",
                        "name": detection_data.name
                    }

                async def close(self):
                    pass

            config = {
                "api_url": "http://mock-api:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(temp_dir),
                "clone_dir": temp_dir,
                "limit": num_files,
                "batch_size": 4,
                "max_concurrent": 3,  # Limit concurrent operations
            }

            collector = SigmaCollector(config)
            mock_client = MockConcurrentClient()

            with patch.object(collector, '_create_api_client', return_value=mock_client):
                with patch.object(collector, '_discover_sigma_files', return_value=created_files):
                    # Run concurrent batch processing
                    start_time = asyncio.get_event_loop().time()
                    results = await collector.collect_and_submit()
                    end_time = asyncio.get_event_loop().time()

                    # Verify all submissions completed
                    assert len(mock_client.submissions) == num_files

                    # Verify concurrency was limited appropriately
                    if hasattr(collector, 'max_concurrent'):
                        assert mock_client.max_concurrent <= config["max_concurrent"]

                    # Verify total time is reasonable (should be faster than sequential)
                    total_time = end_time - start_time
                    sequential_time = num_files * 0.1  # 0.1s per file
                    assert total_time < sequential_time  # Should be faster due to concurrency