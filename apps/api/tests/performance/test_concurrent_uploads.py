"""
Performance tests for concurrent detection uploads.

Tests the system's ability to handle multiple simultaneous
detection uploads and maintains data integrity under load.
"""

import pytest
import asyncio
import aiohttp
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from faker import Faker

fake = Faker()


class TestConcurrentUploads:
    """Test concurrent upload scenarios."""

    @pytest.fixture
    def auth_token(self):
        """Get authentication token for testing."""
        # This would normally authenticate with real API
        # For testing, return a mock token
        return "test_auth_token_for_concurrent_uploads"

    @pytest.fixture
    def base_url(self):
        """Base URL for API testing."""
        return "http://localhost:8000"

    def generate_test_detection(self, index):
        """Generate a test detection for concurrent upload."""
        return {
            "name": f"Concurrent Upload Test Detection {index}",
            "description": f"Detection created during concurrent upload test #{index}",
            "rule_yaml": f"""
title: Concurrent Test Detection {index}
description: Generated for concurrent upload testing
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
        CommandLine|contains: 'concurrent_test_{index}'
    condition: selection
falsepositives:
    - Legitimate process {index}
level: medium
tags:
    - attack.execution
    - attack.t1059
    - concurrent_test
            """,
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "false_positives": [f"Legitimate use case {index}"],
            "tags": [f"concurrent_test_{index}", "performance_test"],
            "status": "testing",
            "visibility": "public",
            "confidence_score": round(0.5 + (index % 5) * 0.1, 2),
        }

    def upload_detection_sync(self, session, base_url, auth_token, detection_data, index):
        """Upload a single detection synchronously."""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }

        start_time = time.time()

        try:
            response = session.post(
                f"{base_url}/api/v1/detections/",
                json=detection_data,
                headers=headers,
                timeout=30
            )

            end_time = time.time()
            upload_time = end_time - start_time

            return {
                "index": index,
                "status_code": response.status_code,
                "success": response.status_code == 201,
                "upload_time": upload_time,
                "response_data": response.json() if response.status_code == 201 else None,
                "error": None
            }

        except Exception as e:
            end_time = time.time()
            upload_time = end_time - start_time

            return {
                "index": index,
                "status_code": None,
                "success": False,
                "upload_time": upload_time,
                "response_data": None,
                "error": str(e)
            }

    def test_concurrent_detection_uploads_threads(self, auth_token, base_url):
        """Test concurrent detection uploads using threading."""
        num_concurrent_uploads = 20
        max_workers = 10

        # Generate test data
        test_detections = [
            self.generate_test_detection(i) for i in range(num_concurrent_uploads)
        ]

        # Track results
        results = []
        start_time = time.time()

        # Use ThreadPoolExecutor for concurrent uploads
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create session for reuse
            import requests
            session = requests.Session()

            # Submit all upload tasks
            future_to_index = {
                executor.submit(
                    self.upload_detection_sync,
                    session,
                    base_url,
                    auth_token,
                    test_detections[i],
                    i
                ): i for i in range(num_concurrent_uploads)
            }

            # Collect results as they complete
            for future in as_completed(future_to_index):
                result = future.result()
                results.append(result)

        end_time = time.time()
        total_time = end_time - start_time

        # Analyze results
        successful_uploads = [r for r in results if r["success"]]
        failed_uploads = [r for r in results if not r["success"]]

        success_rate = len(successful_uploads) / num_concurrent_uploads
        average_upload_time = sum(r["upload_time"] for r in results) / len(results)
        max_upload_time = max(r["upload_time"] for r in results)
        min_upload_time = min(r["upload_time"] for r in results)

        # Performance assertions
        assert success_rate >= 0.95, f"Success rate too low: {success_rate:.2%}"
        assert average_upload_time < 5.0, f"Average upload time too high: {average_upload_time:.2f}s"
        assert max_upload_time < 10.0, f"Max upload time too high: {max_upload_time:.2f}s"
        assert total_time < 30.0, f"Total test time too high: {total_time:.2f}s"

        # Verify no duplicate IDs in successful uploads
        successful_ids = [r["response_data"]["id"] for r in successful_uploads if r["response_data"]]
        assert len(successful_ids) == len(set(successful_ids)), "Duplicate detection IDs found"

        print(f"Concurrent Upload Results:")
        print(f"  Total uploads: {num_concurrent_uploads}")
        print(f"  Successful: {len(successful_uploads)} ({success_rate:.2%})")
        print(f"  Failed: {len(failed_uploads)}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Average upload time: {average_upload_time:.2f}s")
        print(f"  Min/Max upload time: {min_upload_time:.2f}s / {max_upload_time:.2f}s")

    @pytest.mark.asyncio
    async def test_concurrent_detection_uploads_async(self, auth_token, base_url):
        """Test concurrent detection uploads using async/await."""
        num_concurrent_uploads = 25
        concurrent_limit = 10  # Limit concurrent connections

        # Generate test data
        test_detections = [
            self.generate_test_detection(i) for i in range(num_concurrent_uploads)
        ]

        async def upload_detection_async(session, detection_data, index):
            """Upload a single detection asynchronously."""
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json"
            }

            start_time = time.time()

            try:
                async with session.post(
                    f"{base_url}/api/v1/detections/",
                    json=detection_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    end_time = time.time()
                    upload_time = end_time - start_time

                    response_data = await response.json() if response.status == 201 else None

                    return {
                        "index": index,
                        "status_code": response.status,
                        "success": response.status == 201,
                        "upload_time": upload_time,
                        "response_data": response_data,
                        "error": None
                    }

            except Exception as e:
                end_time = time.time()
                upload_time = end_time - start_time

                return {
                    "index": index,
                    "status_code": None,
                    "success": False,
                    "upload_time": upload_time,
                    "response_data": None,
                    "error": str(e)
                }

        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(concurrent_limit)

        async def limited_upload(session, detection_data, index):
            """Upload with concurrency limiting."""
            async with semaphore:
                return await upload_detection_async(session, detection_data, index)

        start_time = time.time()

        # Create aiohttp session with connection limits
        connector = aiohttp.TCPConnector(limit=concurrent_limit, limit_per_host=concurrent_limit)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks for all uploads
            tasks = [
                limited_upload(session, test_detections[i], i)
                for i in range(num_concurrent_uploads)
            ]

            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_time = end_time - start_time

        # Analyze results
        successful_uploads = [r for r in results if r["success"]]
        failed_uploads = [r for r in results if not r["success"]]

        success_rate = len(successful_uploads) / num_concurrent_uploads
        average_upload_time = sum(r["upload_time"] for r in results) / len(results)

        # Async performance should be better than sync
        assert success_rate >= 0.95, f"Async success rate too low: {success_rate:.2%}"
        assert average_upload_time < 3.0, f"Async average upload time too high: {average_upload_time:.2f}s"
        assert total_time < 20.0, f"Async total time too high: {total_time:.2f}s"

        print(f"Async Concurrent Upload Results:")
        print(f"  Total uploads: {num_concurrent_uploads}")
        print(f"  Successful: {len(successful_uploads)} ({success_rate:.2%})")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Average upload time: {average_upload_time:.2f}s")

    def test_large_detection_upload_performance(self, auth_token, base_url):
        """Test upload performance with large detection rules."""
        num_uploads = 10

        # Generate large detection rules
        large_detections = []
        for i in range(num_uploads):
            # Create large YAML content
            large_yaml = f"""
title: Large Performance Test Detection {i}
description: {fake.text(max_nb_chars=2000)}
references:
    - https://example.com/reference/{i}
    - https://attack.mitre.org/techniques/T1059/
author: Performance Test Suite
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection_base:
        EventID: 1
        Image|endswith: '.exe'
    selection_commands:
        CommandLine|contains:
            """ + "\n            ".join([f"- 'command_{j}_{i}'" for j in range(50)]) + """
    selection_paths:
        Image|contains:
            """ + "\n            ".join([f"- 'path_{j}_{i}'" for j in range(30)]) + """
    condition: selection_base and (selection_commands or selection_paths)
falsepositives:
    """ + "\n    ".join([f"- 'False positive {j} for detection {i}'" for j in range(20)]) + """
level: high
tags:
    """ + "\n    ".join([f"- attack.tag_{j}_{i}" for j in range(15)]) + """
            """

            detection_data = {
                "name": f"Large Performance Test Detection {i}",
                "description": fake.text(max_nb_chars=1000),
                "rule_yaml": large_yaml,
                "platforms": ["Windows", "Linux"],
                "data_sources": [
                    "Process Creation", "Command Line", "File Monitoring",
                    "Network Traffic", "Registry", "Authentication Logs"
                ],
                "false_positives": [fake.sentence() for _ in range(10)],
                "tags": [f"large_test_{i}", "performance"] + [fake.word() for _ in range(8)],
                "status": "testing",
                "visibility": "public",
                "confidence_score": 0.8,
            }

            large_detections.append(detection_data)

        # Upload large detections and measure performance
        import requests
        session = requests.Session()

        results = []
        for i, detection_data in enumerate(large_detections):
            result = self.upload_detection_sync(
                session, base_url, auth_token, detection_data, i
            )
            results.append(result)

        # Analyze large upload performance
        successful_large_uploads = [r for r in results if r["success"]]
        average_large_upload_time = sum(r["upload_time"] for r in results) / len(results)

        # Large detections should still upload reasonably fast
        assert len(successful_large_uploads) >= num_uploads * 0.9, "Too many large upload failures"
        assert average_large_upload_time < 8.0, f"Large uploads too slow: {average_large_upload_time:.2f}s"

        # Calculate data size estimates
        avg_detection_size = sum(len(json.dumps(d)) for d in large_detections) / len(large_detections)
        throughput_mb_per_sec = (avg_detection_size * len(successful_large_uploads)) / (1024 * 1024 * sum(r["upload_time"] for r in successful_large_uploads))

        print(f"Large Detection Upload Performance:")
        print(f"  Average detection size: {avg_detection_size:.0f} bytes")
        print(f"  Average upload time: {average_large_upload_time:.2f}s")
        print(f"  Throughput: {throughput_mb_per_sec:.2f} MB/s")

    def test_concurrent_mixed_operations(self, auth_token, base_url):
        """Test concurrent mix of creates, reads, updates, deletes."""
        num_operations = 30

        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        # First, create some detections to work with
        initial_detections = []
        for i in range(10):
            detection_data = self.generate_test_detection(i)
            result = self.upload_detection_sync(session, base_url, auth_token, detection_data, i)
            if result["success"]:
                initial_detections.append(result["response_data"]["id"])

        def mixed_operation(operation_type, index):
            """Perform a mixed operation."""
            start_time = time.time()

            try:
                if operation_type == "create":
                    detection_data = self.generate_test_detection(index + 1000)
                    response = session.post(
                        f"{base_url}/api/v1/detections/",
                        json=detection_data,
                        headers=headers
                    )
                    success = response.status_code == 201

                elif operation_type == "read":
                    response = session.get(
                        f"{base_url}/api/v1/detections/",
                        params={"per_page": 20},
                        headers=headers
                    )
                    success = response.status_code == 200

                elif operation_type == "update" and initial_detections:
                    detection_id = fake.random_element(initial_detections)
                    update_data = {
                        "description": f"Updated at {time.time()}",
                        "confidence_score": round(fake.random.uniform(0.1, 1.0), 2)
                    }
                    response = session.put(
                        f"{base_url}/api/v1/detections/{detection_id}",
                        json=update_data,
                        headers=headers
                    )
                    success = response.status_code in [200, 404]  # 404 if already deleted

                elif operation_type == "delete" and initial_detections:
                    detection_id = fake.random_element(initial_detections)
                    response = session.delete(
                        f"{base_url}/api/v1/detections/{detection_id}",
                        headers=headers
                    )
                    success = response.status_code in [204, 404]  # 404 if already deleted
                    if response.status_code == 204:
                        try:
                            initial_detections.remove(detection_id)
                        except ValueError:
                            pass

                else:
                    success = True  # Skip unsupported operations

                end_time = time.time()
                operation_time = end_time - start_time

                return {
                    "operation": operation_type,
                    "index": index,
                    "success": success,
                    "operation_time": operation_time,
                    "error": None
                }

            except Exception as e:
                end_time = time.time()
                operation_time = end_time - start_time

                return {
                    "operation": operation_type,
                    "index": index,
                    "success": False,
                    "operation_time": operation_time,
                    "error": str(e)
                }

        # Generate mix of operations
        operations = []
        for i in range(num_operations):
            op_type = fake.random_element(["create", "read", "read", "update", "delete"])  # Bias toward reads
            operations.append((op_type, i))

        # Execute mixed operations concurrently
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=8) as executor:
            future_to_op = {
                executor.submit(mixed_operation, op_type, index): (op_type, index)
                for op_type, index in operations
            }

            results = []
            for future in as_completed(future_to_op):
                result = future.result()
                results.append(result)

        end_time = time.time()
        total_time = end_time - start_time

        # Analyze mixed operation results
        successful_ops = [r for r in results if r["success"]]
        op_types = {}
        for result in results:
            op_type = result["operation"]
            if op_type not in op_types:
                op_types[op_type] = {"total": 0, "successful": 0, "avg_time": 0}
            op_types[op_type]["total"] += 1
            if result["success"]:
                op_types[op_type]["successful"] += 1

        # Calculate average times per operation type
        for op_type in op_types:
            op_results = [r for r in results if r["operation"] == op_type]
            op_types[op_type]["avg_time"] = sum(r["operation_time"] for r in op_results) / len(op_results)

        success_rate = len(successful_ops) / num_operations

        # Mixed operations should maintain good performance
        assert success_rate >= 0.90, f"Mixed operation success rate too low: {success_rate:.2%}"
        assert total_time < 45.0, f"Mixed operations took too long: {total_time:.2f}s"

        print(f"Mixed Operations Performance:")
        print(f"  Total operations: {num_operations}")
        print(f"  Success rate: {success_rate:.2%}")
        print(f"  Total time: {total_time:.2f}s")
        for op_type, stats in op_types.items():
            print(f"  {op_type}: {stats['successful']}/{stats['total']} "
                  f"({stats['successful']/stats['total']:.2%}) "
                  f"avg: {stats['avg_time']:.2f}s")

    def test_memory_usage_during_concurrent_uploads(self, auth_token, base_url):
        """Test memory usage during concurrent uploads."""
        try:
            import psutil
            import os
        except ImportError:
            pytest.skip("psutil not available for memory monitoring")

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        num_uploads = 50
        test_detections = [self.generate_test_detection(i) for i in range(num_uploads)]

        memory_samples = []

        def monitor_memory():
            """Monitor memory usage during uploads."""
            while True:
                try:
                    current_memory = process.memory_info().rss / 1024 / 1024  # MB
                    memory_samples.append(current_memory)
                    time.sleep(0.1)  # Sample every 100ms
                except:
                    break

        # Start memory monitoring in background
        import threading
        memory_thread = threading.Thread(target=monitor_memory, daemon=True)
        memory_thread.start()

        # Perform concurrent uploads
        import requests
        session = requests.Session()

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [
                executor.submit(
                    self.upload_detection_sync,
                    session,
                    base_url,
                    auth_token,
                    test_detections[i],
                    i
                ) for i in range(num_uploads)
            ]

            results = [future.result() for future in as_completed(futures)]

        # Stop memory monitoring
        memory_thread = None

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        peak_memory = max(memory_samples) if memory_samples else final_memory
        memory_growth = peak_memory - initial_memory

        successful_uploads = len([r for r in results if r["success"]])

        # Memory usage should be reasonable
        assert memory_growth < 100, f"Memory growth too high: {memory_growth:.2f} MB"
        assert successful_uploads >= num_uploads * 0.95, "Too many upload failures during memory test"

        print(f"Memory Usage During Concurrent Uploads:")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        print(f"  Peak memory: {peak_memory:.2f} MB")
        print(f"  Memory growth: {memory_growth:.2f} MB")
        print(f"  Successful uploads: {successful_uploads}/{num_uploads}")