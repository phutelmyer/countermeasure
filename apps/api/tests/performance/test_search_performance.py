"""
Performance tests for search functionality.

Tests search performance across large datasets including
full-text search, filtering, pagination, and complex queries.
"""

import pytest
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from faker import Faker

fake = Faker()


class TestSearchPerformance:
    """Test search performance with large datasets."""

    @pytest.fixture
    def auth_token(self):
        """Get authentication token for testing."""
        return "test_auth_token_for_search_performance"

    @pytest.fixture
    def base_url(self):
        """Base URL for API testing."""
        return "http://localhost:8000"

    @pytest.fixture
    def large_dataset(self, auth_token, base_url):
        """Create large dataset for search testing."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        created_detection_ids = []
        created_actor_ids = []

        # Create diverse actors
        actor_types = ["nation_state", "cybercriminal", "hacktivist", "unknown"]
        countries = ["Russia", "China", "North Korea", "Iran", "Unknown", "USA", "Israel"]

        for i in range(50):  # Create 50 actors
            actor_data = {
                "name": f"Test Actor {i:03d} {fake.company()}",
                "aliases": [f"Alias{i}", f"Group{i}", fake.word().title()],
                "description": f"{fake.text(max_nb_chars=200)} Actor {i} specializes in {fake.word()} operations.",
                "country": random.choice(countries),
                "motivation": random.choice(["Financial Gain", "Espionage", "Hacktivism", "Testing", "Disruption"]),
                "first_seen": f"202{random.randint(0, 4)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
                "actor_type": random.choice(actor_types),
                "sophistication": random.choice(["novice", "intermediate", "advanced", "expert"]),
                "resource_level": random.choice(["individual", "club", "contest", "team", "organization", "government"]),
            }

            try:
                response = session.post(f"{base_url}/api/v1/actors/", json=actor_data, headers=headers)
                if response.status_code == 201:
                    created_actor_ids.append(response.json()["id"])
            except:
                pass  # Continue creating other actors

        # Create diverse detections with searchable content
        platforms = ["Windows", "Linux", "macOS"]
        data_sources = [
            "Process Creation", "Network Traffic", "File Monitoring", "Registry",
            "Authentication Logs", "Command Line", "DNS", "HTTP", "Email"
        ]

        search_keywords = [
            "powershell", "malware", "suspicious", "attack", "trojan", "backdoor",
            "persistence", "lateral", "movement", "credential", "dump", "injection",
            "shellcode", "payload", "command", "control", "exfiltration", "phishing"
        ]

        for i in range(500):  # Create 500 detections
            # Include searchable keywords in various fields
            selected_keywords = random.sample(search_keywords, k=random.randint(1, 4))

            detection_data = {
                "name": f"Detection {i:03d}: {' '.join(selected_keywords).title()} Activity",
                "description": f"{fake.text(max_nb_chars=300)} This detection identifies {random.choice(selected_keywords)} behavior patterns used by threat actors.",
                "rule_yaml": f"""
title: Performance Test Detection {i:03d}
description: {fake.sentence()} Detects {random.choice(selected_keywords)} activity patterns.
references:
    - https://attack.mitre.org/techniques/T{random.randint(1000, 1599)}/
author: Performance Test Suite
date: 2024/01/01
logsource:
    category: {random.choice(['process_creation', 'network_connection', 'file_event', 'registry_event'])}
    product: {random.choice(['windows', 'linux', 'macos'])}
    service: {random.choice(['sysmon', 'auditd', 'osquery'])}
detection:
    selection:
        EventID: {random.randint(1, 25)}
        {random.choice(['Image', 'CommandLine', 'TargetFilename'])}|contains: '{random.choice(selected_keywords)}'
    condition: selection
falsepositives:
    - Legitimate {random.choice(selected_keywords)} usage
    - Administrative tools
level: {random.choice(['low', 'medium', 'high', 'critical'])}
tags:
    - attack.{random.choice(['execution', 'persistence', 'privilege_escalation', 'defense_evasion'])}
    - attack.t{random.randint(1000, 1599)}
    - {random.choice(selected_keywords)}
                """,
                "platforms": random.sample(platforms, k=random.randint(1, 3)),
                "data_sources": random.sample(data_sources, k=random.randint(1, 5)),
                "false_positives": [
                    f"Legitimate {random.choice(selected_keywords)} usage",
                    f"Administrative {fake.word()} tools",
                    f"Security {fake.word()} software"
                ],
                "tags": selected_keywords + [f"tag_{random.randint(1, 100)}", "performance_test"],
                "status": random.choice(["draft", "testing", "active", "deprecated"]),
                "visibility": random.choice(["public", "private"]),
                "confidence_score": round(random.uniform(0.1, 1.0), 2),
            }

            # Randomly associate with actors
            if created_actor_ids and random.choice([True, False]):
                detection_data["actor_ids"] = random.sample(
                    created_actor_ids,
                    k=min(random.randint(1, 3), len(created_actor_ids))
                )

            try:
                response = session.post(f"{base_url}/api/v1/detections/", json=detection_data, headers=headers)
                if response.status_code == 201:
                    created_detection_ids.append(response.json()["id"])
            except:
                pass  # Continue creating other detections

        return {
            "detection_ids": created_detection_ids,
            "actor_ids": created_actor_ids,
            "total_detections": len(created_detection_ids),
            "total_actors": len(created_actor_ids)
        }

    def test_basic_search_performance(self, auth_token, base_url, large_dataset):
        """Test basic search performance across different search terms."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        search_terms = [
            "powershell", "malware", "suspicious", "attack", "windows",
            "process", "network", "file", "registry", "credential"
        ]

        search_results = []

        for search_term in search_terms:
            start_time = time.time()

            response = session.get(
                f"{base_url}/api/v1/detections/",
                params={"search": search_term, "per_page": 50},
                headers=headers
            )

            end_time = time.time()
            search_time = end_time - start_time

            if response.status_code == 200:
                data = response.json()
                result_count = len(data.get("items", []))
                total_count = data.get("total", 0)

                search_results.append({
                    "term": search_term,
                    "search_time": search_time,
                    "result_count": result_count,
                    "total_matches": total_count,
                    "success": True
                })
            else:
                search_results.append({
                    "term": search_term,
                    "search_time": search_time,
                    "success": False
                })

        # Analyze search performance
        successful_searches = [r for r in search_results if r["success"]]
        average_search_time = sum(r["search_time"] for r in successful_searches) / len(successful_searches)
        max_search_time = max(r["search_time"] for r in successful_searches)

        # Performance assertions
        assert len(successful_searches) == len(search_terms), "Some searches failed"
        assert average_search_time < 2.0, f"Average search time too high: {average_search_time:.2f}s"
        assert max_search_time < 5.0, f"Max search time too high: {max_search_time:.2f}s"

        print(f"Basic Search Performance Results:")
        print(f"  Dataset size: {large_dataset['total_detections']} detections")
        print(f"  Average search time: {average_search_time:.3f}s")
        print(f"  Max search time: {max_search_time:.3f}s")
        print(f"  Search terms tested: {len(search_terms)}")

        for result in search_results:
            if result["success"]:
                print(f"    '{result['term']}': {result['search_time']:.3f}s "
                      f"({result['total_matches']} matches)")

    def test_pagination_performance(self, auth_token, base_url, large_dataset):
        """Test pagination performance with large result sets."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Test different page sizes
        page_sizes = [10, 25, 50, 100]
        pagination_results = []

        for page_size in page_sizes:
            # Test first few pages
            for page in [1, 2, 3, 5, 10]:
                start_time = time.time()

                response = session.get(
                    f"{base_url}/api/v1/detections/",
                    params={"page": page, "per_page": page_size},
                    headers=headers
                )

                end_time = time.time()
                page_time = end_time - start_time

                if response.status_code == 200:
                    data = response.json()
                    result_count = len(data.get("items", []))

                    pagination_results.append({
                        "page_size": page_size,
                        "page": page,
                        "page_time": page_time,
                        "result_count": result_count,
                        "success": True
                    })
                else:
                    pagination_results.append({
                        "page_size": page_size,
                        "page": page,
                        "page_time": page_time,
                        "success": False
                    })

        # Analyze pagination performance
        successful_pages = [r for r in pagination_results if r["success"]]

        # Group by page size
        by_page_size = {}
        for result in successful_pages:
            size = result["page_size"]
            if size not in by_page_size:
                by_page_size[size] = []
            by_page_size[size].append(result)

        print(f"Pagination Performance Results:")
        for page_size, results in by_page_size.items():
            avg_time = sum(r["page_time"] for r in results) / len(results)
            max_time = max(r["page_time"] for r in results)
            print(f"  Page size {page_size}: avg {avg_time:.3f}s, max {max_time:.3f}s")

            # Larger page sizes should not be disproportionately slower
            assert avg_time < 3.0, f"Page size {page_size} too slow: {avg_time:.2f}s"

    def test_complex_filter_performance(self, auth_token, base_url, large_dataset):
        """Test performance of complex filter combinations."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        complex_queries = [
            # Single filters
            {"status": "active"},
            {"platform": "Windows"},
            {"visibility": "public"},

            # Multiple filters
            {"status": "active", "platform": "Windows"},
            {"status": "active", "visibility": "public"},
            {"platform": "Windows", "visibility": "public"},

            # With search
            {"search": "malware", "status": "active"},
            {"search": "powershell", "platform": "Windows"},

            # Complex combinations
            {"search": "suspicious", "status": "active", "platform": "Windows", "visibility": "public"},
            {"search": "attack", "status": "testing", "per_page": 100},
        ]

        filter_results = []

        for i, query_params in enumerate(complex_queries):
            start_time = time.time()

            response = session.get(
                f"{base_url}/api/v1/detections/",
                params=query_params,
                headers=headers
            )

            end_time = time.time()
            query_time = end_time - start_time

            if response.status_code == 200:
                data = response.json()
                result_count = len(data.get("items", []))
                total_matches = data.get("total", 0)

                filter_results.append({
                    "query_index": i,
                    "params": query_params,
                    "query_time": query_time,
                    "result_count": result_count,
                    "total_matches": total_matches,
                    "success": True
                })
            else:
                filter_results.append({
                    "query_index": i,
                    "params": query_params,
                    "query_time": query_time,
                    "success": False
                })

        # Analyze complex filter performance
        successful_queries = [r for r in filter_results if r["success"]]
        average_query_time = sum(r["query_time"] for r in successful_queries) / len(successful_queries)
        max_query_time = max(r["query_time"] for r in successful_queries)

        # Complex queries should still be reasonably fast
        assert len(successful_queries) == len(complex_queries), "Some complex queries failed"
        assert average_query_time < 3.0, f"Average complex query time too high: {average_query_time:.2f}s"
        assert max_query_time < 8.0, f"Max complex query time too high: {max_query_time:.2f}s"

        print(f"Complex Filter Performance Results:")
        print(f"  Average query time: {average_query_time:.3f}s")
        print(f"  Max query time: {max_query_time:.3f}s")

        # Show details for slowest queries
        sorted_queries = sorted(successful_queries, key=lambda x: x["query_time"], reverse=True)
        print(f"  Slowest queries:")
        for result in sorted_queries[:3]:
            print(f"    {result['query_time']:.3f}s: {result['params']} "
                  f"({result['total_matches']} matches)")

    def test_concurrent_search_performance(self, auth_token, base_url, large_dataset):
        """Test search performance under concurrent load."""
        import requests

        num_concurrent_searches = 20
        search_scenarios = [
            {"search": "malware"},
            {"search": "powershell", "platform": "Windows"},
            {"status": "active"},
            {"search": "attack", "per_page": 50},
            {"platform": "Linux", "visibility": "public"},
            {"search": "suspicious", "status": "testing"},
        ]

        def perform_search(scenario_index):
            """Perform a single search operation."""
            session = requests.Session()
            headers = {"Authorization": f"Bearer {auth_token}"}

            scenario = search_scenarios[scenario_index % len(search_scenarios)]

            start_time = time.time()

            try:
                response = session.get(
                    f"{base_url}/api/v1/detections/",
                    params=scenario,
                    headers=headers,
                    timeout=30
                )

                end_time = time.time()
                search_time = end_time - start_time

                success = response.status_code == 200
                result_count = 0

                if success:
                    data = response.json()
                    result_count = len(data.get("items", []))

                return {
                    "scenario_index": scenario_index,
                    "scenario": scenario,
                    "search_time": search_time,
                    "result_count": result_count,
                    "success": success,
                    "error": None
                }

            except Exception as e:
                end_time = time.time()
                search_time = end_time - start_time

                return {
                    "scenario_index": scenario_index,
                    "scenario": scenario,
                    "search_time": search_time,
                    "result_count": 0,
                    "success": False,
                    "error": str(e)
                }

        # Execute concurrent searches
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(perform_search, i)
                for i in range(num_concurrent_searches)
            ]

            concurrent_results = [future.result() for future in as_completed(futures)]

        end_time = time.time()
        total_time = end_time - start_time

        # Analyze concurrent search performance
        successful_searches = [r for r in concurrent_results if r["success"]]
        failed_searches = [r for r in concurrent_results if not r["success"]]

        success_rate = len(successful_searches) / num_concurrent_searches
        average_search_time = sum(r["search_time"] for r in successful_searches) / len(successful_searches) if successful_searches else 0
        max_search_time = max(r["search_time"] for r in successful_searches) if successful_searches else 0

        # Concurrent searches should maintain good performance
        assert success_rate >= 0.95, f"Concurrent search success rate too low: {success_rate:.2%}"
        assert average_search_time < 5.0, f"Average concurrent search time too high: {average_search_time:.2f}s"
        assert total_time < 30.0, f"Total concurrent search time too high: {total_time:.2f}s"

        print(f"Concurrent Search Performance Results:")
        print(f"  Total searches: {num_concurrent_searches}")
        print(f"  Success rate: {success_rate:.2%}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Average search time: {average_search_time:.3f}s")
        print(f"  Max search time: {max_search_time:.3f}s")
        print(f"  Failed searches: {len(failed_searches)}")

    def test_large_result_set_performance(self, auth_token, base_url, large_dataset):
        """Test performance when returning large result sets."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Test queries that should return many results
        large_result_queries = [
            {"per_page": 100},  # Large page size
            {"per_page": 200},  # Very large page size
            {"status": "active", "per_page": 100},  # Filtered large page
            {"platform": "Windows", "per_page": 150},  # Platform filter with large page
        ]

        large_result_performance = []

        for query_params in large_result_queries:
            start_time = time.time()

            response = session.get(
                f"{base_url}/api/v1/detections/",
                params=query_params,
                headers=headers
            )

            end_time = time.time()
            query_time = end_time - start_time

            if response.status_code == 200:
                data = response.json()
                result_count = len(data.get("items", []))
                response_size = len(response.text)  # Approximate response size

                large_result_performance.append({
                    "params": query_params,
                    "query_time": query_time,
                    "result_count": result_count,
                    "response_size_kb": response_size / 1024,
                    "success": True
                })
            else:
                large_result_performance.append({
                    "params": query_params,
                    "query_time": query_time,
                    "success": False
                })

        # Analyze large result set performance
        successful_queries = [r for r in large_result_performance if r["success"]]

        print(f"Large Result Set Performance:")
        for result in successful_queries:
            per_page = result["params"].get("per_page", 50)
            time_per_item = result["query_time"] / result["result_count"] if result["result_count"] > 0 else 0

            print(f"  Page size {per_page}: {result['query_time']:.3f}s "
                  f"({result['result_count']} items, "
                  f"{result['response_size_kb']:.1f}KB, "
                  f"{time_per_item*1000:.1f}ms/item)")

            # Large result sets should still be reasonably fast
            assert result["query_time"] < 10.0, f"Large result query too slow: {result['query_time']:.2f}s"
            assert time_per_item < 0.05, f"Time per item too high: {time_per_item*1000:.1f}ms"

    def test_search_accuracy_vs_performance(self, auth_token, base_url, large_dataset):
        """Test search accuracy versus performance trade-offs."""
        import requests
        session = requests.Session()
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Test different search approaches
        search_tests = [
            # Exact matches should be fast
            {"search": "Detection 001", "description": "Exact name match"},
            {"search": "powershell", "description": "Single keyword"},

            # Partial matches
            {"search": "Detection", "description": "Common prefix"},
            {"search": "malware attack", "description": "Multiple keywords"},

            # Complex searches
            {"search": "suspicious powershell activity", "description": "Complex phrase"},
            {"search": "lateral movement credential", "description": "Technical terms"},
        ]

        accuracy_results = []

        for test_case in search_tests:
            search_term = test_case["search"]
            description = test_case["description"]

            start_time = time.time()

            response = session.get(
                f"{base_url}/api/v1/detections/",
                params={"search": search_term, "per_page": 100},
                headers=headers
            )

            end_time = time.time()
            search_time = end_time - start_time

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])

                # Analyze result relevance (simple heuristic)
                relevant_results = 0
                for item in items:
                    item_text = (item.get("name", "") + " " + item.get("description", "")).lower()
                    search_words = search_term.lower().split()

                    # Count how many search words appear in the result
                    matches = sum(1 for word in search_words if word in item_text)
                    if matches > 0:
                        relevant_results += 1

                relevance_ratio = relevant_results / len(items) if items else 0

                accuracy_results.append({
                    "search_term": search_term,
                    "description": description,
                    "search_time": search_time,
                    "total_results": len(items),
                    "relevant_results": relevant_results,
                    "relevance_ratio": relevance_ratio,
                    "success": True
                })
            else:
                accuracy_results.append({
                    "search_term": search_term,
                    "description": description,
                    "search_time": search_time,
                    "success": False
                })

        print(f"Search Accuracy vs Performance:")
        for result in accuracy_results:
            if result["success"]:
                print(f"  {result['description']}: {result['search_time']:.3f}s "
                      f"({result['total_results']} results, "
                      f"{result['relevance_ratio']:.2%} relevant)")

                # Relevance should be reasonable for simple searches
                if "exact" in result["description"].lower() or "single" in result["description"].lower():
                    assert result["relevance_ratio"] >= 0.8, f"Low relevance for {result['description']}: {result['relevance_ratio']:.2%}"

                # All searches should complete quickly
                assert result["search_time"] < 5.0, f"Search too slow: {result['description']} took {result['search_time']:.2f}s"