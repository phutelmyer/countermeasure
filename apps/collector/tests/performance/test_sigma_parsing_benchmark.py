"""
Performance benchmarks for SIGMA parsing speed.

Tests parsing performance across different rule complexities,
file sizes, and batch processing scenarios.
"""

import pytest
import time
import tempfile
import statistics
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import yaml

from src.collectors.detection.sigma_parser import SigmaParser
from src.collectors.detection.sigma_enricher import SigmaEnricher


class TestSigmaParsingBenchmark:
    """Benchmark SIGMA parsing performance."""

    def generate_simple_sigma_rule(self, index):
        """Generate a simple SIGMA rule for benchmarking."""
        return f"""
title: Simple Benchmark Rule {index}
id: benchmark-{index:08d}-1234-5678-9abc-def012345678
description: Simple rule for performance benchmarking
author: Benchmark Suite
date: 2024/01/01
status: experimental
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
        CommandLine|contains: 'benchmark_{index}'
    condition: selection
falsepositives:
    - Legitimate benchmark process
level: medium
tags:
    - attack.execution
    - attack.t1059
    - benchmark
        """

    def generate_complex_sigma_rule(self, index):
        """Generate a complex SIGMA rule for benchmarking."""
        # Create complex rule with many conditions and fields
        return f"""
title: Complex Benchmark Rule {index}
id: complex-{index:08d}-abcd-ef12-3456-789012345678
description: Complex rule with multiple conditions for performance benchmarking
author: Benchmark Suite
date: 2024/01/01
modified: 2024/01/01
status: experimental
references:
    - https://attack.mitre.org/techniques/T1059/
    - https://example.com/reference/{index}
    - https://benchmark.test/rule/{index}
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection_base:
        EventID: 1
        Image|endswith:
            - '.exe'
            - '.scr'
            - '.pif'
            - '.com'
            - '.bat'
    selection_paths:
        Image|contains:
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'
            - '\\\\Downloads\\\\'
            - '\\\\Users\\\\Public\\\\'
    selection_commands:
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'cscript'
            - 'mshta'
            - 'rundll32'
            - 'regsvr32'
            - 'bitsadmin'
            - 'certutil'
            - 'msiexec'
    selection_suspicious:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'invoke-expression'
            - 'downloadstring'
            - 'iex'
            - 'bypass'
            - 'hidden'
            - 'noprofile'
            - 'noninteractive'
            - 'windowstyle'
    filter_legitimate:
        ParentImage|endswith:
            - '\\\\explorer.exe'
            - '\\\\services.exe'
            - '\\\\winlogon.exe'
            - '\\\\system32\\\\svchost.exe'
        User|contains:
            - 'SYSTEM'
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
    condition: (selection_base and (selection_paths or selection_commands or selection_suspicious)) and not filter_legitimate
falsepositives:
    - Legitimate administrative tools
    - Software installation processes
    - System maintenance scripts
    - Security monitoring tools
    - Backup software operations
    - Development and testing environments
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - attack.defense_evasion
    - attack.t1218
    - attack.t1064
    - powershell
    - command_line
    - suspicious_process
    - complex_benchmark_{index}
        """

    def generate_mega_complex_sigma_rule(self, index):
        """Generate an extremely complex SIGMA rule for stress testing."""
        # Create rule with many nested conditions and extensive content
        command_variants = [f"command_variant_{i}" for i in range(20)]
        file_paths = [f"\\\\path_{i}\\\\" for i in range(15)]
        process_names = [f"process_{i}.exe" for i in range(25)]

        return f"""
title: Mega Complex Benchmark Rule {index}
id: mega-{index:08d}-9999-8888-7777-666655554444
description: Extremely complex rule with hundreds of conditions for stress testing parser performance. This rule includes extensive detection logic with multiple selection criteria, complex filtering, and comprehensive false positive handling.
author: Performance Stress Test Suite
date: 2024/01/01
modified: 2024/01/01
status: experimental
references:
    - https://attack.mitre.org/techniques/T1059/
    - https://attack.mitre.org/techniques/T1055/
    - https://attack.mitre.org/techniques/T1218/
    - https://example.com/mega-complex-rule/{index}
    - https://benchmark.test/stress/{index}
    - https://security.research/complex-detections/{index}
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection_base:
        EventID: 1
    selection_executables:
        Image|endswith: {yaml.dump(process_names, default_flow_style=True)}
    selection_file_paths:
        Image|contains: {yaml.dump(file_paths, default_flow_style=True)}
    selection_command_variants:
        CommandLine|contains: {yaml.dump(command_variants, default_flow_style=True)}
    selection_powershell_variants:
        CommandLine|contains:
            - 'powershell'
            - 'pwsh'
            - 'powershell.exe'
            - 'powershell_ise.exe'
            - 'System.Management.Automation'
    selection_encoding_techniques:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'frombase64string'
            - 'convert::frombase64string'
            - '[convert]::frombase64string'
            - 'system.convert::frombase64string'
            - 'text.encoding'
            - '[text.encoding]'
            - 'ascii.getstring'
            - 'unicode.getstring'
            - 'utf8.getstring'
    selection_obfuscation:
        CommandLine|contains:
            - 'invoke-expression'
            - 'iex'
            - 'invoke-command'
            - 'icm'
            - 'get-content'
            - 'gc'
            - 'out-string'
            - 'out-file'
            - 'set-content'
            - 'add-content'
    selection_network_activity:
        CommandLine|contains:
            - 'downloadstring'
            - 'downloadfile'
            - 'webclient'
            - 'system.net.webclient'
            - 'invoke-webrequest'
            - 'iwr'
            - 'invoke-restmethod'
            - 'irm'
            - 'bitstransfer'
            - 'start-bitstransfer'
    filter_system_processes:
        ParentImage|endswith:
            - '\\\\explorer.exe'
            - '\\\\services.exe'
            - '\\\\winlogon.exe'
            - '\\\\csrss.exe'
            - '\\\\lsass.exe'
            - '\\\\smss.exe'
            - '\\\\wininit.exe'
            - '\\\\system32\\\\svchost.exe'
            - '\\\\system32\\\\dllhost.exe'
            - '\\\\system32\\\\conhost.exe'
    filter_legitimate_users:
        User|contains:
            - 'SYSTEM'
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
            - 'DWM-'
            - 'UMFD-'
    filter_known_good_paths:
        Image|startswith:
            - 'C:\\\\Windows\\\\System32\\\\'
            - 'C:\\\\Windows\\\\SysWOW64\\\\'
            - 'C:\\\\Program Files\\\\'
            - 'C:\\\\Program Files (x86)\\\\'
    filter_signed_binaries:
        Signed: 'true'
        SignatureStatus: 'Valid'
    condition: selection_base and (selection_executables or selection_file_paths or selection_command_variants or selection_powershell_variants or selection_encoding_techniques or selection_obfuscation or selection_network_activity) and not (filter_system_processes or filter_legitimate_users or filter_known_good_paths or filter_signed_binaries)
falsepositives:
    - Legitimate PowerShell administrative scripts
    - Software installation and update processes
    - System maintenance and monitoring tools
    - Enterprise management software
    - Development and testing environments
    - Backup and archival software
    - Security monitoring and analysis tools
    - Performance monitoring applications
    - IT automation and orchestration tools
    - Cloud management and deployment scripts
    - Database administration and maintenance
    - Network monitoring and diagnostic tools
    - Virtualization management software
    - Container orchestration platforms
    - CI/CD pipeline execution
level: critical
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - attack.defense_evasion
    - attack.t1218
    - attack.t1055
    - attack.t1027
    - attack.command_and_control
    - attack.t1071
    - attack.t1105
    - powershell
    - obfuscation
    - encoding
    - network_activity
    - process_injection
    - command_line
    - suspicious_execution
    - mega_complex_benchmark_{index}
    - stress_test
    - performance_benchmark
        """

    def test_simple_rule_parsing_performance(self):
        """Benchmark parsing performance for simple SIGMA rules."""
        num_rules = 1000
        parser = SigmaParser()

        # Generate simple rules
        simple_rules = [self.generate_simple_sigma_rule(i) for i in range(num_rules)]

        # Benchmark parsing
        parsing_times = []

        for i, rule_content in enumerate(simple_rules):
            start_time = time.time()

            try:
                parsed_rule = parser.parse_yaml_content(rule_content)
                success = parsed_rule is not None
            except Exception:
                success = False

            end_time = time.time()
            parse_time = end_time - start_time
            parsing_times.append(parse_time)

            # Ensure parsing succeeds for valid rules
            assert success, f"Failed to parse simple rule {i}"

        # Analyze performance
        total_time = sum(parsing_times)
        average_time = statistics.mean(parsing_times)
        median_time = statistics.median(parsing_times)
        max_time = max(parsing_times)
        min_time = min(parsing_times)
        std_dev = statistics.stdev(parsing_times)

        # Performance assertions for simple rules
        assert average_time < 0.01, f"Simple rule parsing too slow: {average_time:.4f}s average"
        assert max_time < 0.05, f"Simple rule max parse time too high: {max_time:.4f}s"
        assert total_time < 20.0, f"Total simple parsing time too high: {total_time:.2f}s"

        # Calculate throughput
        rules_per_second = num_rules / total_time

        print(f"Simple Rule Parsing Performance:")
        print(f"  Rules parsed: {num_rules}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average time per rule: {average_time*1000:.2f}ms")
        print(f"  Median time per rule: {median_time*1000:.2f}ms")
        print(f"  Min/Max time: {min_time*1000:.2f}ms / {max_time*1000:.2f}ms")
        print(f"  Standard deviation: {std_dev*1000:.2f}ms")
        print(f"  Throughput: {rules_per_second:.1f} rules/second")

    def test_complex_rule_parsing_performance(self):
        """Benchmark parsing performance for complex SIGMA rules."""
        num_rules = 200
        parser = SigmaParser()

        # Generate complex rules
        complex_rules = [self.generate_complex_sigma_rule(i) for i in range(num_rules)]

        # Benchmark parsing
        parsing_times = []
        successful_parses = 0

        for i, rule_content in enumerate(complex_rules):
            start_time = time.time()

            try:
                parsed_rule = parser.parse_yaml_content(rule_content)
                if parsed_rule is not None:
                    successful_parses += 1
                    success = True
                else:
                    success = False
            except Exception:
                success = False

            end_time = time.time()
            parse_time = end_time - start_time
            parsing_times.append(parse_time)

            # Most complex rules should parse successfully
            if not success and i < 10:  # Check first 10 for debugging
                print(f"Warning: Failed to parse complex rule {i}")

        # Analyze performance
        total_time = sum(parsing_times)
        average_time = statistics.mean(parsing_times)
        success_rate = successful_parses / num_rules

        # Performance assertions for complex rules
        assert success_rate >= 0.95, f"Complex rule success rate too low: {success_rate:.2%}"
        assert average_time < 0.05, f"Complex rule parsing too slow: {average_time:.4f}s average"
        assert total_time < 30.0, f"Total complex parsing time too high: {total_time:.2f}s"

        rules_per_second = successful_parses / total_time

        print(f"Complex Rule Parsing Performance:")
        print(f"  Rules parsed: {num_rules}")
        print(f"  Successful parses: {successful_parses} ({success_rate:.1%})")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average time per rule: {average_time*1000:.2f}ms")
        print(f"  Throughput: {rules_per_second:.1f} rules/second")

    def test_mega_complex_rule_parsing_performance(self):
        """Benchmark parsing performance for extremely complex SIGMA rules."""
        num_rules = 50
        parser = SigmaParser()

        # Generate mega complex rules
        mega_rules = [self.generate_mega_complex_sigma_rule(i) for i in range(num_rules)]

        # Benchmark parsing
        parsing_times = []
        successful_parses = 0

        for i, rule_content in enumerate(mega_rules):
            start_time = time.time()

            try:
                parsed_rule = parser.parse_yaml_content(rule_content)
                if parsed_rule is not None:
                    successful_parses += 1
                    success = True
                else:
                    success = False
            except Exception as e:
                success = False
                # Log first few failures for debugging
                if i < 5:
                    print(f"Mega complex rule {i} parse error: {e}")

            end_time = time.time()
            parse_time = end_time - start_time
            parsing_times.append(parse_time)

        # Analyze performance
        total_time = sum(parsing_times)
        average_time = statistics.mean(parsing_times)
        success_rate = successful_parses / num_rules

        # Performance assertions for mega complex rules (more lenient)
        assert success_rate >= 0.8, f"Mega complex rule success rate too low: {success_rate:.2%}"
        assert average_time < 0.2, f"Mega complex rule parsing too slow: {average_time:.4f}s average"
        assert total_time < 20.0, f"Total mega complex parsing time too high: {total_time:.2f}s"

        if successful_parses > 0:
            rules_per_second = successful_parses / total_time
        else:
            rules_per_second = 0

        print(f"Mega Complex Rule Parsing Performance:")
        print(f"  Rules parsed: {num_rules}")
        print(f"  Successful parses: {successful_parses} ({success_rate:.1%})")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average time per rule: {average_time*1000:.2f}ms")
        print(f"  Throughput: {rules_per_second:.1f} rules/second")

    def test_concurrent_parsing_performance(self):
        """Test parsing performance with concurrent workers."""
        num_rules = 500
        max_workers = 4

        # Generate mixed complexity rules
        rules = []
        for i in range(num_rules):
            if i % 3 == 0:
                rules.append(self.generate_complex_sigma_rule(i))
            else:
                rules.append(self.generate_simple_sigma_rule(i))

        def parse_rule(rule_content):
            """Parse a single rule and return timing info."""
            parser = SigmaParser()
            start_time = time.time()

            try:
                parsed_rule = parser.parse_yaml_content(rule_content)
                success = parsed_rule is not None
            except Exception:
                success = False

            end_time = time.time()
            return {
                "parse_time": end_time - start_time,
                "success": success
            }

        # Test sequential parsing
        sequential_start = time.time()
        sequential_results = [parse_rule(rule) for rule in rules]
        sequential_time = time.time() - sequential_start

        # Test concurrent parsing
        concurrent_start = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            concurrent_results = list(executor.map(parse_rule, rules))
        concurrent_time = time.time() - concurrent_start

        # Analyze results
        sequential_success = sum(1 for r in sequential_results if r["success"])
        concurrent_success = sum(1 for r in concurrent_results if r["success"])

        sequential_rate = sequential_success / sequential_time
        concurrent_rate = concurrent_success / concurrent_time
        speedup = concurrent_rate / sequential_rate

        # Concurrent parsing should be faster
        assert concurrent_success >= sequential_success * 0.95, "Concurrent parsing had more failures"
        assert speedup > 1.5, f"Concurrent speedup too low: {speedup:.2f}x"
        assert concurrent_time < sequential_time, "Concurrent parsing should be faster"

        print(f"Concurrent Parsing Performance:")
        print(f"  Rules: {num_rules}, Workers: {max_workers}")
        print(f"  Sequential: {sequential_time:.2f}s ({sequential_rate:.1f} rules/s)")
        print(f"  Concurrent: {concurrent_time:.2f}s ({concurrent_rate:.1f} rules/s)")
        print(f"  Speedup: {speedup:.2f}x")

    def test_batch_file_parsing_performance(self):
        """Test parsing performance when processing batch files."""
        batch_sizes = [10, 50, 100, 200]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            for batch_size in batch_sizes:
                # Create batch of SIGMA files
                rule_files = []
                for i in range(batch_size):
                    rule_file = temp_path / f"batch_rule_{i:03d}.yml"
                    rule_content = self.generate_simple_sigma_rule(i)
                    rule_file.write_text(rule_content)
                    rule_files.append(rule_file)

                # Benchmark batch processing
                parser = SigmaParser()
                start_time = time.time()

                parsed_rules = []
                for rule_file in rule_files:
                    try:
                        parsed_rule = parser.parse_file(rule_file)
                        if parsed_rule:
                            parsed_rules.append(parsed_rule)
                    except Exception:
                        pass  # Continue with other files

                end_time = time.time()
                batch_time = end_time - start_time

                success_rate = len(parsed_rules) / batch_size
                throughput = len(parsed_rules) / batch_time

                # Batch processing should be efficient
                assert success_rate >= 0.95, f"Batch success rate too low: {success_rate:.2%}"
                assert throughput > 50, f"Batch throughput too low: {throughput:.1f} rules/s"

                print(f"Batch Processing (size {batch_size}): "
                      f"{batch_time:.3f}s, {throughput:.1f} rules/s")

    def test_memory_usage_during_parsing(self):
        """Test memory usage during intensive parsing."""
        try:
            import psutil
            import os
        except ImportError:
            pytest.skip("psutil not available for memory monitoring")

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Parse many rules to test memory usage
        num_rules = 1000
        parser = SigmaParser()

        memory_samples = []

        for i in range(num_rules):
            # Generate and parse rule
            if i % 2 == 0:
                rule_content = self.generate_complex_sigma_rule(i)
            else:
                rule_content = self.generate_simple_sigma_rule(i)

            try:
                parser.parse_yaml_content(rule_content)
            except Exception:
                pass  # Continue parsing

            # Sample memory every 50 rules
            if i % 50 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_samples.append(current_memory)

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        peak_memory = max(memory_samples) if memory_samples else final_memory
        memory_growth = peak_memory - initial_memory

        # Memory usage should be reasonable
        assert memory_growth < 50, f"Memory growth too high: {memory_growth:.2f} MB"

        print(f"Memory Usage During Parsing:")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        print(f"  Peak memory: {peak_memory:.2f} MB")
        print(f"  Memory growth: {memory_growth:.2f} MB")
        print(f"  Rules parsed: {num_rules}")

    def test_enrichment_performance(self):
        """Test performance of SIGMA rule enrichment."""
        num_rules = 200
        enricher = SigmaEnricher()

        # Generate rules with various content for enrichment
        test_rules = []
        for i in range(num_rules):
            rule_content = self.generate_complex_sigma_rule(i)
            test_rules.append(rule_content)

        # Benchmark enrichment
        enrichment_times = []
        successful_enrichments = 0

        for i, rule_content in enumerate(test_rules):
            start_time = time.time()

            try:
                enriched_data = enricher.enrich_sigma_rule(rule_content)
                if enriched_data:
                    successful_enrichments += 1
                    success = True
                else:
                    success = False
            except Exception:
                success = False

            end_time = time.time()
            enrichment_time = end_time - start_time
            enrichment_times.append(enrichment_time)

        # Analyze enrichment performance
        total_time = sum(enrichment_times)
        average_time = statistics.mean(enrichment_times)
        success_rate = successful_enrichments / num_rules

        # Enrichment should be fast
        assert success_rate >= 0.9, f"Enrichment success rate too low: {success_rate:.2%}"
        assert average_time < 0.02, f"Enrichment too slow: {average_time:.4f}s average"

        throughput = successful_enrichments / total_time

        print(f"SIGMA Enrichment Performance:")
        print(f"  Rules enriched: {num_rules}")
        print(f"  Success rate: {success_rate:.1%}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average time per rule: {average_time*1000:.2f}ms")
        print(f"  Throughput: {throughput:.1f} enrichments/second")

    def test_end_to_end_processing_performance(self):
        """Test end-to-end processing performance (parse + enrich + validate)."""
        num_rules = 100

        parser = SigmaParser()
        enricher = SigmaEnricher()

        # Generate test rules
        test_rules = [self.generate_complex_sigma_rule(i) for i in range(num_rules)]

        # Benchmark end-to-end processing
        e2e_times = []
        successful_processing = 0

        for i, rule_content in enumerate(test_rules):
            start_time = time.time()

            try:
                # Parse
                parsed_rule = parser.parse_yaml_content(rule_content)
                if not parsed_rule:
                    continue

                # Enrich
                enriched_data = enricher.enrich_sigma_rule(rule_content)
                if not enriched_data:
                    continue

                # Basic validation (check required fields)
                if (enriched_data.get("name") and
                    enriched_data.get("platforms") and
                    enriched_data.get("data_sources")):
                    successful_processing += 1

                success = True

            except Exception:
                success = False

            end_time = time.time()
            e2e_time = end_time - start_time
            e2e_times.append(e2e_time)

        # Analyze end-to-end performance
        total_time = sum(e2e_times)
        average_time = statistics.mean(e2e_times)
        success_rate = successful_processing / num_rules

        # End-to-end processing should be efficient
        assert success_rate >= 0.85, f"E2E success rate too low: {success_rate:.2%}"
        assert average_time < 0.1, f"E2E processing too slow: {average_time:.4f}s average"

        throughput = successful_processing / total_time

        print(f"End-to-End Processing Performance:")
        print(f"  Rules processed: {num_rules}")
        print(f"  Success rate: {success_rate:.1%}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average time per rule: {average_time*1000:.2f}ms")
        print(f"  Throughput: {throughput:.1f} rules/second")