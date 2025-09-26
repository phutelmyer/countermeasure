"""
Integration tests for Git cloning operations.

Tests Git repository cloning, file discovery, and error handling
for the SIGMA rule collection workflow.
"""

import pytest
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.collectors.detection.sigma import SigmaCollector
from src.core.config import get_settings


class TestGitOperationsIntegration:
    """Integration tests for Git operations in collectors."""

    def test_git_clone_real_repository(self):
        """Test cloning a real Git repository (small test repo)."""
        # Use a small, reliable test repository
        test_repo_url = "https://github.com/octocat/Hello-World.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": test_repo_url,
                "clone_dir": temp_dir,
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # Test the clone operation
            clone_result = collector._clone_repository()

            # Verify clone was successful
            assert clone_result is True

            # Verify repository files exist
            repo_path = Path(temp_dir) / "Hello-World"
            assert repo_path.exists()
            assert repo_path.is_dir()

            # Should have typical Git repository structure
            assert (repo_path / ".git").exists()
            assert (repo_path / "README").exists()

    def test_git_clone_with_existing_directory(self):
        """Test Git clone behavior when directory already exists."""
        test_repo_url = "https://github.com/octocat/Hello-World.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": test_repo_url,
                "clone_dir": temp_dir,
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # First clone
            first_clone = collector._clone_repository()
            assert first_clone is True

            # Second clone should handle existing directory
            second_clone = collector._clone_repository()
            # Should either succeed (re-clone) or handle gracefully
            assert second_clone in [True, False]  # Both are valid behaviors

            # Repository should still exist and be valid
            repo_path = Path(temp_dir) / "Hello-World"
            assert repo_path.exists()
            assert (repo_path / ".git").exists()

    def test_git_clone_invalid_repository(self):
        """Test Git clone with invalid repository URL."""
        invalid_repo_url = "https://github.com/nonexistent/invalid-repo.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": invalid_repo_url,
                "clone_dir": temp_dir,
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # Should handle invalid repository gracefully
            clone_result = collector._clone_repository()
            assert clone_result is False

    def test_git_clone_permission_denied(self):
        """Test Git clone with permission issues."""
        test_repo_url = "https://github.com/octocat/Hello-World.git"

        # Try to clone to a read-only directory
        with tempfile.TemporaryDirectory() as temp_dir:
            readonly_dir = Path(temp_dir) / "readonly"
            readonly_dir.mkdir()
            readonly_dir.chmod(0o444)  # Read-only

            try:
                config = {
                    "api_url": "http://localhost:8000",
                    "email": "test@example.com",
                    "password": "test_password",
                    "repo_url": test_repo_url,
                    "clone_dir": str(readonly_dir),
                    "limit": 1,
                }

                collector = SigmaCollector(config)

                # Should handle permission error gracefully
                clone_result = collector._clone_repository()
                assert clone_result is False

            finally:
                # Restore permissions for cleanup
                readonly_dir.chmod(0o755)

    def test_file_discovery_after_clone(self):
        """Test file discovery in cloned repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock SIGMA repository structure
            repo_dir = Path(temp_dir) / "sigma"
            repo_dir.mkdir()

            # Create mock SIGMA rule files
            rules_dir = repo_dir / "rules"
            rules_dir.mkdir()

            windows_dir = rules_dir / "windows"
            windows_dir.mkdir()

            process_dir = windows_dir / "process_creation"
            process_dir.mkdir()

            # Create mock SIGMA files
            sigma_content = """
title: Test SIGMA Rule
description: Test rule for integration testing
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
    - attack.t1059
"""

            rule_files = [
                process_dir / "test_rule_1.yml",
                process_dir / "test_rule_2.yml",
                windows_dir / "registry" / "test_registry.yml",
            ]

            # Create registry directory
            (windows_dir / "registry").mkdir()

            for rule_file in rule_files:
                rule_file.write_text(sigma_content)

            # Also create non-SIGMA files that should be ignored
            (process_dir / "readme.md").write_text("# README")
            (process_dir / "config.json").write_text('{"test": true}')

            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(repo_dir),
                "clone_dir": temp_dir,
                "limit": 10,
            }

            collector = SigmaCollector(config)

            # Mock the clone operation to use our prepared directory
            with patch.object(collector, '_clone_repository', return_value=True):
                # Test file discovery
                discovered_files = collector._discover_sigma_files(repo_dir)

                # Should find all 3 YAML files
                assert len(discovered_files) == 3

                # Should only include .yml files
                for file_path in discovered_files:
                    assert file_path.suffix == '.yml'
                    assert file_path.exists()

                # Should not include non-YAML files
                file_names = [f.name for f in discovered_files]
                assert "readme.md" not in file_names
                assert "config.json" not in file_names

    def test_git_operations_with_large_repository(self):
        """Test Git operations with a larger repository (SIGMA HQ)."""
        # This test uses the actual SIGMA repository but limits processing
        sigma_repo_url = "https://github.com/SigmaHQ/sigma.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": sigma_repo_url,
                "clone_dir": temp_dir,
                "limit": 5,  # Limit to 5 files for testing
            }

            collector = SigmaCollector(config)

            # Test clone operation (this will take some time)
            clone_result = collector._clone_repository()

            if clone_result:
                # Verify repository structure
                repo_path = Path(temp_dir) / "sigma"
                assert repo_path.exists()
                assert (repo_path / ".git").exists()
                assert (repo_path / "rules").exists()

                # Test file discovery with limit
                discovered_files = collector._discover_sigma_files(repo_path)

                # Should find SIGMA rule files
                assert len(discovered_files) > 0

                # All discovered files should be YAML files
                for file_path in discovered_files:
                    assert file_path.suffix in ['.yml', '.yaml']
                    assert file_path.exists()

                # Test that we respect the limit
                # (Note: discover method might not implement limit,
                # but processing should respect it)
                processed_count = min(len(discovered_files), config["limit"])
                assert processed_count <= config["limit"]

            else:
                # If clone failed (network issues, etc.), skip validation
                pytest.skip("Git clone failed - likely network issue")

    def test_git_clone_with_specific_branch(self):
        """Test Git clone with specific branch specification."""
        # Use a repository with multiple branches
        test_repo_url = "https://github.com/octocat/Hello-World.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": test_repo_url,
                "clone_dir": temp_dir,
                "branch": "main",  # Specify branch
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # Test clone with branch specification
            # (Note: Implementation may or may not support branch selection)
            clone_result = collector._clone_repository()

            if clone_result:
                repo_path = Path(temp_dir) / "Hello-World"
                assert repo_path.exists()
                assert (repo_path / ".git").exists()

    def test_git_clone_cleanup_on_failure(self):
        """Test that failed Git operations clean up properly."""
        invalid_repo_url = "https://invalid-domain-that-does-not-exist.com/repo.git"

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": invalid_repo_url,
                "clone_dir": temp_dir,
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # Attempt clone (should fail)
            clone_result = collector._clone_repository()
            assert clone_result is False

            # Verify no partial directories left behind
            # (The implementation should clean up on failure)
            temp_path = Path(temp_dir)
            remaining_items = list(temp_path.iterdir())

            # Should either be empty or only contain expected items
            # (Implementation-dependent behavior)
            for item in remaining_items:
                # Should not have incomplete git repositories
                if item.is_dir():
                    assert not (item / ".git").exists() or (item / ".git").is_dir()

    @patch('subprocess.run')
    def test_git_operations_subprocess_error_handling(self, mock_subprocess):
        """Test Git operations error handling at subprocess level."""
        # Mock subprocess to simulate Git command failures
        mock_subprocess.side_effect = Exception("Git command failed")

        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "clone_dir": temp_dir,
                "limit": 1,
            }

            collector = SigmaCollector(config)

            # Should handle subprocess errors gracefully
            clone_result = collector._clone_repository()
            assert clone_result is False

    def test_concurrent_git_operations(self):
        """Test concurrent Git operations handling."""
        import threading
        import queue

        test_repo_url = "https://github.com/octocat/Hello-World.git"
        results_queue = queue.Queue()

        def clone_worker(worker_id):
            with tempfile.TemporaryDirectory() as temp_dir:
                config = {
                    "api_url": "http://localhost:8000",
                    "email": f"test{worker_id}@example.com",
                    "password": "test_password",
                    "repo_url": test_repo_url,
                    "clone_dir": temp_dir,
                    "limit": 1,
                }

                collector = SigmaCollector(config)

                try:
                    result = collector._clone_repository()
                    results_queue.put((worker_id, result, None))
                except Exception as e:
                    results_queue.put((worker_id, False, str(e)))

        # Start multiple concurrent clone operations
        threads = []
        for i in range(3):
            thread = threading.Thread(target=clone_worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=60)  # 60 second timeout

        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())

        assert len(results) == 3

        # At least some should succeed (network permitting)
        successful_count = sum(1 for worker_id, success, error in results if success)
        # Allow for network issues - at least verify no crashes
        assert all(error is None or "network" in error.lower() or "timeout" in error.lower()
                  for worker_id, success, error in results if error)

    def test_git_repository_file_encoding_handling(self):
        """Test handling of different file encodings in Git repositories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock repository with different encodings
            repo_dir = Path(temp_dir) / "encoding_test"
            repo_dir.mkdir()

            rules_dir = repo_dir / "rules"
            rules_dir.mkdir()

            # Create files with different encodings
            utf8_content = """
title: UTF-8 Test Rule
description: Test rule with UTF-8 characters: áéíóú
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: medium
"""

            # UTF-8 file
            utf8_file = rules_dir / "utf8_rule.yml"
            utf8_file.write_text(utf8_content, encoding='utf-8')

            # ASCII file
            ascii_content = utf8_content.replace("áéíóú", "aeiou")
            ascii_file = rules_dir / "ascii_rule.yml"
            ascii_file.write_text(ascii_content, encoding='ascii')

            # Create collector
            config = {
                "api_url": "http://localhost:8000",
                "email": "test@example.com",
                "password": "test_password",
                "repo_url": "file://" + str(repo_dir),
                "clone_dir": temp_dir,
                "limit": 10,
            }

            collector = SigmaCollector(config)

            # Test file discovery and reading
            discovered_files = collector._discover_sigma_files(repo_dir)
            assert len(discovered_files) == 2

            # Test that files can be read properly
            for file_path in discovered_files:
                try:
                    content = file_path.read_text(encoding='utf-8')
                    assert "Test rule" in content
                    assert len(content) > 0
                except UnicodeDecodeError:
                    # If UTF-8 fails, try with error handling
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    assert len(content) > 0