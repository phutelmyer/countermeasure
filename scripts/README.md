# Countermeasure Platform Scripts

Enterprise-grade utility scripts for the Countermeasure threat detection confidence platform.

## Available Scripts

### 🔄 `import_sigma_rules.py`

Enterprise-grade SIGMA rules import utility with comprehensive features:

- **Authentication**: Secure API authentication with credential validation
- **Batch Processing**: Configurable batch sizes for optimal performance
- **Error Handling**: Comprehensive error tracking and reporting
- **Verification**: Post-import validation and metadata verification
- **Logging**: Structured logging to both console and file
- **Dry Run**: Preview mode to test without making changes
- **Reset Mode**: Option to clear existing detections before import

#### Quick Start

```bash
# Navigate to collector directory to access uv environment
cd apps/collector

# Import 100 SIGMA rules with default settings
uv run python ../../scripts/import_sigma_rules.py --limit 100

# Show help and all available options
uv run python ../../scripts/import_sigma_rules.py --help
```

#### Common Usage Examples

```bash
# Basic import with custom limit
python scripts/import_sigma_rules.py --limit 200

# Import with custom API endpoint and credentials
python scripts/import_sigma_rules.py \
    --api-url https://api.countermeasure.example.com \
    --email admin@company.com \
    --limit 500 \
    --batch-size 25

# Dry run to preview what would be imported
python scripts/import_sigma_rules.py --limit 50 --dry-run

# Reset existing detections before importing new ones
python scripts/import_sigma_rules.py --limit 100 --reset

# Import specific categories only
python scripts/import_sigma_rules.py \
    --limit 100 \
    --categories process_creation network_connection

# Verbose logging for debugging
python scripts/import_sigma_rules.py --limit 50 --verbose
```

#### Environment Variables

You can set default values using environment variables:

```bash
export COUNTERMEASURE_API_URL=https://api.countermeasure.example.com
export COUNTERMEASURE_EMAIL=admin@company.com

# Then run with simplified command
python scripts/import_sigma_rules.py --limit 100
```

#### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--api-url` | `http://localhost:8000` | Countermeasure API base URL |
| `--email` | `admin@countermeasure.dev` | API user email |
| `--password` | (prompted) | API user password |
| `--repo-url` | `https://github.com/SigmaHQ/sigma.git` | SIGMA repository URL |
| `--categories` | (all) | Specific SIGMA categories to import |
| `--limit` | `100` | Maximum number of rules to import |
| `--batch-size` | `50` | Number of rules per batch |
| `--dry-run` | `false` | Preview mode without making changes |
| `--reset` | `false` | Delete existing detections first |
| `--verbose` | `false` | Enable verbose logging |

#### Output and Logging

The script provides comprehensive output including:

- **Real-time Progress**: Live updates during import process
- **Detailed Statistics**: Total processed, successful, failed counts
- **Verification Report**: Post-import metadata validation
- **Final Report**: Complete execution summary
- **Log Files**: Detailed logs saved to `scripts/sigma_import.log`

#### Example Output

```
🚀 Starting Countermeasure SIGMA Rules Import
============================================================
✅ Authentication successful
🗑️  Found 50 existing detections - deleting...
✅ Successfully deleted 50/50 detections
📥 Importing 100 SIGMA rules...

============================================================
🎯 SIGMA COLLECTION SUMMARY
============================================================
📂 Repository: https://github.com/SigmaHQ/sigma.git
📊 Total Processed: 100
✅ Successfully Imported: 97
❌ Failed: 3
⏱️  Execution Time: 12.3s
📈 Success Rate: 97.0%
============================================================

======================================================================
🔍 IMPORT VERIFICATION REPORT
======================================================================
📊 Total Detections: 97
🖥️  With Platforms: 89
📡 With Data Sources: 94
⚠️  With False Positives: 67
📝 With Log Sources: 97

📋 Sample Detections:
--- Sample 1: PowerShell Core DLL Loaded By Non PowerShell Process ---
Platforms: ['Windows']
Data Sources: ['Image Load']
False Positives: ['Legitimate PowerShell modules']
Log Sources: product:windows | category:image_load
```

#### Security Considerations

- **Credentials**: Passwords are never logged or stored
- **API Authentication**: Uses secure token-based authentication
- **Input Validation**: All inputs are validated and sanitized
- **Error Handling**: Sensitive information is not exposed in error messages

#### Troubleshooting

**Authentication Issues:**
```bash
# Check API connectivity
curl http://localhost:8000/health

# Verify credentials manually
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -d "email=admin@countermeasure.dev&password=YourPassword"
```

**Import Failures:**
- Check the log file: `scripts/sigma_import.log`
- Use `--verbose` flag for detailed debugging
- Verify API server is running and accessible
- Check network connectivity to SIGMA repository

**Permission Issues:**
```bash
# Make script executable
chmod +x scripts/import_sigma_rules.py

# Check Python path and dependencies
python scripts/import_sigma_rules.py --help
```

## Script Development Guidelines

When creating new scripts for the Countermeasure platform:

### 🏗️ **Enterprise Standards**

1. **Comprehensive Documentation**: Include docstrings, comments, and help text
2. **Error Handling**: Catch and handle all possible error conditions
3. **Logging**: Use structured logging with appropriate levels
4. **Configuration**: Support environment variables and command-line options
5. **Validation**: Validate all inputs and configurations
6. **Security**: Never log or expose sensitive information
7. **Testing**: Include dry-run modes and verification steps

### 📝 **Code Structure**

```python
#!/usr/bin/env python3
"""
Module docstring with purpose, usage examples, and metadata.
"""

import argparse
import asyncio
import logging
# ... other imports

class ScriptManager:
    """Main script logic encapsulated in a class."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize with configuration."""
        pass

    async def run(self) -> int:
        """Main execution method returning exit code."""
        pass

def create_argument_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    pass

async def main() -> int:
    """Main entry point."""
    pass

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
```

### 🔧 **Best Practices**

- Use type hints throughout
- Implement comprehensive error handling
- Provide detailed help text and examples
- Support both interactive and automated usage
- Include progress indicators for long-running operations
- Generate detailed reports and summaries
- Log to both console and file
- Support dry-run modes for testing

## Contributing

When adding new scripts to this directory:

1. Follow the established patterns and conventions
2. Include comprehensive documentation and examples
3. Add the script to this README with usage instructions
4. Ensure enterprise-grade quality and security standards
5. Test thoroughly in both development and production scenarios

## Support

For issues with these scripts:

1. Check the log files for detailed error information
2. Use verbose mode (`--verbose`) for debugging
3. Verify your environment and dependencies
4. Consult the main project documentation in `CLAUDE.md`
5. Report issues through the appropriate channels