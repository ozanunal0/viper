# Development Guide for VIPER CTI Project

This document describes the development workflow and tools used in the VIPER CTI project.

## Setting Up the Development Environment

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Code Quality Tools

### Linting and Formatting

We use the following tools to ensure code quality:

- **Black**: Code formatter
  ```bash
  black .
  ```

- **isort**: Import statement organizer
  ```bash
  isort .
  ```

- **flake8**: Linting
  ```bash
  flake8 .
  ```

### Running Tests

Tests are written using pytest:

```bash
# Run all tests
pytest

# Run only unit tests
pytest tests/unit/

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=src tests/
```

### Security Scanning

We use the following tools for security scanning:

- **bandit**: Security issue scanner
  ```bash
  bandit -r src/
  ```

- **safety**: Dependency vulnerability scanner
  ```bash
  safety check -r requirements.txt
  ```

## Pre-commit Hooks

Pre-commit hooks run automatically when you commit changes and check for:
- Trailing whitespace
- Properly formatted files
- YAML syntax errors
- Correctly sorted imports
- Properly formatted code (Black)
- Linting issues (flake8)
- Security issues (bandit)

You can manually run the pre-commit hooks on all files:
```bash
pre-commit run --all-files
```

## Continuous Integration

This project uses GitHub Actions for CI. The workflow runs:
- Linting checks
- Formatting checks
- Security scans
- Unit tests

The CI pipeline runs automatically on pushes to main and on pull requests.

## Adding New Dependencies

1. Add runtime dependencies to `requirements.txt`
2. Add development dependencies to `requirements-dev.txt`
3. Run `pip install -r requirements.txt -r requirements-dev.txt`
