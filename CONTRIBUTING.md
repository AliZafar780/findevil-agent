# Contributing to FindEvil Agent

Thank you for your interest in contributing! This document provides guidelines for contributions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/findevil-agent.git`
3. Install dependencies: `pip install -e ".[dev]"`
4. Run tests: `pytest tests/`

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run the full test suite: `pytest tests/ -v`
4. Run environment check: `python -m src.cli check`
5. Push and create a Pull Request

## Code Style

- Follow PEP 8 for Python code
- Use type hints for all function signatures
- Write docstrings for all public functions
- Use `pathlib.Path` for file operations (not `os.path`)
- Use `shutil.which()` for finding system tools (not hardcoded paths)

## Testing

- All tools must have corresponding tests
- Edge cases must be covered (null bytes, path traversal, missing files, etc.)
- Tests must pass on Linux, macOS, and Windows
- Run: `pytest tests/ -v --tb=short`

## Adding a New Forensic Tool

1. Create the tool function in `src/tools/`
2. Register the tool in `src/server.py` tool definitions
3. Add the handler function
4. Add tests in `tests/test_server.py`
5. Update `test_edge_cases.py` with security tests

## Pull Request Checklist

- [ ] Tests pass on all platforms
- [ ] New tests added for changes
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No hardcoded paths
- [ ] Cross-platform compatible
