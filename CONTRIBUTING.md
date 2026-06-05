# Contributing to FindEvil Agent

Thank you for your interest in contributing! This document provides guidelines for contributions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/findevil-agent.git`
3. Install dependencies: `pip install -e ".[dev,core]"`
4. Run tests: `pytest tests/ -v`

## Commit Conventions

This project uses **Conventional Commits**:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type       | Usage                                      |
|------------|--------------------------------------------|
| `feat`     | New feature or tool                        |
| `fix`      | Bug fix                                    |
| `perf`     | Performance improvement                    |
| `security` | Security hardening                         |
| `test`     | Adding or fixing tests                     |
| `docs`     | Documentation changes                      |
| `refactor` | Code restructuring (no functional change)  |
| `style`    | Formatting, linting (no logic change)      |
| `ci`       | CI/CD configuration changes                |
| `chore`    | Build, deps, tooling                       |

### Examples

```
feat(tools): add bulk_extractor carving tool
fix(server): resolve audit buffer race condition with asyncio.Lock
docs(readme): add FAQ section and install group documentation
perf(ioc): lazy-load YARA rules to reduce startup time by 40%
```

### Breaking Changes

Add `!` after the type/scope and include a `BREAKING CHANGE` footer:

```
feat(api)!: restructure MCP tool registration interface

BREAKING CHANGE: handler_map changed from dict to OrderedDict
```

## Branching Strategy

```
main          — Production-ready releases (CI-protected)
├── develop   — Integration branch for feature work
│   ├── feature/xxx  — New tools, features
│   ├── fix/xxx      — Bug fixes
│   └── docs/xxx     — Documentation-only changes
```

- Create feature branches from `develop`
- Merge back to `develop` via squash-merge
- `develop` merges to `main` for releases

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature develop`
2. Make your changes
3. Run the full test suite: `pytest tests/ -v`
4. Run linting and type-checking:
   ```bash
   black --check src/ tests/
   ruff check src/ tests/
   mypy src/
   ```
5. Run environment check: `python -m src.cli check`
6. Commit with conventional message
7. Push and create a Pull Request against `develop`

## Code Style

- Follow PEP 8 for Python code (enforced by Black)
- Use type hints for all function signatures (enforced by mypy strict)
- Write docstrings for all public functions (NumPy or Google style)
- Use `pathlib.Path` for file operations (not `os.path`)
- Use `shutil.which()` for finding system tools (not hardcoded paths)
- Maximum line length: 100 characters

## Testing

- All tools must have corresponding tests
- Edge cases must be covered (null bytes, path traversal, missing files, etc.)
- Tests must pass on Linux, macOS, and Windows
- Run: `pytest tests/ -v --tb=short -x`
- Run edge cases: `pytest tests/test_edge_cases.py -v`
- Run with coverage: `pytest tests/ --cov=src --cov-report=term-missing`

## Adding a New Forensic Tool

1. Create the tool function in `src/tools/your_tool.py`
2. Define a Pydantic result model (e.g., `YourToolResult(BaseModel)`)
3. Register the tool definition in `src/server.py` `_register_tools()`
4. Add the async handler function in `src/server.py`
5. Map the handler in the `handler_map` in `_register_tools()`
6. Add tests in `tests/test_server.py` (happy path + error)
7. Add edge case tests in `tests/test_edge_cases.py`
8. Register fallback chains in `src/agent/tool_selector.py` (if AI-safe)
9. Document the tool in `README.md` tool table

## Pull Request Process

1. Ensure your branch is up to date with `develop`
2. Run full test suite: `pytest tests/ -v -x`
3. Run lint + type-check: `black --check src/ tests/ && ruff check src/ tests/ && mypy src/`
4. Update `CHANGELOG.md` under `[Unreleased]` with your change
5. Create PR against `develop` with a clear title and description
6. Link any related issues
7. Wait for CI to pass (all 9 checks: lint, type-check, test × 4, build, Docker, audit)
8. Request review from a maintainer

## Pull Request Checklist

- [ ] Tests pass on all platforms (`pytest tests/ -v`)
- [ ] Lint and type-check pass (`black --check src/ tests/ && ruff check src/ tests/ && mypy src/`)
- [ ] New tests added for changes (unit + edge cases)
- [ ] Code follows style guidelines
- [ ] Documentation updated (README, ARCHITECTURE, etc.)
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No hardcoded paths (use `shutil.which()` or `tool_resolver`)
- [ ] Cross-platform compatible (Linux, macOS, Windows)
- [ ] Commit messages follow Conventional Commits
