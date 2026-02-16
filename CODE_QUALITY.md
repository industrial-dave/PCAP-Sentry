# Code Quality and Linting

This document describes PCAP Sentry's code quality tools and linting practices.

## Overview

PCAP Sentry uses automated linting and static analysis tools to maintain code quality and catch common errors before they reach production.

## OpenSSF Compliance

**Requirement:** "The project MUST enable one or more compiler warning flags, a 'safe' language mode, or use a separate 'linter' tool to look for code quality errors or common simple mistakes."

**Status:** ✅ **FULLY COMPLIANT**

Python doesn't have traditional compiler warnings, but PCAP Sentry uses industry-standard linting tools:

1. ✅ **Ruff** - Fast, comprehensive Python linter
2. ✅ **Bandit** - Security-focused linter
3. ✅ **Safety** - Dependency vulnerability scanner
4. ✅ **CodeQL** - Semantic code analysis

## Linting Tools

### 1. Ruff (Primary Linter)

[Ruff](https://docs.astral.sh/ruff/) is an extremely fast Python linter written in Rust, combining the functionality of multiple tools.

**Configuration:** [ruff.toml](ruff.toml)

**Enabled Rule Sets:**
- **E/W** - pycodestyle (PEP 8 compliance)
- **F** - pyflakes (unused imports, undefined names)
- **I** - isort (import sorting)
- **N** - pep8-naming (naming conventions)
- **UP** - pyupgrade (modern Python idioms)
- **B** - flake8-bugbear (likely bugs and design problems)
- **C4** - flake8-comprehensions (better list/dict comprehensions)
- **SIM** - flake8-simplify (simplification suggestions)
- **RET** - flake8-return (return statement issues)
- **ARG** - flake8-unused-arguments (unused parameters)
- **PTH** - flake8-use-pathlib (encourage pathlib over os.path)
- **ERA** - eradicate (commented-out code)
- **PL** - pylint (comprehensive checks)
- **PERF** - perflint (performance anti-patterns)
- **RUF** - ruff-specific rules

**Usage:**
```bash
# Check for issues
ruff check Python/ tests/

# Auto-fix issues
ruff check --fix Python/ tests/

# Check formatting
ruff format --check Python/ tests/

# Apply formatting
ruff format Python/ tests/
```

**Examples of Issues Caught:**
- Unused imports and variables
- Undefined names
- Syntax errors
- PEP 8 violations (indentation, line length, spacing)
- Mutable default arguments
- Bare `except:` clauses
- F-string misuse
- Performance anti-patterns (e.g., calling `list()` unnecessarily)
- Security issues (assert usage, shell injection risks)

### 2. Bandit (Security Linter)

[Bandit](https://bandit.readthedocs.io/) finds common security issues in Python code.

**Usage:**
```bash
# Scan all Python files
bandit -r Python/

# Generate JSON report
bandit -r Python/ -f json -o bandit-report.json
```

**Security Issues Detected:**
- Use of `assert` for security checks
- Hardcoded passwords/secrets
- SQL injection risks
- Shell injection vulnerabilities
- Use of `pickle` (deserialization attacks)
- Weak cryptography (MD5, DES)
- Path traversal vulnerabilities
- Use of `eval()` or `exec()`

### 3. Safety (Dependency Scanner)

[Safety](https://github.com/pyupio/safety) checks dependencies for known security vulnerabilities.

**Usage:**
```bash
# Check installed packages
safety check

# Check requirements file
safety check -r requirements.txt
```

**Scans Against:**
- PyPI Security Advisory Database
- CVE (Common Vulnerabilities and Exposures)
- Known vulnerable package versions

### 4. CodeQL (Semantic Analysis)

GitHub's [CodeQL](https://codeql.github.com/) performs deep semantic code analysis.

**Configuration:** [.github/workflows/codeql.yml](.github/workflows/codeql.yml)

**Scans:**
- Runs automatically on every push/PR
- Weekly scheduled scan (Mondays 04:17 UTC)
- Results appear in GitHub Security tab

## CI Integration

All linting tools run automatically in CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)):

### Lint Job
```yaml
- name: Run ruff linter
  run: ruff check Python/ tests/ --output-format=github

- name: Run ruff formatter check
  run: ruff format --check Python/ tests/
```

### Security Job
```yaml
- name: Run safety check
  run: safety check --json

- name: Run bandit security scan
  run: bandit -r Python/ -f json -o bandit-report.json
```

**Note:** Safety uses `continue-on-error: true` to provide warnings without blocking PRs. Ruff and Bandit (medium+ severity) block merges on failure.

## Local Development Workflow

### Initial Setup

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Verify installation:
```bash
ruff --version
bandit --version
safety --version
```

### Pre-Commit Checks

Before committing code, run:

```bash
# Quick check
ruff check Python/ tests/

# Full check with auto-fix
ruff check --fix Python/ tests/
ruff format Python/ tests/

# Security scan
bandit -r Python/
```

### Git Hooks (Optional)

You can set up a pre-commit hook to run ruff automatically:

**.git/hooks/pre-commit** (make executable with `chmod +x`):
```bash
#!/bin/bash
echo "Running ruff linter..."
ruff check Python/ tests/
if [ $? -ne 0 ]; then
    echo "❌ Linting failed. Please fix errors before committing."
    exit 1
fi
echo "✅ Linting passed!"
```

## Configuration Details

### ruff.toml

Key configuration choices:

**Target Python Version:**
```toml
target-version = "py310"
```
- Supports Python 3.10+ (project runs on 3.10, 3.11, 3.12)

**Line Length:**
```toml
line-length = 120
```
- Balances readability with screen width

**Ignored Rules:**
```toml
ignore = [
    "E501",    # Line too long (handled by formatter)
    "PLR0913", # Too many arguments (common in GUI code)
    "N802-N806", # Mixed case names (tkinter convention)
    "ARG001-002", # Unused arguments (GUI event handlers)
]
```
- Pragmatic choices for GUI application development

**Per-File Ignores:**
```toml
[lint.per-file-ignores]
"tests/*" = ["S101", "PLR0915"]
```
- Tests can use `assert` and be longer

### Code Quality Metrics

**Ruff Performance:**
- Checks ~7,000 lines of code in <1 second
- 10-100x faster than traditional linters
- Automatically fixable rules reduce manual work

**Current Status:**
- Main codebase (10,700+ lines) regularly linted
- CI enforces linting on every change
- All contributors must pass linter checks

## IDE Integration

### VS Code

Install the [Ruff extension](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff):

**.vscode/settings.json** (optional):
```json
{
  "ruff.enable": true,
  "ruff.lint.enable": true,
  "ruff.format.enable": true,
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll": true,
      "source.organizeImports": true
    }
  }
}
```

### PyCharm/IntelliJ

1. Settings → Tools → External Tools
2. Add Ruff as external tool
3. Configure file watcher to run on save

## Common Issues and Fixes

### Issue: "Undefined name 'X'"
**Solution:** Import missing module or fix typo

### Issue: "Unused import 'Y'"
**Solution:** Remove unused import or use `# noqa: F401` if intentionally imported for re-export

### Issue: "Line too long"
**Solution:** Run `ruff format` to auto-fix, or break line manually

### Issue: "Mutable default argument"
```python
# Bad
def func(data=[]):
    ...

# Good
def func(data=None):
    if data is None:
        data = []
    ...
```

### Issue: "Bare except clause"
```python
# Bad
try:
    risky_operation()
except:
    pass

# Good
try:
    risky_operation()
except (ValueError, KeyError) as e:
    logger.error(f"Operation failed: {e}")
```

## Performance Impact

Linting runs:
- **Locally:** <1 second for entire codebase
- **In CI:** ~5 seconds as part of lint job
- **Total CI overhead:** Minimal (parallelized with other jobs)

## Continuous Improvement

The linting configuration evolves with the project:

1. **New rules:** Added when valuable patterns emerge
2. **Rule adjustments:** Based on false positives or team feedback
3. **Performance tuning:** Exclude unnecessary files/directories
4. **Tool updates:** Regular updates to get latest checks

## Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Safety Documentation](https://github.com/pyupio/safety)
- [PEP 8 Style Guide](https://pep8.org/)
- [OpenSSF Linter Guidance](https://www.bestpractices.dev/en/criteria#warnings)

## Summary

✅ **Ruff linter** configured with comprehensive rule set  
✅ **Security scanning** with Bandit and Safety  
✅ **CI enforcement** on every push and PR  
✅ **Documentation** for contributors in CONTRIBUTING.md  
✅ **Configuration** in ruff.toml and CI workflow  
✅ **Evidence** of regular usage via CI logs  

PCAP Sentry meets and exceeds the OpenSSF requirement for using linter tools to detect code quality issues and common mistakes.
