# Contributing to PCAP Sentry

Thank you for your interest in contributing to PCAP Sentry! This document provides guidelines for contributing to the project.

## Code of Conduct

This project is committed to providing a welcoming and inclusive experience for everyone. Be respectful and considerate in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report:
- **Check existing issues** to avoid duplicates
- **Test with the latest release** to ensure the bug still exists
- **Gather details**: version, OS, steps to reproduce, expected vs actual behavior

Use the [Bug Report template](https://github.com/industrial-dave/PCAP-Sentry/issues/new?template=bug_report.yml) when filing issues.

### Suggesting Features

Feature suggestions are welcome! Use the [Feature Request template](https://github.com/industrial-dave/PCAP-Sentry/issues/new?template=feature_request.yml).

Consider:
- How does it fit with PCAP Sentry's focus on malware detection and network analysis?
- Would this benefit multiple users?
- Is it feasible given the project's architecture?

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the coding standards below
4. **Test thoroughly** - run existing tests and add new ones if needed
5. **Commit** with clear messages following [Conventional Commits](https://www.conventionalcommits.org/)
6. **Push** to your fork and submit a pull request

#### Coding Standards

**Python Style:**
- Follow [PEP 8](https://pep8.org/)
- Use descriptive variable names
- Add docstrings for functions and classes
- Keep functions focused and under 50 lines when possible

**Security:**
- Never hardcode credentials or API keys
- Validate and sanitize all user inputs
- Use secure random number generation for cryptographic purposes
- Follow principle of least privilege

**Comments:**
- Explain *why*, not *what*
- Document security-sensitive code thoroughly
- Keep comments up-to-date with code changes

#### Commit Messages

Format: `<type>: <description>`

Types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style/formatting (no logic changes)
- `refactor:` - Code restructuring (no behavior changes)
- `test:` - Adding or updating tests
- `security:` - Security improvements
- `perf:` - Performance improvements
- `build:` - Build system changes
- `ci:` - CI/CD changes

Examples:
```
feat: Add DNS tunneling detection heuristic
fix: Prevent crash when parsing malformed PCAP files
security: Implement HMAC verification for ML models
docs: Update installation instructions for Python 3.14
```

### Testing

Run the test suite before submitting:

```bash
python tests/test_stability.py
python tests/test_stress.py
```

Add tests for new features:
- Unit tests for new functions
- Integration tests for new analysis features
- Security tests for input validation

### Documentation

Update documentation when changing functionality:
- **USER_MANUAL.md** - User-facing feature changes
- **README.md** - Installation, quick start, or overview changes
- **Code comments** - Complex logic or security-sensitive code

## Development Setup

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.14+
- Git
- Virtual environment recommended

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/PCAP-Sentry.git
cd PCAP-Sentry

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt

# Run from source
python Python/pcap_sentry_gui.py
```

### Building

```bash
# Build EXE only
build_exe.bat -NoPush

# Build installer only
build_installer.bat

# Build both (for releases)
build_release.bat
```

## Security Vulnerabilities

**Do not** report security vulnerabilities through public GitHub issues.

Instead, email details to the repository owner or use GitHub's private security advisory feature. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Recognition

Contributors will be recognized in:
- Pull request merge acknowledgments
- Release notes for significant contributions
- Special recognition for security disclosures

## Questions?

- Check the [User Manual](USER_MANUAL.md)
- Search [existing issues](https://github.com/industrial-dave/PCAP-Sentry/issues)
- Open a new issue for clarification

## License

By contributing to PCAP Sentry, you agree that your contributions will be licensed under the [GNU General Public License v3.0](LICENSE).

---

Thank you for helping make PCAP Sentry better! 🛡️
