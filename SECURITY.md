# Security Policy

## Supported Versions

PCAP Sentry follows a date-based versioning scheme (YYYY.MM.DD-increment). We recommend always using the latest release.

| Version Pattern | Supported          |
| --------------- | ------------------ |
| Latest Release  | :white_check_mark: |
| Older Releases  | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Preferred Method: Private Security Advisory

Use GitHub's private security advisory feature:
1. Go to the [Security tab](https://github.com/industrial-dave/PCAP-Sentry/security)
2. Click **Report a vulnerability**
3. Fill out the advisory form with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Suggested fix (if any)

### Alternative: Private Email

If you prefer email or cannot use GitHub's advisory feature, contact the repository owner directly through GitHub.

### What to Include

- **Description**: Clear explanation of the vulnerability
- **Impact**: What an attacker could do
- **Reproduction**: Detailed steps to reproduce
- **System Info**: OS, Python version, PCAP Sentry version
- **Proof of Concept**: Code/files if applicable (use a private gist or attachment)
- **Suggested Fix**: If you have a recommendation

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: Next planned release

## Security Practices

PCAP Sentry implements multiple security controls:

### Input Validation
- Path traversal protection for file operations
- PCAP file signature verification
- URL scheme validation (centralized `_safe_urlopen()` wrapper blocks file://, ftp://, etc.)
- URL validation and sanitization
- Size limits on API responses (10MB)

### Cryptographic Security
- SHA-256 verification for downloads
- HMAC validation for ML model integrity
- Secure random number generation for cryptographic operations

### Credential Management
- OS native credential storage (Windows Credential Manager)
- No hardcoded credentials or API keys
- API key protection (blocks transmission over HTTP)

### Network Security
- TLS verification for HTTPS requests
- Connection pooling with timeout limits
- User-Agent identification
- Response size limits

### Code Security
- Regular dependency updates
- CodeQL scanning via GitHub Actions
- Static analysis in development
- Input sanitization throughout codebase

## Scope

**In Scope:**
- PCAP Sentry application code (Python/)
- Build and installer scripts
- Bundled dependencies in releases

**Out of Scope:**
- Third-party packages (report to upstream)
- User-provided PCAP files (malicious files by design)
- Local LLM servers (Ollama, LM Studio, etc.)
- Operating system vulnerabilities

## Disclosure Policy

- We follow **coordinated disclosure** principles
- We will credit reporters (unless anonymity is requested)
- Security fixes will be released with a security advisory
- CVE IDs will be requested for significant vulnerabilities

## Security Updates

Security updates are announced through:
- GitHub Security Advisories
- Release notes with `[SECURITY]` prefix
- Commits tagged with `security:` type

## Recognition

We appreciate security researchers who report vulnerabilities responsibly. Contributors will be credited in:
- Security advisories
- Release notes
- This SECURITY.md file (Hall of Fame section, if applicable)

Thank you for helping keep PCAP Sentry secure!
