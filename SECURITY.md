# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| > 1.0.0 | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

### DO NOT open public issues for security vulnerabilities

We take security seriously. If you discover a security vulnerability, please report it privately.

### How to Report

**Email:** support@attendance-system.dev

**Include:**

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and attack scenario
3. **Reproduction**: Step-by-step instructions to reproduce
4. **Proof of Concept**: Code or screenshots demonstrating the issue
5. **Suggested Fix**: If you have one

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix Timeline**: 7-30 days depending on severity
- **Public Disclosure**: After fix is released (90-day embargo)

## Security Best Practices

### For Administrators

1. **Keep Credentials Secure**
   - Never commit `local.properties` or `google-services.json`
   - Use strong, unique passwords
   - Enable two-factor authentication

2. **Firebase Security**
   - Configure strict security rules
   - Limit API access to specific domains
   - Regularly audit access logs

3. **Network Security**
   - Use HTTPS-only connections
   - Implement certificate pinning if needed
   - Monitor network traffic

### For Developers

1. **Code Review**
   - Review all code changes for security issues
   - Use automated security scanning tools
   - Never merge without approval

2. **Dependency Management**
   - Keep dependencies updated
   - Use Dependabot for automatic updates
   - Audit third-party libraries

3. **Data Protection**
   - Encrypt sensitive data at rest
   - Use secure communication channels
   - Implement proper access controls

## Known Security Features

### Application Security

- **Root Detection**: App detects rooted devices
- **Network Security**: HTTPS-only enforcement via `network_security_config.xml`
- **Data Encryption**: AES-256-GCM for sensitive data
- **Authentication**: Firebase Auth with biometric support
- **Code Obfuscation**: R8/ProGuard in release builds

### Data Protection

- **Local Storage**: Encrypted Room database
- **Firebase**: Strict security rules
- **Biometric Auth**: Fingerprint/face unlock
- **Session Management**: Automatic timeout

## Security Updates

Subscribe to security advisories:

- GitHub Security Advisories
- Release notes for security patches
- Email notifications (if configured)

## Acknowledgments

We appreciate responsible disclosure. Security researchers who report valid vulnerabilities will be acknowledged in our release notes (unless they prefer to remain anonymous).

## Contact

**Security Team:** support@attendance-system.dev

**Response Hours:** Monday-Friday, 9 AM - 5 PM IST
