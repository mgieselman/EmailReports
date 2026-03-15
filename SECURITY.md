# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in EmailReports, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/mgieselman/EmailReports/security/advisories/new) to submit your report.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Security Measures

This project implements several security measures:

- **defusedxml** for safe XML parsing (prevents XXE and XML bomb attacks)
- **Decompression limits** (50 MB) on .gz and .zip attachments
- **OData injection prevention** in Microsoft Graph API queries
- **HTML escaping** on all report field values in alert output
- **Secret scanning** and **push protection** enabled on the repository
- **Dependabot** for automated dependency vulnerability alerts and updates
- **Gitleaks** runs on every push to detect accidentally committed secrets
- **Client secrets** stored in Azure Key Vault, never in app settings or code
- **Application-scoped permissions** with Exchange access policies to restrict mailbox access
