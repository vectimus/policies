# Security Policy

## Reporting a vulnerability

If you discover a way to bypass a Vectimus Cedar policy or find a vulnerability in the policy evaluation logic, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the [Security tab](https://github.com/vectimus/policies/security/advisories) of this repository.
2. **Email**: Send details to security@vectimus.com.

### What to include

- Description of the bypass or vulnerability
- Steps to reproduce (Cedar policy, input payload, expected vs actual decision)
- Potential impact
- Suggested fix if you have one

## Response timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Dependent on severity, typically within 30 days for critical issues

## Scope

The following are in scope for this repository:

- Cedar policy bypass (action that should be denied is allowed)
- False negatives in pattern matching
- Missing coverage for documented attack patterns
- Policy annotation errors that misrepresent compliance mappings

## License

Apache 2.0
