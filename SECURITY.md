# Security Policy

## Supported versions

Security fixes are released for the latest published version. Older versions are not patched.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub Private Vulnerability Reporting:

1. Open the repository on GitHub.
2. Go to the **Security** tab and choose **Report a vulnerability**.
3. Describe the issue, the affected version and, if you have one, a minimal reproduction.

The maintainers confirm receipt, assess the report and coordinate a fix and a release. Please give us a reasonable time to fix the issue before you disclose it.

## Scope

In scope: any way to make the client connect to a blocked address or hostname, bypass the scheme, port or redirect checks, or leak credentials or query strings through error messages.

Out of scope: use of `WithAllowPrivateNetworks(true)` with untrusted input, which is documented as unsafe. Also out of scope: a resolver that the caller chose to trust and that returns wrong answers.
