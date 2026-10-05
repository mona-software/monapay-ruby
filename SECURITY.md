# Security Policy

This policy covers every repository in the [mona-software](https://github.com/mona-software) organization: the MONA Pay SDKs, plugins and connectors, the MONA Cloud, MONA Mail and MONA Domain tools, the MCP servers, and the open-source SEO, GEO and education tools.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull request or discussion.

Email **info@themona.global** with the subject `[security] <repository name>` and include:

- the affected repository, package and version (or commit);
- a description of the issue and its impact;
- steps to reproduce, a proof of concept, or the request and response that show the problem;
- whether you would like to be credited, and under which name.

If you find a credential, token or other secret committed to one of our repositories, report it the same way and do not use it.

## What to expect

- We acknowledge your report within **2 business days**.
- We investigate, keep you informed of our progress, and tell you when a fix is released.
- With your permission, we credit you in the release notes once the fix is available.

## Coordinated disclosure

Please give us the opportunity to release a fix before disclosing the issue publicly. We will agree on a disclosure date with you once the fix is ready.

## Supported versions

Security fixes are released for the latest published version of each package. Please upgrade to the latest release before reporting, and confirm the issue still occurs.

## Guidelines for testing

- Only test against accounts and data you own, or sandbox environments.
- Do not access, modify or delete other users' data.
- Do not run tests that degrade service for others, such as denial-of-service or high-volume automated scanning.
- Social engineering and physical attacks are out of scope.

Issues in third-party services or platforms these projects integrate with (for example WordPress, WooCommerce or Shopify) should be reported to their maintainers.

## Secure integration

- Never commit credentials or secrets (username, password, client secret, webhook secret); load them from the environment.
- Verify the webhook signature on the raw request body, before parsing or processing it.
- Use `transaction_code` as an idempotency key so a repeated webhook is never applied twice.
