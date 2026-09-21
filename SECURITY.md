# Security Policy

## Supported Versions

This repository contains the source for [taktak.hu](https://taktak.hu/), a statically generated security portfolio.

The project does not use versioned software releases. Security fixes are applied to the current production version only.

| Version / Branch | Supported |
| --- | --- |
| Current production site |
| `main` |
| `dev`  |  Development only |
| Older commits, forks, or local copies |

The `main` branch represents the source used to build the production website. The `dev` branch may contain unfinished or experimental changes and is not deployed publicly.

## Reporting a Vulnerability

If you discover a security vulnerability affecting this repository or the deployed website, please report it privately.

**Do not open a public GitHub issue containing vulnerability details.**

The preferred reporting method is GitHub's **Private Vulnerability Reporting** feature for this repository.

When submitting a report, please include, where applicable:

- A description of the vulnerability
- The affected page, component, dependency, or workflow
- Steps required to reproduce the issue
- The potential security impact
- Relevant screenshots, logs, or proof-of-concept material
- Any suggested remediation

Please avoid including unnecessary sensitive information in the report.

## Scope

Examples of issues that are appropriate to report include:

- Cross-site scripting or unsafe content rendering
- Exposure of credentials, tokens, or other sensitive information
- Vulnerabilities in site dependencies with an exploitable impact
- GitHub Actions or deployment workflow vulnerabilities
- Security issues affecting the production site or its custom-domain configuration
- Vulnerabilities that could modify, expose, or compromise published content

Issues affecting third-party platforms or services should normally be reported directly to the relevant provider unless they are caused by this project's configuration or code.

## Responsible Testing

Please make a reasonable effort to avoid:

- Denial-of-service or resource-exhaustion testing
- Destructive testing
- Social engineering or phishing
- Accessing or modifying data that does not belong to you
- Automated testing that generates excessive traffic
- Public disclosure before there has been a reasonable opportunity to investigate the issue

This policy does not grant authorization to test systems or infrastructure that are not controlled by this project.

## Response Process

I aim to acknowledge valid security reports within **7 days**.

After reviewing a report:

- If the issue is accepted, I will confirm the finding, assess its impact, and work toward remediation.
- If additional information is required, I may request further reproduction details.
- If the report is declined, I will provide the reason where practical.
- For an accepted issue that requires additional time to resolve, I aim to provide an update at least every **14 days** until it is resolved.

Fix and disclosure timelines will depend on the severity and complexity of the issue.

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

Where appropriate, coordinated disclosure and researcher credit can be discussed after the issue has been resolved.

Security reports and responsible disclosure are nevertheless appreciated.

