<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Security Policies and Procedures

This document outlines security procedures and general policies for the
Visa Vulnerability Agentic Harness (`vvaharness`) project.

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Disclosure Policy](#disclosure-policy)
- [Supported Versions](#supported-versions)
- [Comments on this Policy](#comments-on-this-policy)

## Reporting a Vulnerability

Visa and the `vvaharness` maintainers take all security vulnerabilities
seriously. Thank you for improving the security of our software. We appreciate
your efforts and responsible disclosure and will make every effort to
acknowledge your contributions.

Please report security vulnerabilities by emailing the security team at:

<!-- TODO(VISA): replace with the official Visa security reporting address -->
- **`<security-reporting@visa.com>`**

For coordinated disclosure and additional reporting channels, see:

<!-- TODO(VISA): replace with the official Visa vulnerability-disclosure / PSIRT URL -->
- Visa Vulnerability Disclosure Program: `<https://www.visa.com/security-disclosure>`

Please do **not** report security vulnerabilities through public GitHub issues.

The security team will acknowledge your email within **48 hours**, and will
send a more detailed response within **48 hours** indicating the next steps in
handling your report. After the initial reply, the security team will keep you
informed of the progress toward a fix and full announcement, and may ask for
additional information or guidance.

When reporting, please include as much of the following as you can to help us
triage quickly:

- The version (or commit) of `vvaharness` affected.
- The profile/backend in use (`via: cli` / `via: sdk` / `via: openai`) and OS.
- A description of the issue and its security impact.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if available.
- Any known mitigations or workarounds.

Report security vulnerabilities in **third-party dependencies** to the party
that maintains the affected component.

## Disclosure Policy

When the security team receives a vulnerability report, it is assigned to a
primary handler. This person coordinates the fix and release process, involving
the following steps:

- Confirm the problem and determine the affected versions.
- Audit code to find any potential similar problems.
- Prepare fixes for all releases still under maintenance. These fixes are
  released as quickly as possible.

Public disclosure is coordinated with the reporter; please give us reasonable
time to remediate before any public discussion of the issue.

## Supported Versions

Security fixes are provided for the versions listed below.

<!-- TODO(VISA): adjust the supported-version matrix to match the release policy -->

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Operational security of the tool itself

For how `vvaharness` protects scan inputs and outputs at runtime — secret/PII
redaction, sandboxed tool access, credential handling, and TLS — see
[`docs/security.md`](docs/security.md).

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a
pull request or open a discussion.
