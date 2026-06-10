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

# Changelog

## [1.0.0] — 2026-06-09

Initial open-source release.

### What's included
- 9-stage agentic SAST pipeline: repository survey → threat model →
  decompose → deep-dive → pre-filter → adversarial verify → dedup →
  chain → SARIF 2.1.0
- Multi-model: works with the Claude CLI, Anthropic SDK, or any
  OpenAI-compatible endpoint; mix backends per role
- Precision controls: call-graph validation, taint-flow analysis,
  multi-agent voting, CVSS 3.1 scoring
- Batch mode: clone and scan multiple repositories from a CSV manifest
- Three shipped configuration profiles: CLI-first default, Bash-enabled
  CLI, and multi-backend

