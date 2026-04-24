# Changelog

All notable changes to Vectimus policies will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `file-integrity` / `mcp-safety`: protect `.codex/hooks.json` and `.codex/config.toml` from agent-initiated writes and MCP tool calls, matching existing `.claude/` and `.cursor/` protections. Required for the experimental OpenAI Codex CLI hook support in vectimus/vectimus#37.

## [2.2.0] - 2026-04-24

### Added

- vectimus-supchain-009: Block pip install of TeamPCP-compromised xinference versions 2.6.0, 2.6.1 and 2.6.2 (VTMS-2026-0108). Covers both `package_operation` (context.command) and `shell_command` (resource.command) action surfaces. Pin to xinference>=2.6.3.
- vectimus-supchain-010: Block any agent-initiated pip install where the Vectimus supply-chain checker has not set `context.pip_package_verified=true` (VTMS-2026-0108). Closes the structural pip hash-verification gap that enabled TeamPCP-style PyPI attacks to go undetected at the tool-call boundary. Requires operator hash registration in `.vectimus/supply-allowlist.toml`.

## [2.1.0] - 2026-03-29

### Added

- vectimus-fileint-013: Block agent-initiated writes to AI coding assistant application-data config directories (`~/.config/claude/`, `~/.config/cursor/`, `~/.config/windsurf/`, `~/.config/continue/`, Windows AppData equivalents) — closes Stage 2 MCP server registration gap from SANDWORM_MODE npm supply chain attack (VTMS-2026-0001)

## [2.0.0] - 2026-03-15

### Changed

- **BREAKING**: Reorganised policies from 2 packs (base, owasp-agentic) into 11 domain-based packs: destructive-ops, secrets, supply-chain, infrastructure, code-execution, data-exfiltration, file-integrity, database, git-safety, mcp-safety, agent-governance
- Rule IDs are preserved (no breaking changes to audit logs or incident references)
- Rules previously split across base and OWASP packs by framework are now grouped by security domain
- D1 sync script now auto-discovers packs instead of hardcoding pack names

### Added

- `VERSION` file for machine-readable version tracking
- `manifest.json` with pack metadata for Sentinel pipeline consumption
- `schema.cedarschema` defining Cedar entity types (Agent, Tool, Resource, MCP_Server) and actions
- `tests/` directory with incident replay fixtures (starting with VTMS-2026-0003)
- Documentation for Sentinel integration and test fixtures in README
- NIST CSF 2.0 control mappings (PR.DS-01, PR.DS-02, PR.AA-05, PR.PS-01, DE.CM-01, DE.CM-06, DE.AE-02, GV.SC-05) across all packs
- ISO 27001:2022 Annex A control mappings (A.5.23, A.8.2, A.8.3, A.8.6, A.8.9, A.8.15, A.8.23, A.8.25) across all packs
- OWASP-ASI09 (Human-Agent Trust) coverage via escalation enforcement and audit trail integrity rules in agent-governance pack

## [1.0.0] - 2026-03-14

### Added

- Initial release: policies extracted from vectimus/vectimus repo
- **base** pack (9 policy files, 52 rules): agent safety, database safety, destructive commands, file protection, git safety, infrastructure safety, MCP tools, package operations, secret access
- **owasp-agentic** pack (9 policy files, 29 rules): ASI01 through ASI10 (excluding ASI09)
- GitHub Action to notify consumer repos on new tags
