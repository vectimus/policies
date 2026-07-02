# Changelog

All notable changes to Vectimus policies will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.4.0] - 2026-07-02

### Added

- vectimus-supchain-009: Block pip install of Hugging Face Transformers 4.56.x–5.2.x (CVE-2026-4372 unauthenticated RCE via config.json injection) (VTMS-2026-0279)

## [2.3.0] - 2026-05-03

### Added

- vectimus-secrets-005: Block creating symlinks pointing at env files, secrets, credentials or SSH/AWS configs.  Closes the symlink-evasion bypass reported in vectimus/vectimus#38 where an agent ran `ln -s /path/.env /tmp/link && cat /tmp/link` to read .env files past `vectimus-secrets-001`.  Includes sandbox replay fixtures under `tests/VTMS-2026-0038/` covering `.env`, `.ssh`, `.aws`, chained `&& cat`, `--symbolic` long flag, and legitimate-symlink negative controls.
- `file-integrity` / `mcp-safety`: protect `.codex/hooks.json` and `.codex/config.toml` from agent-initiated writes and MCP tool calls, matching existing `.claude/` and `.cursor/` protections. Required for the experimental OpenAI Codex CLI hook support in vectimus/vectimus#37.

### Changed

- Renamed `destructive-ops` rule prefix from `vectimus-destops-*` to `vectimus-destruct-*` to align with the IDs already shipped in the Vectimus PyPI package since 0.21.0.  This is a drift fix — end-users via `pip install vectimus` already have `destruct` IDs in their audit logs and allowlists; canonical was the outlier.  Affected rules: 001 through 006.

### Fixed

- `VERSION` file out of sync with `manifest.json` (was 2.1.0 vs 2.2.0); both now track the canonical version.

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
