# Vectimus Policies

**11 packs  |  79 policies  |  380 rules**

Cedar policies that govern what AI coding agents can and cannot do.  Every rule traces back to a real incident, published vulnerability or security framework scenario.

![Packs](https://img.shields.io/badge/packs-11-blue)
![Policies](https://img.shields.io/badge/policies-79-blue)
![Rules](https://img.shields.io/badge/rules-380-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

## Policy packs

[Browse all policies on the web →](https://vectimus.com/policies)

| Pack | What it blocks |
|------|----------------|
| `destructive-ops` | `rm -rf /`, `mkfs`, fork bombs, `chmod 777 /` |
| `secrets` | Reading `.env`, credentials, API keys, private keys |
| `supply-chain` | Lockfile tampering, rogue registries, `npm publish` without review |
| `infrastructure` | `terraform destroy`, `kubectl delete`, IAM privilege escalation |
| `code-execution` | Reverse shells, `eval()` chains, download-and-execute patterns |
| `data-exfiltration` | Base64 piping to `curl`, DNS tunnelling, credential exfiltration |
| `file-integrity` | Writes to CI configs, certs, `.claude/`, IDE settings, agent memory |
| `database` | `DROP DATABASE`, ORM `--force` flags, migration destruction |
| `git-safety` | `push --force`, `reset --hard`, `clean -f` |
| `mcp-safety` | Unapproved MCP servers, parameter injection, tool impersonation |
| `agent-governance` | Autonomous spawning, persistence, inter-agent comms, audit tampering |

## Example policy

Every rule has `@incident` (the real attack it prevents) and `@controls` (compliance framework mappings):

```cedar
@id("vectimus-destops-001")
@description("Block recursive deletion of root, home or current directory")
@incident("Home directory deletion via rm -rf reported in Claude Code sessions, 2025")
@controls("SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.9")
@suggested_alternative("Delete specific files or directories by name instead of using broad recursive deletion.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*rm -rf /*" ||
    context.command like "*rm -rf ~*" ||
    context.command like "*rm -rf .*"
};
```

Every rule traces to a real incident, published CVE, or compliance framework requirement. No filler.

## Compliance coverage

These annotations exist so auditors can trace controls to enforcement. Evidence for your audit, not a compliance checkbox.

| Framework | Prefix | Coverage |
|-----------|--------|----------|
| OWASP Agentic Top 10 | `OWASP-ASI` | All 10 categories enforced |
| SOC 2 Type II | `SOC2-` | CC6.1, CC6.6, CC6.8, CC7.2, CC7.3, CC8.1 |
| NIST AI RMF | `NIST-AI-` | GOVERN 1.1/1.5, MAP 1.5, MEASURE 2.5/2.6, MANAGE 2.2/3.2 |
| NIST CSF 2.0 | `NIST-CSF-` | PR.DS, PR.PS, DE.CM, RS.AN |
| ISO 27001:2022 | `ISO27001-` | A.8 technology controls, A.5 organizational controls |
| EU AI Act | `EU-AI-` | Articles 9, 12, 13, 14, 15 |
| SLSA | `SLSA-` | L2 supply chain controls |
| CIS Controls | `CIS-` | CIS-16 |

## How policies are updated

1. **Sentinel discovers a threat.** A 3-agent pipeline monitors attack disclosures, CVEs and community reports.
2. **Sentinel writes a policy.** It generates Cedar, runs it through a sandbox prover and opens a PR to this repo.
3. **Human reviews and merges.** Every policy PR gets human approval before it ships.
4. **Auto-sync to local installs.** Vectimus checks for policy updates from the Vectimus API every 24 hours. No manual intervention needed.

## Sentinel Integration

[Sentinel](https://github.com/vectimus/sentinel) is the automated security pipeline that analyzes AI agent incidents and opens PRs to this repo with new or updated policies. Its Security Engineer agent reads `manifest.json`, `VERSION`, and `schema.cedarschema` to understand the current policy landscape before proposing changes.

## Test Fixtures

The `tests/` directory contains incident replay fixtures used by Sentinel and consumer repos to validate policy decisions. Each subdirectory is named after an incident ID (e.g., `VTMS-2026-0003`) and contains:

- `entities.json` — Cedar entities (Agent, Tool, Resource) involved in the incident
- `request_block.json` — a request that the policies must DENY
- `request_allow.json` — a related request that the policies must ALLOW (to verify no over-blocking)

## Consumer repos

Tagged releases dispatch `policies-updated` events to consumer repos, which open their own sync PRs:

- [vectimus/vectimus](https://github.com/vectimus/vectimus) (Python)
- [vectimus/openclaw](https://github.com/vectimus/openclaw) (TypeScript)
- [vectimus/sentinel](https://github.com/vectimus/sentinel) (Security pipeline)

## Repo structure

```
<pack-name>/
├── pack.toml              # Name, version, description
├── <pack_name>.cedar      # One or more forbid/permit rules
```

Policies are language-agnostic Cedar text files. They produce identical allow/deny decisions whether evaluated by cedarpy, cedar-wasm or any other conformant Cedar implementation.

## Contributing

### Policy format

Every rule requires these annotations:

- **`@id`** — Unique identifier following `vectimus-<pack>-<nnn>` pattern
- **`@description`** — What the rule blocks, in plain English
- **`@incident`** — The real-world attack or incident that motivated this rule
- **`@controls`** — Comma-separated compliance framework mappings
- **`@suggested_alternative`** — What the agent should do instead

### Process

1. **Add or edit** the relevant `.cedar` file in the appropriate pack directory
2. **Include an `@incident` annotation.** No incident, no rule.
3. **Map to compliance frameworks** via `@controls`. Check the table above for prefixes.
4. **Run the test suite** in consumer repos (`vectimus/vectimus`, `vectimus/openclaw`) to verify evaluation
5. **Update CHANGELOG.md** with your changes
6. **Open a PR.** Tag it with the pack name.

### Versioning

This repo uses semantic versioning:

- **Patch** (`v2.0.1`) — Rule tuning, false-positive fixes, description changes
- **Minor** (`v2.1.0`) — New policies added, existing policies unchanged
- **Major** (`v3.0.0`) — Policy removals, schema changes, behavioral changes to existing rules

## Install Vectimus

These policies are consumed by the main [Vectimus](https://github.com/vectimus/vectimus) package. To start enforcing them:

```bash
pipx install vectimus    # or: uv tool install vectimus
vectimus init
```

Works with Claude Code, Cursor, GitHub Copilot and Gemini CLI via native hooks. See the [main repo](https://github.com/vectimus/vectimus) for setup.

## License

Apache 2.0
