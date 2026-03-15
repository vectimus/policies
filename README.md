# Vectimus Policies

Cedar policies for [Vectimus](https://github.com/vectimus/vectimus) -- the single source of truth for all AI agent governance rules.

These policies are language-agnostic Cedar text files. They produce identical allow/deny decisions whether evaluated by cedarpy (Python), cedar-wasm (TypeScript) or any other conformant Cedar implementation.

## Structure

Policies are organised by security domain. Each domain is an independent pack with its own `pack.toml` manifest.

```
destructive-ops/         # Filesystem destruction, disk corruption, fork bombs
secrets/                 # Credential, key and environment file protection
supply-chain/            # Package publishing, lockfiles, registry configs, untrusted sources
infrastructure/          # Cloud/container/IaC destruction, privilege escalation
code-execution/          # Reverse shells, eval patterns, download-execute chains
data-exfiltration/       # Encoded transfers, DNS tunnelling, credential piping
file-integrity/          # CI/CD pipelines, certs, governance configs, agent instructions
database/                # ORM destructive flags, DROP commands
git-safety/              # Force push, reset --hard, clean -f
mcp-safety/              # MCP server allowlisting, input parameter inspection
agent-governance/        # Autonomy limits, spawn control, inter-agent comms, persistence
```

Each pack has a `pack.toml` manifest with name, version and description. Each `.cedar` file contains one or more rules with `@id`, `@description`, `@incident`, `@controls` and `@enforcement` annotations.

## Compliance framework mappings

Every rule carries `@controls` annotations mapping to one or more compliance frameworks. The pack structure organises by security domain; compliance frameworks are cross-cutting views.

| Framework | Annotation prefix | Example |
|-----------|------------------|---------|
| SOC 2 Type II | `SOC2-` | `SOC2-CC6.1` |
| NIST AI RMF | `NIST-` | `NIST-AI-MG-3.2` |
| NIST CSF 2.0 | `NIST-CSF-` | `NIST-CSF-PR.DS-01` |
| EU AI Act | `EU-AI-` | `EU-AI-14` |
| OWASP Agentic Top 10 | `OWASP-ASI` | `OWASP-ASI01` |
| ISO 27001:2022 | `ISO27001-` | `ISO27001-A.8.3` |
| SLSA | `SLSA-` | `SLSA-L2` |
| CIS Controls | `CIS-` | `CIS-16` |

## Versioning

This repo uses semantic versioning:

- **Patch** (`v2.0.1`): rule tuning, false positive fixes, description changes
- **Minor** (`v2.1.0`): new policies added, existing policies unchanged
- **Major** (`v3.0.0`): policy removals, schema changes, behavioral changes to existing rules

Tag a release whenever policies change. Consumer repos (vectimus/vectimus, vectimus/openclaw) receive automated PRs via repository dispatch.

## Consumer repos

When a new tag is pushed, a GitHub Action dispatches a `policies-updated` event to consumer repos. Each consumer has its own sync workflow that downloads the tagged policies and opens a PR.

Current consumers:
- [vectimus/vectimus](https://github.com/vectimus/vectimus) (Python)
- [vectimus/openclaw](https://github.com/vectimus/openclaw) (TypeScript)

## Contributing

1. Edit the relevant `.cedar` file
2. Every rule must have an `@id`, `@description` and `@incident` annotation
3. Run the full test suite in the consuming repos before tagging a release
4. Update the CHANGELOG
5. Tag and push

## License

Apache 2.0 -- same as the main Vectimus project.
