# Vectimus Policies

Cedar policies for [Vectimus](https://github.com/vectimus/vectimus) — the single source of truth for all AI agent governance rules.

These policies are language-agnostic Cedar text files. They produce identical allow/deny decisions whether evaluated by cedarpy (Python), cedar-wasm (TypeScript) or any other conformant Cedar implementation.

## Structure

```
base/                    # Baseline security rules mapped to real-world incidents
  pack.toml              # Pack manifest (name, version, description)
  agent_safety.cedar     # Agent spawning and permission bypass
  database_safety.cedar  # DROP, TRUNCATE, destructive SQL
  destructive_commands.cedar  # rm -rf, kill -9, terraform destroy
  file_protection.cedar  # .env reads, config overwrites, dotfile access
  git_safety.cedar       # force-push, reset --hard, branch deletion
  infrastructure_safety.cedar  # Deploy, cloud CLI, Terraform/Pulumi
  mcp_tools.cedar        # MCP server lockdown, input inspection
  package_operations.cedar     # npm publish, lockfile tampering
  secret_access.cedar    # SSH keys, API tokens, credential files

owasp-agentic/           # OWASP Top 10 for Agentic Applications (2026)
  pack.toml              # Pack manifest (depends on base)
  asi01_goal_hijack.cedar
  asi02_tool_misuse.cedar
  asi03_identity_privilege.cedar
  asi04_supply_chain.cedar
  asi05_code_execution.cedar
  asi06_memory_poisoning.cedar
  asi07_inter_agent.cedar
  asi08_cascading_failures.cedar
  asi10_rogue_agents.cedar
```

Each pack has a `pack.toml` manifest with name, version and dependency metadata. Each `.cedar` file contains one or more rules with `@id`, `@description`, `@incident`, `@controls` and `@enforcement` annotations.

## Versioning

This repo uses semantic versioning:

- **Patch** (`v1.0.1`): rule tuning, false positive fixes, description changes
- **Minor** (`v1.1.0`): new policies added, existing policies unchanged
- **Major** (`v2.0.0`): policy removals, schema changes, behavioral changes to existing rules

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

Apache 2.0 — same as the main Vectimus project.
