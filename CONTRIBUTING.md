# Contributing to Vectimus Policies

Contributions are welcome. Every rule must trace back to a real incident.

## Adding a policy

1. **Identify the incident.** Find or reference a documented agentic AI security incident. No hypothetical rules.
2. **Choose the right pack.** Place your rule in the pack directory that matches the security domain (e.g. `supply-chain/`, `destructive-ops/`).
3. **Write the Cedar rule** with all required annotations:

```cedar
@id("vectimus-<pack>-<nnn>")
@description("What this rule blocks, in plain English")
@incident("The real attack or vulnerability that motivated this rule")
@controls("Comma-separated compliance framework mappings")
@suggested_alternative("What the agent should do instead")
forbid (
    principal,
    action == Vectimus::Action::"<action_type>",
    resource
) when {
    // match conditions
};
```

4. **Map to compliance frameworks** via `@controls`. Use these prefixes:
   - `SOC2-` (e.g. `SOC2-CC6.1`)
   - `NIST-AI-` (e.g. `NIST-AI-GV-1.1`)
   - `NIST-CSF-` (e.g. `NIST-CSF-PR.DS-01`)
   - `ISO27001-` (e.g. `ISO27001-A.8.9`)
   - `EU-AI-` (e.g. `EU-AI-15`)
   - `OWASP-ASI` (e.g. `OWASP-ASI01`)
   - `SLSA-` (e.g. `SLSA-L2`)
   - `CIS-` (e.g. `CIS-16`)

5. **Test the policy** in consumer repos (`vectimus/vectimus`) to verify the Cedar evaluates correctly.
6. **Update CHANGELOG.md** with your changes.
7. **Open a PR.** Tag it with the pack name.

## The rules

- **No incident, no rule.** Every policy must reference a real documented attack or vulnerability.
- **One rule per concern.** Don't bundle unrelated checks into a single policy.
- **Test both deny and allow.** Prove the policy blocks the attack AND allows legitimate use.

## Versioning

- **Patch** (`v2.0.1`) — Rule tuning, false-positive fixes, description changes
- **Minor** (`v2.1.0`) — New policies added, existing policies unchanged
- **Major** (`v3.0.0`) — Policy removals, schema changes, behavioral changes to existing rules

## Security vulnerabilities

If you discover a way to bypass a policy, do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under Apache 2.0.
