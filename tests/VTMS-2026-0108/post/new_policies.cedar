// vectimus-supchain-009
// VTMS-2026-0108 | OWASP: ASI04 | SOC2-CC6.8 | NIST-AI-MG-3.2 | EU-AI-15
// @controls OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25
// TeamPCP supply chain attack: xinference 2.6.0-2.6.2 contained base64-encoded credential-stealing payload
// exfiltrating SSH keys, AWS/GCP credentials, Kubernetes tokens and crypto wallets to C2 at lucyatemysuperbox[.]space
// Blocks pip install of known-compromised xinference versions 2.6.0, 2.6.1 and 2.6.2 via both
// package_operation (context.command) and shell_command (resource.command) action surfaces
@id("vectimus-supchain-009")
forbid (
    principal,
    action in [Vectimus::Action::"package_operation", Vectimus::Action::"shell_command"],
    resource
) when {
    (context has command &&
        (context.command like "*xinference==2.6.0*" ||
         context.command like "*xinference==2.6.1*" ||
         context.command like "*xinference==2.6.2*")) ||
    (resource has command &&
        (resource.command like "*xinference==2.6.0*" ||
         resource.command like "*xinference==2.6.1*" ||
         resource.command like "*xinference==2.6.2*"))
};
// Override: pin to xinference>=2.6.3 (first clean release after yanked versions).
// Verify package hash matches the registered hash in .vectimus/supply-allowlist.toml
// before requesting human approval to install an unlisted version.

// vectimus-supchain-010
// VTMS-2026-0108 | OWASP: ASI04 | SOC2-CC6.8 | NIST-AI-MG-3.2 | EU-AI-15
// @controls OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25
// Structural supply-chain gap: TeamPCP-style PyPI package compromises go undetected at the
// tool-call boundary without pip hash verification, mirroring the npm hash-allowlist pattern
// already implemented for npm in vectimus-supchain-010 (npm).
// Blocks any agent-initiated pip install where the Vectimus supply-chain checker has not set
// context.pip_package_verified=true, requiring operator-maintained hash registration in
// .vectimus/supply-allowlist.toml before an AI agent may install a Python package.
@id("vectimus-supchain-010")
forbid (
    principal,
    action in [Vectimus::Action::"package_operation", Vectimus::Action::"shell_command"],
    resource
) when {
    (
        (context has command && context.command like "*pip install*") ||
        (resource has command && resource.command like "*pip install*")
    ) &&
    !(context has pip_package_verified && context.pip_package_verified == true)
};
// Override: register the package name and expected hash in .vectimus/supply-allowlist.toml.
// The Vectimus supply-chain checker will set context.pip_package_verified=true when the
// resolved wheel hash matches the allowlist entry. Human approval is required for first-time
// registration of any new package or version bump.
