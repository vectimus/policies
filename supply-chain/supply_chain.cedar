// Supply chain integrity -- block dangerous package management commands,
// lockfile tampering, registry configuration changes and untrusted
// dependency sources.

@id("vectimus-supchain-001")
@description("Block npm publish to prevent supply-chain attacks")
@incident("Clinejection: malicious npm packages published by compromised AI agent, February 2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Use npm pack to create a tarball for review, then request human approval before publishing.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};

@id("vectimus-supchain-002")
@description("Block pip install from non-standard indexes")
@incident("Dependency confusion attacks via private index spoofing, 2024-2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages from the default PyPI index, or request human approval for custom indexes.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*pip install*--index-url*" ||
    context.command like "*pip install*-i *"
};

@id("vectimus-supchain-003")
@description("Block npm install with URL sources instead of registry packages")
@incident("Trojanised packages installed via direct URL bypassing registry checks, 2025")
@controls("SLSA-L2, SOC2-CC6.8, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages from the npm registry by name instead of using direct URLs.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install http:*"
};

@id("vectimus-supchain-004")
@description("Block global npm installs which affect the system-wide environment")
@incident("Global npm install of compromised package affected all projects on developer machine, 2025")
@controls("SOC2-CC6.8, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages locally to the project with npm install (no -g flag) to limit blast radius.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install -g*"
};

@id("vectimus-supchain-005")
@description("Block agent modification of package lockfiles")
@incident("Dependency lockfile poisoning in ephemeral sandboxes, OWASP ASI05 Scenario 8")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Run the package manager install command to regenerate lockfiles naturally.  Do not edit lockfiles directly.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*package-lock.json" ||
    context.file_path like "*yarn.lock" ||
    context.file_path like "*pnpm-lock.yaml" ||
    context.file_path like "*Pipfile.lock" ||
    context.file_path like "*poetry.lock" ||
    context.file_path like "*uv.lock" ||
    context.file_path like "*Cargo.lock" ||
    context.file_path like "*Gemfile.lock" ||
    context.file_path like "*composer.lock"
};

@id("vectimus-supchain-006")
@description("Block modification of package registry configuration files")
@incident("Malicious MCP server impersonating Postmark on npm, 2025")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Package registry configuration should be managed by a human administrator, not modified by agents.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.npmrc" ||
    context.file_path like "*.pypirc" ||
    context.file_path like "*pip.conf" ||
    context.file_path like "*.cargo/config*" ||
    context.file_path like "*.yarnrc*"
};

@id("vectimus-supchain-007")
@description("Block cargo install from git URLs which bypass registry review")
@incident("Amazon Q supply chain compromise via poisoned extension, 2025")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install Rust packages from crates.io by name.  Git-sourced dependencies bypass registry verification.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*cargo install*--git*"
};

@id("vectimus-supchain-008")
@description("Block adding git submodules which can introduce unvetted code")
@incident("Agent-in-the-middle via agent cards in A2A protocol, Trustwave 2025")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Use package managers to add dependencies.  If a git submodule is needed, request human review of the source repository first.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git submodule add*"
};

// vectimus-supchain-009
// VTMS-2026-0108 | OWASP: ASI04 | SOC2-CC6.8 | NIST-AI-MG-3.2 | EU-AI-15
// @controls OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25
// TeamPCP supply chain attack: xinference 2.6.0-2.6.2 contained a base64-encoded credential-stealing
// payload injected into xinference/__init__.py that executed on import, exfiltrating SSH keys,
// AWS/GCP credentials, Kubernetes tokens and crypto wallets to C2 at lucyatemysuperbox[.]space.
// Blocks pip install of known-compromised xinference versions 2.6.0, 2.6.1 and 2.6.2 across both
// package_operation (context.command) and shell_command (resource.command) action surfaces.
@id("vectimus-supchain-009")
@description("Block pip install of TeamPCP-compromised xinference versions 2.6.0, 2.6.1, 2.6.2")
@incident("VTMS-2026-0108: TeamPCP trojanised xinference 2.6.0-2.6.2 on PyPI, April 2026")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Pin to xinference>=2.6.3 (first clean release after yanked versions). Verify the wheel hash matches the entry in .vectimus/supply-allowlist.toml before requesting human approval for any unlisted version.")
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

// vectimus-supchain-010
// VTMS-2026-0108 | OWASP: ASI04 | SOC2-CC6.8 | NIST-AI-MG-3.2 | EU-AI-15
// @controls OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25
// Structural supply-chain gap: TeamPCP-style PyPI package compromises go undetected at the
// tool-call boundary without pip hash verification, mirroring the npm hash-allowlist pattern
// from VTMS-2026-0001 (SANDWORM_MODE). Closes the pip equivalent of that gap.
// Blocks any agent-initiated pip install where the Vectimus supply-chain checker has not set
// context.pip_package_verified=true, requiring operator-maintained hash registration in
// .vectimus/supply-allowlist.toml before an AI agent may install any Python package.
@id("vectimus-supchain-010")
@description("Block pip install unless package hash pre-verified by Vectimus supply-chain checker")
@incident("VTMS-2026-0108: structural pip hash-verification gap enabling TeamPCP-style PyPI attacks")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, SLSA-L2, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Register the package name and expected hash in .vectimus/supply-allowlist.toml. The Vectimus supply-chain checker sets context.pip_package_verified=true when the resolved wheel hash matches the allowlist entry. Human approval is required for first-time registration of any new package or version bump.")
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
