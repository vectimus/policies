// Data exfiltration -- detect and block data exfiltration patterns that are
// the observable consequence of goal hijack via prompt injection.
// Vectimus cannot detect the goal manipulation itself but can intercept
// the exfiltration actions that typically follow.

@id("vectimus-exfil-001")
@description("Block base64-encoded data exfiltration via curl or wget")
@incident("Amazon Q Developer secrets leaked via DNS and prompt injection, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("If you need to send data to an external service, request human approval and use an approved API endpoint.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*base64*|*curl*" ||
    context.command like "*base64*|*wget*" ||
    context.command like "*curl*base64*" ||
    context.command like "*wget*base64*" ||
    // Windows PowerShell
    context.command like "*[Convert]::ToBase64String*Invoke-WebRequest*" ||
    context.command like "*[Convert]::ToBase64String*Invoke-RestMethod*" ||
    context.command like "*certutil*-encode*" ||
    // Windows cmd
    context.command like "*certutil*-encode*|*curl*"
};

@id("vectimus-exfil-002")
@description("Block DNS exfiltration via nslookup or dig with piped input")
@incident("Amazon Q Developer secrets leaked via DNS exfiltration, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Use standard DNS lookup tools without piped encoded data.  If DNS queries are needed, run them directly with explicit domain names.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*nslookup*$(*" ||
    context.command like "*dig*$(*" ||
    context.command like "*nslookup*`*" ||
    context.command like "*dig*`*" ||
    // Windows PowerShell
    context.command like "*Resolve-DnsName*$(*" ||
    context.command like "*Resolve-DnsName*`(*"
};

@id("vectimus-exfil-003")
@description("Block piping credential or system files to network transfer tools")
@incident("EchoLeak: zero-click indirect prompt injection against M365 Copilot, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Do not pipe sensitive file contents to network tools.  Access files locally and use approved channels for data transfer.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*cat /etc/passwd*|*curl*" ||
    context.command like "*cat /etc/shadow*|*curl*" ||
    context.command like "*cat /etc/passwd*|*wget*" ||
    context.command like "*cat /etc/shadow*|*wget*" ||
    context.command like "*cat /etc/passwd*|*nc *" ||
    context.command like "*cat /etc/shadow*|*nc *" ||
    // Windows -- credential database and registry exfiltration
    context.command like "*type*\\SAM*|*curl*" ||
    context.command like "*type*\\SYSTEM*|*curl*" ||
    context.command like "*reg save*HKLM\\SAM*" ||
    context.command like "*reg save*HKLM\\SYSTEM*" ||
    // Windows PowerShell
    context.command like "*Get-Content*SAM*|*Invoke-WebRequest*" ||
    context.command like "*Get-Content*SYSTEM*|*Invoke-RestMethod*"
};

// vectimus-exfil-004
// VTMS-2026-0037 | OWASP: ASI04 | SOC2-CC6.6 | NIST-AI-GV-1.1 | EU-AI-15
// @controls OWASP-ASI04, SOC2-CC6.6, NIST-AI-GV-1.1, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23
// TeamPCP/CanisterWorm (March 2026): the threat actor backdoored the Trivy VS Code extension
// (v1.8.12-1.8.13) with hidden natural-language prompts directing locally installed AI coding
// assistants (Claude Code, Copilot, Gemini CLI, Codex, Kiro) to harvest auth tokens and
// exfiltrate them via the victim's own GitHub CLI.  Existing file_read policies block direct
// credential file reads (vectimus-secrets-001 through -003) but the GitHub CLI exfiltration
// path — gh auth token, gh api POST, gh issue create, gh gist create — was not covered.
// Blocks GitHub CLI shell commands used as AI-agent-directed credential exfiltration channels.
@id("vectimus-exfil-004")
@description("Block GitHub CLI commands used as AI-agent-directed credential exfiltration channels")
@incident("VTMS-2026-0037: TeamPCP/CanisterWorm — backdoored Trivy VS Code extension (v1.8.12-1.8.13) injected hidden prompts directing AI assistants to exfiltrate auth tokens via gh auth token, gh api POST, gh issue create and gh gist create")
@controls("OWASP-ASI04, SOC2-CC6.6, NIST-AI-GV-1.1, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Use read-only gh commands (gh pr list, gh repo view, gh issue list) for repository inspection.  Auth token retrieval and write operations via GitHub CLI require human approval.  Programmatic GitHub API writes should use a scoped GitHub App token via an approved workflow, not the ambient gh credential.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // gh auth token — retrieves the raw stored GitHub authentication token in plaintext;
    // no legitimate AI coding-assistant use case; primary CanisterWorm Phase 3 primitive
    context.command like "*gh auth token*" ||

    // gh api with write-method flags — used to POST credential payloads to arbitrary
    // GitHub API endpoints (issues, gists, comments) as an exfiltration channel
    (context.command like "*gh api *" && context.command like "*--method POST*") ||
    (context.command like "*gh api *" && context.command like "*-X POST*") ||
    (context.command like "*gh api *" && context.command like "*--method PATCH*") ||
    (context.command like "*gh api *" && context.command like "*-X PATCH*") ||
    (context.command like "*gh api *" && context.command like "*--method PUT*") ||
    (context.command like "*gh api *" && context.command like "*-X PUT*") ||

    // gh issue create / gh gist create with shell command substitution — used to embed
    // harvested environment-variable or file content into issue/gist bodies
    (context.command like "*gh issue create*" && context.command like "*$(*") ||
    (context.command like "*gh issue create*" && context.command like "*$GITHUB_TOKEN*") ||
    (context.command like "*gh issue create*" && context.command like "*$GH_TOKEN*") ||
    (context.command like "*gh gist create*" && context.command like "*$(*") ||
    (context.command like "*gh gist create*" && context.command like "*$GITHUB_TOKEN*") ||
    (context.command like "*gh gist create*" && context.command like "*$GH_TOKEN*") ||

    // gh gist create referencing home-directory paths — catches credential file exfiltration
    // where the harvested file content is piped to gist (e.g. gh gist create ~/.env)
    (context.command like "*gh gist create*" && context.command like "*~/*")
};
// Override: legitimate programmatic GitHub write operations (e.g. automated release notes)
// should use a scoped GitHub App installation token injected at the workflow level, not the
// ambient gh CLI credential.  If a supervised workflow requires gh api writes, set
// context.approved_gh_api_write = true in the request context to bypass this rule.
