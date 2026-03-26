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
// VTMS-2026-0011 | OWASP: ASI04 | SOC2-CC6.6 | NIST-AI-GV-1.3 | EU-AI-15
// @controls OWASP-ASI04, OWASP-ASI01, SOC2-CC6.6, NIST-AI-GV-1.3, EU-AI-15, NIST-CSF-PR.DS-02, ISO27001-A.8.23
// ContextCrush (2026-03-05): poisoned Context7 MCP documentation caused agents to POST
// .env credentials to attacker-controlled GitHub repos via curl issue creation.
// Closes the shell_command exfiltration gap left by the web_request-scoped EXAG-001.
// Blocks curl/wget/PowerShell commands that transmit .env or credential file contents
// via shell substitution, @ file-upload syntax, or pipe to an outbound HTTP request.
@id("vectimus-exfil-004")
@description("Block curl/wget/PowerShell POST commands that transmit .env credential file contents to external endpoints")
@incident("VTMS-2026-0011: ContextCrush — Context7 MCP documentation poisoning, 2026-03-05")
@controls("OWASP-ASI04, OWASP-ASI01, SOC2-CC6.6, NIST-AI-GV-1.3, EU-AI-15, NIST-CSF-PR.DS-02, ISO27001-A.8.23")
@suggested_alternative("To transmit configuration data to an external service, request human approval and supply credentials via a secrets manager — never read credential files directly inside a shell command.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // curl: shell substitution reading .env content inline (e.g. --data "$(cat .env)")
    context.command like "*curl*$(cat*.env*" ||
    context.command like "*curl*$(cat *env*" ||
    // curl: @ file-upload syntax pointing at a .env file (e.g. --data @.env, -d @.env)
    context.command like "*curl*--data*@*.env*" ||
    context.command like "*curl* -d *@*.env*" ||
    context.command like "*curl*--data-binary*@*.env*" ||
    context.command like "*curl*--data-urlencode*@*.env*" ||
    // curl: .env piped directly into curl (e.g. cat .env | curl -X POST ...)
    context.command like "*cat*.env*|*curl*" ||
    context.command like "*cat *env*|*curl*" ||
    // wget: shell substitution reading .env content (e.g. --post-data="$(cat .env)")
    context.command like "*wget*--post-data*$(cat*.env*" ||
    context.command like "*wget*--post-data*$(cat *env*" ||
    // wget: --post-file pointing at a .env file
    context.command like "*wget*--post-file=*.env*" ||
    context.command like "*wget*--post-file *.env*" ||
    // wget: .env piped into wget POST
    context.command like "*cat*.env*|*wget*--post*" ||
    context.command like "*cat *env*|*wget*--post*" ||
    // PowerShell: Get-Content of .env piped to web request cmdlets
    context.command like "*Get-Content*.env*|*Invoke-WebRequest*" ||
    context.command like "*Get-Content*.env*|*Invoke-RestMethod*" ||
    context.command like "*Get-Content *env*|*Invoke-WebRequest*" ||
    context.command like "*Get-Content *env*|*Invoke-RestMethod*"
};
// Override: approved workflows that must transmit environment data should use a secrets
// manager integration (e.g. AWS Secrets Manager, HashiCorp Vault) with explicit
// per-secret injection rather than reading credential files in shell commands.
// Add the specific approved command pattern to context.allowed_exfil_commands.
