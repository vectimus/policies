# Changelog

All notable changes to Vectimus policies will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-14

### Added

- Initial release: policies extracted from vectimus/vectimus repo
- **base** pack (9 policy files, 52 rules): agent safety, database safety, destructive commands, file protection, git safety, infrastructure safety, MCP tools, package operations, secret access
- **owasp-agentic** pack (9 policy files, 29 rules): ASI01 through ASI10 (excluding ASI09)
- GitHub Action to notify consumer repos on new tags
