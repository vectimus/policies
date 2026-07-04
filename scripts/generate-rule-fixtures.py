"""Generate skeleton tests/rules/<id>/ fixtures for every @id() in *.cedar.

Strategy
--------
For each @id() forbid block:

1. Find the action expression to set the request action.
2. Find the first context.<key> like "<pattern>" clause to derive a payload.
3. Synthesize a value for context.<key> by stripping wildcards from the
   pattern.  Cedar's like wildcard matches any chars, so removing wildcards
   produces a concrete string containing every literal segment in order,
   which the pattern will then match.

The generator only writes a fixture if the directory does NOT already exist,
so manual fixtures are preserved across regenerations.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "tests" / "rules"

ACTION_RE = re.compile(r'action\s*==\s*Vectimus::Action::"([^"]+)"', re.DOTALL)
LIKE_RE = re.compile(r'context\.(\w+)\s+like\s+"([^"]*)"')

# Resource id chosen per action, just so the fixture parses.
DEFAULT_RESOURCE_BY_ACTION = {
    "shell_command": "shell",
    "file_read": "file",
    "file_write": "file",
    "infrastructure": "infra",
    "git_operation": "git",
    "package_operation": "package",
    "agent_spawn": "agent",
    "agent_message": "agent",
    "mcp_tool": "mcp_server",
    "web_request": "web",
}


def synthesize_value(pattern: str) -> str:
    """Strip wildcards from a Cedar like pattern, leaving the literal segments.

    Whitespace adjacent to a wildcard is literal in the pattern and must be
    preserved (e.g. ``"foo *"`` requires the matched string to contain
    ``"foo "`` then anything; if we strip the trailing space the pattern no
    longer matches).
    """
    value = pattern.replace("*", "")
    while "  " in value:
        value = value.replace("  ", " ")
    return value


def find_rule_block(text: str, rule_id: str) -> str | None:
    """Find the forbid {...} block that follows @id("<rule_id>")."""
    needle = f'@id("{rule_id}")'
    start = text.find(needle)
    if start == -1:
        return None
    forbid_pos = text.find("forbid", start)
    if forbid_pos == -1:
        return None
    when_brace = text.find("{", forbid_pos)
    if when_brace == -1:
        return None
    depth = 1
    i = when_brace + 1
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[forbid_pos:i]


def gather_rules() -> list[tuple[str, str]]:
    """Return [(rule_id, forbid_block), ...] across all .cedar files."""
    rules: list[tuple[str, str]] = []
    for cedar_file in sorted(REPO_ROOT.glob("**/*.cedar")):
        text = cedar_file.read_text()
        for m in re.finditer(r'@id\("([^"]+)"\)', text):
            rule_id = m.group(1)
            block = find_rule_block(text, rule_id)
            if block:
                rules.append((rule_id, block))
    return rules


def make_fixture(rule_id: str, block: str) -> dict | None:
    """Produce a skeleton request fixture from one forbid block."""
    action_match = ACTION_RE.search(block)
    if not action_match:
        return None
    action_name = action_match.group(1)

    like_match = LIKE_RE.search(block)
    if not like_match:
        return None

    context_key = like_match.group(1)
    pattern = like_match.group(2)
    value = synthesize_value(pattern)

    resource_id = DEFAULT_RESOURCE_BY_ACTION.get(action_name, "resource")

    return {
        "description": f"Auto-generated DENY fixture for {rule_id}",
        "principal": 'Vectimus::Agent::"coding_agent"',
        "action": f'Vectimus::Action::"{action_name}"',
        "resource": f'Vectimus::Resource::"{resource_id}"',
        "context": {context_key: value},
        "expected": "DENY",
        "expected_policy": rule_id,
    }


def make_entities(action_name: str) -> list[dict]:
    resource_id = DEFAULT_RESOURCE_BY_ACTION.get(action_name, "resource")
    return [
        {
            "uid": {"type": "Vectimus::Agent", "id": "coding_agent"},
            "attrs": {"name": "coding_agent", "framework": "claude-code"},
            "parents": [],
        },
        {
            "uid": {"type": "Vectimus::Resource", "id": resource_id},
            "attrs": {},
            "parents": [],
        },
    ]


def main() -> None:
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped_existing = 0
    skipped_unconditional = 0

    for rule_id, block in gather_rules():
        rule_dir = RULES_DIR / rule_id
        if rule_dir.exists():
            skipped_existing += 1
            continue

        fixture = make_fixture(rule_id, block)
        if fixture is None:
            skipped_unconditional += 1
            print(f"SKIP {rule_id}: no context.* like clause (unconditional or attr-based)")
            continue

        action_match = ACTION_RE.search(block)
        action_name = action_match.group(1) if action_match else "shell_command"

        rule_dir.mkdir(parents=True)
        (rule_dir / "entities.json").write_text(
            json.dumps(make_entities(action_name), indent=2) + "\n"
        )
        (rule_dir / "request_block.json").write_text(json.dumps(fixture, indent=2) + "\n")
        written += 1

    total = written + skipped_existing + skipped_unconditional
    print(
        f"\n{written} written, {skipped_existing} kept (existing), "
        f"{skipped_unconditional} skipped (no context-based like clause), "
        f"{total} rules total"
    )


if __name__ == "__main__":
    main()
