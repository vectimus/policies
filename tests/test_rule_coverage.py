"""Coverage gate: every @id() in *.cedar must have a fixture under tests/rules/.

When a new rule is added without a fixture this test fails, with a clear
diff of which rule IDs are missing.  Use ``scripts/generate-rule-fixtures.py``
to scaffold a skeleton fixture.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = Path(__file__).resolve().parent / "rules"
ID_RE = re.compile(r'@id\("([^"]+)"\)')


def _all_rule_ids() -> set[str]:
    ids: set[str] = set()
    for cedar_file in sorted(REPO_ROOT.glob("**/*.cedar")):
        for m in ID_RE.finditer(cedar_file.read_text()):
            ids.add(m.group(1))
    return ids


def _covered_rule_ids() -> set[str]:
    if not RULES_DIR.is_dir():
        return set()
    return {p.name for p in RULES_DIR.iterdir() if p.is_dir() and (p / "request_block.json").exists()}


def test_every_rule_has_a_fixture() -> None:
    declared = _all_rule_ids()
    covered = _covered_rule_ids()
    missing = sorted(declared - covered)
    orphaned = sorted(covered - declared)

    parts = []
    if missing:
        parts.append(
            f"{len(missing)} rules without a fixture under tests/rules/:\n  - "
            + "\n  - ".join(missing)
            + "\n  Run scripts/generate-rule-fixtures.py to scaffold."
        )
    if orphaned:
        parts.append(
            f"{len(orphaned)} fixture directories with no matching @id (rule renamed/deleted?):\n  - "
            + "\n  - ".join(orphaned)
        )
    if parts:
        raise AssertionError("\n\n".join(parts))
