#!/usr/bin/env python3
"""Completeness guard: every Windows-targeting file_path pattern has a companion.

Consumer evaluators that run on a POSIX host canonicalise Windows/UNC paths to
lowercase + forward-slash before matching, so a `context.file_path` pattern
spelled the native way -- uppercase (`*CLAUDE.md`) or backslash-separated
(`*\\Windows\\System32\\*`) -- would stop matching unless the same rule also
carries a lowercase/forward-slash companion.  A missing companion is a silent
fail-open (a write the pack means to deny is allowed once canonicalised).

This script scans the packs in the repository it lives in and fails (exit 1) if
any forbid rule positively denies on a Windows-targeting file_path glob without
its canonical companion in the same rule.  It runs in this repo's own CI, where
the tree IS the authoritative corpus that feeds the live API -- so upstream
drift is caught at the source, independent of any downstream vendored copy.

Structural, not lexical: comments, `unless` clauses, `permit` rules and negated
predicates do not count as companions, and a rule mixing file_path patterns with
a non-flat-OR boolean shape (`&&`, `!`, parentheses) is refused rather than
mis-read.  Deliberately dependency-free (stdlib only) so CI needs no install.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_RULE_ID_RE = re.compile(r'@id\("([^"]+)"\)')
_FILE_PATH_LIKE_RE = re.compile(r'context\.file_path\s+like\s+"((?:\\.|[^"\\])*)"')

# (rule id, exact glob) intentionally left without a companion because a
# canonicalised path can never reach them -- keep in lockstep with the vendored
# guard's EXEMPT set (tests/test_pi.py in the vectimus repo).
EXEMPT: set[tuple[str, str]] = {
    ("vectimus-mcp-005", "*Jenkinsfile*"),
    ("vectimus-infra-007", "/Users/*/../*"),
    ("vectimus-infra-007", r"*\Users\*\..\*"),
    ("vectimus-infra-007", r"C:\Users\*\..\*"),
}


class UnsupportedCompanionShapeError(Exception):
    """A forbid rule carries file_path patterns in a boolean shape the flat-OR
    collector cannot verify, so the guard fails closed rather than guess."""


def _cedar_unescape(glob: str) -> str:
    return glob.replace("\\\\", "\\")


def _strip_comments(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        in_str = False
        kept: list[str] = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                in_str = not in_str
            elif ch == "/" and not in_str and i + 1 < len(line) and line[i + 1] == "/":
                break
            kept.append(ch)
            i += 1
        out.append("".join(kept))
    return "\n".join(out)


def _strip_string_literals(text: str) -> str:
    out: list[str] = []
    in_str = False
    for ch in text:
        if ch == '"':
            in_str = not in_str
            continue
        out.append(" " if in_str else ch)
    return "".join(out)


def _extract_when(text: str) -> str:
    m = re.search(r"\bwhen\s*\{", text)
    if not m:
        return ""
    start = text.index("{", m.start())
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : j]
    return text[start + 1 :]


def _denying_file_path_globs(rule_body: str) -> set[str]:
    if not re.search(r"\bforbid\b", rule_body):
        return set()
    when_block = _extract_when(rule_body)
    matches = list(_FILE_PATH_LIKE_RE.finditer(when_block))
    if not matches:
        return set()
    outside = _strip_string_literals(when_block)
    if any(tok in outside for tok in ("&&", "!", "(", ")")):
        raise UnsupportedCompanionShapeError(
            "a forbid rule mixes file_path patterns with a non-flat-OR boolean "
            "shape (&&, !, or parentheses); refusing to guess which globs deny"
        )
    return {_cedar_unescape(m.group(1)) for m in matches}


def _iter_rules(root: Path):
    for cedar in sorted(root.glob("*/*.cedar")):
        text = _strip_comments(cedar.read_text())
        ids = list(_RULE_ID_RE.finditer(text))
        for i, m in enumerate(ids):
            end = ids[i + 1].start() if i + 1 < len(ids) else len(text)
            globs = _denying_file_path_globs(text[m.end() : end])
            if globs:
                yield cedar.name, m.group(1), globs


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    missing: list[str] = []
    for pack, rule_id, deny_globs in _iter_rules(root):
        for glob in deny_globs:
            canonical = glob.replace("\\", "/").lower()
            if canonical == glob:
                continue
            if (rule_id, glob) in EXEMPT:
                continue
            if canonical not in deny_globs:
                missing.append(f"{pack} {rule_id}: {glob!r} -> needs companion {canonical!r}")
    if missing:
        print("Windows-companion completeness guard FAILED:\n  " + "\n  ".join(missing))
        print(
            "\nAdd the lowercase/forward-slash companion beside each pattern, or "
            "(only if a canonicalised path can never reach the rule) add an EXEMPT "
            "entry with the reason."
        )
        return 1
    print("Windows-companion completeness guard passed: every Windows-targeting "
          "file_path pattern has its canonical companion.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
