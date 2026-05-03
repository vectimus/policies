"""Sandbox replay tests for VTMS-* fixtures.

Each fixture under ``tests/VTMS-<year>-<id>/`` describes one incident:

- ``entities.json``  — Cedar entities involved
- ``request_block*.json`` — requests the policies must DENY
- ``request_allow*.json`` — requests the policies must ALLOW (no over-blocking)

Each request file declares ``expected: "DENY" | "ALLOW"``.  The runner loads
all ``.cedar`` files in the repo, runs cedarpy.is_authorized, and asserts the
decision matches.

Cedar uses default-deny when no permit policies are present.  Vectimus policies
are forbid-only, so we apply the same convention as the vectimus evaluator:
``decision == DENY`` with empty ``reasons`` means no forbid rule matched and is
treated as ALLOW.
"""

from __future__ import annotations

import json
from pathlib import Path

import cedarpy
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent


def _load_policies() -> str:
    """Concatenate every .cedar file in the repo into a single policies blob."""
    policies = ""
    for cedar_file in sorted(REPO_ROOT.glob("**/*.cedar")):
        policies += cedar_file.read_text() + "\n"
    return policies


def _discover_cases() -> list[tuple[str, Path, Path]]:
    """Yield (test_id, fixture_dir, request_file) for every request_*.json fixture."""
    cases: list[tuple[str, Path, Path]] = []
    for fixture_dir in sorted(TESTS_DIR.glob("VTMS-*")):
        if not fixture_dir.is_dir():
            continue
        for request_file in sorted(fixture_dir.glob("request_*.json")):
            test_id = f"{fixture_dir.name}/{request_file.stem}"
            cases.append((test_id, fixture_dir, request_file))
    return cases


CASES = _discover_cases()


@pytest.fixture(scope="session")
def policies_text() -> str:
    return _load_policies()


@pytest.mark.parametrize(
    "fixture_dir,request_file",
    [(c[1], c[2]) for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_sandbox_replay(fixture_dir: Path, request_file: Path, policies_text: str) -> None:
    entities = json.loads((fixture_dir / "entities.json").read_text())
    request = json.loads(request_file.read_text())
    expected = request["expected"]

    response = cedarpy.is_authorized(
        {
            "principal": request["principal"],
            "action": request["action"],
            "resource": request["resource"],
            "context": request.get("context", {}),
        },
        policies_text,
        entities,
    )

    reasons = list(response.diagnostics.reasons) if response.diagnostics.reasons else []
    errors = list(response.diagnostics.errors) if response.diagnostics.errors else []

    if response.decision == cedarpy.Decision.Allow:
        actual = "ALLOW"
    elif not reasons:
        # Default-deny with no matched forbid rule -> treat as ALLOW
        actual = "ALLOW"
    else:
        actual = "DENY"

    description = request.get("description", "")
    assert actual == expected, (
        f"\nFixture: {fixture_dir.name}/{request_file.name}\n"
        f"Description: {description}\n"
        f"Expected: {expected}\n"
        f"Actual: {actual}\n"
        f"Matched policies: {reasons}\n"
        f"Errors: {errors}"
    )


def test_at_least_one_fixture_discovered() -> None:
    """Sanity check — fail loudly if fixture discovery silently breaks."""
    assert len(CASES) > 0, "No VTMS-*/request_*.json fixtures found"
