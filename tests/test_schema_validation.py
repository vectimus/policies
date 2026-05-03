"""Validate every Cedar policy in the repo against the schema.

Catches things the runtime-only sandbox replay can't:

- wrong action namespace (``Vectimus::Action::"x"`` vs bare ``Action::"x"``)
- undefined entity types in principal/resource
- references to context fields that don't exist on the action
- unknown attributes on entities

These are silent failures at evaluation time — the policy just never matches —
but they're hard errors at validation time.
"""

from __future__ import annotations

from pathlib import Path

import cedarpy

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema.cedarschema"


def test_schema_exists() -> None:
    assert SCHEMA_PATH.exists(), f"Schema not found at {SCHEMA_PATH}"


def test_policies_validate_against_schema() -> None:
    policies = ""
    for cedar_file in sorted(REPO_ROOT.glob("**/*.cedar")):
        policies += cedar_file.read_text() + "\n"

    schema = SCHEMA_PATH.read_text()
    result = cedarpy.validate_policies(policies, schema)

    if not result.validation_passed:
        errors = "\n".join(f"  - {e}" for e in result.errors)
        raise AssertionError(f"Cedar schema validation failed:\n{errors}")
