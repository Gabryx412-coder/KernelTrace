"""Parsing e validazione delle regole di detection YAML.

Mirror in Python dello schema Rust
(`kerneltrace-agent::detection::rule::Rule`), usato per validare le regole
prima del deploy senza richiedere una toolchain Rust (es. in una pipeline
CI che verifica le pull request sulla directory `rules/community/`).
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPERATORS = {"equals", "contains", "regex", "in", "present"}
VALID_MATCH_KINDS = {"simple", "sequence"}
VALID_CORRELATION_KEYS = {"pid", "ppid"}


@dataclasses.dataclass
class RuleValidationError:
    rule_path: Path
    message: str

    def __str__(self) -> str:
        return f"{self.rule_path}: {self.message}"


@dataclasses.dataclass
class RuleSummary:
    """Riepilogo di una regola valida, usato dal comando `rules list`."""

    id: str
    name: str
    severity: str
    enabled: bool
    match_kind: str
    source_path: Path


def _validate_condition(condition: dict[str, Any], rule_path: Path) -> list[RuleValidationError]:
    errors = []
    field = condition.get("field")
    operator = condition.get("operator")

    if not field or not isinstance(field, str):
        errors.append(RuleValidationError(rule_path, "condition missing required 'field'"))

    if operator not in VALID_OPERATORS:
        errors.append(
            RuleValidationError(
                rule_path,
                f"condition has invalid operator '{operator}', expected one of {sorted(VALID_OPERATORS)}",
            )
        )

    if operator != "present" and "value" not in condition:
        errors.append(
            RuleValidationError(rule_path, "condition missing required 'value' (except for 'present')")
        )

    return errors


def validate_rule_dict(data: dict[str, Any], rule_path: Path) -> list[RuleValidationError]:
    """Valida un dizionario di regola già parsato, restituendo l'elenco
    degli errori riscontrati (vuoto se la regola è valida)."""
    errors: list[RuleValidationError] = []

    if not data.get("id"):
        errors.append(RuleValidationError(rule_path, "missing required field 'id'"))
    if not data.get("name"):
        errors.append(RuleValidationError(rule_path, "missing required field 'name'"))

    severity = data.get("severity")
    if severity not in VALID_SEVERITIES:
        errors.append(
            RuleValidationError(
                rule_path,
                f"invalid severity '{severity}', expected one of {sorted(VALID_SEVERITIES)}",
            )
        )

    match_spec = data.get("match")
    if not isinstance(match_spec, dict):
        errors.append(RuleValidationError(rule_path, "missing or invalid 'match' section"))
        return errors

    kind = match_spec.get("kind")
    if kind not in VALID_MATCH_KINDS:
        errors.append(
            RuleValidationError(
                rule_path,
                f"invalid match kind '{kind}', expected one of {sorted(VALID_MATCH_KINDS)}",
            )
        )
        return errors

    if kind == "simple":
        conditions = match_spec.get("conditions", [])
        if not conditions:
            errors.append(RuleValidationError(rule_path, "simple match must have at least one condition"))
        for condition in conditions:
            errors.extend(_validate_condition(condition, rule_path))

    elif kind == "sequence":
        first = match_spec.get("first", [])
        then = match_spec.get("then", [])
        within_seconds = match_spec.get("within_seconds")
        correlate_by = match_spec.get("correlate_by")

        if not first:
            errors.append(RuleValidationError(rule_path, "sequence match requires non-empty 'first'"))
        if not then:
            errors.append(RuleValidationError(rule_path, "sequence match requires non-empty 'then'"))
        if not isinstance(within_seconds, int) or within_seconds <= 0:
            errors.append(RuleValidationError(rule_path, "'within_seconds' must be a positive integer"))
        if correlate_by not in VALID_CORRELATION_KEYS:
            errors.append(
                RuleValidationError(
                    rule_path,
                    f"invalid correlate_by '{correlate_by}', expected one of {sorted(VALID_CORRELATION_KEYS)}",
                )
            )

        for condition in first:
            errors.extend(_validate_condition(condition, rule_path))
        for condition in then:
            errors.extend(_validate_condition(condition, rule_path))

    return errors


def load_and_validate_rule_file(path: Path) -> tuple[RuleSummary | None, list[RuleValidationError]]:
    """Carica e valida un singolo file di regola YAML.

    Restituisce una tupla `(summary, errors)`: `summary` è `None` se il
    file non è una regola valida, nel qual caso `errors` contiene almeno
    un elemento.
    """
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [RuleValidationError(path, f"cannot read file: {exc}")]

    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as exc:
        return None, [RuleValidationError(path, f"invalid YAML syntax: {exc}")]

    if not isinstance(data, dict):
        return None, [RuleValidationError(path, "rule file must contain a YAML mapping")]

    errors = validate_rule_dict(data, path)
    if errors:
        return None, errors

    match_spec = data["match"]
    summary = RuleSummary(
        id=data["id"],
        name=data["name"],
        severity=data["severity"],
        enabled=data.get("enabled", True),
        match_kind=match_spec["kind"],
        source_path=path,
    )
    return summary, []


def validate_rules_directory(directory: Path) -> tuple[list[RuleSummary], list[RuleValidationError]]:
    """Valida tutti i file `.yaml`/`.yml` in una directory (non
    ricorsivamente, coerente con il comportamento del parser Rust)."""
    summaries: list[RuleSummary] = []
    all_errors: list[RuleValidationError] = []

    if not directory.is_dir():
        return [], [RuleValidationError(directory, "not a directory or does not exist")]

    for path in sorted(directory.iterdir()):
        if path.suffix not in (".yaml", ".yml"):
            continue

        summary, errors = load_and_validate_rule_file(path)
        if summary is not None:
            summaries.append(summary)
        all_errors.extend(errors)

    return summaries, all_errors