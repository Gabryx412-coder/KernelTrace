"""Validazione strutturale della configurazione YAML dell'agente.

Questo modulo replica in Python solo i vincoli strutturali di alto
livello già imposti dallo schema Rust (`kerneltrace-agent::config::schema`),
utile per una validazione rapida senza dover invocare il binario Rust
(es. in una pipeline CI che valida un file di configurazione proposto in
una pull request, su un runner che non ha Cargo installato).

La validazione qui è deliberatamente meno rigorosa di quella Rust (che
resta la fonte di verità, applicata realmente al momento del caricamento
da parte dell'agente): l'obiettivo è individuare rapidamente errori
grossolani (chiavi sconosciute, tipi palesemente sbagliati) senza
duplicare l'intera logica di deserializzazione `serde`.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import yaml

# Chiavi di primo livello riconosciute dallo schema Rust
# (`kerneltrace-agent::config::schema::Config`). Tenute in sincronia
# manualmente: un cambiamento allo schema Rust che aggiunge/rimuove una
# sezione di primo livello deve essere riflesso qui.
KNOWN_TOP_LEVEL_KEYS = {
    "agent",
    "logging",
    "monitoring",
    "rules",
    "output",
    "container",
    "response",
}

KNOWN_OUTPUT_SINKS = {"stdout", "file", "json"}
KNOWN_LOG_FORMATS = {"json", "pretty", "compact"}
KNOWN_HASH_ALGORITHMS = {"sha256", "blake3"}


@dataclasses.dataclass
class ValidationIssue:
    """Un singolo problema rilevato nella configurazione."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclasses.dataclass
class ValidationResult:
    """Esito della validazione di un file di configurazione."""

    issues: list[ValidationIssue]

    @property
    def is_valid(self) -> bool:
        return len(self.issues) == 0


def _check_unknown_keys(data: dict[str, Any], known: set[str], path: str) -> list[ValidationIssue]:
    issues = []
    for key in data:
        if key not in known:
            issues.append(ValidationIssue(path=path, message=f"unknown key '{key}'"))
    return issues


def validate_config_dict(data: dict[str, Any]) -> ValidationResult:
    """Valida un dizionario già parsato (utile per testare la logica senza
    dover scrivere un file su disco a ogni test)."""
    issues: list[ValidationIssue] = []

    if not isinstance(data, dict):
        return ValidationResult(
            issues=[ValidationIssue(path="$", message="root document must be a mapping")]
        )

    issues.extend(_check_unknown_keys(data, KNOWN_TOP_LEVEL_KEYS, "$"))

    output = data.get("output")
    if isinstance(output, dict):
        sinks = output.get("sinks", [])
        if isinstance(sinks, list):
            for sink in sinks:
                if sink not in KNOWN_OUTPUT_SINKS:
                    issues.append(
                        ValidationIssue(
                            path="$.output.sinks",
                            message=f"unknown sink kind '{sink}', expected one of {sorted(KNOWN_OUTPUT_SINKS)}",
                        )
                    )
            needs_file_path = any(s in ("file", "json") for s in sinks)
            if needs_file_path and not output.get("file_path"):
                issues.append(
                    ValidationIssue(
                        path="$.output.file_path",
                        message="required when 'file' or 'json' sink is enabled",
                    )
                )

    logging_section = data.get("logging")
    if isinstance(logging_section, dict):
        log_format = logging_section.get("format")
        if log_format is not None and log_format not in KNOWN_LOG_FORMATS:
            issues.append(
                ValidationIssue(
                    path="$.logging.format",
                    message=f"unknown log format '{log_format}', expected one of {sorted(KNOWN_LOG_FORMATS)}",
                )
            )

    monitoring = data.get("monitoring")
    if isinstance(monitoring, dict):
        algorithm = monitoring.get("fim_hash_algorithm")
        if algorithm is not None and algorithm not in KNOWN_HASH_ALGORITHMS:
            issues.append(
                ValidationIssue(
                    path="$.monitoring.fim_hash_algorithm",
                    message=f"unknown hash algorithm '{algorithm}', expected one of {sorted(KNOWN_HASH_ALGORITHMS)}",
                )
            )

        watch_paths = monitoring.get("fim_watch_paths", [])
        if isinstance(watch_paths, list):
            for watch_path in watch_paths:
                if not isinstance(watch_path, str):
                    issues.append(
                        ValidationIssue(
                            path="$.monitoring.fim_watch_paths",
                            message=f"path entries must be strings, got {type(watch_path).__name__}",
                        )
                    )

    rules_section = data.get("rules")
    if isinstance(rules_section, dict):
        directories = rules_section.get("directories", [])
        if isinstance(directories, list):
            for directory in directories:
                if isinstance(directory, str) and not Path(directory).exists():
                    issues.append(
                        ValidationIssue(
                            path="$.rules.directories",
                            message=f"directory does not exist: {directory}",
                        )
                    )

    return ValidationResult(issues=issues)


def validate_config_file(path: Path) -> ValidationResult:
    """Carica e valida un file di configurazione YAML da disco."""
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ValidationResult(
            issues=[ValidationIssue(path=str(path), message=f"cannot read file: {exc}")]
        )

    try:
        data = yaml.safe_load(contents) or {}
    except yaml.YAMLError as exc:
        return ValidationResult(
            issues=[ValidationIssue(path=str(path), message=f"invalid YAML syntax: {exc}")]
        )

    return validate_config_dict(data)