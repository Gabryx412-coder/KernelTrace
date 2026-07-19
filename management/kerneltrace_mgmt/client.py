"""Client per il consumo del flusso di eventi prodotto dall'agente.

L'agente KernelTrace non espone (in questa fase) un'API di rete: gli
eventi sono disponibili come file JSON Lines (sink `json`, vedi
`kerneltrace-agent::output::json`). Questo modulo fornisce un iteratore
che segue tale file in stile `tail -f`, per costruire strumenti di
consultazione o inoltro senza dover reimplementare il parsing degli
eventi in Rust.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class EventStreamError(Exception):
    """Errore nella lettura o nel parsing del flusso di eventi."""


def _iter_existing_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8") as handle:
        yield from handle


def tail_events(path: Path, poll_interval_seconds: float = 0.5) -> Iterator[dict[str, Any]]:
    """Segue un file JSON Lines in stile `tail -f`, restituendo un
    generatore di eventi già deserializzati come dizionari Python.

    Le righe che non sono JSON valido (es. una scrittura parziale
    interrotta a metà, rara ma possibile su crash improvvisi dell'agente)
    vengono scartate silenziosamente: un singolo evento malformato non
    deve interrompere la lettura del resto dello stream, coerentemente con
    la stessa filosofia di resilienza della pipeline Rust
    (`kerneltrace_agent::events::pipeline`).
    """
    if not path.exists():
        raise EventStreamError(f"event file does not exist: {path}")

    with path.open("r", encoding="utf-8") as handle:
        # Ci posizioniamo alla fine del file esistente: il comportamento
        # "tail -f" segue solo le righe scritte da questo momento in poi,
        # coerente con l'aspettativa di un operatore che vuole osservare
        # l'attività in tempo reale, non rileggere l'intera cronologia.
        handle.seek(0, 2)

        while True:
            line = handle.readline()
            if not line:
                time.sleep(poll_interval_seconds)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_all_events(path: Path) -> list[dict[str, Any]]:
    """Legge tutti gli eventi esistenti in un file JSON Lines, senza
    seguirne le scritture future. Utile per analisi puntuali (es. `grep`
    su un file di eventi archiviato) piuttosto che monitoraggio live."""
    if not path.exists():
        raise EventStreamError(f"event file does not exist: {path}")

    events = []
    for line in _iter_existing_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def filter_by_tag(events: list[dict[str, Any]], tag: str) -> list[dict[str, Any]]:
    """Filtra una lista di eventi già deserializzati per la presenza di un
    dato tag (es. `suspected_reverse_shell`, `rule:builtin-...`)."""
    return [event for event in events if tag in event.get("tags", [])]