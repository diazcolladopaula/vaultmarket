"""Static catalogue of item models and their base prices."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cached_property, lru_cache
from importlib import resources


@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    material: str
    wear: int
    base_price: int  # cents

    @property
    def key(self) -> str:
        return f"{self.kind}/{self.material}/{self.wear}"


@dataclass(frozen=True)
class Catalog:
    entries: tuple[CatalogEntry, ...]
    wear_labels: tuple[str, ...]

    def get(self, kind: str, material: str, wear: int) -> CatalogEntry:
        return self._index[f"{kind}/{material}/{wear}"]

    @cached_property
    def _index(self) -> dict[str, CatalogEntry]:
        return {e.key: e for e in self.entries}

    def wear_label(self, wear: int) -> str:
        return self.wear_labels[wear]


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    text = resources.files("vaultmarket").joinpath("data/catalog.json").read_text("utf-8")
    raw = json.loads(text)
    entries = tuple(
        CatalogEntry(e["kind"], e["material"], e["wear"], e["base_price"]) for e in raw["items"]
    )
    return Catalog(entries, tuple(raw["wear_labels"]))
