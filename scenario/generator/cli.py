"""Assemble the full Elastibank dataset and write it as _bulk NDJSON, one file per data stream."""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import assets, attack, beacon, noise
from .ecs import Doc

DEFAULT_SEED = 29
BEACON_WINDOW = timedelta(hours=48)


def generate(anchor: datetime, seed: int = DEFAULT_SEED) -> dict[str, list[dict]]:
    """Build every doc for the scenario, keyed by data stream and sorted by @timestamp.

    Each component draws from its own seeded RNG so changing one never shifts another.
    """
    background_start = anchor + attack.INITIAL_ACCESS_AT
    docs: list[Doc] = []
    docs += attack.build_attack_chain(anchor)
    docs += attack.build_false_positives(anchor)
    docs += beacon.build_beacon(anchor - BEACON_WINDOW, anchor, random.Random(f"{seed}:beacon"))
    docs += beacon.build_decoy_beacons(background_start, anchor, random.Random(f"{seed}:decoys"))
    docs += noise.build_noise(background_start, anchor, random.Random(f"{seed}:noise"))

    groups: dict[str, list[dict]] = defaultdict(list)
    for stream, doc in docs:
        groups[stream].append(doc)
    for stream_docs in groups.values():
        stream_docs.sort(key=lambda d: d["@timestamp"])
    return dict(groups)


def write_bulk(groups: dict[str, list[dict]], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for stream in sorted(groups):
        path = out_dir / f"{stream}.ndjson"
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for doc in groups[stream]:
                fh.write('{"create":{}}\n')
                fh.write(json.dumps(doc, separators=(",", ":"), sort_keys=True))
                fh.write("\n")
        paths.append(path)
    return paths


def write_lookups(out_dir: Path) -> list[Path]:
    """Write the asset and user inventories under ``out_dir/lookup``, keyed by ``_id`` so a re-load overwrites."""
    lookup_dir = out_dir / "lookup"
    lookup_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for index, docs, key in (
        ("elastibank-assets", assets.build_assets(), lambda d: d["host"]["name"]),
        ("elastibank-users", assets.build_users(), lambda d: d["user"]["name"]),
    ):
        path = lookup_dir / f"{index}.ndjson"
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for doc in sorted(docs, key=key):
                fh.write(json.dumps({"index": {"_id": key(doc)}}, separators=(",", ":")) + "\n")
                fh.write(json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n")
        paths.append(path)
    return paths


def _parse_anchor(text: str) -> datetime:
    # datetime.fromisoformat only accepts a trailing "Z" from Python 3.11.
    parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"anchor {text!r} has no timezone; use e.g. 2026-11-02T10:00:00Z")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m scenario.generator", description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="directory for the _bulk NDJSON files")
    parser.add_argument("--anchor", help="ISO-8601 time with a UTC offset to treat as 'now' (default: now, UTC)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)

    try:
        anchor = _parse_anchor(args.anchor) if args.anchor else datetime.now(timezone.utc)
    except ValueError as exc:
        print(f"error: invalid --anchor: {exc}", file=sys.stderr)
        return 2

    groups = generate(anchor, args.seed)
    write_bulk(groups, args.out)
    write_lookups(args.out)
    for stream in sorted(groups):
        print(f"{stream}\t{len(groups[stream])}")
    return 0
