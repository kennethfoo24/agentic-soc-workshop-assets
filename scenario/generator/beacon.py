"""The low-and-slow C2 beacon (no rule detects it) and regular-but-benign decoys to hunt past."""
from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta

from . import ecs
from .ecs import Doc
from .org import C2_DOMAIN, C2_IP, HOSTS, VICTIM_HOST, host

_WINDOWS_UPDATE = ("ctldl.windowsupdate.com", "198.51.100.20", 80)
_EDR_CLOUD = ("edr-cloud.elastibank.example", "198.51.100.55", 443)


def _ticks(
    first: datetime, end: datetime, interval_s: float, jitter: float, rng: random.Random
) -> Iterator[datetime]:
    t = first
    while t < end:
        yield t
        t += timedelta(seconds=interval_s * (1 + rng.uniform(-jitter, jitter)))


def build_beacon(
    start: datetime,
    end: datetime,
    rng: random.Random,
    interval_s: int = 300,
    jitter: float = 0.10,
) -> list[Doc]:
    victim = host(VICTIM_HOST)
    docs: list[Doc] = []
    for t in _ticks(start, end, interval_s, jitter, rng):
        docs.append(
            ecs.network_flow(t, victim, C2_IP, 443, C2_DOMAIN, rng.randint(300, 900), rng.randint(200, 1500))
        )
    t = start
    while t < end:
        docs.append(ecs.dns_query(t, victim, C2_DOMAIN, C2_IP))
        t += timedelta(hours=1)
    return docs


def build_decoy_beacons(start: datetime, end: datetime, rng: random.Random) -> list[Doc]:
    workstations = [h for h in HOSTS if h.tier == 2]
    docs: list[Doc] = []

    domain, ip, port = _WINDOWS_UPDATE
    for h in workstations:
        first = start + timedelta(seconds=rng.uniform(0, 3600))
        for t in _ticks(first, end, 3600, 30 / 3600, rng):
            docs.append(
                ecs.network_flow(t, h, ip, port, domain, rng.randint(600, 1500), rng.randint(60_000, 400_000))
            )

    domain, ip, port = _EDR_CLOUD
    for h in workstations[::5]:
        first = start + timedelta(seconds=rng.uniform(0, 900))
        for t in _ticks(first, end, 900, 0.02, rng):
            docs.append(
                ecs.network_flow(t, h, ip, port, domain, rng.randint(1200, 1800), rng.randint(800, 1600))
            )
    return docs
