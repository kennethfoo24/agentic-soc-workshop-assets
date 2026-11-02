"""Benign background activity from every workstation: browsing flows + DNS, morning logons, app launches."""
from __future__ import annotations

import random
from datetime import datetime, time, timedelta, timezone

from . import ecs
from .ecs import Doc
from .org import HOSTS, USER_BY_HOST, VICTIM_HOST

BUSINESS_HOURS = range(8, 18)  # UTC
BUSINESS_RATE = 8.0  # browsing flows per workstation per hour
QUIET_RATE = 0.5

_INTERNAL_DOMAINS = (
    "intranet.elastibank.example",
    "wiki.elastibank.example",
    "hr.elastibank.example",
    "mail.elastibank.example",
    "files.elastibank.example",
)
_EXTERNAL_DOMAINS = (
    "www.google.com",
    "docs.google.com",
    "outlook.office365.com",
    "login.microsoftonline.com",
    "teams.microsoft.com",
    "github.com",
    "stackoverflow.com",
    "www.linkedin.com",
    "slack.com",
    "zoom.us",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "www.reuters.com",
    "www.bbc.com",
    "news.example",
    "weather.example",
    "bank-news.example",
    "market-data.example",
    "payments.example",
    "crm.example",
)


def _destinations() -> list[tuple[str, str]]:
    external = [(d, f"198.51.100.{100 + i}") for i, d in enumerate(_EXTERNAL_DOMAINS)]
    internal = [(d, f"10.10.5.{10 + i}") for i, d in enumerate(_INTERNAL_DOMAINS)]
    return internal + external


_DESTINATIONS = _destinations()

_APPS = (
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("teams.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
)


def _hour_buckets(start: datetime, end: datetime):
    t = start
    while t < end:
        nxt = min(end, t.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
        yield t, nxt
        t = nxt


def _browsing(start: datetime, end: datetime, rng: random.Random) -> list[Doc]:
    docs: list[Doc] = []
    workstations = [h for h in HOSTS if h.tier == 2]
    for h in workstations:
        for b0, b1 in _hour_buckets(start, end):
            rate = (BUSINESS_RATE if b0.hour in BUSINESS_HOURS else QUIET_RATE) / 3600
            t = b0
            while True:
                t += timedelta(seconds=rng.expovariate(rate))
                if t >= b1:
                    break
                domain, ip = rng.choice(_DESTINATIONS)
                out = min(60_000, max(300, int(rng.lognormvariate(7.2, 0.8))))
                inn = min(5_000_000, max(1_000, int(rng.lognormvariate(10.0, 1.2))))
                docs.append(ecs.dns_query(t, h, domain, ip))
                docs.append(ecs.network_flow(t, h, ip, 443 if rng.random() < 0.85 else 80, domain, out, inn))
    return docs


# A few workstations legitimately talk to one service far more than the beacon does (sync clients, shares).
# They are bursty and large-and-variable in bytes, so volume alone must not point at the beacon.
_HEAVY_DESTINATIONS = (
    ("outlook.office365.com", "198.51.100.102", 35.0, 4.0),
    ("files.elastibank.example", "10.10.5.14", 35.0, 4.0),
)
# Single-host rare domains of the sort people visit on their own time: different visit rates, DNS every time.
_RARE_DOMAINS = (
    ("cyclingforum.example", "198.51.100.200", 0.6),
    ("recipebox.example", "198.51.100.201", 1.0),
    ("vendor-portal.example", "198.51.100.202", 1.5),
    ("ticketswap.example", "198.51.100.203", 2.0),
    ("fantasyleague.example", "198.51.100.204", 3.0),
    ("classifieds.example", "198.51.100.205", 4.0),
)
_DNS_EVERY_N_HEAVY_FLOWS = 10  # resolver caching: heavy pairs do not look up the name on every flow


def _poisson_flows(h, domain, ip, start, end, business_rate, quiet_rate, rng, *, heavy, dns_every=1):
    docs: list[Doc] = []
    n = 0
    for b0, b1 in _hour_buckets(start, end):
        rate = (business_rate if b0.hour in BUSINESS_HOURS else quiet_rate) / 3600
        if rate <= 0:
            continue
        t = b0
        while True:
            t += timedelta(seconds=rng.expovariate(rate))
            if t >= b1:
                break
            if heavy:
                out = min(200_000, max(300, int(rng.lognormvariate(8.0, 1.2))))
                inn = min(20_000_000, max(500, int(rng.lognormvariate(10.5, 1.5))))
            else:
                out = min(60_000, max(300, int(rng.lognormvariate(7.2, 0.8))))
                inn = min(5_000_000, max(1_000, int(rng.lognormvariate(10.0, 1.2))))
            if n % dns_every == 0:
                docs.append(ecs.dns_query(t, h, domain, ip))
            docs.append(ecs.network_flow(t, h, ip, 443, domain, out, inn))
            n += 1
    return docs


def _heavy_and_rare(start: datetime, end: datetime, rng: random.Random) -> list[Doc]:
    others = [h for h in HOSTS if h.tier == 2 and h.name != VICTIM_HOST]
    docs: list[Doc] = []
    for h in others[3::12][:4]:
        for domain, ip, business, quiet in _HEAVY_DESTINATIONS:
            docs += _poisson_flows(h, domain, ip, start, end, business, quiet, rng,
                                   heavy=True, dns_every=_DNS_EVERY_N_HEAVY_FLOWS)
    for h, (domain, ip, business) in zip(others[7::8], _RARE_DOMAINS):
        docs += _poisson_flows(h, domain, ip, start, end, business, business / 10, rng, heavy=False)
    return docs


def _mornings(start: datetime, end: datetime, rng: random.Random) -> list[Doc]:
    docs: list[Doc] = []
    first = start.astimezone(timezone.utc).date()
    last = end.astimezone(timezone.utc).date()
    workstations = [h for h in HOSTS if h.tier == 2]
    day = first
    while day <= last:
        for h in workstations:
            user = USER_BY_HOST[h.name]
            logon = datetime.combine(day, time(8), tzinfo=timezone.utc) + timedelta(minutes=rng.uniform(0, 90))
            times = [logon] + [logon + timedelta(minutes=m) for m in (1, 2, 3)]
            if not all(start <= t < end for t in times):
                continue
            docs.append(ecs.auth_logon(logon, h, user, h.ip, "Interactive"))
            for t, (name, exe) in zip(times[1:], _APPS):
                exe = exe.format(user=user)
                docs.append(
                    ecs.process_start(t, h, user, name, exe, f'"{exe}"', "explorer.exe",
                                      "C:\\Windows\\Explorer.EXE", pid=rng.randint(2000, 9000), ppid=4012)
                )
        day += timedelta(days=1)
    return docs


def build_noise(start: datetime, end: datetime, rng: random.Random) -> list[Doc]:
    return _browsing(start, end, rng) + _heavy_and_rare(start, end, rng) + _mornings(start, end, rng)
