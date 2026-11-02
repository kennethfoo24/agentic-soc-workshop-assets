"""The fictional Elastibank estate: hosts, users and the fixed scenario constants."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    tier: int
    role: str
    os: str = "windows"


@dataclass(frozen=True)
class User:
    name: str
    full_name: str
    dept: str
    privileged: bool


VICTIM_HOST = "WS-FIN-042"
VICTIM_USER = "j.martin"
LATERAL_TARGET = "FIN-DB01"
STOLEN_ACCOUNT = "svc_findb"
ADMIN_FP_HOST = "WS-IT-003"
ADMIN_FP_USER = "adm.lee"
C2_DOMAIN = "telemetry.azure-cdnedge.net"
C2_IP = "203.0.113.47"
EMAIL_DOMAIN = "elastibank.example"

_SERVERS = (
    Host("DC01", "10.10.0.10", 0, "Domain controller"),
    Host("ADFS01", "10.10.0.11", 0, "AD FS federation server"),
    Host("FIN-DB01", "10.10.1.20", 1, "Core banking database"),
    Host("SWG01", "10.10.1.21", 1, "SWIFT gateway"),
)

# (name prefix, first number, last number, last-octet base, department)
_WORKSTATION_RANGES = (
    ("WS-FIN-", 31, 50, 0, "Finance"),
    ("WS-OPS-", 1, 15, 100, "Operations"),
    ("WS-IT-", 1, 15, 150, "IT"),
)


def _workstations() -> tuple[Host, ...]:
    hosts = []
    for prefix, first, last, base, dept in _WORKSTATION_RANGES:
        for n in range(first, last + 1):
            hosts.append(Host(f"{prefix}{n:03d}", f"10.10.20.{base + n}", 2, f"{dept} workstation"))
    return tuple(hosts)


HOSTS: tuple[Host, ...] = _SERVERS + _workstations()

_FIRST_NAMES = (
    "Alex", "Blake", "Casey", "Dana", "Eden", "Frankie", "Gray", "Harper", "Indy", "Jamie",
    "Kit", "Logan", "Morgan", "Nico", "Oakley", "Parker", "Quinn", "Reese", "Sam", "Taylor",
    "Uma", "Val", "Wren", "Xan", "Yuri", "Zane", "Avery", "Bailey", "Cameron", "Drew",
    "Emery", "Finley", "Greer", "Hollis", "Imani", "Jules", "Kendall", "Lane", "Marlow", "Noel",
    "Ollie", "Peyton", "Remy", "Sasha", "Tatum", "Umber", "Vesper", "Wynn", "Yael", "Zion",
)
_SURNAMES = (
    "adler", "bishop", "castillo", "dubois", "ekstrom", "fischer", "garcia", "hoang", "ivanov",
    "jensen", "kowalski", "lindqvist", "moreau", "nakamura", "okafor", "petrov", "quintero",
    "rossi", "santos", "tanaka", "ueda", "varga", "walsh", "xu", "yilmaz", "zhou", "abbott",
    "brandt", "chen", "dalton", "ellis", "foster", "grant", "hale", "irwin", "jaffe", "keane",
    "lowe", "marsh", "nolan", "ortiz", "pruitt", "quigley", "reyes", "stone", "thorne", "usher",
    "voss", "whitlock", "yates",
)


def _workstation_users() -> dict[str, User]:
    """One regular user per workstation, keyed by host name. WS-FIN-042 is j.martin."""
    users = {}
    workstations = [h for h in HOSTS if h.tier == 2]
    for i, h in enumerate(workstations):
        dept = h.role.removesuffix(" workstation")
        if h.name == VICTIM_HOST:
            users[h.name] = User(VICTIM_USER, "Jordan Martin", dept, False)
            continue
        first, surname = _FIRST_NAMES[i], _SURNAMES[i]
        users[h.name] = User(f"{first[0].lower()}.{surname}", f"{first} {surname.title()}", dept, False)
    return users


USER_BY_HOST: dict[str, str] = {h: u.name for h, u in _workstation_users().items()}

_SPECIAL_USERS = (
    User(STOLEN_ACCOUNT, "Core banking service account", "Finance Systems", True),
    User("svc_backup", "Backup service account", "IT", True),
    User(ADMIN_FP_USER, "Lee (IT administrator)", "IT", True),
    User("procurement", "Procurement mailbox", "Procurement", False),
)

USERS: tuple[User, ...] = tuple(_workstation_users().values()) + _SPECIAL_USERS

_HOST_INDEX = {h.name: h for h in HOSTS}
_USER_INDEX = {u.name: u for u in USERS}


def host(name: str) -> Host:
    return _HOST_INDEX[name]


def user(name: str) -> User:
    return _USER_INDEX[name]
