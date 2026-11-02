"""Asset and user inventories for the ES|QL lookup tools: the ground truth the org-context skill describes."""
from __future__ import annotations

from .org import EMAIL_DOMAIN, HOSTS, USERS

_CRITICALITY = {
    0: "Tier 0 - domain control",
    1: "Tier 1 - crown jewel",
    2: "Tier 2 - workstation",
}


def build_assets() -> list[dict]:
    return [
        {
            "host": {"name": h.name, "ip": h.ip},
            "asset": {"tier": h.tier, "role": h.role, "criticality": _CRITICALITY[h.tier]},
        }
        for h in HOSTS
    ]


def build_users() -> list[dict]:
    return [
        {
            "user": {
                "name": u.name,
                "full_name": u.full_name,
                "department": u.dept,
                "privileged": u.privileged,
                "email": f"{u.name}@{EMAIL_DOMAIN}",
            }
        }
        for u in USERS
    ]
