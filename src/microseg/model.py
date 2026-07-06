"""Data model for the kitchen micro-segmenter.

A Policy is a device inventory plus the flows that are *explicitly* sanctioned between
zones. Everything else is denied by construction (see nftables.generate).
"""
from dataclasses import dataclass

# Trust tiers: higher number = more sensitive. The zero-trust invariant is that a
# lower-tier zone must not be able to reach a higher-tier one without an audited exception.
TIERS = {"iot": 1, "boh": 2, "pos": 3, "admin": 4}


@dataclass(frozen=True)
class Device:
    id: str
    ip: str
    zone: str


@dataclass(frozen=True)
class Flow:
    src_zone: str
    dst_zone: str
    port: int
    proto: str = "tcp"
    note: str = ""
    audited_exception: bool = False


@dataclass
class Policy:
    zones: dict   # zone name -> trust-tier label (a key of TIERS)
    devices: list
    flows: list

    @staticmethod
    def from_dict(data):
        return Policy(
            zones=dict(data.get("zones", {})),
            devices=[Device(**d) for d in data.get("devices", [])],
            flows=[Flow(**f) for f in data.get("flows", [])],
        )
