#!/usr/bin/env python3

"""
get_tls_pin - print the pinned TLS certificate fingerprints of a host
MIT License - Copyright (c) 2026 c4ffein

I wouldn't recommend to use this if you are not aware of the security implications

The reading half of `crypto pins-update`: standard library only, no network, read-only, so that another tool can
call it right before it connects. It trusts the pins file as it trusts its own config (same user, same disk):
everything that had to be verified was verified by crypto when it wrote the file.

Usage: get_tls_pin.py hostname[:port]   (default port: 443)
- prints the SHA-256 (64 hex chars) of every certificate pinned for that host and not expired, one per line
- exit code 0 when there is at least one, 1 when there is none (and nothing on stdout), 2 on a bad call
A host has a set of pins, not one: the old and the new certificate overlap during a rotation. Accept any of them.
"""

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# Kept identical to crypto.py, which writes the file: the tests run one against the other
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
DIGITS = frozenset("0123456789")
HEX_CHARS = frozenset("0123456789abcdef")


def is_valid_host_key(value: object) -> bool:
    """`hostname:port`, lowercase: 1 to 253 allowlisted characters not starting or ending with . or -, 1 to 5 digits"""
    if not isinstance(value, str):
        return False
    hostname, colon, port = value.rpartition(":")
    return (
        bool(colon)
        and 1 <= len(hostname) <= 253
        and set(hostname) <= HOST_CHARS
        and hostname[0] not in ".-"
        and hostname[-1] not in ".-"
        and 1 <= len(port) <= 5
        and set(port) <= DIGITS
    )


def is_valid_sha256(value: object) -> bool:
    """64 lowercase hex characters"""
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX_CHARS


def pins_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME", "")
    return (Path(state_home) if state_home.startswith("/") else Path.home() / ".local/state") / "crypto" / "pins.json"


def host_key(target: str) -> str | None:
    key = target.lower() if ":" in target else f"{target.lower()}:443"
    return key if is_valid_host_key(key) else None


def live_pins(document: object, key: str, now: datetime) -> list[str]:
    """The fingerprints of `key` whose certificate has not expired. Anything unexpected in the file is an error
    (ValueError / KeyError / TypeError / AttributeError), not something to work around."""
    if document["version"] != 1:
        raise ValueError("not a version 1 pins document")
    entry = document["hosts"].get(key)
    pins = []
    for pin in entry["pins"] if entry is not None else []:
        if not is_valid_sha256(pin["sha256"]):
            raise ValueError("invalid sha256")
        if datetime.strptime(pin["not_after"], TIME_FORMAT).replace(tzinfo=UTC) > now:
            pins.append(pin["sha256"])
    return pins


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    key = host_key(argv[1])
    if key is None:
        print("get_tls_pin: invalid host (hostname[:port])", file=sys.stderr)
        return 2
    path = pins_path()
    try:
        with path.open("rb") as file:
            pins = live_pins(json.load(file), key, datetime.now(UTC))
    except FileNotFoundError:
        print(f"get_tls_pin: no pins file ({path}): run `crypto pins-update`", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        print(f"get_tls_pin: unusable pins file ({path}): {type(exc).__name__}", file=sys.stderr)
        return 1
    if not pins:
        print(f"get_tls_pin: no valid pin for {key}: run `crypto pins-update`", file=sys.stderr)
        return 1
    print("\n".join(pins))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
