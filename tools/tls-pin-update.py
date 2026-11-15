#!/usr/bin/env python3

"""
tls-pin-update - fetch the TLS pins my server collects, and generate tls-pin-get from them
MIT License - Copyright (c) 2026 c4ffein

I wouldn't recommend to use this if you are not aware of the security implications

One ssh command prints the pins.json that `crypto pins-collect --watch` keeps on the server. It is validated,
strictly: the exact schema, nothing more, nothing less, and recent. Then two files are written:
- ~/.local/state/crypto/pins.json: the pins, as data
- tls-pin-get, next to this script: a shell script that prints the pins of a host (`tls-pin-get hostname[:port]`),
  in about a millisecond. It is generated code, so: only values that passed the validation go in, and only
  characters that mean nothing to a shell. It is created after asking, the first time, and overwritten afterwards
  only when it carries the canary below: a file that is not ours is never touched.
Standard library only.
What it does not do: compare with what this machine is served. It trusts the server's view alone, and ssh (your
key, the server's line in known_hosts) to bring it back untouched. `crypto pins-update` is the one that compares.

Usage: tls-pin-update.py                (runs the configured command)
       tls-pin-update.py command ...    (runs that instead: anything that prints the pins.json)

The configured command is the `fetch` of ~/.config/crypto/tls-pin-update.json (XDG_CONFIG_HOME is honoured), a
list of arguments run as they are, without a shell:
  {"fetch": ["ssh", "user@server", "docker", "exec", "cctl-svc-crypto", "cat", "/data/crypto/pins.json"]}
Without that file it is FETCH, below. A file that is there and is not exactly that is an error: nothing is run.
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

# What prints the server's pins.json, when ~/.config/crypto/tls-pin-update.json does not say. `docker exec` and not
# `cctl service script crypto pins`: a command given to ssh does not get the PATH of a login shell (no
# ~/.local/bin), nor its aliases.
FETCH = ["ssh", "debian@p1.c4ffein.io", "docker", "exec", "cctl-svc-crypto", "cat", "/data/crypto/pins.json"]
FETCH_TIMEOUT = 120  # seconds, a passphrase to type included
MAX_AGE = timedelta(hours=1)  # the server collects every 5 minutes: older than this, it has stopped
CLOCK_SKEW = timedelta(minutes=10)
MAX_BYTES = 1024 * 1024
MAX_HOSTS = 256
MAX_PINS_PER_HOST = 16
MAX_ARGUMENTS = 64  # of a configured command

# The generated script, next to this one as it was called (a symlink is not followed)
GET_PATH = Path(__file__).absolute().with_name("tls-pin-get")
# A line of every tls-pin-get we generate, and of nothing else: what makes a file ours to overwrite
CANARY = "tls-pin-update canary 2851f5cf-ff99-4c0f-be7b-a6949c52a024"

# Kept identical to crypto.py
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
DIGITS = frozenset("0123456789")
HEX_CHARS = frozenset("0123456789abcdef")

CONFIG_FIELDS = ("fetch",)
DOCUMENT_FIELDS = ("version", "generated_at", "hosts")
HOST_FIELDS = ("checked_at", "pins")
PIN_FIELDS = ("sha256", "not_after", "first_seen", "last_seen", "source")
SHELL_SAFE = HOST_CHARS | {":"}  # all a generated line is made of, besides what is written here: no quote, no space


def pins_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME", "")
    return (Path(state_home) if state_home.startswith("/") else Path.home() / ".local/state") / "crypto" / "pins.json"


def config_path() -> Path:
    """Read-only: never written by us"""
    config_home = os.environ.get("XDG_CONFIG_HOME", "")
    directory = Path(config_home) if config_home.startswith("/") else Path.home() / ".config"
    return directory / "crypto" / "tls-pin-update.json"


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


def parse_time(value: object) -> datetime:
    """TIME_FORMAT, to the character: strptime alone would take `2026-1-5T1:2:3Z`"""
    if not isinstance(value, str):
        raise ValueError("a timestamp is not a string")
    moment = datetime.strptime(value, TIME_FORMAT).replace(tzinfo=UTC)
    if moment.strftime(TIME_FORMAT) != value:
        raise ValueError("a timestamp is not written as YYYY-MM-DDTHH:MM:SSZ")
    return moment


def fields(value: object, names: tuple[str, ...], what: str) -> list:
    """The values of an object that has exactly these fields"""
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError(f"{what} must have exactly: {', '.join(names)}")
    return [value[name] for name in names]


def clean_pin(pin: object, key: str) -> dict:
    sha256, not_after, first_seen, last_seen, source = fields(pin, PIN_FIELDS, f"a pin of {key}")
    if not is_valid_sha256(sha256):
        raise ValueError(f"invalid sha256 for {key}")
    if source != "collected":
        raise ValueError(f"a pin of {key} is not one the server collected")
    parse_time(not_after)
    if parse_time(first_seen) > parse_time(last_seen):
        raise ValueError(f"a pin of {key} was last seen before it was first seen")
    return dict(zip(PIN_FIELDS, (sha256, not_after, first_seen, last_seen, source), strict=True))


def clean_host(key: str, entry: object) -> dict:
    if not is_valid_host_key(key):
        raise ValueError("invalid host name")
    checked_at, pins = fields(entry, HOST_FIELDS, key)
    if checked_at is not None:
        parse_time(checked_at)
    if not isinstance(pins, list) or len(pins) > MAX_PINS_PER_HOST:
        raise ValueError(f"the pins of {key} must be a list of at most {MAX_PINS_PER_HOST}")
    pins = [clean_pin(pin, key) for pin in pins]
    if len({pin["sha256"] for pin in pins}) != len(pins):
        raise ValueError(f"the same pin twice for {key}")
    return {"checked_at": checked_at, "pins": pins}


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    """A JSON object, without the leniency of json: the same key twice is an error, not the last one wins"""
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("the same key twice in an object")
    return dict(pairs)


def refuse_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def strict_json(raw: bytes) -> object:
    """JSON and nothing else: UTF-8, of a bounded size, no duplicate key, no NaN. ValueError otherwise."""
    if len(raw) > MAX_BYTES:
        raise ValueError(f"more than {MAX_BYTES} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object, parse_constant=refuse_constant)
    except RecursionError:
        raise ValueError("nested too deep") from None


def configured_fetch(path: Path) -> list[str] | None:
    """The command of the config file, {"fetch": ["ssh", ...]}. None when there is no file. ValueError when there
    is one that is not exactly that: a file that is there is never ignored, we do not fall back to FETCH."""
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"could not read it: {type(exc).__name__}") from None
    (command,) = fields(strict_json(raw), CONFIG_FIELDS, "the config")
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_ARGUMENTS:
        raise ValueError(f"fetch must be a list of 1 to {MAX_ARGUMENTS} arguments")
    if not all(isinstance(argument, str) and argument and "\0" not in argument for argument in command):
        raise ValueError("every argument of fetch must be a non-empty string")
    return command


def clean_document(raw: bytes, now: datetime) -> dict:
    """The fetched document, rebuilt from its validated fields alone. ValueError when it is not exactly what
    pins-collect writes, or not recent: nothing of it is used then."""
    version, generated_at, hosts = fields(strict_json(raw), DOCUMENT_FIELDS, "the document")
    if type(version) is not int or version != 1:
        raise ValueError("not a version 1 pins document")
    generated = parse_time(generated_at)
    if generated > now + CLOCK_SKEW:
        raise ValueError(f"generated in the future ({generated_at}): check the clocks")
    if now - generated > MAX_AGE:
        raise ValueError(f"stale, generated {generated_at}: is the collector still running?")
    if not isinstance(hosts, dict) or not 1 <= len(hosts) <= MAX_HOSTS:
        raise ValueError(f"hosts must be an object of 1 to {MAX_HOSTS} hosts")
    hosts = {key: clean_host(key, entry) for key, entry in hosts.items()}
    return {"version": 1, "generated_at": generated_at, "hosts": hosts}


def render_script(document: dict, now: datetime) -> str:
    """tls-pin-get: a `case` of the hosts, each printing its pins that have not expired. Everything that comes from
    the document is checked once more, here, against what a shell takes literally: a mistake above must not
    become code."""
    cases = []
    for key, entry in document["hosts"].items():
        pins = [pin["sha256"] for pin in entry["pins"] if parse_time(pin["not_after"]) > now]
        for value in (key, *pins):
            if not value or not set(value) <= SHELL_SAFE:
                raise ValueError("refusing to write this into a shell script")
        if pins:
            cases.append(f"  '{key}') printf '%s\\n' {' '.join(pins)} ;;")
    generated_at = parse_time(document["generated_at"]).strftime(TIME_FORMAT)
    return "\n".join(
        [
            "#!/bin/sh",
            "# tls-pin-get - print the pinned TLS certificate fingerprints of a host",
            f"# Generated by tls-pin-update.py from what the server collected at {generated_at}.",
            "# Do not edit: every update writes it again. The next line is how tls-pin-update.py knows that this",
            "# file is its own to overwrite.",
            f"# {CANARY}",
            "#",
            "# Usage: tls-pin-get hostname[:port]   (lowercase; default port: 443)",
            "# - prints the SHA-256 (64 hex chars) of every certificate pinned for that host, one per line",
            "# - exit code 0 when there is at least one, 1 when there is none (and nothing on stdout), 2 on a bad call",
            "# A host has a set of pins, not one: the old and the new certificate overlap during a rotation.",
            "# Accept any of them.",
            "",
            'if [ "$#" -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then',
            "  echo 'usage: tls-pin-get hostname[:port]' >&2",
            "  exit 2",
            "fi",
            'case "$1" in',
            "  *:*) key=$1 ;;",
            "  *) key=$1:443 ;;",
            "esac",
            'case "$key" in',
            *cases,
            "  *) printf 'tls-pin-get: no pin for %s: run tls-pin-update.py\\n' \"$key\" >&2; exit 1 ;;",
            "esac",
            "",
        ]
    )


def is_ours(path: Path) -> bool | None:
    """None when there is nothing at `path`, True when it is a file that carries our canary, False for anything else
    (somebody's file, a symlink, a directory): that we never touch."""
    if path.is_symlink():
        return False
    try:
        with path.open("rb") as file:
            head = file.read(4096)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    return f"# {CANARY}".encode() in head.splitlines()


def confirm_creation(path: Path) -> bool:
    """The first time: say what is about to appear, and where. No terminal (cron, a pipe) is a no."""
    if not sys.stdin.isatty():
        print(f"tls-pin-update: {path} not generated: run me once from a terminal to confirm it", file=sys.stderr)
        return False
    print(f"By default, this tool generates {path} next to itself:")
    print("a shell script that prints the pins of a host, written again at every update.")
    try:
        return input("Create it? [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def known_pins(path: Path) -> set[tuple[str, str]] | None:
    """(host, sha256) of the file we already have, to say what is new. None when there is no usable one."""
    try:
        hosts = json.loads(path.read_bytes())["hosts"]
        return {(key, pin["sha256"]) for key, entry in hosts.items() for pin in entry["pins"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return None


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Through a temp file in the same directory, then a rename: a reader sees the old file or the new one"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temp_path = Path(temp_name)
    try:
        with os.fdopen(temp_fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        temp_path.chmod(mode)  # mkstemp creates 0o600
        temp_path.replace(path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def fetch(command: list[str]) -> bytes:
    """What the command prints. ValueError when it could not be run, or failed."""
    try:
        fetched = subprocess.run(command, stdout=subprocess.PIPE, timeout=FETCH_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"could not run {command[0]}: {type(exc).__name__}") from None
    if fetched.returncode != 0:
        raise ValueError(f"{command[0]} failed (exit code {fetched.returncode})")
    return fetched.stdout


def report(document: dict, known: set[tuple[str, str]] | None) -> None:
    for key, entry in document["hosts"].items():
        for pin in entry["pins"]:
            new = known is not None and (key, pin["sha256"]) not in known
            print(f"{key:<44} {pin['sha256']}{'  NEW' if new else ''}")
        if not entry["pins"]:
            print(f"{key:<44} no pin: the server never verified it")


def main(argv: list[str]) -> int:
    if argv[1:2] in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    try:
        command = argv[1:] or configured_fetch(config_path()) or FETCH
    except ValueError as exc:
        print(f"tls-pin-update: {config_path()}: {exc}", file=sys.stderr)
        return 1
    now = datetime.now(UTC)
    try:
        raw = fetch(command)
    except ValueError as exc:
        print(f"tls-pin-update: {exc}", file=sys.stderr)
        return 1
    try:
        document = clean_document(raw, now)
        script = render_script(document, now)
    except ValueError as exc:
        print(f"tls-pin-update: refused what {command[0]} printed: {exc}", file=sys.stderr)
        return 1
    ours = is_ours(GET_PATH)
    if ours is False:
        print(f"tls-pin-update: {GET_PATH} is not a file I generated (no canary): move it away", file=sys.stderr)
        return 1
    generate = ours or confirm_creation(GET_PATH)
    path = pins_path()
    known = known_pins(path)
    try:
        atomic_write(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(), 0o600)
        if generate:
            atomic_write(GET_PATH, script.encode(), 0o755)
    except OSError as exc:
        print(f"tls-pin-update: could not write: {exc}", file=sys.stderr)
        return 1
    report(document, known)
    print(f"{len(document['hosts'])} hosts, collected {document['generated_at']} -> {path}")
    if generate:
        print(f"generated {GET_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
