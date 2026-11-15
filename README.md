# crypto
KISS CLI crypto tools for TLS certificate verification, in Python

**I wouldn't recommend to use this if you are not aware of the security implications**

## Install

```bash
pip install cryptography
```

## Usage

```
crypto - crypto tools
─────────────────────
- crypto host-check hostname[:port]                 ── check the TLS certificate of a remote server
- crypto host-check hostname[:port] --timeout N     ── set connection timeout (default: 4s)
- crypto host-check hostname[:port] --max-depth N   ── set max chain depth (default: 4)
- crypto host-check hostname[:port] --expect-fail   ── expect verification to fail (for testing)
- crypto host-check hostname[:port] --fingerprint   ── on success, print only the SHA256 fingerprint (hex)
- crypto get-cacert                                 ── get cacert.pem from curl.se, used to select a root CA
- crypto pins-collect                               ── server: verify the configured hosts into pins.json
- crypto pins-collect --watch N                     ── every N minutes (default: 5), cacert.pem every day
- crypto pins-update                                ── client: fetch them (remote_command), check, store
- crypto pins-update --max-age N                    ── refuse pins older than N hours (default: 48)
- crypto pins-update --no-local-check               ── store them without checking the hosts from here
─────────────────────
Global options:
  -v, --verbose                                     ── enable detailed output
  -h, --help                                        ── show this help message
─────────────────────
Files (XDG_CONFIG_HOME, XDG_STATE_HOME, XDG_DATA_HOME are honoured):
  ~/.config/crypto/config.toml                      ── hosts = [...] and / or remote_command = [...]
  CRYPTO_HOSTS="a.example b.example:993"            ── the hosts, in place of config.toml (a container)
  ~/.local/state/crypto/pins.json                   ── the pins, for other tools to read
  ~/.local/share/c4ffein-crypto-cli/cacert.pem      ── the root CAs
```

## Examples

```bash
# Get root CA bundle first (required)
./crypto.py get-cacert

# Check a certificate
./crypto.py host-check github.com

# Check with port
./crypto.py host-check smtp.gmail.com:465

# Verbose mode
./crypto.py -v host-check api.anthropic.com

# Print only the verified leaf certificate's SHA256 fingerprint (scriptable)
./crypto.py host-check api.anthropic.com --fingerprint
```

## Pins

A pin is the SHA256 of a leaf certificate, checked by a client on top of the usual CA and hostname verification.
Leaf certificates rotate every few weeks, and a pin refreshed from whatever the network shows is worth nothing:
the pins here come from a second vantage point (a server of yours), and are compared with what this machine sees.

```
server:  crypto pins-collect    verifies its hosts (CRYPTO_HOSTS or config.toml), merges what they serve into pins.json
client:  crypto pins-update     runs remote_command (ssh ... cat pins.json), validates, cross-checks, stores
tools:   tls-pin-update.py      the simple client: one ssh command, strict validation, generates tls-pin-get
         tls-pin-get host       (generated) prints the fingerprints of a host, one per line, in a millisecond
```

- **`pins-collect`** keeps a set of pins per host (the old and the new certificate overlap during a rotation),
  each until its certificate expires. A host that fails keeps its pins; the exit code is 1. With `--watch N` it
  never ends: a round every N minutes (5 by default), `cacert.pem` downloaded again every day, one line per round
  plus what changed or failed, and SIGTERM stops it at once. One writer at a time: a second one is refused.
- **`pins-update`** trusts the transport to authenticate the answer (ssh and its `known_hosts`), and nothing else:
  the output is size-limited and strictly validated. It refuses pins that are stale (`--max-age`, 48 hours by
  default: the collector stopped) or older than the stored ones. For each host it then verifies what this
  machine is served. When that certificate is not one the server saw, it says so and asks whether to trust it as
  well; no terminal means no, and the exit code is 1. What you approve is kept until its certificate expires.
- **`tools/tls-pin-update.py`** is the simple client, for when comparing is not wanted: one ssh command (the
  `fetch` of `~/.config/crypto/tls-pin-update.json`, or the arguments it is given) and a validation of what it
  prints, in plain Python: the exact schema that `pins-collect` writes (an unknown or missing field, a duplicate
  key, a wrong type, a timestamp that is not in the one format: all refused), size limits, and fresh (an hour). It trusts the server's view alone. Then it
  writes `pins.json`, and generates `tls-pin-get` next to itself. Standard library only: copy it to
  `~/.local/bin`.
- **`tls-pin-get`** is that generated file: a POSIX shell script with the pins in it, as a `case` of the hosts,
  because the tools that need a pin start in a few milliseconds and a Python process is 40 more. Exit code 0 with
  at least one fingerprint, 1 with none (unknown host, everything expired), 2 on a bad call. A tool calling it
  should use an argv (no shell), check that every line is 64 hex chars, accept any of them, and refuse to
  connect when there is none.
  - It is code written from data, hence the rules: only validated values go in, and only characters that mean
    nothing to a shell (`a-z 0-9 . - :`), checked a second time by the generator.
  - The first time, the updater says what it is about to create and asks; without a terminal it creates
    nothing. Afterwards it overwrites the file only when it carries its canary (a fixed UUID in a comment): a
    file of that name that is not its own, or a symlink, is never touched, and the run fails.
  - It is a snapshot: the pins of the last update, without those that had already expired then. Run the
    updater from a timer to keep it fresh.

### Server, as a [containerctl](https://github.com/c4ffein/containerctl) service

Three small files and nothing else: no config file, no build context. The hosts are an environment variable of
the service (`CRYPTO_HOSTS`: hostname[:port], separated by spaces, newlines or commas), `crypto.py` is fetched at
build time. Nothing listens: the container runs `pins-collect --watch 5`.

```toml
# ~/.config/containerctl/images/crypto.toml
tag = "crypto:latest"
```

```dockerfile
# ~/.config/containerctl/images/crypto.Dockerfile
FROM python:3.13-alpine
# Replace `main` by a commit hash to pin what runs here
ADD https://raw.githubusercontent.com/c4ffein/crypto/main/crypto.py /app/crypto.py
RUN chmod 644 /app/crypto.py \
    && pip install --no-cache-dir "cryptography>=42" \
    && adduser -D -u 1000 crypto \
    && mkdir -p /data \
    && chown crypto:crypto /data
USER crypto
# cacert.pem and pins.json both go to the volume: the root filesystem is read-only
ENV XDG_DATA_HOME=/data XDG_STATE_HOME=/data
CMD ["python3", "/app/crypto.py", "pins-collect", "--watch", "5"]
```

```toml
# ~/.config/containerctl/services/crypto.toml
image = "crypto:latest"
restart = "unless-stopped"
volumes = ["crypto-data:/data"]            # cacert.pem and pins.json: outlive the container
command = ["python3", "/app/crypto.py", "pins-collect", "--watch", "5"]
read_only = true
tmpfs = ["/tmp"]
cap_drop = ["ALL"]
no_new_privileges = true
pids_limit = 64
memory = "256m"
# Unhealthy (an issue) when the pins have not been written for 20 minutes: 4 rounds missed
health_cmd = "python3 -c \"import os, sys, time; sys.exit(time.time() - os.stat('/data/crypto/pins.json').st_mtime > 1200)\""
health_interval = "5m"
health_start_period = "2m"

[scripts]
pins = ["cat", "/data/crypto/pins.json"]   # what a client reads

[env]
# `containerctl service recreate crypto` after an edit
CRYPTO_HOSTS = """
api.anthropic.com
smtp.gmail.com:465
"""
```

```bash
containerctl image build crypto && containerctl service up crypto
containerctl logs cctl-svc-crypto            # one line per round
containerctl service script crypto pins      # what a client reads
```

### Client

```toml
# ~/.config/crypto/config.toml
remote_command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "debian@server",
                  "containerctl", "service", "script", "crypto", "pins"]
```

A key that only reads the pins: on the server, in `~/.ssh/authorized_keys`, with the full path of containerctl
(a forced command does not see your shell aliases):

```
command="/full/path/to/containerctl service script crypto pins",restrict ssh-ed25519 AAAA... crypto-pins
```

Or the simple client, without `crypto.py` nor `cryptography` on this machine:

```bash
cp tools/tls-pin-update.py ~/.local/bin/
tls-pin-update.py                            # the first time: asks before creating ~/.local/bin/tls-pin-get
tls-pin-get api.anthropic.com                # one fingerprint per line
```

What it runs comes from `~/.config/crypto/tls-pin-update.json` (or from its arguments: `tls-pin-update.py cat
some-pins.json`). There is no default: without that file, or with one that is not exactly this, it is an error and
nothing is run.

```json
{"fetch": ["/usr/bin/ssh", "user@server", "docker", "exec", "cctl-svc-crypto", "cat", "/data/crypto/pins.json"]}
```

It is a list of arguments, run without a shell on this machine. A full path for `ssh` is not looked up in `PATH`.
What follows the server name is another matter: ssh joins it and gives it to your shell on the server.

## What it does

- Verifies hostname (SAN/CN with wildcards)
- Checks certificate validity (expiration)
- Walks the chain via AIA extensions
- Verifies cryptographic signatures (RSA, ECDSA, DSA, EdDSA)
- Checks that every issuer is a CA allowed to sign (basicConstraints, path length, keyUsage)
- Validates against Mozilla's root CA bundle
- Collects, fetches and cross-checks certificate pins (see Pins)

## Development

See `Makefile` for lint and test targets.

## License

MIT License - Copyright (c) 2025 c4ffein
