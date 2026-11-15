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
- crypto pins-collect                               ── server: verify config.toml's hosts into pins.json
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
  ~/.local/state/crypto/pins.json                   ── the pins: get_tls_pin.py reads them for other tools
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
server:  crypto pins-collect    verifies the hosts of its config.toml, merges what they serve into its pins.json
client:  crypto pins-update     runs remote_command (ssh ... cat pins.json), validates, cross-checks, stores
tools:   get_tls_pin.py host    prints the stored fingerprints of a host, one per line
```

- **`pins-collect`** keeps a set of pins per host (the old and the new certificate overlap during a rotation),
  each until its certificate expires. A host that fails keeps its pins; the exit code is 1.
- **`pins-update`** trusts the transport to authenticate the answer (ssh and its `known_hosts`), and nothing else:
  the output is size-limited and strictly validated. It refuses pins that are stale (`--max-age`, 48 hours by
  default: the collector stopped) or older than the stored ones. For each host it then verifies what this
  machine is served. When that certificate is not one the server saw, it says so and asks whether to trust it as
  well; no terminal means no, and the exit code is 1. What you approve is kept until its certificate expires.
- **`get_tls_pin.py`** is separate on purpose: standard library only, no network, read-only, about 40 ms. Exit
  code 0 with at least one fingerprint, 1 with none (unknown host, no file, everything expired), 2 on a bad call.
  A tool calling it should use an argv (no shell), check that every line is 64 hex chars, accept any of them, and
  refuse to connect when there is none.

### Server, as a [containerctl](https://github.com/c4ffein/containerctl) service

`deploy/` holds the files; nothing listens, the container waits for scripts.

```bash
mkdir -p ~/.config/crypto ~/.config/containerctl/images/crypto
cp deploy/crypto/config.toml ~/.config/crypto/config.toml               # the hosts
cp deploy/containerctl/images/crypto.* ~/.config/containerctl/images/
cp crypto.py ~/.config/containerctl/images/crypto/                      # the build context
cp deploy/containerctl/services/crypto.toml ~/.config/containerctl/services/
containerctl image build crypto && containerctl service up crypto
containerctl service script crypto collect   # get-cacert + pins-collect: to be run on a schedule
containerctl service script crypto pins      # what a client reads
```

In the container, `XDG_DATA_HOME` and `XDG_STATE_HOME` point at the volume and `XDG_CONFIG_HOME` at the
read-only config: the root filesystem stays read-only.

### Client

```toml
# ~/.config/crypto/config.toml (see deploy/crypto/config.client.toml)
remote_command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "debian@server",
                  "containerctl", "service", "script", "crypto", "pins"]
```

A key that only reads the pins: on the server, in `~/.ssh/authorized_keys`, with the full path of containerctl
(a forced command does not see your shell aliases):

```
command="/full/path/to/containerctl service script crypto pins",restrict ssh-ed25519 AAAA... crypto-pins
```

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
