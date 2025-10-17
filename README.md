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
- crypto get-cacert                                 ── get cacert.pem from curl.se, used to select a root CA
─────────────────────
Global options:
  -v, --verbose                                     ── enable detailed output
  -h, --help                                        ── show this help message
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
```

## What it does

- Verifies hostname (SAN/CN with wildcards)
- Checks certificate validity (expiration)
- Walks the chain via AIA extensions
- Verifies cryptographic signatures (RSA, ECDSA, DSA, EdDSA)
- Validates against Mozilla's root CA bundle

## Development

See `Makefile` for lint and test targets.

## License

MIT License - Copyright (c) 2025 c4ffein
