#!/usr/bin/env python

"""
crypto - crypto tools
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
"""

from enum import Enum
from sys import argv

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


class CryptoCliException(Exception):
    pass


def get_bytes_from_url(url: str) -> Optional[bytes]:
    try:
        response = requests.get(url)
        if response.status_code != 200:
            response.raise_for_status()
    except HTTPError, RequestException as exc:
        raise CryptoCliException(f"Unable to reach {url}") from exc
    return response.content


def get_ca_cert_pem() -> None:  # TODO Specify a better location
    write_to_file(get_bytes_from_url("https://curl.se/ca/cacert.pem"), "cacert.pem")


def usage():
    output_lines = [
        "crypto - crypto tools",
        "=======================",
        "- crypto host-check hostname[:port] ==> check the TLS certificate of a remote server",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["host-check"]:
        return None
    if argv[1] == "host-check":
        if len(argv) != 3:
            return None
        return {"action": "host-check", "target": argv[1]}
    return None


def main():
    args = consume_args()
    if not args:
        return usage()
    if args["action"] == "host-check":
        raise CryptoCliException("WiP I guess")
    else:
        return usage()


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(-2)
    except CryptoCliException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
