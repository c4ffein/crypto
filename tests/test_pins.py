#!/usr/bin/env python3
"""
Tests for the pins commands (pins-collect, pins-update) and for get_tls_pin.py, which reads what they write.
Offline: the verification of a host is replaced by a dict of what each host "serves", and the remote command
is a local process printing a file.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent.parent))

import crypto
import get_tls_pin
from crypto import CryptoCliException

GET_TLS_PIN = Path(__file__).parent.parent / "get_tls_pin.py"
KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(name="a.test", expires_in_days=30):
    """Any certificate will do: these tests replace the verification, they need a fingerprint and an expiry"""
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now + timedelta(days=expires_in_days))
        .sign(KEY, hashes.SHA256())
    )


def sha(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def make_document(hosts, generated_at=None, source="collected"):
    """A pins document: hosts is {"host:port": [certificates]}"""
    now = datetime.now(UTC)
    return {
        "version": 1,
        "generated_at": crypto.format_time(generated_at or now),
        "hosts": {
            key: {"checked_at": crypto.format_time(now), "pins": [crypto.new_pin(cert, now, source) for cert in certs]}
            for key, certs in hosts.items()
        },
    }


class PinsTestCase(unittest.TestCase):
    """A temporary config and pins file, and hosts that serve what self.served says (an exception: it fails)"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.config_path = self.dir / "config" / "crypto" / "config.toml"
        self.pins_path = self.dir / "state" / "crypto" / "pins.json"
        self.remote_path = self.dir / "remote.json"
        self.served = {}
        for name, value in (
            ("CONFIG_PATH", self.config_path),
            ("PINS_PATH", self.pins_path),
            ("verify_host", self.verify_host),
            ("confirm", self.refuse_to_confirm),
        ):
            patcher = mock.patch.object(crypto, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        silence = mock.patch.multiple(sys, stdout=mock.DEFAULT, stderr=mock.DEFAULT)
        silence.start()
        self.addCleanup(silence.stop)

    def verify_host(self, target, timeout=None, max_depth=None):
        served = self.served[target]
        if isinstance(served, Exception):
            raise served
        return served

    def refuse_to_confirm(self, question):
        self.fail(f"The user was asked: {question}")

    def write_config(self, **values):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text("".join(f"{name} = {json.dumps(value)}\n" for name, value in values.items()))

    def write_remote(self, document):
        """Make `remote_command` print this document (or these raw bytes)"""
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        self.remote_path.write_bytes(raw)
        printer = "import sys; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())"
        self.write_config(remote_command=[sys.executable, "-c", printer, str(self.remote_path)])

    def stored(self):
        return json.loads(self.pins_path.read_text())

    def stored_pins(self, key):
        return {pin["sha256"]: pin["source"] for pin in self.stored()["hosts"][key]["pins"]}

    def collect(self):
        return crypto.pins_collect(timeout=1, max_depth=4)

    def update(self, max_age_hours=48, local_check=True):
        return crypto.pins_update(max_age_hours, local_check, timeout=1, max_depth=4)


class TestPinsCollect(PinsTestCase):
    def test_first_run_stores_what_each_host_serves(self):
        a, b = make_cert("a.test"), make_cert("b.test")
        self.write_config(hosts=["a.test", "b.test:993"])
        self.served = {"a.test:443": a, "b.test:993": b}
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(a): "collected"})
        self.assertEqual(self.stored_pins("b.test:993"), {sha(b): "collected"})
        self.assertIsNotNone(self.stored()["hosts"]["a.test:443"]["checked_at"])
        self.assertEqual(stat.S_IMODE(self.pins_path.stat().st_mode), 0o600)

    def test_host_names_are_normalized(self):
        self.write_config(hosts=["A.Test", "a.test:443"])
        self.served = {"a.test:443": make_cert()}
        self.assertEqual(self.collect(), 0)
        self.assertEqual(list(self.stored()["hosts"]), ["a.test:443"])

    def test_rotation_keeps_the_old_and_the_new_certificate(self):
        old, new = make_cert(), make_cert()
        self.write_config(hosts=["a.test"])
        self.served = {"a.test:443": old}
        self.collect()
        self.served = {"a.test:443": new}
        self.collect()
        self.assertEqual(self.stored_pins("a.test:443"), {sha(old): "collected", sha(new): "collected"})

    def test_same_certificate_is_stored_once(self):
        self.write_config(hosts=["a.test"])
        self.served = {"a.test:443": make_cert()}
        self.collect()
        self.collect()
        self.assertEqual(len(self.stored_pins("a.test:443")), 1)

    def test_pin_of_an_expired_certificate_is_dropped(self):
        expired, current = make_cert(expires_in_days=-1), make_cert()
        crypto.store_pins(make_document({"a.test:443": [expired]}))
        self.write_config(hosts=["a.test"])
        self.served = {"a.test:443": current}
        self.collect()
        self.assertEqual(self.stored_pins("a.test:443"), {sha(current): "collected"})

    def test_failing_host_keeps_its_pins_and_fails_the_run(self):
        a, b = make_cert("a.test"), make_cert("b.test")
        self.write_config(hosts=["a.test", "b.test"])
        self.served = {"a.test:443": a, "b.test:443": b}
        self.collect()
        checked_at = self.stored()["hosts"]["a.test:443"]["checked_at"]
        self.served = {"a.test:443": CryptoCliException("Connection refused"), "b.test:443": b}
        self.assertEqual(self.collect(), 1)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(a): "collected"})
        self.assertEqual(self.stored()["hosts"]["a.test:443"]["checked_at"], checked_at)
        self.assertEqual(self.stored_pins("b.test:443"), {sha(b): "collected"})

    def test_host_that_never_verified_has_no_pin(self):
        self.write_config(hosts=["a.test"])
        self.served = {"a.test:443": CryptoCliException("Cert verification error")}
        self.assertEqual(self.collect(), 1)
        self.assertEqual(self.stored()["hosts"]["a.test:443"], {"checked_at": None, "pins": []})

    def test_host_removed_from_the_config_is_dropped(self):
        self.write_config(hosts=["a.test", "b.test"])
        self.served = {"a.test:443": make_cert(), "b.test:443": make_cert()}
        self.collect()
        self.write_config(hosts=["b.test"])
        self.collect()
        self.assertEqual(list(self.stored()["hosts"]), ["b.test:443"])

    def test_config_problems_are_clean_errors(self):
        with self.assertRaisesRegex(CryptoCliException, "Config not found"):
            self.collect()
        for hosts in ("a.test", [], ["a.test", 3], [""]):
            self.write_config(hosts=hosts)
            with self.assertRaisesRegex(CryptoCliException, "Missing or invalid 'hosts'"):
                self.collect()
        self.write_config(hosts=["a.test/../../x"])
        with self.assertRaisesRegex(CryptoCliException, "Invalid host"):
            self.collect()
        self.assertFalse(self.pins_path.exists())


class TestParsePins(unittest.TestCase):
    def parse(self, document, trust_source=False):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        return crypto.parse_pins(raw, "test", trust_source)

    def test_valid_document_round_trips(self):
        document = make_document({"a.test:443": [make_cert(), make_cert()], "b.test:993": []})
        self.assertEqual(self.parse(document), document)

    def test_a_remote_cannot_claim_a_pin_was_approved_here(self):
        document = make_document({"a.test:443": [make_cert()]}, source="approved")
        self.assertEqual(self.parse(document)["hosts"]["a.test:443"]["pins"][0]["source"], "collected")
        self.assertEqual(
            self.parse(document, trust_source=True)["hosts"]["a.test:443"]["pins"][0]["source"], "approved"
        )

    def test_unknown_fields_do_not_come_through(self):
        document = make_document({"a.test:443": [make_cert()]})
        document["extra"] = document["hosts"]["a.test:443"]["extra"] = "x"
        document["hosts"]["a.test:443"]["pins"][0]["extra"] = "x"
        self.assertNotIn("extra", json.dumps(self.parse(document)))

    def test_anything_else_is_refused(self):
        valid = make_document({"a.test:443": [make_cert()]})

        def altered(change):
            document = json.loads(json.dumps(valid))
            change(document)
            return document

        def pin(document):
            return document["hosts"]["a.test:443"]["pins"][0]

        bad = {
            "not json": b"<html>",
            "not an object": [],
            "wrong version": altered(lambda d: d.update(version=2)),
            "no generated_at": altered(lambda d: d.pop("generated_at")),
            "bad generated_at": altered(lambda d: d.update(generated_at="yesterday")),
            "hosts not an object": altered(lambda d: d.update(hosts=[])),
            "host with a path": altered(lambda d: d["hosts"].update({"../../etc/passwd:443": {"pins": []}})),
            "host in uppercase": altered(lambda d: d["hosts"].update({"A.test:443": {"pins": []}})),
            "host without port": altered(lambda d: d["hosts"].update({"a.test": {"pins": []}})),
            "entry not an object": altered(lambda d: d["hosts"].update({"b.test:443": "x"})),
            "pins not a list": altered(lambda d: d["hosts"]["a.test:443"].update(pins={})),
            "bad checked_at": altered(lambda d: d["hosts"]["a.test:443"].update(checked_at=3)),
            "pin not an object": altered(lambda d: d["hosts"]["a.test:443"].update(pins=["x"])),
            "short sha256": altered(lambda d: pin(d).update(sha256="ab" * 31)),
            "uppercase sha256": altered(lambda d: pin(d).update(sha256="AB" * 32)),
            "sha256 not a string": altered(lambda d: pin(d).update(sha256=1)),
            "bad not_after": altered(lambda d: pin(d).update(not_after=None)),
            "too many pins": altered(lambda d: d["hosts"]["a.test:443"].update(pins=[pin(d)] * 17)),
            "too many hosts": altered(lambda d: d.update(hosts={f"h{i}.test:443": {"pins": []} for i in range(257)})),
            "too large": json.dumps(valid).encode() + b" " * crypto.PINS_MAX_BYTES,
            "too deep": b"[" * 100000,
        }
        for name, document in bad.items():
            with self.subTest(name), self.assertRaisesRegex(CryptoCliException, "Invalid pins from test"):
                self.parse(document)

    def test_our_own_file_must_say_where_a_pin_comes_from(self):
        document = make_document({"a.test:443": [make_cert()]})
        del document["hosts"]["a.test:443"]["pins"][0]["source"]
        with self.assertRaisesRegex(CryptoCliException, "invalid pin source"):
            self.parse(document, trust_source=True)


class TestPinsUpdate(PinsTestCase):
    def test_agreeing_host_is_stored(self):
        cert = make_cert()
        self.write_remote(make_document({"a.test:443": [cert]}))
        self.served = {"a.test:443": cert}
        self.assertEqual(self.update(), 0)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(cert): "collected"})
        self.assertEqual(stat.S_IMODE(self.pins_path.stat().st_mode), 0o600)

    def test_disagreement_declined_keeps_the_remote_pins_only_and_fails(self):
        remote, here = make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [remote]}))
        self.served = {"a.test:443": here}
        with mock.patch.object(crypto, "confirm", return_value=False) as confirm:
            self.assertEqual(self.update(), 1)
        confirm.assert_called_once()
        self.assertEqual(self.stored_pins("a.test:443"), {sha(remote): "collected"})

    def test_disagreement_approved_adds_the_certificate_seen_here(self):
        remote, here = make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [remote]}))
        self.served = {"a.test:443": here}
        with mock.patch.object(crypto, "confirm", return_value=True):
            self.assertEqual(self.update(), 0)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(remote): "collected", sha(here): "approved"})

    def test_approved_pin_outlives_the_next_update_without_asking_again(self):
        remote, here = make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [remote]}))
        self.served = {"a.test:443": here}
        with mock.patch.object(crypto, "confirm", return_value=True):
            self.update()
        self.assertEqual(self.update(), 0)  # confirm is back to failing the test when called
        self.assertEqual(self.stored_pins("a.test:443"), {sha(remote): "collected", sha(here): "approved"})

    def test_approved_pin_becomes_collected_once_the_remote_sees_it(self):
        remote, here = make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [remote]}))
        self.served = {"a.test:443": here}
        with mock.patch.object(crypto, "confirm", return_value=True):
            self.update()
        self.write_remote(make_document({"a.test:443": [remote, here]}))
        self.assertEqual(self.update(), 0)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(remote): "collected", sha(here): "collected"})

    def test_host_that_cannot_be_checked_from_here_is_still_stored(self):
        cert = make_cert()
        self.write_remote(make_document({"a.test:443": [cert]}))
        self.served = {"a.test:443": crypto.CryptoCliNetworkException("Unable to resolve host")}
        self.assertEqual(self.update(), 0)
        self.assertEqual(self.stored_pins("a.test:443"), {sha(cert): "collected"})

    def test_no_local_check_connects_to_nothing(self):
        cert = make_cert()
        self.write_remote(make_document({"a.test:443": [cert]}))
        self.assertEqual(self.update(local_check=False), 0)  # self.served is empty: a check would be a KeyError
        self.assertEqual(self.stored_pins("a.test:443"), {sha(cert): "collected"})

    def test_expired_remote_pin_is_not_stored(self):
        expired, current = make_cert(expires_in_days=-1), make_cert()
        self.write_remote(make_document({"a.test:443": [expired, current]}))
        self.served = {"a.test:443": current}
        self.update()
        self.assertEqual(self.stored_pins("a.test:443"), {sha(current): "collected"})

    def test_host_the_remote_no_longer_lists_is_dropped(self):
        a, b = make_cert(), make_cert()
        self.served = {"a.test:443": a, "b.test:443": b}
        self.write_remote(make_document({"a.test:443": [a], "b.test:443": [b]}))
        self.update()
        self.write_remote(make_document({"b.test:443": [b]}))
        self.update()
        self.assertEqual(list(self.stored()["hosts"]), ["b.test:443"])

    def assert_refused(self, message, **kwargs):
        before = self.pins_path.read_bytes() if self.pins_path.exists() else None
        with self.assertRaisesRegex(CryptoCliException, message):
            self.update(**kwargs)
        self.assertEqual(self.pins_path.read_bytes() if self.pins_path.exists() else None, before)

    def test_stale_remote_pins_are_refused(self):
        three_days_ago = datetime.now(UTC) - timedelta(days=3)
        self.write_remote(make_document({"a.test:443": [make_cert()]}, generated_at=three_days_ago))
        self.assert_refused("stale")
        self.served = {"a.test:443": make_cert()}
        with mock.patch.object(crypto, "confirm", return_value=False):
            self.update(max_age_hours=24 * 7)  # the same document is fine for who accepts a week

    def test_remote_pins_from_the_future_are_refused(self):
        tomorrow = datetime.now(UTC) + timedelta(days=1)
        self.write_remote(make_document({"a.test:443": [make_cert()]}, generated_at=tomorrow))
        self.assert_refused("from the future")

    def test_remote_pins_older_than_the_stored_ones_are_refused(self):
        cert = make_cert()
        self.served = {"a.test:443": cert}
        self.write_remote(make_document({"a.test:443": [cert]}))
        self.update()
        an_hour_ago = datetime.now(UTC) - timedelta(hours=1)
        self.write_remote(make_document({"a.test:443": [make_cert()]}, generated_at=an_hour_ago))
        self.assert_refused("older than the ones stored")

    def test_invalid_remote_output_is_refused(self):
        self.write_remote(b"Welcome to p1!\n")
        self.assert_refused("Invalid pins from remote_command")
        self.write_remote(b"x" * (crypto.PINS_MAX_BYTES + 1))
        self.assert_refused("more than")

    def test_failing_remote_command_is_a_clean_error(self):
        self.write_config(remote_command=[sys.executable, "-c", "import sys; sys.exit(3)"])
        self.assert_refused("exit code 3")
        self.write_config(remote_command=[str(self.dir / "no-such-command")])
        self.assert_refused("Unable to run remote_command")
        self.write_config(hosts=["a.test"])
        self.assert_refused("Missing or invalid 'remote_command'")

    def test_remote_command_that_hangs_is_killed(self):
        self.write_config(remote_command=[sys.executable, "-c", "import time; time.sleep(60)"])
        with mock.patch.object(crypto, "REMOTE_COMMAND_TIMEOUT", 0.5):
            self.assert_refused("was killed")


class TestConfirm(unittest.TestCase):
    def test_no_terminal_is_a_no(self):
        with mock.patch.object(sys, "stdin") as stdin, mock.patch("builtins.input", return_value="y") as answer:
            stdin.isatty.return_value = False
            self.assertFalse(crypto.confirm("Trust?"))
            answer.assert_not_called()

    def test_only_an_explicit_yes_is_a_yes(self):
        for said, expected in (("y", True), ("YES", True), ("", False), ("n", False), ("maybe", False)):
            with mock.patch.object(sys, "stdin") as stdin, mock.patch("builtins.input", return_value=said):
                stdin.isatty.return_value = True
                self.assertEqual(crypto.confirm("Trust?"), expected, said)


class TestXdgDirs(unittest.TestCase):
    def test_absolute_variable_is_used(self):
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": "/data"}):
            self.assertEqual(crypto.xdg_dir("XDG_STATE_HOME", ".local/state"), Path("/data"))
            self.assertEqual(get_tls_pin.pins_path(), Path("/data/crypto/pins.json"))

    def test_relative_or_empty_variable_is_ignored(self):
        for value in ("relative/dir", ""):
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": value}):
                self.assertEqual(crypto.xdg_dir("XDG_STATE_HOME", ".local/state"), Path.home() / ".local/state")
                self.assertEqual(get_tls_pin.pins_path(), Path.home() / ".local/state/crypto/pins.json")

    def test_reader_and_writer_agree_on_the_format(self):
        self.assertEqual(get_tls_pin.TIME_FORMAT, crypto.TIME_FORMAT)
        for module in (crypto, get_tls_pin):
            for name in ("HOST_CHARS", "DIGITS", "HEX_CHARS"):
                self.assertEqual(getattr(module, name), getattr(crypto, name), name)

    def test_host_key_validation(self):
        long_name = "a" * 253
        good = ("a.test:443", "a:1", "1.2.3.4:65535", "a-b.c-d.test:993", f"{long_name}:443")
        bad = (
            "",
            ":",
            "a.test",
            "a.test:",
            ":443",
            "a.test:443:443",
            "a.test:123456",
            "a.test:44a",
            "a.test:٤٤٣",  # digits, but not ASCII ones
            "A.test:443",
            ".a.test:443",
            "a.test.:443",
            "-a.test:443",
            "a.test-:443",
            "a_b.test:443",
            "a/../b:443",
            "a b:443",
            "a.test:443\n",
            "é.test:443",
            f"{long_name}a:443",
            None,
            443,
            ["a.test:443"],
        )
        for module in (crypto, get_tls_pin):
            for value in good:
                self.assertTrue(module.is_valid_host_key(value), (module.__name__, value))
            for value in bad:
                self.assertFalse(module.is_valid_host_key(value), (module.__name__, value))

    def test_sha256_validation(self):
        good = ("ab" * 32, "0123456789abcdef" * 4)
        bad = (
            "",
            "ab" * 31,
            "ab" * 33,
            "AB" * 32,
            "g" * 64,
            "ab" * 31 + "a\n",
            " " * 64,
            None,
            1,
            ["a"] * 64,
            b"a" * 64,
        )
        for module in (crypto, get_tls_pin):
            for value in good:
                self.assertTrue(module.is_valid_sha256(value), (module.__name__, value))
            for value in bad:
                self.assertFalse(module.is_valid_sha256(value), (module.__name__, value))


class TestGetTlsPin(PinsTestCase):
    """get_tls_pin.py as another tool runs it: a process, pointed at a pins file written by crypto"""

    def run_getter(self, *args):
        env = {**os.environ, "XDG_STATE_HOME": str(self.dir / "state")}
        return subprocess.run([sys.executable, "-I", str(GET_TLS_PIN), *args], capture_output=True, text=True, env=env)

    def test_prints_every_valid_pin_of_the_host(self):
        old, new, other = make_cert(), make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [old, new], "b.test:993": [other]}))
        self.update(local_check=False)
        for target in ("a.test", "a.test:443", "A.TEST"):
            result = self.run_getter(target)
            self.assertEqual((result.returncode, result.stdout.split()), (0, [sha(old), sha(new)]), target)
        self.assertEqual(self.run_getter("b.test:993").stdout.split(), [sha(other)])

    def test_approved_pin_is_printed_too(self):
        remote, here = make_cert(), make_cert()
        self.write_remote(make_document({"a.test:443": [remote]}))
        self.served = {"a.test:443": here}
        with mock.patch.object(crypto, "confirm", return_value=True):
            self.update()
        self.assertEqual(self.run_getter("a.test").stdout.split(), [sha(remote), sha(here)])

    def test_pin_that_expired_since_the_update_is_not_printed(self):
        expired, current = make_cert(expires_in_days=-1), make_cert()
        crypto.store_pins(make_document({"a.test:443": [expired, current], "b.test:443": [expired]}))
        self.assertEqual(self.run_getter("a.test").stdout.split(), [sha(current)])
        result = self.run_getter("b.test")
        self.assertEqual((result.returncode, result.stdout), (1, ""))

    def test_nothing_to_print_is_exit_code_one(self):
        result = self.run_getter("a.test")  # no pins file at all
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        crypto.store_pins(make_document({"a.test:443": [make_cert()]}))
        for target in ("b.test", "a.test:8443"):  # another host, another port
            result = self.run_getter(target)
            self.assertEqual((result.returncode, result.stdout), (1, ""), target)

    def test_unusable_pins_file_is_exit_code_one(self):
        self.pins_path.parent.mkdir(parents=True)
        document = make_document({"a.test:443": [make_cert()]})
        document["hosts"]["a.test:443"]["pins"][0]["sha256"] = "not a fingerprint"
        for content in ("", "[]", "{}", '{"version": 2, "hosts": {}}', json.dumps(document)):
            self.pins_path.write_text(content)
            result = self.run_getter("a.test")
            self.assertEqual((result.returncode, result.stdout), (1, ""), content)
            self.assertNotIn("Traceback", result.stderr)

    def test_bad_call_is_exit_code_two(self):
        for args in ((), ("a.test", "b.test"), ("a b",), ("../../etc/passwd",), ("a.test:port",), ("--help",)):
            result = self.run_getter(*args)
            self.assertEqual((result.returncode, result.stdout), (2, ""), args)


if __name__ == "__main__":
    unittest.main()
