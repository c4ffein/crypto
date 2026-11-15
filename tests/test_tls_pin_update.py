#!/usr/bin/env python3
"""
Tests for tools/tls-pin-update.py and for the tls-pin-get shell script it generates.
The script is copied to a temporary directory first, so that what it generates "next to itself" lands there, and
it is given a local command in place of ssh. Standard library only, as the script is.
"""

import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parent.parent
SOURCE = ROOT / "tools" / "tls-pin-update.py"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SHA_A, SHA_B, SHA_C = "a" * 64, "b" * 64, "c" * 64


def stamp(moment):
    return moment.strftime(TIME_FORMAT)


def make_pin(sha, expires_in_days=30):
    now = datetime.now(UTC)
    return {
        "sha256": sha,
        "not_after": stamp(now + timedelta(days=expires_in_days)),
        "first_seen": stamp(now),
        "last_seen": stamp(now),
        "source": "collected",
    }


def make_document(hosts, generated_at=None):
    """A pins document as pins-collect writes it: hosts is {"host:port": [sha256 or pin, ...]}"""
    now = datetime.now(UTC)
    return {
        "version": 1,
        "generated_at": stamp(generated_at or now),
        "hosts": {
            key: {"checked_at": stamp(now), "pins": [make_pin(pin) if isinstance(pin, str) else pin for pin in pins]}
            for key, pins in hosts.items()
        },
    }


class UpdateTestCase(unittest.TestCase):
    """tls-pin-update.py alone in a directory of its own, so that tls-pin-get appears there"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.script = Path(shutil.copy(SOURCE, self.bin / "tls-pin-update.py"))
        self.get = self.bin / "tls-pin-get"
        self.remote = self.dir / "remote.json"
        self.pins = self.dir / "state" / "crypto" / "pins.json"
        self.env = {**os.environ, "XDG_STATE_HOME": str(self.dir / "state")}
        spec = importlib.util.spec_from_file_location("tls_pin_update", self.script)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def serve(self, served):
        self.remote.write_bytes(served if isinstance(served, bytes) else json.dumps(served).encode())

    def update(self, served):
        """Run the script as a process, without a terminal, with `cat` of what the server would print"""
        self.serve(served)
        command = [sys.executable, "-I", str(self.script), "cat", str(self.remote)]
        return subprocess.run(command, capture_output=True, text=True, env=self.env, stdin=subprocess.DEVNULL)

    def update_at_a_terminal(self, served, answer):
        """Run main() here, with a terminal for stdin and `answer` typed at the prompt"""
        self.serve(served)
        stdout = io.StringIO()
        with (
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(self.module.sys, "stdin") as stdin,
            mock.patch("builtins.input", return_value=answer) as asked,
            contextlib.redirect_stdout(stdout),
        ):
            stdin.isatty.return_value = True
            code = self.module.main(["tls-pin-update.py", "cat", str(self.remote)])
        return code, stdout.getvalue(), asked

    def seed(self):
        """As if a previous run had generated tls-pin-get: a file that carries the canary"""
        self.get.write_text(f"#!/bin/sh\n# {self.module.CANARY}\nexit 1\n")

    def get_pins(self, *args):
        return subprocess.run(["sh", str(self.get), *args], capture_output=True, text=True, cwd=self.dir)

    def snapshot(self):
        return {path: path.read_bytes() if path.is_file() else None for path in (self.get, self.pins)}


class TestGeneratedScript(UpdateTestCase):
    def setUp(self):
        super().setUp()
        self.seed()

    def test_prints_the_pins_of_a_host(self):
        result = self.update(make_document({"a.test:443": [SHA_A, SHA_B], "b.test:993": [SHA_C]}))
        self.assertEqual(result.returncode, 0, result.stderr)
        for target in ("a.test", "a.test:443"):
            got = self.get_pins(target)
            self.assertEqual((got.returncode, got.stdout.split(), got.stderr), (0, [SHA_A, SHA_B], ""), target)
        self.assertEqual(self.get_pins("b.test:993").stdout.split(), [SHA_C])

    def test_nothing_to_print_is_exit_code_one(self):
        expired = make_pin(SHA_B, expires_in_days=-1)
        self.update(make_document({"a.test:443": [SHA_A, expired], "old.test:443": [expired], "never.test:443": []}))
        self.assertEqual(self.get_pins("a.test").stdout.split(), [SHA_A])  # without the expired one
        for target in ("old.test", "never.test", "unknown.test", "a.test:8443", "b.test:993", "A.TEST", ""):
            got = self.get_pins(target)
            self.assertEqual((got.returncode, got.stdout), (1, ""), target)
            self.assertIn("no pin for", got.stderr)

    def test_bad_call_is_exit_code_two(self):
        self.update(make_document({"a.test:443": [SHA_A]}))
        for args in ((), ("a.test", "b.test"), ("-h",), ("--help",)):
            got = self.get_pins(*args)
            self.assertEqual((got.returncode, got.stdout), (2, ""), args)

    def test_argument_is_only_ever_compared(self):
        """Whatever is asked, nothing of it is run, expanded or matched as a pattern"""
        self.update(make_document({"a.test:443": [SHA_A]}))
        for hostile in ("$(touch pwned)", "`touch pwned`", "a.test; touch pwned", "*", "?.test", "a.test:443'", "-n"):
            got = self.get_pins(hostile)
            self.assertEqual((got.returncode, got.stdout), (1, ""), hostile)
        self.assertFalse((self.dir / "pwned").exists())

    def test_script_is_a_valid_executable_shell_script_of_ours(self):
        self.update(make_document({"a.test:443": [SHA_A]}))
        self.assertEqual(stat.S_IMODE(self.get.stat().st_mode), 0o755)
        self.assertEqual(subprocess.run(["sh", "-n", str(self.get)], capture_output=True).returncode, 0)
        text = self.get.read_text()
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn(f"# {self.module.CANARY}\n", text)
        self.assertEqual(subprocess.run([str(self.get), "a.test"], capture_output=True, text=True).stdout, SHA_A + "\n")

    def test_pins_are_stored_as_data_too_and_nothing_else_is_left(self):
        self.update(make_document({"a.test:443": [SHA_A]}))
        self.assertEqual(stat.S_IMODE(self.pins.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.pins.read_text())["hosts"]["a.test:443"]["pins"][0]["sha256"], SHA_A)
        left = sorted(p.name for p in self.bin.iterdir() if p.name != "__pycache__")  # the one of this test
        self.assertEqual(left, ["tls-pin-get", "tls-pin-update.py"])
        self.assertEqual([p.name for p in self.pins.parent.iterdir()], ["pins.json"])

    def test_every_update_writes_it_again(self):
        self.update(make_document({"a.test:443": [SHA_A]}))
        self.update(make_document({"a.test:443": [SHA_B], "b.test:443": [SHA_C]}))
        self.assertEqual(self.get_pins("a.test").stdout.split(), [SHA_B])
        self.assertEqual(self.get_pins("b.test").stdout.split(), [SHA_C])

    def test_new_pins_are_pointed_out_after_the_first_run(self):
        first = self.update(make_document({"a.test:443": [SHA_A]}))
        self.assertNotIn("NEW", first.stdout)
        second = self.update(make_document({"a.test:443": [SHA_A, SHA_B]}))
        lines = {line.split()[1]: line for line in second.stdout.splitlines() if line.startswith("a.test")}
        self.assertNotIn("NEW", lines[SHA_A])
        self.assertIn("NEW", lines[SHA_B])

    def test_render_refuses_what_a_shell_would_not_take_literally(self):
        """The validation makes this unreachable: the generator checks again anyway"""
        now = datetime.now(UTC)
        for key, sha in (("a.test:443'; touch pwned; '", SHA_A), ("a.test:443", "$(touch pwned)"), ("a b:443", SHA_A)):
            document = {"generated_at": stamp(now), "hosts": {key: {"pins": [make_pin(sha)]}}}
            with self.subTest(key=key, sha=sha), self.assertRaisesRegex(ValueError, "refusing to write"):
                self.module.render_script(document, now)


class TestFirstTimeAndCanary(UpdateTestCase):
    def test_without_a_terminal_nothing_is_generated_but_the_pins_are_stored(self):
        result = self.update(make_document({"a.test:443": [SHA_A]}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.get.exists())
        self.assertIn("not generated: run me once from a terminal", result.stderr)
        self.assertTrue(self.pins.exists())

    def test_first_time_says_what_it_generates_and_asks(self):
        code, said, asked = self.update_at_a_terminal(make_document({"a.test:443": [SHA_A]}), answer="y")
        self.assertEqual(code, 0)
        self.assertIn(f"By default, this tool generates {self.get} next to itself", said)
        asked.assert_called_once()
        self.assertEqual(self.get_pins("a.test").stdout.split(), [SHA_A])

    def test_anything_but_yes_generates_nothing(self):
        for answer in ("n", "", "maybe"):
            code, _, asked = self.update_at_a_terminal(make_document({"a.test:443": [SHA_A]}), answer=answer)
            self.assertEqual(code, 0)
            asked.assert_called_once()
            self.assertFalse(self.get.exists(), answer)
            self.assertTrue(self.pins.exists())

    def test_once_generated_it_is_overwritten_without_asking(self):
        self.update_at_a_terminal(make_document({"a.test:443": [SHA_A]}), answer="y")
        code, _, asked = self.update_at_a_terminal(make_document({"a.test:443": [SHA_B]}), answer="n")
        self.assertEqual(code, 0)
        asked.assert_not_called()
        result = self.update(make_document({"a.test:443": [SHA_C]}))  # nor does it need a terminal anymore
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.get_pins("a.test").stdout.split(), [SHA_C])

    def assert_untouched(self, before):
        result = self.update(make_document({"a.test:443": [SHA_A]}))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("is not a file I generated (no canary)", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.pins.exists())  # all or nothing: the pins are not stored either

    def test_file_without_the_canary_is_never_overwritten(self):
        for content in ("#!/bin/sh\necho mine\n", "", f"#!/bin/sh\n# almost {self.module.CANARY}\n"):
            self.get.write_text(content)
            self.assert_untouched(self.snapshot())
            self.assertEqual(self.get.read_text(), content)

    def test_canary_must_be_a_line_near_the_top(self):
        self.get.write_text("#!/bin/sh\n" + "# padding\n" * 1000 + f"# {self.module.CANARY}\n")
        self.assert_untouched(self.snapshot())

    def test_symlink_is_never_followed(self):
        elsewhere = self.dir / "elsewhere"
        elsewhere.write_text(f"#!/bin/sh\n# {self.module.CANARY}\n")  # even to a file that carries the canary
        self.get.symlink_to(elsewhere)
        before = elsewhere.read_text()
        self.assert_untouched(self.snapshot())
        self.assertTrue(self.get.is_symlink())
        self.assertEqual(elsewhere.read_text(), before)

    def test_directory_in_the_way_is_refused(self):
        self.get.mkdir()
        self.assert_untouched(self.snapshot())


class TestValidation(UpdateTestCase):
    """The exact schema of what pins-collect writes: nothing more, nothing less"""

    def setUp(self):
        super().setUp()
        self.seed()
        self.update(make_document({"a.test:443": [SHA_A]}))
        self.valid = make_document({"a.test:443": [SHA_A]})

    def altered(self, change):
        document = json.loads(json.dumps(self.valid))
        change(document)
        return document

    def assert_refused(self, served, message="refused what cat printed"):
        before = self.snapshot()
        result = self.update(served)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_valid_document_is_stored_as_it_came(self):
        self.assertEqual(self.update(self.valid).returncode, 0)
        self.assertEqual(json.loads(self.pins.read_text()), self.valid)

    def test_anything_else_is_refused_and_both_files_are_kept(self):
        def host(document):
            return document["hosts"]["a.test:443"]

        def pin(document):
            return host(document)["pins"][0]

        text = json.dumps(self.valid)
        bad = {
            "a login banner": b"Welcome to p1!\n",
            "nothing": b"",
            "not an object": b"[]",
            "not utf-8": text.encode("utf-16"),
            "the same key twice": text.replace('"version": 1', '"version": 1, "version": 1').encode(),
            "NaN": text.replace('"version": 1', '"version": NaN').encode(),
            "too deep": b"[" * 100000,
            "too large": text.encode() + b" " * (1024 * 1024),
            "unknown field in the document": self.altered(lambda d: d.update(extra=1)),
            "unknown field in a host": self.altered(lambda d: host(d).update(extra=1)),
            "unknown field in a pin": self.altered(lambda d: pin(d).update(extra=1)),
            "missing field in the document": self.altered(lambda d: d.pop("generated_at")),
            "missing field in a host": self.altered(lambda d: host(d).pop("checked_at")),
            "missing field in a pin": self.altered(lambda d: pin(d).pop("source")),
            "version 2": self.altered(lambda d: d.update(version=2)),
            "version true": self.altered(lambda d: d.update(version=True)),
            "version 1.0": self.altered(lambda d: d.update(version=1.0)),
            "version as text": self.altered(lambda d: d.update(version="1")),
            "generated_at not padded": self.altered(lambda d: d.update(generated_at="2026-1-5T1:2:3Z")),
            "generated_at with an offset": self.altered(lambda d: d.update(generated_at="2026-01-05T01:02:03+00:00")),
            "generated_at a number": self.altered(lambda d: d.update(generated_at=1700000000)),
            "hosts a list": self.altered(lambda d: d.update(hosts=[])),
            "no host": self.altered(lambda d: d.update(hosts={})),
            "too many hosts": self.altered(lambda d: d.update(hosts={f"h{i}.test:443": host(d) for i in range(257)})),
            "host with a path": self.altered(lambda d: d["hosts"].update({"../../x:443": host(d)})),
            "host in uppercase": self.altered(lambda d: d["hosts"].update({"A.test:443": host(d)})),
            "host without a port": self.altered(lambda d: d["hosts"].update({"b.test": host(d)})),
            "host with a quote": self.altered(lambda d: d["hosts"].update({"b.test:443'": host(d)})),
            "host entry a list": self.altered(lambda d: d["hosts"].update({"b.test:443": []})),
            "checked_at not a timestamp": self.altered(lambda d: host(d).update(checked_at="yesterday")),
            "pins an object": self.altered(lambda d: host(d).update(pins={})),
            "too many pins": self.altered(lambda d: host(d).update(pins=[make_pin(f"{i:064x}") for i in range(17)])),
            "the same pin twice": self.altered(lambda d: host(d).update(pins=[pin(d), pin(d)])),
            "pin a string": self.altered(lambda d: host(d).update(pins=[SHA_A])),
            "short sha256": self.altered(lambda d: pin(d).update(sha256="ab")),
            "uppercase sha256": self.altered(lambda d: pin(d).update(sha256="A" * 64)),
            "sha256 with a command": self.altered(lambda d: pin(d).update(sha256="$(touch pwned)".ljust(64, "a"))),
            "sha256 a number": self.altered(lambda d: pin(d).update(sha256=1)),
            "not_after not a timestamp": self.altered(lambda d: pin(d).update(not_after="soon")),
            "first_seen missing its Z": self.altered(lambda d: pin(d).update(first_seen=pin(d)["first_seen"][:-1])),
            "last seen before first seen": self.altered(lambda d: pin(d).update(last_seen="2020-01-01T00:00:00Z")),
            "a pin approved elsewhere": self.altered(lambda d: pin(d).update(source="approved")),
        }
        for name, served in bad.items():
            with self.subTest(name):
                self.assert_refused(served)
        self.assertEqual(self.get_pins("a.test").stdout.split(), [SHA_A])
        self.assertFalse((self.dir / "pwned").exists())

    def test_stale_pins_are_refused(self):
        two_hours_ago = datetime.now(UTC) - timedelta(hours=2)
        self.assert_refused(make_document({"a.test:443": [SHA_A]}, generated_at=two_hours_ago), "stale")

    def test_pins_from_the_future_are_refused(self):
        tomorrow = datetime.now(UTC) + timedelta(days=1)
        self.assert_refused(make_document({"a.test:443": [SHA_A]}, generated_at=tomorrow), "in the future")

    def test_failing_command_is_a_clean_error(self):
        before = self.snapshot()
        for command, message in (
            ([sys.executable, "-c", "import sys; sys.exit(255)"], "failed (exit code 255)"),
            ([str(self.dir / "no-such-command")], "could not run"),
        ):
            result = subprocess.run([sys.executable, "-I", str(self.script), *command], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(message, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_help(self):
        result = subprocess.run([sys.executable, "-I", str(self.script), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage: tls-pin-update.py", result.stdout)

    def test_format_is_the_one_of_crypto(self):
        """The validators are copied, not imported (the script stands alone): the copies must stay identical"""
        sources = [(ROOT / "crypto.py").read_text(), SOURCE.read_text()]
        for constant in ("TIME_FORMAT", "HOST_CHARS", "DIGITS", "HEX_CHARS"):
            lines = {next(line for line in text.splitlines() if line.startswith(f"{constant} = ")) for text in sources}
            self.assertEqual(len(lines), 1, constant)
        for function in ("is_valid_host_key", "is_valid_sha256"):
            bodies = {text.split(f"def {function}(")[1].split("\n\n\n")[0] for text in sources}
            self.assertEqual(len(bodies), 1, function)


if __name__ == "__main__":
    unittest.main()
