"""Apple container PostgreSQL harnesses wait for the TCP listener (#2755).

The image entrypoint starts a temporary Unix-socket-only server during init.
A pg_isready without -h can pass against that socket while the TCP listener
the tests use is still down.
"""

import pathlib
import shlex
import subprocess
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
HARNESSES = (
    SCRIPTS / "postgres_portfolio_tests_apple.sh",
    SCRIPTS / "postgres_reusable_sekai_tests.sh",
)


def pg_isready_calls(path):
    """Argument lists of every pg_isready invocation in a harness."""
    calls = []
    for line in path.read_text().splitlines():
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            if token == "pg_isready" or token.endswith("/pg_isready"):
                args = []
                for token in tokens[index + 1 :]:
                    if token in {"then", "do", "fi", "done"} or token.startswith(
                        (">", ";", "2>")
                    ):
                        break
                    args.append(token)
                calls.append(args)
    return calls


def option(args, name):
    return args[args.index(name) + 1] if name in args else None


class TcpReadiness(unittest.TestCase):
    def test_every_pg_isready_probes_loopback_tcp(self):
        for path in HARNESSES:
            with self.subTest(script=path.name):
                calls = pg_isready_calls(path)
                self.assertGreaterEqual(len(calls), 2, path.name)
                for args in calls:
                    self.assertEqual(option(args, "-h"), "127.0.0.1", args)
                    self.assertEqual(option(args, "-p"), "5432", args)

    def test_harnesses_parse(self):
        for path in HARNESSES:
            with self.subTest(script=path.name):
                subprocess.run(["bash", "-n", str(path)], check=True)
