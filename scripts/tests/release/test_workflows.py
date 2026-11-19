"""Release invariants no workflow linter expresses, asserted on the parsed YAML.

scripts/release/ enforces these at run time; these tests keep the workflows
from bypassing the scripts. Assert on structure (triggers, permissions, job
graph, step order), not on the wording of a step.
"""

import json
import shlex
import unittest

import yaml

from tests.release import ROOT

WORKFLOWS = ROOT / ".github" / "workflows"
VERIFIED_SHA = "${{ needs.verify-tag.outputs.sha }}"
TAGGED = "needs.verify-tag.outputs.tag != ''"
HEAD_CHECK = 'test "$(git rev-parse HEAD)" = "$SHA"'


def load(name: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / name).read_text())
    doc["on"] = doc.pop(True, doc.get("on"))  # YAML 1.1 reads a bare `on` key as True.
    return doc


def runs(step: dict) -> str:
    return step.get("run", "")


def uses(step: dict) -> str:
    return step.get("uses", "")


def is_mutation(step: dict) -> bool:
    """A step that changes a GitHub Release, pushes an image, or mints an attestation."""
    return (
        uses(step).startswith(("actions/attest", "taiki-e/upload-rust-binary-action"))
        or any(f"github-release.sh {cmd}" in runs(step) for cmd in ("draft", "upload", "publish"))
        or "record-image-digest.sh" in runs(step)
        or "build/release.sh" in runs(step)
    )


def is_guard(step: dict) -> bool:
    return "github-release.sh guard" in runs(step)


def needs(job: dict) -> set:
    value = job.get("needs", [])
    return {value} if isinstance(value, str) else set(value)


def strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


class Dispatcher(unittest.TestCase):
    """A v* tag push only starts release.yml from main; it can do nothing else."""

    def setUp(self):
        self.wf = load("release-dispatch.yml")

    def test_triggers_only_on_v_tags(self):
        self.assertEqual(self.wf["on"], {"push": {"tags": ["v*"]}})

    def test_can_only_dispatch_workflows(self):
        self.assertEqual(self.wf["permissions"], {"actions": "write", "contents": "read"})
        for job in self.wf["jobs"].values():
            self.assertNotIn("permissions", job)

    def test_runs_one_step_that_dispatches_release_on_main(self):
        [job] = self.wf["jobs"].values()
        [step] = job["steps"]
        self.assertNotIn("uses", step)
        self.assertEqual(step["run"].strip(), 'gh workflow run release.yml --ref main -f tag="$TAG"')


class Release(unittest.TestCase):
    def setUp(self):
        self.wf = load("release.yml")
        self.jobs = self.wf["jobs"]

    def test_never_runs_on_push(self):
        self.assertNotIn("push", self.wf["on"])
        self.assertIn("tag", self.wf["on"]["workflow_dispatch"]["inputs"])

    def test_one_run_per_tag(self):
        self.assertIn("inputs.tag", self.wf["concurrency"]["group"])
        self.assertFalse(self.wf["concurrency"]["cancel-in-progress"])

    def test_a_tagged_run_must_start_from_main(self):
        first = self.jobs["verify-tag"]["steps"][0]
        self.assertEqual(first["if"], "inputs.tag != ''")
        self.assertEqual(first["env"]["WORKFLOW_REF"], "${{ github.ref }}")
        self.assertIn("refs/heads/main", runs(first))

    def test_verifies_the_tag_with_mains_verifier_and_keys(self):
        steps = self.jobs["verify-tag"]["steps"]
        main_checkout = next(s for s in steps if s.get("with", {}).get("path") == "main-tree")
        self.assertNotIn("ref", main_checkout["with"], "main's verifier must come from the workflow ref")
        verify = next(s for s in steps if "verify-tag.sh" in runs(s))
        self.assertTrue(verify["env"]["MAIN_TREE"].endswith("/main-tree"))
        self.assertIn("${MAIN_TREE}/scripts/release/verify-tag.sh", verify["run"])
        self.assertIn("${MAIN_TREE}/security/release-tag-fingerprints", verify["run"])
        self.assertIn('ancestry "$TAG" "$sha"', verify["run"])

    def test_every_later_job_builds_the_verified_commit(self):
        for name, job in self.jobs.items():
            if name == "verify-tag":
                continue
            with self.subTest(job=name):
                self.assertIn("verify-tag", needs(job))
                if "uses" in job:  # A reusable workflow gets the commit as its input.
                    self.assertEqual(job["with"]["sha"], VERIFIED_SHA)
                    continue
                steps = job["steps"]
                for i, step in enumerate(steps):
                    if uses(step).startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["ref"], VERIFIED_SHA)
                        self.assertIn(HEAD_CHECK, runs(steps[i + 1]))

    def test_never_uses_the_event_commit_or_ref_name(self):
        for value in strings(self.jobs):
            for banned in ("github.sha", "github.ref_name", "GITHUB_SHA", "GITHUB_REF", "github.event_name"):
                self.assertNotIn(banned, value)

    def test_release_changes_go_through_the_release_script(self):
        for value in strings(self.jobs):
            self.assertNotIn("gh release ", value)

    def test_every_mutating_job_refuses_a_published_release_first(self):
        mutating = set()
        for name, job in self.jobs.items():
            steps = job.get("steps", [])
            first = next((i for i, s in enumerate(steps) if is_mutation(s)), None)
            if first is None:
                continue
            mutating.add(name)
            with self.subTest(job=name):
                guards = [s for s in steps[:first] if is_guard(s)]
                self.assertTrue(guards, f"{name} mutates before the guard")
                self.assertTrue(all("if" not in s for s in guards), f"{name} guard must always run")
                self.assertEqual(job.get("if"), TAGGED)
        self.assertEqual(
            mutating,
            {"attest", "sekai-release", "record-image-digest", "publish",
             "compatibility-matrix", "sekai-binaries", "image", "image-manifest"},
        )

    def test_publish_runs_last_after_every_other_job(self):
        def upstream(name: str) -> set:
            found = set()
            for dep in needs(self.jobs[name]):
                found |= {dep} | upstream(dep)
            return found

        self.assertEqual(upstream("publish"), set(self.jobs) - {"publish"})
        self.assertFalse(any("publish" in needs(job) for job in self.jobs.values()))

    def test_package_reads_pull_requests_for_gate_flags(self):
        self.assertEqual(self.jobs["package"]["permissions"], {"contents": "read", "pull-requests": "read"})

    def test_a_tagged_release_checks_the_public_api_against_the_last_final_tag(self):
        steps = self.jobs["scripts"]["steps"]
        semver = next(s for s in steps if "check-semver.py release" in runs(s))
        self.assertEqual(semver["if"], "needs.verify-tag.outputs.tag != ''")

    def test_never_names_a_latest_image(self):
        for value in strings(self.jobs):
            self.assertNotIn(":latest", value)

    def test_write_permissions_are_job_scoped(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})
        writers = {
            name: {k for k, v in job.get("permissions", {}).items() if v == "write"}
            for name, job in self.jobs.items()
        }
        self.assertEqual(
            {name: perms for name, perms in writers.items() if perms},
            {
                "attest": {"id-token", "attestations"},
                "sekai-release": {"contents"},
                "record-image-digest": {"contents"},
                "publish": {"contents"},
                "compatibility-matrix": {"contents"},
                "sekai-binaries": {"contents"},
                "image": {"packages"},
                "image-manifest": {"packages"},
            },
        )


def perf_gate_calls(step: dict) -> list:
    """The argument lists of every perf-gate invocation in a step's script."""
    script = runs(step).replace("\\\n", " ")
    calls = []
    for line in script.splitlines():
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            if token.endswith("/perf-gate"):
                calls.append(tokens[index + 1 :])
    return calls


def option(args: list, name: str):
    return args[args.index(name) + 1] if name in args else None


class Performance(unittest.TestCase):
    """The scheduled object-path matrix gates regressions at 20% (#3004)."""

    def setUp(self):
        self.workflow = load("performance.yml")

    def test_object_path_regression_gate_enforces_twenty_percent_on_its_manifest(self):
        steps = self.workflow["jobs"]["object-path"]["steps"]
        gates = [
            args
            for step in steps
            for args in perf_gate_calls(step)
            if option(args, "--manifest") == "benchmarks/manifest-object-path-v1.json"
        ]
        self.assertEqual(len(gates), 1)
        self.assertIn("--enforce", gates[0])
        self.assertEqual(option(gates[0], "--regression-threshold-percent"), "20")

    def test_object_path_matrix_runs_behind_the_postgres_wrapper(self):
        steps = self.workflow["jobs"]["object-path"]["steps"]
        self.assertTrue(
            any("scripts/object-path-with-postgres.sh" in runs(step) for step in steps)
        )

    def test_gates_compare_against_a_runner_class_baseline(self):
        """A baseline from other hardware makes the verdict about the machine (#2901)."""
        for job in ("benchmark", "object-path"):
            self.assertEqual(self.workflow["jobs"][job]["runs-on"], "ubuntu-latest", job)
            gates = {
                (option(args, "--manifest"), option(args, "--baseline"))
                for step in self.workflow["jobs"][job]["steps"]
                for args in perf_gate_calls(step)
                if option(args, "--baseline")
            }
            self.assertTrue(gates, job)
            for manifest, baseline in gates:
                report = json.loads((ROOT / baseline).read_text())
                self.assertTrue(
                    report["hardware"]["description"].startswith("github-hosted ubuntu-latest"),
                    f"{job}: {baseline}",
                )
                expected = json.loads((ROOT / manifest).read_text())["fixture_version"]
                self.assertEqual(report["fixture_version"], expected, f"{job}: {baseline}")

    def test_smoke_job_runs_the_smoke_manifest(self):
        steps = self.workflow["jobs"]["object-path-smoke"]["steps"]
        self.assertTrue(
            any("benchmarks/manifest-object-path-smoke-v1.json" in runs(step) for step in steps)
        )


if __name__ == "__main__":
    unittest.main()
