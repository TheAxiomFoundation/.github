"""Exercise pin-bump guard arguments with a strict trusted CLI stand-in."""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import yaml


TEMP_PARENT = "/private/tmp" if Path("/private/tmp").is_dir() else None

WORKFLOW = Path(os.environ.get(
    "AXIOM_PIN_BUMP_TEST_WORKFLOW",
    str(Path(__file__).resolve().parents[1] / ".github/workflows/validate-rulespec.yml"),
))
BASE = "a" * 40
HEAD = "b" * 40
PROPOSED = "e" * 40
MODULE = "uk/statutes/unchanged.yaml"
MANIFEST = ".axiom/encoding-manifests/uk/statutes/unchanged.json"
BASE_PREPARATION_STEP = "Prepare protected-base manifest audit"


def run_guard(*, mode="full-toolchain-bump", valid=True, encoder="fixture",
              inherited=False, scenario="manifest", base_pin="a" * 40,
              integrity_fail_after=0, event="pull_request"):
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    shell = next(step["run"] for step in steps if step.get("name") == "Reject manual RuleSpec changes")
    with tempfile.TemporaryDirectory(prefix="encoder-guard-pin-manifest-", dir=TEMP_PARENT) as directory:
        root = Path(directory)
        workspace = root / "rulespec-uk"
        workspace.mkdir()
        module = workspace / MODULE
        module.parent.mkdir(parents=True)
        module.write_text("fixture: unchanged\n")
        manifest = workspace / MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"valid": valid, "sha256": hashlib.sha256(module.read_bytes()).hexdigest()}))
        base_workspace = root / "base" / "rulespec-uk"
        base_workspace.mkdir(parents=True)
        base_module = base_workspace / MODULE
        base_module.parent.mkdir(parents=True)
        base_module.write_bytes(module.read_bytes())
        base_manifest = base_workspace / MANIFEST
        base_manifest.parent.mkdir(parents=True)
        base_manifest.write_text(json.dumps({"valid": valid if inherited else True,
                                            "sha256": hashlib.sha256(module.read_bytes()).hexdigest()}))
        if scenario in ("legacy", "new-module"):
            manifest.unlink()
            base_manifest.unlink()
        if scenario == "new-module":
            (workspace / "uk/statutes/new.yaml").write_text("fixture: new\n")
        if scenario == "jurisdiction":
            for repo in (workspace, base_workspace):
                source = repo / MANIFEST
                destination = repo / "uk/.axiom/encoding-manifests/statutes/unchanged.json"
                destination.parent.mkdir(parents=True)
                source.rename(destination)
        dependencies = root / "dependencies with spaces"
        checkout = dependencies / "axiom-encode"
        checkout.mkdir(parents=True)
        (checkout / "pin").write_text(PROPOSED)
        base_dependencies = root / "base-dependencies"
        (base_dependencies / "axiom-encode").mkdir(parents=True)
        (base_dependencies / "axiom-encode/pin").write_text(base_pin)
        protected = root / "protected"
        protected.mkdir()
        tools = root / "tools"
        tools.mkdir()
        (tools / "python").symlink_to(sys.executable)
        if event == "merge_group":
            # A queue's first parent need not be the protected group base.
            # Supply a valid distinct commit so fallback cannot mask that fact.
            git = tools / "git"
            git.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
                import sys
                assert sys.argv[1:] == ['rev-parse', '--verify', 'HEAD~1^{commit}']
                print('c' * 40)
                """))
            git.chmod(0o755)
        integrity = root / "integrity"
        integrity.mkdir()
        (integrity / "check.py").write_text(textwrap.dedent("""\
            import os
            from pathlib import Path
            import sys
            assert sys.argv[1:] == ['verify']
            path = Path(__file__).with_name('count')
            count = int(path.read_text()) + 1 if path.exists() else 1
            path.write_text(str(count))
            boundary = int(os.environ['INTEGRITY_FAIL_AFTER'])
            if boundary and count >= boundary:
                sys.exit('DependencyIntegrityError: fixture drift before consumer')
            """))
        calls = root / "calls.jsonl"
        calls.touch()
        supervisor = protected / "axiom-encode-signing-supervisor"
        supervisor.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import json
            import os
            import sys

            args = sys.argv[1:]
            with open(os.environ['GUARD_CALLS'], 'a') as log:
                log.write(json.dumps({'supervisor': args}) + '\\n')
            boundary = args.index('--')
            protected = args[args.index('--trusted-python-runtime-root') + 1].removesuffix('/python')
            assert args[:boundary] == [
                '--trusted-signing-roots', protected + '/signing-trust-roots.json',
                '--trusted-python-runtime-root', protected + '/python',
                '--trusted-python-import-root', protected + '/python/lib/python3.13/site-packages',
                '--trusted-python-package-root', protected + '/python/lib/python3.13/site-packages/axiom_encode',
            ]
            command = args[boundary + 1:]
            assert command[0] == protected + '/axiom-encode'
            os.execv(command[0], command)
            """))
        cli = protected / "axiom-encode"
        cli.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import argparse
            import hashlib
            import json
            import os
            from pathlib import Path
            import sys

            argv = sys.argv[1:]
            assert argv[0] == 'guard-generated'
            parser = argparse.ArgumentParser()
            for name in ('repo', 'base-ref', 'head-ref', 'corpus-path', 'expected-encoder-checkout'):
                parser.add_argument('--' + name, required=True)
            parser.add_argument('--all', action='store_true')
            parser.add_argument('--json', action='store_true')
            args = parser.parse_args(argv[1:])
            assert args.base_ref == os.environ['EXPECTED_BASE']
            is_base = args.repo == os.environ['BASE_RULESPEC_ROOT']
            assert args.head_ref == (os.environ['EXPECTED_BASE'] if is_base else os.environ['GITHUB_SHA'])
            pin = (Path(args.expected_encoder_checkout) / 'pin').read_text()
            assert pin == os.environ['BASE_ENCODER' if is_base else 'PROPOSED_ENCODER']
            assert args.corpus_path == os.environ['BASE_DEPENDENCY_ROOT' if is_base else 'AXIOM_DEPENDENCY_ROOT'] + '/axiom-corpus'
            with open(os.environ['GUARD_CALLS'], 'a') as log:
                log.write(json.dumps({'cli': argv, 'encoder_ref': pin,
                                      'encoder_fixture': os.environ['ENCODER_FIXTURE']}) + '\\n')
            # Model the observed --all/default selection distinction. This is
            # a strict fixture gate, not external signature authentication.
            issues = []
            if args.all:
                root = Path(args.repo)
                # Model exact legacy --all behavior: jurisdiction-only manifests
                # are omitted by the external encoder's root inventory.
                for module in sorted((root / 'uk/statutes').glob('*.yaml')):
                    manifest = root / '.axiom/encoding-manifests/uk/statutes' / (module.stem + '.json')
                    if not manifest.exists():
                        issues.append(f"uk/statutes/{module.name} is missing a matching .axiom/encoding-manifests manifest")
                        continue
                    payload = json.loads(manifest.read_text())
                    if not payload['valid']:
                        issues.append(f"{manifest.relative_to(root)} has stale validation_waiver_set_sha256")
                    if payload['sha256'] != hashlib.sha256(module.read_bytes()).hexdigest():
                        issues.append('unchanged manifest rejected at proposed encoder')
                if os.environ['ENCODER_FIXTURE'] == 'absolute-path-error':
                    issues.append(f".axiom/encoding-manifests/uk/statutes/oversized.json cannot be read safely: encoder apply manifest exceeds byte limit: {root}/.axiom/encoding-manifests/uk/statutes/oversized.json")
            if args.json:
                print(json.dumps({'repo': args.repo, 'passed': not issues, 'issues': issues}))
            else:
                print('\\n'.join(issues) if issues else 'guard fixture accepted')
            sys.exit(1 if issues else 0)
            """))
        supervisor.chmod(0o755)
        cli.chmod(0o755)
        base_protected = root / "base-protected"
        base_protected.mkdir()
        for path in (supervisor, cli):
            destination = base_protected / path.name
            destination.write_bytes(path.read_bytes())
            destination.chmod(0o755)
        shell = shell.replace("/opt/axiom-verification", str(protected)).replace(
            "/opt/axiom-dependency-integrity", str(integrity))
        shell = shell.replace("/opt/axiom-base-verification", str(base_protected))
        for expression, value in (
            ("${{ github.event_name }}", event),
            ("${{ github.event.pull_request.base.sha }}", BASE),
            ("${{ github.event.merge_group.base_sha }}", BASE),
            ("${{ github.event.before }}", ""),
            ("${{ inputs.python-version }}", "3.13"),
        ):
            shell = shell.replace(expression, value)
        assert "${{" not in shell
        result = subprocess.run(["bash", "-c", shell], cwd=workspace, env={
            **os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(root),
            "AXIOM_DEPENDENCY_ROOT": str(dependencies), "GITHUB_SHA": HEAD,
            "RULESPEC_VALIDATION_MODE": mode, "EXPECTED_BASE": BASE,
            "PROPOSED_ENCODER": PROPOSED, "GUARD_CALLS": str(calls),
            "PROTECTED_RUNTIME": str(protected), "ENCODER_FIXTURE": encoder,
            "MODULE": MODULE, "MANIFEST": MANIFEST,
            "DEPENDENCY_PINS_CHANGED": "true" if mode == "full-toolchain-bump" else "false",
            "BASE_RULESPEC_ROOT": str(base_workspace), "BASE_DEPENDENCY_ROOT": str(base_dependencies),
            "BASE_ENCODER": base_pin,
            "INTEGRITY_FAIL_AFTER": str(integrity_fail_after),
        }, capture_output=True, text=True, timeout=30)
        return result, [json.loads(line) for line in calls.read_text().splitlines()]


OFFICIAL_ENCODER = "https://github.com/TheAxiomFoundation/axiom-encode"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                               "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@example.com",
                               "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@example.com"}).stdout.strip()


class BaseEncoderMainRecordTests(unittest.TestCase):
    """The base audit's encoder clone gets the head checkout's official-main fetch record.

    The guard proves a non-pin producer's ancestry against the encoder checkout's FETCH_HEAD (falling back to a
    refs/heads/main the clone doesn't have either). Without the record the base audit can only report that ancestry
    is unprovable, so the head audit's real verdict on an inherited manifest reads as a new issue.
    """

    def setUp(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        run = next(step["run"] for step in steps if step.get("name") == BASE_PREPARATION_STEP)
        start, end = "# base-encoder-main-record-start\n", "# base-encoder-main-record-end\n"
        self.assertEqual((run.count(start), run.count(end)), (1, 1))
        self.fragment = run.split(start, 1)[1].split(end, 1)[0]
        self.assertLess(run.index(end), run.index('add base-encoder "$base_dependencies/axiom-encode" repository'),
                        "the record must be in place before the base encoder's integrity snapshot")
        directory = tempfile.TemporaryDirectory(prefix="encoder-guard-main-record-", dir=TEMP_PARENT)
        self.addCleanup(directory.cleanup)
        self.root = root = Path(directory.name)
        # Official main: an old producer, then the pin, then a newer producer.
        self.origin = root / "origin"
        git(root, "init", "-q", "-b", "main", str(self.origin))
        commits = []
        for message in ("old producer", "pin", "newer producer"):
            git(self.origin, "commit", "-q", "--allow-empty", "-m", message)
            commits.append(git(self.origin, "rev-parse", "HEAD"))
        self.old, self.pin, self.newer = commits
        # The head checkout as the workflow leaves it: detached at the pin after the authenticated fetch of main.
        self.dependencies = root / "dependencies"
        self.head = self.dependencies / "axiom-encode"
        self.head.mkdir(parents=True)
        git(self.head, "init", "-q")
        git(self.head, "fetch", "-q", "--no-tags", str(self.origin), "+refs/heads/main:refs/remotes/origin/main")
        git(self.head, "checkout", "-q", "--detach", self.pin)
        self.head_record = self.head / ".git/FETCH_HEAD"
        # A local fetch records the local path; the runner's fetch records the official URL.
        written = self.head_record.read_text()
        self.assertTrue(written.startswith(f"{self.newer}\t\tbranch 'main' of "), written)
        self.official = f"{self.newer}\t\tbranch 'main' of {OFFICIAL_ENCODER}\n"
        self.head_record.write_text(self.official)
        # The base clone exactly as the loop above the fragment makes it.
        self.base_dependencies = root / "base-dependencies"
        self.base_dependencies.mkdir()
        self.base = self.base_dependencies / "axiom-encode"
        git(root, "-c", "core.hooksPath=/dev/null", "clone", "-q", "--shared", "--no-checkout", str(self.head),
            str(self.base))
        git(self.base, "-c", "core.hooksPath=/dev/null", "checkout", "-q", "--detach", self.pin)
        self.base_record = self.base / ".git/FETCH_HEAD"
        self.tools = root / "tools"
        self.tools.mkdir()
        (self.tools / "python").symlink_to(sys.executable)

    def run_fragment(self):
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + self.fragment], cwd=self.root, env={
            **os.environ, "PATH": str(self.tools) + os.pathsep + os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "AXIOM_DEPENDENCY_ROOT": str(self.dependencies), "base_dependencies": str(self.base_dependencies),
        }, capture_output=True, text=True, timeout=30)

    def first_parent_main(self, repo, record):
        commit = record.read_text().split("\t", 1)[0]
        return git(repo, "rev-list", "--first-parent", commit).splitlines()

    def test_a_local_clone_has_no_main_record_of_its_own(self):
        self.assertFalse(self.base_record.exists())
        self.assertNotEqual(subprocess.run(["git", "-C", str(self.base), "show-ref", "--verify", "--hash",
                                            "refs/heads/main"], capture_output=True).returncode, 0)

    def test_the_base_clone_judges_producers_against_the_same_main(self):
        result = self.run_fragment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.base_record.read_bytes(), self.head_record.read_bytes())
        self.assertEqual(self.first_parent_main(self.base, self.base_record),
                         self.first_parent_main(self.head, self.head_record))
        for producer, is_descendant in ((self.old, False), (self.pin, True), (self.newer, True)):
            for repo in (self.head, self.base):
                with self.subTest(producer=producer, repo=repo.parent.name):
                    ancestry = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", self.pin,
                                               producer], capture_output=True)
                    self.assertEqual(ancestry.returncode, 0 if is_descendant else 1)
        self.assertEqual(git(self.base, "rev-parse", "HEAD"), self.pin)
        self.assertEqual(git(self.base, "status", "--porcelain", "--untracked-files=all", "--ignored"), "")

    def test_the_record_may_carry_a_git_suffix_or_not_for_merge(self):
        for line in (f"{self.newer}\t\tbranch 'main' of {OFFICIAL_ENCODER}.git\n",
                     f"{self.newer}\tnot-for-merge\tbranch 'main' of {OFFICIAL_ENCODER}/\n"):
            with self.subTest(line=line):
                self.base_record.unlink(missing_ok=True)
                self.head_record.write_text(line)
                result = self.run_fragment()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.base_record.read_text(), line)

    def test_anything_but_the_authenticated_official_main_record_is_refused(self):
        other = self.root / "elsewhere"
        other.write_text(self.official)
        cases = {
            "missing": lambda: self.head_record.unlink(),
            "symlink": lambda: (self.head_record.unlink(), self.head_record.symlink_to(other)),
            "another repository": lambda: self.head_record.write_text(
                self.official.replace("axiom-encode", "axiom-encode-fork")),
            "another branch": lambda: self.head_record.write_text(self.official.replace("'main'", "'release'")),
            "not the fetched main commit": lambda: self.head_record.write_text(
                self.official.replace(self.newer, self.old)),
            "two records": lambda: self.head_record.write_text(self.official * 2),
            "oversized": lambda: self.head_record.write_text(self.official + " " * 5000),
        }
        for name, corrupt in cases.items():
            with self.subTest(case=name):
                self.base_record.unlink(missing_ok=True)
                if self.head_record.is_symlink() or not self.head_record.exists():
                    self.head_record.unlink(missing_ok=True)
                self.head_record.write_text(self.official)
                corrupt()
                result = self.run_fragment()
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("ManifestAuditError", result.stderr)
                self.assertFalse(self.base_record.exists() or self.base_record.is_symlink())

    def test_a_record_the_clone_already_has_is_never_overwritten_or_followed(self):
        for name in ("file", "symlink"):
            with self.subTest(existing=name):
                self.base_record.unlink(missing_ok=True)
                target = self.root / "target"
                target.write_text("untouched\n")
                if name == "file":
                    self.base_record.write_text("untouched\n")
                else:
                    self.base_record.symlink_to(target)
                result = self.run_fragment()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_text(), "untouched\n")
                if name == "file":
                    self.assertEqual(self.base_record.read_text(), "untouched\n")


class PinBumpManifestTests(unittest.TestCase):
    def test_pin_only_audits_unchanged_manifests_at_proposed_pin(self):
        # Exact a9987a4b and c326d1ac CLI source both admit guard-generated
        # --all and preserve base-ref processing.
        for encoder in ("rulespec-nz/a9987a4b", "rulespec-uk/c326d1ac"):
            for valid in (True, False):
                with self.subTest(encoder=encoder, valid=valid):
                    result, calls = run_guard(valid=valid, encoder=encoder)
                    self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
                    self.assertEqual(len(calls), 4)
                    self.assertIn("--all", calls[-1]["cli"])
                    self.assertEqual(calls[-1]["encoder_ref"], PROPOSED)
                    if not valid:
                        self.assertIn("stale validation_waiver_set_sha256", result.stderr)

    def test_inherited_unmanifested_legacy_module_is_information(self):
        result, calls = run_guard(scenario="legacy")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Inherited manifest audit issues: 1", result.stdout)
        self.assertEqual(len(calls), 4)

    def test_inherited_stale_waiver_manifest_is_information(self):
        result, _ = run_guard(valid=False, inherited=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Inherited manifest audit issues: 1", result.stdout)

    def test_inherited_jurisdiction_only_manifest_is_information(self):
        result, _ = run_guard(scenario="jurisdiction")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Inherited manifest audit issues: 1", result.stdout)

    def test_new_unmanifested_module_with_pin_change_is_rejected(self):
        result, _ = run_guard(scenario="new-module")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("New manifest audit issues: 1", result.stderr)
        self.assertIn("uk/statutes/new.yaml", result.stderr)

    def test_binding_validator_adoption_preserves_unchanged_encoder_content(self):
        for encoder in ("rulespec-nz/a9987a4b", "rulespec-uk/c326d1ac"):
            with self.subTest(encoder=encoder):
                result, calls = run_guard(scenario="legacy", encoder=encoder, base_pin=PROPOSED)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([call["encoder_ref"] for call in calls if "cli" in call], [PROPOSED, PROPOSED])

    def test_inherited_absolute_checkout_path_error_is_information(self):
        result, _ = run_guard(encoder="absolute-path-error")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Inherited manifest audit issues: 1", result.stdout)

    def test_issue_ratchet_preserves_distinct_relative_paths_and_messages(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        shell = next(step["run"] for step in steps if step.get("name") == "Reject manual RuleSpec changes")
        source = shell.split("<<'PYRATCHET'\n", 1)[1].split("\nPYRATCHET", 1)[0]
        code = compile(source, "manifest-ratchet", "exec")
        repository = "/home/runner/work/rulespec-uk/rulespec-uk"
        dependencies = "/home/runner/work/_temp/dependencies"
        read_error = " cannot be read safely: encoder apply manifest exceeds byte limit: "
        cases = []
        for root, marker, base_root in ((repository, "<repository>", "/audit/base/rulespec-uk"),
                                        (dependencies, "<dependencies>", "/audit/base/dependencies")):
            # One base issue plus two distinct head issues: the root embedded
            # in a relative filename must not become the literal placeholder.
            for prefix in ("uk/statutes/x", "uk/statutes/x ", "uk/statutes/x:"):
                cases.append((prefix + marker + "/foo.yaml: issue",
                              prefix + root + "/foo.yaml: issue"))
            cases.append((marker + "/foo.yaml: issue", root + "/foo.yaml: issue"))
            cases.append(("module.yaml" + read_error + marker + "/foo.yaml",
                          "module.yaml" + read_error + root + "/foo.yaml"))
            cases.append(("module.yaml" + read_error + "relative: " + marker + "/foo.yaml",
                          "module.yaml" + read_error + "relative: " + root + "/foo.yaml"))
            cases.append(("module.yaml" + read_error + "relative: " + base_root + "/foo.yaml",
                          "module.yaml" + read_error + "relative: " + root + "/foo.yaml"))
            cases.append(("module.yaml" + read_error + "relative" + read_error + marker + "/foo.yaml",
                          "module.yaml" + read_error + "relative" + read_error + root + "/foo.yaml"))
        cases.extend((
            ("module.yaml: MissingManifest: issue", "module.yaml: StaleManifest: issue"),
            ("module.yaml: issue detail one", "module.yaml: issue detail two"),
        ))
        with tempfile.TemporaryDirectory(prefix="encoder-guard-ratchet-", dir=TEMP_PARENT) as directory:
            before, after = Path(directory) / "base.json", Path(directory) / "head.json"
            args = ["ratchet", str(before), "1", str(after), "1",
                    "/audit/base/rulespec-uk", repository, "/audit/base/dependencies", dependencies]
            for inherited, added in cases:
                with self.subTest(inherited=inherited, added=added):
                    before.write_text(json.dumps({"passed": False, "issues": [inherited]}))
                    after.write_text(json.dumps({"passed": False, "issues": [inherited, added]}))
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as rejection:
                            exec(code, {"__name__": "__main__"})
                    self.assertEqual(rejection.exception.code, 1)
                    self.assertIn("Inherited manifest audit issues: 1", stdout.getvalue())
                    self.assertIn("New manifest audit issues: 1", stderr.getvalue())
                    if added.startswith("uk/statutes/"):
                        self.assertIn(added, stderr.getvalue())
                    if "relative: " in added:
                        self.assertIn(added.split(read_error, 1)[1], stderr.getvalue())
                    self.assertNotIn("Manifest audit ratchet passed", stdout.getvalue())
            # Checkout relocation changes only actual absolute path fields.
            for base_root, head_root in ((args[5], repository), (args[7], dependencies)):
                for prefix in ("", "module.yaml" + read_error,
                               "module.yaml cannot be read safely: encoder apply manifest is not a regular file: ",
                               "module.yaml cannot be read safely: encoder apply manifest exceeds the 1048576-byte safety limit: ",
                               "module.yaml cannot be read safely: Could not safely open encoder apply manifest: "):
                    with self.subTest(prefix=prefix, root=head_root):
                        before.write_text(json.dumps({"passed": False, "issues": [prefix + base_root + "/foo: bar.yaml"]}))
                        after.write_text(json.dumps({"passed": False, "issues": [prefix + head_root + "/foo: bar.yaml"]}))
                        stdout, stderr = io.StringIO(), io.StringIO()
                        with mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            exec(code, {"__name__": "__main__"})
                        self.assertIn("Inherited manifest audit issues: 1", stdout.getvalue())
                        self.assertIn("Manifest audit ratchet passed: no new issues.", stdout.getvalue())
                        self.assertEqual(stderr.getvalue(), "")

    def test_audit_integrity_failure_prevents_consumption_inside_status_capture(self):
        result, calls = run_guard(integrity_fail_after=2)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [], "integrity failure was masked by guard status capture")

    def test_base_corpus_fetch_integrity_failure_prevents_conditional_consumption(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        preparation = next(step for step in steps if step.get("name") == "Prepare protected-base manifest audit")
        source = preparation["run"].split("base_corpus_fetch() {\n", 1)[1].split("\n}", 1)[0]
        with tempfile.TemporaryDirectory(prefix="encoder-guard-base-fetch-", dir=TEMP_PARENT) as directory:
            root = Path(directory)
            integrity = root / "integrity"
            integrity.mkdir()
            (integrity / "check.py").write_text('raise SystemExit("DependencyIntegrityError: fixture drift")\n')
            runtime = root / "runtime/python/bin"
            runtime.mkdir(parents=True)
            marker = root / "consumed"
            executable = runtime / "python3.13"
            executable.write_text(f"#!{sys.executable} -I\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n")
            executable.chmod(0o755)
            tools = root / "tools"
            tools.mkdir()
            (tools / "python").symlink_to(sys.executable)
            source = source.replace("/opt/axiom-dependency-integrity", str(integrity))
            source = source.replace("/opt/axiom-base-verification", str(root / "runtime"))
            source = source.replace("${{ inputs.python-version }}", "3.13")
            for invocation in ("if base_corpus_fetch corpus-fetch; then exit 0; else exit $?; fi",
                               "if ! base_corpus_fetch corpus-fetch --help; then exit 1; fi"):
                with self.subTest(invocation=invocation):
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n" + invocation],
                                            env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")},
                                            capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("DependencyIntegrityError", result.stderr)
                    self.assertFalse(marker.exists(), "integrity failure was masked by conditional corpus-fetch")

    def test_base_corpus_fetch_runs_the_console_entry_point_and_keeps_its_status(self):
        """corpus-fetch lives in axiom_encode.entrypoint, not axiom_encode.cli.

        Encoders since axiom-encode#1742 dispatch corpus-fetch in the console
        script's target and delegate everything else to axiom_encode.cli,
        whose parser rejects corpus-fetch. Run the real function against a
        stand-in runtime whose modules mirror that split.
        """
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        preparation = next(step for step in steps if step.get("name") == "Prepare protected-base manifest audit")
        source = preparation["run"].split("base_corpus_fetch() {\n", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("axiom_encode.cli", source)
        with tempfile.TemporaryDirectory(prefix="encoder-guard-base-fetch-", dir=TEMP_PARENT) as directory:
            root = Path(directory)
            integrity = root / "integrity"
            integrity.mkdir()
            (integrity / "check.py").write_text("")
            package = root / "stub/axiom_encode"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("")
            (package / "cli.py").write_text(
                "import sys\n"
                "def main():\n"
                "    if sys.argv[1:2] == ['corpus-fetch']:\n"
                "        raise SystemExit(\"invalid choice: 'corpus-fetch'\")\n"
                "    return 0\n"
            )
            (package / "entrypoint.py").write_text(
                "import sys\n"
                "def main():\n"
                "    argv = sys.argv[1:]\n"
                "    if argv[:1] == ['corpus-fetch']:\n"
                "        if '--help' in argv:\n"
                "            print('usage: axiom-encode corpus-fetch')\n"
                "            return 0\n"
                "        return int(argv[argv.index('--fixture-status') + 1])\n"
                "    from axiom_encode.cli import main as cli_main\n"
                "    return cli_main()\n"
            )
            runtime = root / "runtime/python/bin"
            runtime.mkdir(parents=True)
            # The sealed runtime's interpreter, run exactly as the step does.
            executable = runtime / "python3.13"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "args = sys.argv[1:]\n"
                "assert args[:3] == ['-I', '-B', '-c'], args\n"
                "code = args[3]\n"
                "sys.argv = ['-c', *args[4:]]\n"
                f"sys.path.insert(0, {str(root / 'stub')!r})\n"
                "exec(compile(code, '<string>', 'exec'), {'__name__': '__main__'})\n"
            )
            executable.chmod(0o755)
            tools = root / "tools"
            tools.mkdir()
            (tools / "python").symlink_to(sys.executable)
            source = source.replace("/opt/axiom-dependency-integrity", str(integrity))
            source = source.replace("/opt/axiom-base-verification", str(root / "runtime"))
            source = source.replace("${{ inputs.python-version }}", "3.13")
            for invocation, status in (
                ("base_corpus_fetch corpus-fetch --help", 0),
                ("base_corpus_fetch corpus-fetch --corpus-path corpus --fixture-status 0", 0),
                ("base_corpus_fetch corpus-fetch --corpus-path corpus --fixture-status 3", 3),
                ("if base_corpus_fetch corpus-fetch --fixture-status 5; then exit 0; else exit $?; fi", 5),
            ):
                with self.subTest(invocation=invocation):
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n" + invocation],
                                            env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")},
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
            # The protected-base step's capability probe passes for such an encoder.
            probe = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n"
                                    "if ! base_corpus_fetch corpus-fetch --help >/dev/null 2>&1; then exit 1; fi"],
                                   env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")},
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)

    def test_merge_group_audit_uses_protected_base_instead_of_first_parent(self):
        result, calls = run_guard(event="merge_group", scenario="legacy")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = [call["cli"] for call in calls if "cli" in call]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(command[command.index("--base-ref") + 1], BASE)
        self.assertEqual(commands[0][commands[0].index("--head-ref") + 1], BASE)
        self.assertEqual(commands[1][commands[1].index("--head-ref") + 1], HEAD)

    def test_other_validation_modes_preserve_changed_manifest_behavior(self):
        for mode in ("changed", "changed-corpus-toolchain-bump", "full-push"):
            with self.subTest(mode=mode):
                result, calls = run_guard(mode=mode, valid=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("--all", calls[-1]["cli"])
                args = calls[-1]["cli"]
                self.assertEqual(args[args.index("--base-ref") + 1], BASE)
                self.assertEqual(args[args.index("--head-ref") + 1], HEAD)

    def test_selection_precedes_manifest_guard_and_module_validation(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        names = [step.get("name") for step in steps]
        selection = names.index("Select RuleSpec validation targets")
        guard = names.index("Reject manual RuleSpec changes")
        validation = names.index("Validate RuleSpec YAML")
        self.assertLess(selection, guard)
        self.assertLess(guard, validation)

    def test_protected_base_audit_preparation_uses_bound_base_refs(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        steps = workflow["jobs"]["validate"]["steps"]
        preparation = next(step for step in steps if step.get("name") == "Prepare protected-base manifest audit")
        self.assertIn("dependency_pins_changed == 'true'", preparation["if"])
        self.assertEqual(preparation["working-directory"], "${{ runner.temp }}")
        self.assertEqual(preparation["env"]["BASE_ENCODER_REF"], "${{ needs.shards.outputs.base_axiom_encode_ref }}")
        self.assertEqual(preparation["env"]["BASE_CORPUS_REF"], "${{ needs.shards.outputs.base_axiom_corpus_ref }}")
        source = preparation["run"]
        for fragment in ('checkout --detach "$BASE_SHA"', 'axiom-encode:$BASE_ENCODER_REF',
                         'axiom-corpus:$BASE_CORPUS_REF', '--require-hashes --no-deps -r "$locked"',
                         'base-encoder "$base_dependencies/axiom-encode" repository',
                         'base-corpus "$base_dependencies/axiom-corpus" repository',
                         'base-verification-runtime /opt/axiom-base-verification runtime'):
            self.assertIn(fragment, source)
        self.assertLess(steps.index(preparation), next(i for i, step in enumerate(steps)
                       if step.get("name") == "Reject manual RuleSpec changes"))

    def test_issue_ratchet_accepts_exactly_head_subsets_and_rejects_invalid_results(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        shell = next(step["run"] for step in steps if step.get("name") == "Reject manual RuleSpec changes")
        self.assertIn("<<'PYRATCHET'", shell)
        source = shell.split("<<'PYRATCHET'\n", 1)[1].split("\nPYRATCHET", 1)[0]
        code = compile(source, "manifest-ratchet", "exec")
        with tempfile.TemporaryDirectory(prefix="encoder-guard-ratchet-", dir=TEMP_PARENT) as directory:
            before, after = Path(directory) / "base.json", Path(directory) / "head.json"
            def check(base, head, base_status=None, head_status=None):
                before.write_text(json.dumps(base))
                after.write_text(json.dumps(head))
                args = ["ratchet", str(before), str(int(not base["passed"])) if base_status is None else base_status,
                        str(after), str(int(not head["passed"])) if head_status is None else head_status,
                        "base/repository", "head/repository", "base/dependencies", "head/dependencies"]
                with mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        exec(code, {"__name__": "__main__"})
                    except SystemExit as exc:
                        return exc.code
                return 0
            for base_bits in range(8):
                for head_bits in range(8):
                    base = {f"relative/module-{i}.yaml: issue" for i in range(3) if base_bits & (1 << i)}
                    head = {f"relative/module-{i}.yaml: issue" for i in range(3) if head_bits & (1 << i)}
                    with self.subTest(base=base_bits, head=head_bits):
                        self.assertEqual(check({"passed": not base, "issues": sorted(base)},
                                               {"passed": not head, "issues": sorted(head)}), 0 if head <= base else 1)
            accepted = {"passed": True, "issues": []}
            for invalid, status in (({"passed": True, "issues": ["issue"]}, "0"),
                                    ({"passed": False, "issues": []}, "1"),
                                    ({"passed": False, "issues": [42]}, "1"),
                                    ({"passed": False, "issues": [""]}, "1"),
                                    (accepted, "2"), (accepted, "1")):
                self.assertNotEqual(check(invalid, accepted, base_status=status), 0)
                self.assertNotEqual(check(accepted, invalid, head_status=status), 0)


if __name__ == "__main__":
    unittest.main()
