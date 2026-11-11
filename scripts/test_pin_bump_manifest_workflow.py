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
PRE1883_FIX = "b5e85ab4135be6ed4acaf2b2cd2b783648af2f6e"
PRE1883_BUG = "630aa73931e5aa87c51d25fe448e38dbcfaed50f"
PRE1883_IDENTITY_ISSUE = (
    "Cannot verify the running pinned encoder identity: "
    "encoder Git metadata is unavailable: git rev-parse failed"
)


def workflow_steps():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]


def step_source(name):
    return next(step["run"] for step in workflow_steps() if step.get("name") == name)


def marked_source(source, name):
    start, end = f"# {name}-start\n", f"# {name}-end\n"
    assert (source.count(start), source.count(end)) == (1, 1), name
    return source.split(start, 1)[1].split(end, 1)[0]


def heredoc(source, label):
    return source.split(f"<<'{label}'", 1)[1].split("\n", 1)[1].split("\n" + label, 1)[0]


def run_guard(*, mode="full-toolchain-bump", valid=True, encoder="fixture",
              inherited=False, scenario="manifest", base_pin="a" * 40,
              integrity_fail_after=0, event="pull_request", base_ancestry=0, head_ancestry=0,
              base_bug_ancestry=0, pin_direction=0,
              audit_results=None, bridge_predicate_status=0):
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
        if bridge_predicate_status:
            python = tools / "python"
            python.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
                import os
                import sys
                args = sys.argv[1:]
                if args[:2] == ['-I', '-']:
                    source = sys.stdin.read()
                    if 'expected = "Cannot verify the running pinned encoder identity:' in source:
                        sys.exit(int(os.environ['BRIDGE_PREDICATE_STATUS']))
                    sys.argv = ['-', *args[2:]]
                    exec(compile(source, '<stdin>', 'exec'), {'__name__': '__main__'})
                else:
                    os.execv(sys.executable, [sys.executable, *args])
                """))
            python.chmod(0o755)
        else:
            (tools / "python").symlink_to(sys.executable)
        git_command = tools / "git"
        git_command.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import os
            import sys
            args = sys.argv[1:]
            if args == ['rev-parse', '--verify', 'HEAD~1^{commit}']:
                # The protected queue base must win over this unrelated parent.
                print('c' * 40)
            else:
                assert args[0] == '-C', args
                is_base = args[1] == os.environ['BASE_DEPENDENCY_ROOT'] + '/axiom-encode'
                expected = os.environ['BASE_ENCODER_REF' if is_base else 'HEAD_ENCODER_REF']
                if not is_base and args[2:] == ['merge-base', '--is-ancestor',
                                                os.environ['BASE_ENCODER_REF'], expected]:
                    # The producer-carry gate asks whether the pin moves forward.
                    sys.exit(int(os.environ['PIN_DIRECTION']))
                # Only the base checks for the #1859 commit; both sides check #1883.
                commits = [os.environ['PRE1883_FIX']] + ([os.environ['PRE1883_BUG']] if is_base else [])
                assert args[2:4] == ['merge-base', '--is-ancestor'] and args[4] in commits, args
                assert args[5:] == [expected], args
                if args[4] == os.environ['PRE1883_BUG']:
                    sys.exit(int(os.environ['BASE_BUG_ANCESTRY']))
                sys.exit(int(os.environ['BASE_ANCESTRY' if is_base else 'HEAD_ANCESTRY']))
            """))
        git_command.chmod(0o755)
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
            for name in ('repo', 'base-ref', 'head-ref', 'corpus-path'):
                parser.add_argument('--' + name, required=True)
            parser.add_argument('--expected-encoder-checkout')
            parser.add_argument('--all', action='store_true')
            parser.add_argument('--json', action='store_true')
            args = parser.parse_args(argv[1:])
            assert args.base_ref == os.environ['EXPECTED_BASE']
            is_base = args.repo == os.environ['BASE_RULESPEC_ROOT']
            assert args.head_ref == (os.environ['EXPECTED_BASE'] if is_base else os.environ['GITHUB_SHA'])
            dependency_root = os.environ['BASE_DEPENDENCY_ROOT' if is_base else 'AXIOM_DEPENDENCY_ROOT']
            expected_checkout = dependency_root + '/axiom-encode'
            if args.expected_encoder_checkout is None:
                assert is_base, 'the head audit must always use its checkout identity'
                assert os.environ['AUDIT_RESULTS'] != 'null', 'unexpected attestation bridge'
            else:
                assert args.expected_encoder_checkout == expected_checkout
            pin = (Path(expected_checkout) / 'pin').read_text()
            assert pin == os.environ['BASE_ENCODER' if is_base else 'PROPOSED_ENCODER']
            assert args.corpus_path == os.environ['BASE_DEPENDENCY_ROOT' if is_base else 'AXIOM_DEPENDENCY_ROOT'] + '/axiom-corpus'
            with open(os.environ['GUARD_CALLS'], 'a') as log:
                log.write(json.dumps({'cli': argv, 'encoder_ref': pin,
                                      'encoder_fixture': os.environ['ENCODER_FIXTURE']}) + '\\n')
            fixture = json.loads(os.environ['AUDIT_RESULTS'])
            if fixture is not None:
                phase = ('bridge' if args.expected_encoder_checkout is None else 'base') if is_base else 'head'
                report = fixture[phase]
                print(report['raw'] if 'raw' in report else json.dumps(report['payload']))
                sys.exit(report['status'])
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
            "BASE_ENCODER": base_pin, "BASE_ENCODER_REF": base_pin, "HEAD_ENCODER_REF": PROPOSED,
            "PRE1883_FIX": PRE1883_FIX, "BASE_ANCESTRY": str(base_ancestry),
            "PRE1883_BUG": PRE1883_BUG, "BASE_BUG_ANCESTRY": str(base_bug_ancestry),
            "HEAD_ANCESTRY": str(head_ancestry), "PIN_DIRECTION": str(pin_direction),
            "AUDIT_RESULTS": json.dumps(audit_results),
            "BRIDGE_PREDICATE_STATUS": str(bridge_predicate_status),
            "INTEGRITY_FAIL_AFTER": str(integrity_fail_after),
        }, capture_output=True, text=True, timeout=120)
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
            # The step passes the Python version through env, so its script
            # carries no expression.
            self.assertEqual(preparation["env"]["PYTHON_VERSION"], "${{ inputs.python-version }}")
            self.assertNotIn("${{", source)
            for invocation in ("if base_corpus_fetch corpus-fetch; then exit 0; else exit $?; fi",
                               "if ! base_corpus_fetch corpus-fetch --help; then exit 1; fi"):
                with self.subTest(invocation=invocation):
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n" + invocation],
                                            env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                                                 "PYTHON_VERSION": "3.13"},
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
            # The step passes the Python version through env, so its script
            # carries no expression.
            self.assertEqual(preparation["env"]["PYTHON_VERSION"], "${{ inputs.python-version }}")
            self.assertNotIn("${{", source)
            for invocation, status in (
                ("base_corpus_fetch corpus-fetch --help", 0),
                ("base_corpus_fetch corpus-fetch --corpus-path corpus --fixture-status 0", 0),
                ("base_corpus_fetch corpus-fetch --corpus-path corpus --fixture-status 3", 3),
                ("if base_corpus_fetch corpus-fetch --fixture-status 5; then exit 0; else exit $?; fi", 5),
            ):
                with self.subTest(invocation=invocation):
                    result = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n" + invocation],
                                            env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                                                 "PYTHON_VERSION": "3.13"},
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
            # The protected-base step's capability probe passes for such an encoder.
            probe = subprocess.run(["bash", "-c", "set -euo pipefail\nbase_corpus_fetch() {\n" + source + "\n}\n"
                                    "if ! base_corpus_fetch corpus-fetch --help >/dev/null 2>&1; then exit 1; fi"],
                                   env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                                        "PYTHON_VERSION": "3.13"},
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


class ProducerRefusalCarryTests(unittest.TestCase):
    """A forward pin change carries the base pin's own producer verdicts only."""

    BASE_PIN = "c" * 40
    HEAD_PIN = "d" * 40
    PATH = ".axiom/encoding-manifests/zm/statutes/act-2018-2/national-health-insurance-act-2018.json"
    FIELD = " validation_execution.axiom_encode"
    EXACT = " does not match the running pinned encoder"
    ANCESTRY = EXACT + ": the pinned encoder commit is not an ancestor of the producer"
    GIT_ONLY_CONTRACTS = ("reviewed candidate promotion", "exact dependent migration",
                          "retained successor migration", "legacy replacement",
                          "path migration", "retirement")

    def setUp(self):
        shell = step_source("Reject manual RuleSpec changes")
        self.code = compile(heredoc(shell, "PYRATCHET"), "manifest-ratchet", "exec")
        directory = tempfile.TemporaryDirectory(prefix="encoder-guard-carry-", dir=TEMP_PARENT)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.base_root, self.head_root = self.root / "base", self.root / "head"

    def manifest(self, producer=None, execution=None):
        producer = self.BASE_PIN if producer is None else producer
        execution = producer if execution is None else execution
        return json.dumps({"schema_version": "fixture", "axiom_encode_git": {"commit": producer},
                           "validation_execution": {"axiom_encode": {"commit": execution}}}).encode()

    def git_only_manifest(self, producer=None, dirty=False):
        producer = self.BASE_PIN if producer is None else producer
        return json.dumps({"schema_version": "fixture", "tool": "fixture",
                           "axiom_encode_git": {"commit": producer, "dirty_tracked": dirty}}).encode()

    def write(self, root, data, path=None):
        target = root / (self.PATH if path is None else path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def write_both(self, data, path=None):
        for root in (self.base_root, self.head_root):
            self.write(root, data, path)

    def reset_trees(self):
        for root in (self.base_root, self.head_root):
            if root.exists() or root.is_symlink():
                subprocess.run(["rm", "-rf", str(root)], check=True)

    def ratchet(self, base, head, *, base_pin=None, older_wording=True, base_pin_produced=True,
                summary=None):
        base_pin = self.BASE_PIN if base_pin is None else base_pin
        before, after = self.root / "base.json", self.root / "head.json"
        before.write_text(json.dumps({"passed": not base, "issues": base}))
        after.write_text(json.dumps({"passed": not head, "issues": head}))
        args = ["ratchet", str(before), str(int(bool(base))), str(after), str(int(bool(head))),
                str(self.base_root), str(self.head_root), str(self.root / "base-deps"), str(self.root / "head-deps")]
        drop = {"BASE_ENCODER_REF", "PRODUCER_CARRY_OLDER_WORDING", "PRODUCER_CARRY_BASE_PIN",
                "GITHUB_STEP_SUMMARY"}
        env = {k: v for k, v in os.environ.items() if k not in drop}
        if base_pin is not False:
            env["BASE_ENCODER_REF"] = base_pin
        env["PRODUCER_CARRY_OLDER_WORDING"] = "true" if older_wording else "false"
        env["PRODUCER_CARRY_BASE_PIN"] = "true" if base_pin_produced else "false"
        if summary is not None:
            env["GITHUB_STEP_SUMMARY"] = str(summary)
        stdout, stderr = io.StringIO(), io.StringIO()
        status = 0
        with mock.patch.object(sys, "argv", args), mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                exec(self.code, {"__name__": "__main__"})
            except SystemExit as exc:
                status = exc.code
        return status, stdout.getvalue(), stderr.getvalue()

    def refusal(self, path=None, field=None):
        return (self.PATH if path is None else path) + (self.FIELD if field is None else field) + self.ANCESTRY

    def older(self, path=None, field=None):
        return (self.PATH if path is None else path) + (self.FIELD if field is None else field) + self.EXACT

    def carry_block(self):
        source = marked_source(heredoc(step_source("Reject manual RuleSpec changes"), "PYRATCHET"),
                               "producer-refusal-carry")
        namespace = {"json": json, "os": os, "Path": Path, "re": __import__("re")}
        exec(compile(textwrap.dedent(source), "producer-refusal-carry", "exec"), namespace)
        return namespace

    def assert_new(self, result, label=""):
        status, stdout, stderr = result
        self.assertEqual(status, 1, label + stdout + stderr)
        self.assertNotIn("Producer refusals carried", stdout, label)
        self.assertNotIn("Traceback", stderr, label)

    def test_manifest_the_base_pin_produced_carries_when_unchanged(self):
        self.write_both(self.manifest())
        status, stdout, stderr = self.ratchet([], [self.refusal()])
        self.assertEqual(status, 0, stdout + stderr)
        self.assertIn("Producer refusals carried from the base pin: 1 (information)", stdout)
        self.assertIn("the base pin produced it", stdout)
        self.assertIn("Manifest audit ratchet passed: no new issues.", stdout)

    def test_older_wording_carries_when_unchanged(self):
        self.write_both(self.manifest(producer="f" * 40))
        status, stdout, stderr = self.ratchet([self.older()], [self.refusal()])
        self.assertEqual(status, 0, stdout + stderr)
        self.assertIn("the base refused it in the older wording", stdout)

    def test_git_only_contracts_carry_from_axiom_encode_git(self):
        for contract in self.GIT_ONLY_CONTRACTS:
            field = " " + contract
            with self.subTest(contract=contract, path="base pin"):
                self.reset_trees()
                self.write_both(self.git_only_manifest())
                status, stdout, stderr = self.ratchet([], [self.refusal(field=field)])
                self.assertEqual(status, 0, contract + stdout + stderr)
                self.assertIn("the base pin produced it", stdout)
            with self.subTest(contract=contract, path="older wording"):
                self.reset_trees()
                self.write_both(self.git_only_manifest(producer="f" * 40))
                status, stdout, stderr = self.ratchet([self.older(field=field)], [self.refusal(field=field)])
                self.assertEqual(status, 0, contract + stdout + stderr)
                self.assertIn("the base refused it in the older wording", stdout)
            for label, data in (("dirty producer", self.git_only_manifest(dirty=True)),
                                ("dirty flag missing", json.dumps({"axiom_encode_git": {"commit": self.BASE_PIN}}).encode()),
                                ("newer producer", self.git_only_manifest(producer="f" * 40))):
                with self.subTest(contract=contract, label=label):
                    self.reset_trees()
                    self.write_both(data)
                    self.assert_new(self.ratchet([], [self.refusal(field=field)]), label)

    def test_gate_flags_switch_each_path(self):
        self.write_both(self.manifest())
        self.assert_new(self.ratchet([], [self.refusal()], base_pin_produced=False), "base pin path off")
        status, stdout, _ = self.ratchet([], [self.refusal()], older_wording=False)
        self.assertEqual(status, 0, stdout)
        self.reset_trees()
        self.write_both(self.manifest(producer="f" * 40))
        self.assert_new(self.ratchet([self.older()], [self.refusal()], older_wording=False), "older path off")
        status, stdout, _ = self.ratchet([self.older()], [self.refusal()], base_pin_produced=False)
        self.assertEqual(status, 0, stdout)

    def test_refusals_without_the_base_pin_evidence_stay_new(self):
        nested = b'{"axiom_encode_git": ' + b"[" * 100000 + b"]" * 100000 + b"}"
        duplicate = ('{"axiom_encode_git": {"commit": "%s"}, "axiom_encode_git": {"commit": "%s"}, '
                     '"validation_execution": {"axiom_encode": {"commit": "%s"}}}'
                     % ("f" * 40, self.BASE_PIN, self.BASE_PIN)).encode()
        cases = {
            "producer newer than the base pin": (self.manifest(producer="f" * 40), None, []),
            "fields disagree": (self.manifest(execution="f" * 40), None, []),
            "producer block missing": (json.dumps({"validation_execution": {"axiom_encode": {"commit": self.BASE_PIN}}}).encode(), None, []),
            "not JSON": (b"not json", None, []),
            "JSON list": (b"[]", None, []),
            "deeply nested JSON": (nested, None, []),
            "duplicate keys": (duplicate, None, []),
            "no base pin": (self.manifest(), False, []),
            "malformed base pin": (self.manifest(), self.BASE_PIN[:39], []),
            "upper-case base pin": (self.manifest(producer="C" * 40), "C" * 40, []),
            "base pin with a newline": (self.manifest(producer=self.BASE_PIN + "\n"), self.BASE_PIN + "\n", []),
            "empty base pin and producer": (self.manifest(producer=""), "", []),
            "short base pin and producer": (self.manifest(producer="c" * 39), "c" * 39, []),
            "older wording for a different field": (self.manifest(producer="f" * 40), None,
                                                    [self.older(field=" retirement")]),
            "older wording for a different manifest": (self.manifest(producer="f" * 40), None,
                                                       [self.older(path=self.PATH.replace("act-2018-2", "act-2018-3"))]),
        }
        for label, (data, base_pin, base_issues) in cases.items():
            with self.subTest(label):
                self.write_both(data)
                result = self.ratchet(base_issues, [self.refusal()], base_pin=base_pin)
                self.assert_new(result, label)
                self.assertIn("New manifest audit issues: 1", result[2])

    def test_changed_missing_or_linked_manifests_stay_new_on_both_paths(self):
        for path_name, data, base_issues in (("base pin", self.manifest(), []),
                                             ("older wording", self.manifest(producer="f" * 40), [self.older()])):
            for label in ("changed", "missing at base", "missing at head", "symlink at head",
                          "symlink at base", "symlinked directory"):
                with self.subTest(path=path_name, label=label):
                    self.reset_trees()
                    if label not in ("missing at base", "symlink at base"):
                        self.write(self.base_root, data)
                    if label == "changed":
                        self.write(self.head_root, data + b"\n")
                    elif label in ("symlink at head", "symlink at base"):
                        target = self.write(self.root / ("elsewhere-" + label.split()[-1]), data)
                        link = (self.head_root if label.endswith("head") else self.base_root) / self.PATH
                        link.parent.mkdir(parents=True, exist_ok=True)
                        link.symlink_to(target)
                        if label.endswith("base"):
                            self.write(self.head_root, data)
                    elif label == "symlinked directory":
                        real = self.root / "real-manifests"
                        self.write(real, data, path=self.PATH.split("/", 2)[2])
                        (self.head_root / ".axiom").mkdir(parents=True, exist_ok=True)
                        (self.head_root / ".axiom/encoding-manifests").symlink_to(real)
                    elif label != "missing at head":
                        self.write(self.head_root, data)
                    self.assert_new(self.ratchet(base_issues, [self.refusal()]), path_name + " " + label)

    def test_only_exact_producer_refusals_under_the_manifest_tree_carry(self):
        produced = self.manifest()
        self.write_both(produced)
        self.write_both(produced, path="zm/statutes/act.json")
        # A traversal that resolves to the real manifest must not carry.
        self.write_both(produced, path="escape/" + self.PATH)
        self.write_both(produced, path=".axiom/encoding-manifests/zm/statutes/act.yaml")
        for issue in (
            self.refusal() + " ",
            self.refusal() + "; also stale",
            self.PATH + self.FIELD + self.EXACT + ": producer identity is malformed",
            self.PATH + self.FIELD + self.EXACT,
            self.PATH + self.ANCESTRY,
            self.PATH + " source_attestation" + self.ANCESTRY,
            self.PATH + " has invalid fields; validation_execution.axiom_encode" + self.ANCESTRY,
            "zm/statutes/act.json" + self.FIELD + self.ANCESTRY,
            ".axiom/encoding-manifests/zm/statutes/act.yaml" + self.FIELD + self.ANCESTRY,
            ".axiom/encoding-manifests/../" + self.PATH + self.FIELD + self.ANCESTRY,
            ".axiom/encoding-manifests/../../" + self.PATH + self.FIELD + self.ANCESTRY,
            ".axiom/encoding-manifests/../../escape/" + self.PATH + self.FIELD + self.ANCESTRY,
            self.PATH + " has invalid source_attestation: bad root",
            str(self.head_root) + "/" + self.PATH + self.FIELD + self.ANCESTRY,
        ):
            with self.subTest(issue=issue):
                self.assert_new(self.ratchet([], [issue]), issue)

    def test_carry_functions_refuse_unsafe_paths_and_keys(self):
        carry = self.carry_block()
        self.write_both(self.manifest())
        for relative in ("", ".axiom//encoding-manifests/x.json", "./" + self.PATH, self.PATH + "/.",
                         ".axiom/encoding-manifests/../" + self.PATH.split("/", 1)[1],
                         "../" + self.head_root.name + "/" + self.PATH):
            with self.subTest(relative=relative):
                self.assertIsNone(carry["manifest_bytes"](self.head_root, relative))
        self.assertEqual(carry["manifest_bytes"](self.head_root, self.PATH), self.manifest())
        literal = ("literal", self.refusal())
        args = (set(), self.base_root, self.head_root, self.BASE_PIN, True, True)
        self.assertEqual(carry["carried_refusal"]((literal,), *args), "the base pin produced it")
        for key in ((literal, literal), (("repository", self.refusal()),), (literal, ("literal", "x")), ()):
            with self.subTest(key=key):
                self.assertIsNone(carry["carried_refusal"](key, *args))
        self.assertEqual(set(carry["CONTRACTS"]), {"validation_execution.axiom_encode", *self.GIT_ONLY_CONTRACTS})

    def test_other_head_issues_for_a_carried_manifest_still_fail(self):
        self.write_both(self.manifest())
        other = self.PATH + " source_attestation cannot be resolved from the signed local corpus release"
        status, stdout, stderr = self.ratchet([], [self.refusal(), other])
        self.assertEqual(status, 1)
        self.assertIn("Producer refusals carried from the base pin: 1 (information)", stdout)
        self.assertIn("New manifest audit issues: 1", stderr)
        self.assertIn("source_attestation", stderr)

    def test_carried_refusals_reach_the_step_summary(self):
        self.write_both(self.manifest())
        summary = self.root / "summary.md"
        status, stdout, stderr = self.ratchet([], [self.refusal()], summary=summary)
        self.assertEqual(status, 0, stdout + stderr)
        text = summary.read_text()
        self.assertIn("### Producer refusals carried from the base pin: 1", text)
        self.assertIn(self.refusal() + " (the base pin produced it)", text)
        status, stdout, _ = self.ratchet([], [self.refusal()], summary=self.root / "missing-dir" / "summary.md")
        self.assertEqual(status, 0, stdout)
        self.assertIn("::warning::Could not write the carried refusals", stdout)

    def test_carry_code_sits_in_the_ratchet_once(self):
        shell = step_source("Reject manual RuleSpec changes")
        self.assertIn("producer-refusal-carry-start", heredoc(shell, "PYRATCHET"))
        for step in workflow_steps():
            if step.get("name") != "Reject manual RuleSpec changes":
                self.assertNotIn("producer-refusal-carry-start", step.get("run", ""))
                self.assertNotIn("producer-carry-gate-start", step.get("run", ""))
        self.assertEqual(shell.count("producer-refusal-carry-start"), 1)
        self.assertEqual(shell.count("producer-carry-gate-start"), 1)
        self.assertLess(shell.index("producer-carry-gate-end"), shell.index("<<'PYRATCHET'"))


class ProducerCarryGateTests(unittest.TestCase):
    """The shell gate enables each carry path from real Git ancestry."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="encoder-guard-carry-gate-", dir=TEMP_PARENT)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        repo = self.root / "deps" / "axiom-encode"
        repo.mkdir(parents=True)
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(self.root),
               "PATH": os.environ.get("PATH", ""), "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.env = env

        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                                  text=True, env=env).stdout.strip()

        git("init", "-q", "-b", "main")
        commits = {}
        for name in ("old", "fix1859", "new", "newer"):
            git("commit", "-q", "--allow-empty", "-m", name)
            commits[name] = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "side", commits["old"])
        git("commit", "-q", "--allow-empty", "-m", "side")
        commits["side"] = git("rev-parse", "HEAD")
        self.commits = commits
        source = marked_source(step_source("Reject manual RuleSpec changes"), "producer-carry-gate")
        self.assertEqual(source.count("630aa73931e5aa87c51d25fe448e38dbcfaed50f"), 1)
        self.gate = textwrap.dedent(source).replace("630aa73931e5aa87c51d25fe448e38dbcfaed50f", commits["fix1859"])

    def run_gate(self, base, head):
        script = ("set -euo pipefail\n" + self.gate +
                  'printf "%s %s\\n" "$PRODUCER_CARRY_OLDER_WORDING" "$PRODUCER_CARRY_BASE_PIN"\n')
        deps = str(self.root / "deps")
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, env={
            **self.env, "BASE_DEPENDENCY_ROOT": deps, "AXIOM_DEPENDENCY_ROOT": deps,
            "BASE_ENCODER_REF": base, "HEAD_ENCODER_REF": head})

    def test_paths_follow_pin_direction_and_base_ancestry(self):
        c = self.commits
        for label, base, head, expected in (
            ("forward from a pre-#1859 base", c["old"], c["new"], "true true"),
            ("forward from the #1859 commit", c["fix1859"], c["new"], "true false"),
            ("forward from a later base", c["new"], c["newer"], "true false"),
            ("backward", c["newer"], c["old"], "false false"),
            ("unchanged pin", c["new"], c["new"], "false false"),
            ("sideways from a pre-#1859 base", c["side"], c["new"], "false false"),
        ):
            with self.subTest(label):
                result = self.run_gate(base, head)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected, label)

    def test_unknown_commits_fail_the_step(self):
        result = self.run_gate("f" * 40, self.commits["new"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("ManifestAuditError: encoder pin direction check failed (status 128)", result.stderr)
        result = self.run_gate(self.commits["old"], "f" * 40)
        self.assertEqual(result.returncode, 1)
        self.assertIn("encoder pin direction check failed", result.stderr)


def audit_report(issues, *, status=None):
    return {"payload": {"passed": not issues, "issues": issues},
            "status": int(bool(issues)) if status is None else status}


class Pre1883ManifestBridgeTests(unittest.TestCase):
    """The old encoder supplies base verdicts; only the normal ratchet admits them."""

    @staticmethod
    def reports(base=None, bridge=None, head=None):
        return {"base": audit_report([PRE1883_IDENTITY_ISSUE] if base is None else base),
                "bridge": audit_report([] if bridge is None else bridge),
                "head": audit_report([] if head is None else head)}

    def test_live_shape_inherits_all_18_v1_manifest_issues(self):
        issues = [f".axiom/encoding-manifests/il/statutes/bootstrap-{i}.json is not an encoder apply manifest"
                  for i in range(18)]
        result, calls = run_guard(base_ancestry=1, head_ancestry=0,
                                  audit_results=self.reports(bridge=issues, head=issues))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Inherited manifest audit issues: 18", result.stdout)
        self.assertIn("Manifest audit ratchet passed: no new issues.", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.count("used the pre-#1883 attestation bridge"), 1)
        commands = [call["cli"] for call in calls if "cli" in call]
        self.assertEqual(len(commands), 3)
        original, retry, head = commands
        expected_index = original.index("--expected-encoder-checkout")
        self.assertEqual(retry, original[:expected_index] + original[expected_index + 2:])
        self.assertIn("--expected-encoder-checkout", head)
        supervisors = [call["supervisor"] for call in calls if "supervisor" in call]
        self.assertEqual(supervisors[0][:supervisors[0].index("--") + 2],
                         supervisors[1][:supervisors[1].index("--") + 2])

    def test_only_pre_base_to_post_head_may_bridge(self):
        # Both-pre is the validator-only repin that passes today on the inherited
        # identity key. Both-post and post-to-pre must preserve that same path.
        for base, head in ((1, 1), (0, 0), (0, 1)):
            with self.subTest(base_contains=base, head_contains=head):
                result, calls = run_guard(base_ancestry=base, head_ancestry=head,
                                          base_pin=PROPOSED if base == head == 1 else BASE,
                                          audit_results=self.reports(head=[PRE1883_IDENTITY_ISSUE]))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Inherited manifest audit issues: 1", result.stdout)
                self.assertNotIn("attestation bridge", result.stdout)
                commands = [call["cli"] for call in calls if "cli" in call]
                self.assertEqual(len(commands), 2)
                self.assertTrue(all("--expected-encoder-checkout" in command for command in commands))

    def test_base_before_1859_never_bridges(self):
        # An encoder pinned before #1859 has no encoder Git metadata check, so its
        # base audit and provisioner keep the existing path even when the head
        # encoder contains the fix.
        for base, head in ((1, 0), (1, 1), (0, 0), (0, 1)):
            with self.subTest(base_contains_fix=base, head_contains_fix=head):
                result, calls = run_guard(base_bug_ancestry=1, base_ancestry=base, head_ancestry=head,
                                          audit_results=self.reports(head=[PRE1883_IDENTITY_ISSUE]))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Inherited manifest audit issues: 1", result.stdout)
                self.assertNotIn("attestation bridge", result.stdout)
                commands = [call["cli"] for call in calls if "cli" in call]
                self.assertEqual(len(commands), 2)
                self.assertTrue(all("--expected-encoder-checkout" in command for command in commands))

    def test_ancestry_errors_fail_before_either_audit(self):
        for bug, base, head in ((0, 2, 0), (0, 128, 0), (0, 1, 2), (0, 0, 128), (2, 1, 0), (128, 1, 0)):
            with self.subTest(bug_status=bug, base_status=base, head_status=head):
                result, calls = run_guard(base_bug_ancestry=bug, base_ancestry=base, head_ancestry=head)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ManifestAuditError", result.stderr)
                self.assertIn("ancestry check failed", result.stderr)
                self.assertEqual(calls, [])

    def test_bridge_predicate_execution_failure_fails_closed(self):
        result, calls = run_guard(base_ancestry=1, head_ancestry=0,
                                  audit_results=self.reports(), bridge_predicate_status=2)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ManifestAuditError: base bridge predicate failed", result.stderr)
        self.assertEqual(len([call for call in calls if "cli" in call]), 1)
        self.assertNotIn("Manifest audit ratchet passed", result.stdout)

    def test_retry_rechecks_dependency_integrity_before_consuming_base(self):
        result, calls = run_guard(base_ancestry=1, head_ancestry=0,
                                  audit_results=self.reports(), integrity_fail_after=3)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DependencyIntegrityError", result.stderr)
        self.assertIn("ManifestAuditError", result.stderr)
        self.assertEqual(len([call for call in calls if "cli" in call]), 1)
        self.assertNotIn("Manifest audit ratchet passed", result.stdout)

    def test_other_single_base_issue_does_not_bridge(self):
        result, calls = run_guard(base_ancestry=1, head_ancestry=0,
                                  audit_results=self.reports(base=["another base issue"], head=["head-only issue"]))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("New manifest audit issues: 1", result.stderr)
        self.assertNotIn("attestation bridge", result.stdout)
        self.assertEqual(len([call for call in calls if "cli" in call]), 2)

    def test_invalid_or_inconsistent_retry_fails_with_manifest_audit_error(self):
        invalid = [
            {"raw": "not JSON", "status": 1},
            {"payload": {"passed": True, "issues": []}, "status": 1},
            {"payload": {"passed": False, "issues": ["inherited"]}, "status": 0},
            {"payload": {"passed": True, "issues": []}, "status": 2},
            {"payload": {"passed": False, "issues": [42]}, "status": 1},
        ]
        for retry in invalid:
            with self.subTest(retry=retry):
                reports = self.reports()
                reports["bridge"] = retry
                result, _ = run_guard(base_ancestry=1, head_ancestry=0, audit_results=reports)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ManifestAuditError", result.stderr)
                self.assertNotIn("Manifest audit ratchet passed", result.stdout)

    def test_identity_or_attestation_failure_in_retry_fails_closed(self):
        unavailable = "running axiom-encode checkout identity is unavailable: "
        attestation = ("Cannot apply generated RuleSpec: the trusted-runtime marker is set "
                       "but the runtime attestation is unreadable at /opt/x/runtime-attestation.json: denied")
        for issue in (PRE1883_IDENTITY_ISSUE,
                      "Cannot verify the running pinned encoder identity: " + unavailable + attestation,
                      ".axiom/encoding-manifests/us/a.json cannot verify pinned encoder identity: " + unavailable + attestation):
            with self.subTest(issue=issue):
                # Even an identical head issue must never bless a failed retry.
                result, _ = run_guard(base_ancestry=1, head_ancestry=0,
                                      audit_results=self.reports(bridge=[issue], head=[issue]))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ManifestAuditError", result.stderr)
                self.assertIn("identity or attestation failure", result.stderr)
                self.assertNotIn("Inherited manifest audit issues", result.stdout)

    # These issues name identity or attestation in a filename or a field, and each describes a manifest rather than the
    # running encoder.
    ORDINARY_ISSUES_NAMING_IDENTITY = (
        ".axiom/encoding-manifests/identity-cards.json is not an encoder apply manifest",
        ".axiom/encoding-manifests/attestation.json is not an encoder apply manifest",
        ".axiom/encoding-manifests/us/a.json replacement receipt identity is stale",
        ".axiom/encoding-manifests/us/a.json has invalid source_attestation: bad root",
    )

    def test_inherited_manifest_issue_naming_identity_or_attestation_stays_inherited(self):
        for issue in self.ORDINARY_ISSUES_NAMING_IDENTITY:
            with self.subTest(issue=issue):
                result, _ = run_guard(base_ancestry=1, head_ancestry=0,
                                      audit_results=self.reports(bridge=[issue], head=[issue]))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Inherited manifest audit issues", result.stdout)
                self.assertNotIn("identity or attestation failure", result.stderr)

    def test_new_head_issue_naming_identity_or_attestation_still_fails(self):
        for issue in self.ORDINARY_ISSUES_NAMING_IDENTITY:
            with self.subTest(issue=issue):
                result, _ = run_guard(base_ancestry=1, head_ancestry=0,
                                      audit_results=self.reports(bridge=[], head=[issue]))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("New manifest audit issues", result.stdout + result.stderr)

    def test_ordinary_mode_never_checks_ancestry_or_uses_bridge(self):
        result, calls = run_guard(mode="changed", base_ancestry=128, head_ancestry=128,
                                  audit_results=self.reports())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = [call["cli"] for call in calls if "cli" in call]
        self.assertEqual(len(commands), 1)
        self.assertIn("--expected-encoder-checkout", commands[0])
        self.assertNotIn("--all", commands[0])
        self.assertNotIn("--json", commands[0])
        self.assertNotIn("attestation bridge", result.stdout)

    def test_bridge_predicate_accepts_only_the_exact_singleton_json(self):
        source = compile(heredoc(step_source("Reject manual RuleSpec changes"), "PYBASEBRIDGE"),
                         "base-bridge-predicate", "exec")
        payloads = [
            ({"passed": False, "issues": [PRE1883_IDENTITY_ISSUE]}, 0),
            ({"passed": False, "issues": [PRE1883_IDENTITY_ISSUE + " "]}, 1),
            ({"passed": False, "issues": [PRE1883_IDENTITY_ISSUE, "other"]}, 1),
            ({"passed": False, "issues": [PRE1883_IDENTITY_ISSUE] * 2}, 1),
            ({"passed": True, "issues": [PRE1883_IDENTITY_ISSUE]}, 1),
            ({"passed": False, "issues": []}, 1), ([], 1),
        ]
        with tempfile.TemporaryDirectory(prefix="encoder-guard-bridge-predicate-", dir=TEMP_PARENT) as directory:
            path = Path(directory) / "base.json"
            for payload, expected in payloads:
                with self.subTest(payload=payload):
                    path.write_text(json.dumps(payload))
                    with mock.patch.object(sys, "argv", ["bridge", str(path)]):
                        with self.assertRaises(SystemExit) as result:
                            exec(source, {"__name__": "__main__"})
                    self.assertEqual(result.exception.code, expected)
            path.write_text("not JSON")
            with mock.patch.object(sys, "argv", ["bridge", str(path)]):
                with self.assertRaises(SystemExit) as result:
                    exec(source, {"__name__": "__main__"})
            self.assertEqual(result.exception.code, 1)

    def test_bridged_ratchet_accepts_exactly_head_subsets_of_retry_issues(self):
        shell = step_source("Reject manual RuleSpec changes")
        codes = {label: compile(heredoc(shell, label), label, "exec")
                 for label in ("PYBASEBRIDGE", "PYBRIDGEIDENTITY", "PYRATCHET")}
        with tempfile.TemporaryDirectory(prefix="encoder-guard-bridge-property-", dir=TEMP_PARENT) as directory:
            before, after = Path(directory) / "base.json", Path(directory) / "head.json"
            for base_bits in range(8):
                for head_bits in range(8):
                    base = {f"relative/module-{i}.yaml: issue" for i in range(3) if base_bits & (1 << i)}
                    head = {f"relative/module-{i}.yaml: issue" for i in range(3) if head_bits & (1 << i)}
                    with self.subTest(base=base_bits, head=head_bits):
                        before.write_text(json.dumps(audit_report([PRE1883_IDENTITY_ISSUE])["payload"]))
                        with mock.patch.object(sys, "argv", ["bridge", str(before)]):
                            with self.assertRaises(SystemExit) as selected:
                                exec(codes["PYBASEBRIDGE"], {"__name__": "__main__"})
                        self.assertEqual(selected.exception.code, 0)
                        # This is the supervised retry result, replacing the
                        # identity-only report before the unchanged comparison.
                        before.write_text(json.dumps(audit_report(sorted(base))["payload"]))
                        after.write_text(json.dumps(audit_report(sorted(head))["payload"]))
                        with mock.patch.object(sys, "argv", ["identity", str(before)]):
                            exec(codes["PYBRIDGEIDENTITY"], {"__name__": "__main__"})
                        args = ["ratchet", str(before), str(int(bool(base))), str(after), str(int(bool(head))),
                                "/base/repository", "/head/repository", "/base/dependencies", "/head/dependencies"]
                        status = 0
                        stdout, stderr = io.StringIO(), io.StringIO()
                        with mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            try:
                                exec(codes["PYRATCHET"], {"__name__": "__main__"})
                            except SystemExit as exc:
                                status = exc.code
                        self.assertEqual(status, 0 if head <= base else 1)
                        self.assertIn(f"Inherited manifest audit issues: {len(head & base)}", stdout.getvalue())
                        if head - base:
                            self.assertIn(f"New manifest audit issues: {len(head - base)}", stderr.getvalue())


class Pre1883AttestationProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.preparation = step_source(BASE_PREPARATION_STEP)
        self.source_fragment = marked_source(self.preparation, "pre1883-attestation-source")
        self.provision_fragment = marked_source(self.preparation, "base-runtime-provision")
        directory = tempfile.TemporaryDirectory(prefix="encoder-guard-attestation-source-", dir=TEMP_PARENT)
        self.addCleanup(directory.cleanup)
        self.root = root = Path(directory.name)
        self.origin = root / "origin"
        git(root, "init", "-q", "-b", "main", str(self.origin))
        (self.origin / "pyproject.toml").write_text('version = "0.1.0"\n')
        git(self.origin, "add", "pyproject.toml")
        git(self.origin, "commit", "-q", "-m", "version bump")
        self.bump = git(self.origin, "rev-parse", "HEAD")
        git(self.origin, "commit", "-q", "--allow-empty", "-m", "base pin")
        self.pin = git(self.origin, "rev-parse", "HEAD")
        git(self.origin, "commit", "-q", "--allow-empty", "-m", "later main")
        self.main = git(self.origin, "rev-parse", "HEAD")
        self.dependencies = root / "dependencies with spaces"
        self.head = self.dependencies / "axiom-encode"
        self.head.mkdir(parents=True)
        git(self.head, "init", "-q")
        git(self.head, "fetch", "-q", "--no-tags", str(self.origin), "+refs/heads/main:refs/remotes/origin/main")
        # A detached HEAD can predate the base. The authenticated main objects
        # must survive the clone so the provisioner can walk base version history.
        git(self.head, "checkout", "-q", "--detach", self.bump)
        self.audit = root / "audit with spaces"
        self.audit.mkdir()
        self.tools = root / "tools"
        self.tools.mkdir()
        (self.tools / "python").symlink_to(sys.executable)
        sudo = self.tools / "sudo"
        sudo.write_text('#!/bin/sh\nexec "$@"\n')
        sudo.chmod(0o755)
        self.integrity = root / "integrity"
        self.integrity.mkdir()
        (self.integrity / "check.py").write_text(
            "import json, os, sys\n"
            "with open(os.environ['PROVISION_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps({'integrity': sys.argv[1:]}) + '\\n')\n")
        base_scripts = root / "base-dependencies/axiom-encode/scripts"
        base_scripts.mkdir(parents=True)
        (base_scripts / "provision_verification_supervisor.py").write_text(
            "import json, os, sys\n"
            "with open(os.environ['PROVISION_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps({'provision': sys.argv[1:]}) + '\\n')\n")
        self.calls = root / "calls.jsonl"
        self.calls.touch()

    def run_fragments(self, gated, *, provision=True):
        source = self.source_fragment + (self.provision_fragment if provision else "")
        source = source.replace("/opt/axiom-dependency-integrity", str(self.integrity))
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + source], cwd=self.root, env={
            **os.environ, "PATH": str(self.tools) + os.pathsep + os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "AXIOM_DEPENDENCY_ROOT": str(self.dependencies), "audit_root": str(self.audit),
            "base_dependencies": str(self.root / "base-dependencies"), "BASE_ENCODER_REF": self.pin,
            "pre1883_base_bridge": "true" if gated else "false", "PROVISION_CALLS": str(self.calls),
            "TRUST_APPLY_ROOT": "apply", "TRUST_EVAL_ROOT": "eval", "TRUST_CORPUS_RELEASE_ROOT": "corpus",
        }, capture_output=True, text=True, timeout=120)

    def test_source_has_independent_full_history_and_attests_only_base_provisioner(self):
        result = self.run_fragments(True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checkout = self.audit / "encoder-attestation-source"
        self.assertTrue((checkout / ".git").is_dir())
        self.assertFalse((checkout / ".git").is_symlink())
        self.assertFalse((checkout / ".git/objects/info/alternates").exists())
        self.assertEqual(git(checkout, "rev-parse", "--is-shallow-repository"), "false")
        self.assertEqual(git(checkout, "rev-parse", "HEAD"), self.pin)
        self.assertNotEqual(subprocess.run(["git", "-C", str(checkout), "symbolic-ref", "-q", "HEAD"],
                                           capture_output=True).returncode, 0)
        self.assertEqual(git(checkout, "config", "--get", "remote.origin.url"), OFFICIAL_ENCODER)
        self.assertEqual(git(checkout, "rev-list", "HEAD").splitlines(), [self.pin, self.bump])
        self.assertEqual(git(checkout, "show", f"{self.bump}:pyproject.toml"), 'version = "0.1.0"')
        self.assertEqual(git(checkout, "cat-file", "-t", self.main), "commit")
        for source in (self.head / ".git/objects").glob("**/*"):
            destination = checkout / ".git/objects" / source.relative_to(self.head / ".git/objects")
            if source.is_file() and destination.is_file():
                self.assertNotEqual((source.stat().st_dev, source.stat().st_ino),
                                    (destination.stat().st_dev, destination.stat().st_ino))
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertIn({"integrity": ["add", "base-encoder-attestation-source", str(checkout), "repository"]}, calls)
        provision = next(call["provision"] for call in calls if "provision" in call)
        self.assertEqual(provision[provision.index("--encoder-origin-repository") + 1],
                         "github.com/TheAxiomFoundation/axiom-encode")
        self.assertEqual(provision[provision.index("--encoder-commit") + 1], self.pin)
        self.assertEqual(provision[provision.index("--encoder-git-root") + 1], str(checkout))

    def test_non_gated_base_provisioner_has_no_attestation_flags_or_checkout(self):
        result = self.run_fragments(False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.audit / "encoder-attestation-source").exists())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        for flag in ("--encoder-origin-repository", "--encoder-commit", "--encoder-git-root"):
            self.assertNotIn(flag, calls[0]["provision"])

    def test_shallow_or_alternates_source_fails_before_provisioning(self):
        for metadata, content in (("shallow", self.bump + "\n"),
                                  ("objects/info/alternates", "/missing/object-store\n"),
                                  ("objects/info/http-alternates", "https://example.invalid/objects\n")):
            with self.subTest(metadata=metadata):
                path = self.head / ".git" / metadata
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                try:
                    result = self.run_fragments(True)
                finally:
                    path.unlink()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.audit / "encoder-attestation-source").exists())
                self.assertEqual(self.calls.read_text(), "")

    def test_both_steps_share_gate_and_head_provisioning_never_receives_flags(self):
        guard = step_source("Reject manual RuleSpec changes")
        self.assertEqual(marked_source(self.preparation, "pre1883-bridge-gate"),
                         marked_source(guard, "pre1883-bridge-gate"))
        for step in workflow_steps():
            if step.get("name") == BASE_PREPARATION_STEP:
                continue
            source = step.get("run", "")
            if "provision_verification_supervisor.py" in source:
                for flag in ("--encoder-origin-repository", "--encoder-commit", "--encoder-git-root"):
                    self.assertNotIn(flag, source)
                call_start = 'sudo "$(command -v python)" -I scripts/provision_verification_supervisor.py'
                invocation = call_start + source.split(call_start, 1)[1].split('\nsudo chown', 1)[0]
                self.assertEqual(invocation, textwrap.dedent(r'''
                    sudo "$(command -v python)" -I scripts/provision_verification_supervisor.py \
                      --destination /opt/axiom-verification \
                      --supervisor "$RUNNER_TEMP/axiom-encode-signing-supervisor" \
                      --site-packages "$RUNNER_TEMP/axiom-verification-site-packages" \
                      --apply-root "$TRUST_APPLY_ROOT" --eval-root "$TRUST_EVAL_ROOT" \
                      --corpus-release-root "$TRUST_CORPUS_RELEASE_ROOT" \
                      ${retired_root_args[@]+"${retired_root_args[@]}"} \
                      --git "$(command -v git)"
                    ''').strip())
        self.assertLess(self.preparation.index("base-encoder-attestation-source"),
                        self.preparation.index("# base-runtime-provision-start"))
        for step in workflow_steps():
            if step.get("name") in (BASE_PREPARATION_STEP, "Reject manual RuleSpec changes"):
                self.assertEqual(step["env"]["BASE_ENCODER_REF"], "${{ needs.shards.outputs.base_axiom_encode_ref }}")
                self.assertEqual(step["env"]["HEAD_ENCODER_REF"], "${{ needs.shards.outputs.axiom_encode_ref }}")


if __name__ == "__main__":
    unittest.main()
