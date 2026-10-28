"""Execute dependency installation and source checks without network or builds."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

import yaml


TEMP_PARENT = "/private/tmp" if Path("/private/tmp").is_dir() else None

WORKFLOW = Path(os.environ.get(
    "AXIOM_DEPENDENCY_TEST_WORKFLOW",
    str(Path(__file__).resolve().parents[1] / ".github/workflows/validate-rulespec.yml"),
))
STEPS = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
DEPENDENCIES = ("axiom-encode", "axiom-rules-engine", "axiom-corpus", "rulespec-us")


def step(name: str) -> dict:
    return next(item for item in STEPS if item.get("name") == name)


class DependencyIntegrityTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        candidate = root / "candidate"
        candidate.mkdir()
        dependencies = root / "dependencies"
        dependencies.mkdir()
        for name in DEPENDENCIES:
            checkout = dependencies / name
            checkout.mkdir()
            (checkout / "toolchain.py").write_text("BEHAVIOR = 'authenticated'\n")
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(checkout), "-c", "user.name=Fixture",
                "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                "commit", "-qm", "authenticated source",
            ], check=True)
        encoder = dependencies / "axiom-encode"
        (encoder / "cmd/axiom-encode-signing-supervisor").mkdir(parents=True)
        (encoder / "cmd/axiom-encode-signing-supervisor/main.go").write_text("package main\n")
        (encoder / "scripts").mkdir()
        (encoder / "scripts/provision_verification_supervisor.py").write_text("print('trusted provisioner')\n")
        subprocess.run(["git", "-C", str(encoder), "add", "."], check=True)
        subprocess.run([
            "git", "-C", str(encoder), "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "real build and provision inputs",
        ], check=True)
        temp = root / "runner-temp"
        temp.mkdir()
        tools = root / "tools"
        tools.mkdir()
        # Only network package installation is stubbed. Unisolated invocations
        # execute the actual interpreter and reproduce candidate pip.py execution.
        python = tools / "python"
        python.write_text(
            "#!/bin/bash\n"
            "if [ \"$1\" = -I ] && [ \"$2\" = -m ] && [ \"$3\" = pip ]; then\n"
            "  test \"$4\" = --isolated || exit 90\n"
            "  test \"$PWD\" != \"$GITHUB_WORKSPACE\" || exit 91\n"
            "  test -z \"${PYTHONPATH:-}\" || exit 92\n"
            "  printf '%s\\n' \"$*\" >> \"$RUNNER_TEMP/installer-calls\"\n"
            "  mkdir -p \"$RUNNER_TEMP/axiom-verification-site-packages\"\n"
            "  printf 'trusted installed package\\n' > \"$RUNNER_TEMP/axiom-verification-site-packages/package.py\"\n"
            "  exit 0\n"
            "fi\n"
            f"exec {shlex.quote(sys.executable)} \"$@\"\n"
        )
        python.chmod(0o755)
        # The locked installers run through uv: stub only its network-facing
        # commands, applying the same workspace and environment checks.
        uv = tools / "uv"
        uv.write_text(
            "#!/bin/bash\n"
            "test \"$PWD\" != \"$GITHUB_WORKSPACE\" || exit 91\n"
            "test -z \"${PYTHONPATH:-}\" || exit 92\n"
            "test \"${UV_NO_CONFIG:-}\" = 1 || exit 93\n"
            "printf '%s\\n' \"$*\" >> \"$RUNNER_TEMP/installer-calls\"\n"
            "case \"$1 ${2:-}\" in\n"
            "  'export '*)\n"
            "    for arg in \"$@\"; do\n"
            "      if [ \"${previous:-}\" = --output-file ]; then\n"
            "        printf 'pytest==9.0.2 \\\\\\n    --hash=sha256:%064d\\n' 0 > \"$arg\"\n"
            "      fi\n"
            "      previous=\"$arg\"\n"
            "    done\n"
            "    printf 'axiom-oracles @ git+https://github.com/TheAxiomFoundation/axiom-oracles@%040d\\n' 0 ;;\n"
            "  'pip install')\n"
            "    for arg in \"$@\"; do\n"
            "      if [ \"${previous:-}\" = --target ]; then\n"
            "        mkdir -p \"$arg\"\n"
            "        printf 'trusted installed package\\n' > \"$arg/package.py\"\n"
            "      fi\n"
            "      previous=\"$arg\"\n"
            "    done ;;\n"
            "  'pip freeze') printf 'pyyaml==6.0.3\\n' ;;\n"
            "esac\n"
        )
        uv.chmod(0o755)
        # Tests exercise the helper logic as the current user. Hosted runs also
        # protect the helper and baseline under root ownership.
        sudo = tools / "sudo"
        sudo.write_text("#!/bin/bash\nif [ \"$1\" = chown ] || [ \"$1\" = chmod ]; then exit 0; fi\nexec \"$@\"\n")
        sudo.chmod(0o755)
        env = {
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_WORKSPACE": str(candidate), "RUNNER_TEMP": str(temp),
            "AXIOM_DEPENDENCY_ROOT": str(dependencies),
            "AXIOM_COMPOSE_REF": "", "PYTHONPATH": str(candidate),
            "TRUST_APPLY_ROOT": "fixture", "TRUST_EVAL_ROOT": "fixture",
            "TRUST_CORPUS_RELEASE_ROOT": "fixture",
        }
        malicious = (
            "import os\nfrom pathlib import Path\n"
            "root = Path(os.environ['AXIOM_DEPENDENCY_ROOT'])\n"
            "for name in ('axiom-encode', 'axiom-rules-engine', 'axiom-corpus', 'rulespec-us'):\n"
            "    (root / name / 'toolchain.py').write_text(\"BEHAVIOR = 'candidate replacement'\\n\")\n"
            "(root / 'axiom-encode/cmd/axiom-encode-signing-supervisor/main.go').write_text('candidate supervisor\\n')\n"
            "(root / 'axiom-encode/scripts/provision_verification_supervisor.py').write_text('candidate provisioner\\n')\n"
            "with (Path(os.environ['RUNNER_TEMP']) / 'candidate-pip-executed').open('a') as output:\n"
            "    output.write('candidate ran\\n')\n"
        )
        (candidate / "pip.py").write_text(malicious)
        return candidate, env

    def run_step(self, name: str, candidate: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        source = step(name)["run"].replace("/opt/axiom-dependency-integrity", env["RUNNER_TEMP"] + "/integrity")
        return subprocess.run(["bash", "-c", source], cwd=candidate,
                              env=env, capture_output=True, text=True)

    def snapshot(self, candidate: Path, env: dict[str, str]) -> None:
        if any(item.get("name") == "Snapshot authenticated dependency sources" for item in STEPS):
            result = self.run_step("Snapshot authenticated dependency sources", candidate, env)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_pip_cannot_replace_real_build_or_provision_inputs(self):
        with tempfile.TemporaryDirectory(prefix="encoder-guard-integrity-", dir=TEMP_PARENT) as directory:
            candidate, env = self.fixture(Path(directory))
            dependencies = Path(env["AXIOM_DEPENDENCY_ROOT"])
            before = {path: path.read_bytes() for path in dependencies.rglob("*") if path.is_file()}
            self.snapshot(candidate, env)
            result = self.run_step("Install Python dependencies", candidate, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((Path(env["RUNNER_TEMP"]) / "candidate-pip-executed").exists(),
                             "the authenticated HEADs remained fixed while candidate pip replaced their sources")
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_source_drift_is_rejected_before_build_or_provision(self):
        for relative in ("cmd/axiom-encode-signing-supervisor/main.go",
                         "scripts/provision_verification_supervisor.py"):
            with self.subTest(source=relative), tempfile.TemporaryDirectory(
                prefix="encoder-guard-integrity-", dir=TEMP_PARENT
            ) as directory:
                candidate, env = self.fixture(Path(directory))
                self.snapshot(candidate, env)
                target = Path(env["AXIOM_DEPENDENCY_ROOT"]) / "axiom-encode" / relative
                target.write_text("candidate replacement\n")
                prefix = step("Provision protected verification supervisor")["run"].split("CGO_ENABLED=0 go build", 1)[0]
                prefix = prefix.replace("/opt/axiom-dependency-integrity", env["RUNNER_TEMP"] + "/integrity")
                marker = Path(env["RUNNER_TEMP"]) / "build-consumed"
                result = subprocess.run(["bash", "-c", prefix + '\ntouch "$RUNNER_TEMP/build-consumed"\n'],
                                        cwd=candidate, env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, "source drift was consumed by the build")
                self.assertFalse(marker.exists())
                self.assertIn("DependencyIntegrityError", result.stderr)

    def test_untracked_and_symlink_drift_fail_closed(self):
        for mutate in ("untracked", "symlink"):
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory(
                prefix="encoder-guard-integrity-", dir=TEMP_PARENT
            ) as directory:
                candidate, env = self.fixture(Path(directory))
                self.snapshot(candidate, env)
                root = Path(env["AXIOM_DEPENDENCY_ROOT"]) / "axiom-encode"
                if mutate == "untracked":
                    (root / "sitecustomize.py").write_text("candidate injected module\n")
                else:
                    (root / "toolchain.py").unlink()
                    (root / "toolchain.py").symlink_to(candidate / "pip.py")
                result = self.run_step("Install Python dependencies", candidate, env)
                self.assertNotEqual(result.returncode, 0, "full source tree drift was accepted")
                self.assertIn("DependencyIntegrityError", result.stderr)

    def test_checkpoints_preserve_sources_and_allow_declared_artifacts(self):
        cases = (
            ("axiom-rules-engine", "toolchain.py", False),
            ("axiom-rules-engine", "sitecustomize.py", False),
            ("axiom-rules-engine", "target/debug/axiom-rules-engine", True),
            ("axiom-corpus", "toolchain.py", False),
            ("axiom-corpus", ".git/config", False),
            ("axiom-corpus", ".git/hooks/pre-commit", False),
            ("axiom-corpus", ".git/info/attributes", False),
            ("axiom-corpus", "data/corpus/provision.txt", True),
            ("axiom-corpus", "releases/pinned/object.json", True),
            ("axiom-corpus", ".git/FETCH_HEAD", True),
        )
        for name, relative, allowed in cases:
            with self.subTest(repository=name, path=relative), tempfile.TemporaryDirectory(
                prefix="encoder-guard-integrity-", dir=TEMP_PARENT
            ) as directory:
                candidate, env = self.fixture(Path(directory))
                self.snapshot(candidate, env)
                target = Path(env["AXIOM_DEPENDENCY_ROOT"]) / name / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative == ".git/config":
                    with target.open("a") as output:
                        output.write("\n# unauthorized configuration mutation\n")
                else:
                    target.write_text("artifact bytes\n")
                helper = Path(env["RUNNER_TEMP"]) / "integrity/check.py"
                action = "refresh-engine" if name == "axiom-rules-engine" else "refresh-corpus"
                result = subprocess.run([sys.executable, "-I", str(helper), action], cwd=candidate,
                                        env=env, capture_output=True, text=True)
                if allowed:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    verified = subprocess.run([sys.executable, "-I", str(helper), "verify"], cwd=candidate,
                                              env=env, capture_output=True, text=True)
                    self.assertEqual(verified.returncode, 0, verified.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("DependencyIntegrityError", result.stderr)

    def test_base_corpus_refresh_preserves_source_and_git_identity(self):
        for relative, allowed in (
            ("releases/pinned/object.json", True),
            ("data/corpus/provisions/fixture.jsonl", True),
            ("toolchain.py", False),
            (".axiom/corpus-locks/pinned.json", False),
            (".git/config", False),
            (".git/hooks/pre-commit", False),
        ):
            with self.subTest(path=relative), tempfile.TemporaryDirectory(
                prefix="encoder-guard-integrity-", dir=TEMP_PARENT
            ) as directory:
                candidate, env = self.fixture(Path(directory))
                self.snapshot(candidate, env)
                source = Path(env["AXIOM_DEPENDENCY_ROOT"]) / "axiom-corpus"
                corpus = Path(directory) / "base-dependencies/axiom-corpus"
                subprocess.run(["git", "clone", "--quiet", "--shared", str(source), str(corpus)], check=True)
                helper = Path(env["RUNNER_TEMP"]) / "integrity/check.py"
                added = subprocess.run([sys.executable, "-I", str(helper), "add", "base-corpus", str(corpus), "repository"],
                                       cwd=candidate, env=env, capture_output=True, text=True)
                self.assertEqual(added.returncode, 0, added.stderr)
                target = corpus / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative == ".git/config":
                    with target.open("a") as output:
                        output.write("\n# unauthorized configuration mutation\n")
                else:
                    target.write_text("artifact bytes\n")
                result = subprocess.run([sys.executable, "-I", str(helper), "refresh-base-corpus"],
                                        cwd=candidate, env=env, capture_output=True, text=True)
                if allowed:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    verified = subprocess.run([sys.executable, "-I", str(helper), "verify"],
                                              cwd=candidate, env=env, capture_output=True, text=True)
                    self.assertEqual(verified.returncode, 0, verified.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("authenticated source changed during artifact creation: base-corpus", result.stderr)

    def test_base_corpus_is_recorded_before_release_and_provisions_acquisition(self):
        preparation = step("Prepare protected-base manifest audit")
        body = preparation["run"]
        baseline = 'add base-corpus "$base_dependencies/axiom-corpus" repository'
        self.assertLess(body.index(baseline), body.index("<<'PYBASECORPUS'"))
        self.assertGreaterEqual(body.count("refresh-base-corpus"), 2)
        self.assertIn('"$base_dependencies/axiom-corpus/.axiom/corpus-locks"', body)
        self.assertIn("corpus-fetch --help", body)
        self.assertIn('--corpus-path "$base_dependencies/axiom-corpus"', body)
        self.assertIn('--release "$base_release_name"', body)
        self.assertIn('--content-sha256 "$base_release_sha256"', body)
        self.assertIn("/opt/axiom-base-verification/python/bin/python", body)
        self.assertLess(body.index("add base-verification-runtime"), body.index("base_corpus_fetch corpus-fetch --help"))
        self.assertLess(body.index("unset R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY"), body.index("uv pip install"))
        self.assertEqual(preparation["env"].get("R2_ACCESS_KEY_ID"), "${{ secrets.R2_CORPUS_READ_ACCESS_KEY_ID }}")
        self.assertEqual(preparation["env"].get("R2_SECRET_ACCESS_KEY"), "${{ secrets.R2_CORPUS_READ_SECRET_ACCESS_KEY }}")

    def test_all_installers_and_source_consumers_use_integrity_checks(self):
        names = {
            "Install Python dependencies", "Fetch pinned signed corpus release object", "Authenticate signed corpus provenance commit",
            "Place the pinned corpus release's provisions", "Provision protected verification supervisor",
            "Build protected axiom-compose runtime", "Build axiom-rules-engine",
            "Expose axiom-rules-engine on PATH", "Link axiom-rules-engine as sibling checkout",
            "Enforce validation waiver ratchet", "Reject manual RuleSpec changes", "Validate RuleSpec YAML", "Execute RuleSpec companion tests",
            "Validate RuleSpec proofs and claims", "Require money proof atoms",
            "Validate PolicyEngine oracle coverage classification", "Install changed-file oracle coverage classifier",
            "Validate changed PolicyEngine oracle coverage classification",
        }
        for name in names:
            body = step(name)["run"]
            self.assertIn("/opt/axiom-dependency-integrity/check.py verify", body, name)
        for item in STEPS:
            if item.get("name") == "Run repository tests":
                break
            body = item.get("run", "")
            for line in body.splitlines():
                if line.lstrip().startswith(("python ", "python3 ")):
                    self.assertIn(" -I ", line, item.get("name"))
            if "-m pip " in body:
                for line in body.splitlines():
                    if "-m pip " in line:
                        self.assertIn("python -I -m pip --isolated ", line, item.get("name"))
        loader = re.search(r"-I -B -c \\\n\s*'([^']+)'", step("Build protected axiom-compose runtime")["run"])
        self.assertIsNotNone(loader, "isolated provisioning must preserve the trusted sibling import")
        with tempfile.TemporaryDirectory(prefix="encoder-guard-integrity-", dir=TEMP_PARENT) as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.mkdir()
            scripts = root / "authenticated/scripts"
            scripts.mkdir(parents=True)
            (scripts / "provision_verification_supervisor.py").write_text("TOKEN = 'authenticated sibling'\n")
            provisioner = scripts / "provision_axiom_compose_runtime.py"
            provisioner.write_text("from provision_verification_supervisor import TOKEN\nassert TOKEN == 'authenticated sibling'\nprint(TOKEN)\n")
            (candidate / "provision_verification_supervisor.py").write_text("raise RuntimeError('candidate sibling imported')\n")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", loader.group(1), str(provisioner)],
                                    cwd=candidate, env={**os.environ, "PYTHONPATH": str(candidate)},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "authenticated sibling")
            self.assertFalse((scripts / "__pycache__").exists(), "provisioning drifted authenticated source bytes")

    def test_no_dependency_cache_restores_before_validation_finishes(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        final_validation = "Validate changed PolicyEngine oracle coverage classification"
        for job_name, job in workflow["jobs"].items():
            for item in job.get("steps", []):
                action = item.get("uses", "").split("@", 1)[0].lower()
                options = item.get("with", {})
                label = item.get("name", action)
                if action == "astral-sh/setup-uv":
                    self.assertIs(options.get("enable-cache"), False, label)
                    self.assertEqual(options.get("working-directory"), "${{ runner.temp }}", label)
                elif action == "actions/setup-go":
                    self.assertIs(options.get("cache"), False, label)
                elif action in {"actions/setup-python", "actions/setup-node"}:
                    self.assertFalse(options.get("cache"), label)
                else:
                    self.assertFalse("cache" in action and not action.endswith("/save"),
                                     f"dependency cache restored before validation: {job_name}/{label}")
                if item.get("name") == final_validation:
                    break
        build = step("Build protected axiom-compose runtime")["run"]
        self.assertIn("export UV_NO_CACHE=1", build)
        self.assertLess(build.index("export UV_NO_CACHE=1"), build.index("uv python install"))

    def test_composer_packages_and_provisioned_runtime_are_sealed_before_use(self):
        build = step("Build protected axiom-compose runtime")["run"]
        staging_add = ('composer-site-packages "$RUNNER_TEMP/axiom-compose-site-packages" runtime')
        runtime_add = "composer-runtime /opt/axiom-compose-verification runtime"
        self.assertIn(staging_add, build)
        self.assertIn(runtime_add, build)
        self.assertLess(build.index(staging_add), build.index("provision_axiom_compose_runtime.py"))
        self.assertLess(build.index(runtime_add), build.index("/opt/axiom-compose-verification/axiom-compose --help"))
        for name in ("Enforce validation waiver ratchet", "Validate RuleSpec YAML",
                     "Execute RuleSpec companion tests"):
            body = step(name)["run"]
            self.assertLess(body.index("/opt/axiom-dependency-integrity/check.py verify"),
                            body.index("composer_args=()"), name)
        for name, relative in (("composer-site-packages", "dependency.py"),
                               ("composer-runtime", "site-packages/dependency.py")):
            with self.subTest(runtime=name), tempfile.TemporaryDirectory(
                prefix="encoder-guard-integrity-", dir=TEMP_PARENT
            ) as directory:
                candidate, env = self.fixture(Path(directory))
                self.snapshot(candidate, env)
                runtime = Path(env["RUNNER_TEMP"]) / name
                package = runtime / relative
                package.parent.mkdir(parents=True, exist_ok=True)
                package.write_text("VALUE = 'authenticated'\n")
                helper = Path(env["RUNNER_TEMP"]) / "integrity/check.py"
                added = subprocess.run([sys.executable, "-I", str(helper), "add", name, str(runtime), "runtime"],
                                       cwd=candidate, env=env, capture_output=True, text=True)
                self.assertEqual(added.returncode, 0, added.stderr)
                package.write_text("VALUE = 'replacement'\n")
                verified = subprocess.run([sys.executable, "-I", str(helper), "verify"],
                                          cwd=candidate, env=env, capture_output=True, text=True)
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn("DependencyIntegrityError", verified.stderr)


if __name__ == "__main__":
    unittest.main()
