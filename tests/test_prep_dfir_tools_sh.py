import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPT = (
    REPO_ROOT / "src/vraptor/resources/scripts/prep_dfir_tools.sh"
)
BASH = shutil.which("bash") or "/bin/bash"
DIRNAME = shutil.which("dirname")
MKDIR = shutil.which("mkdir")
CHMOD = shutil.which("chmod")


class PrepDfirToolsShellTest(unittest.TestCase):
    def make_temp_repo(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        repo_root = Path(temp_dir.name) / "ai-skills"
        script_path = (
            repo_root / "src/vraptor/resources/scripts/prep_dfir_tools.sh"
        )
        script_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_SCRIPT, script_path)
        return repo_root, script_path

    def make_fake_bin(self, repo_root: Path, uname_s: str = "Darwin", uname_m: str = "arm64"):
        if not DIRNAME or not MKDIR or not CHMOD:
            self.fail("dirname, mkdir, and chmod must be available for shell-wrapper tests")

        fake_bin = repo_root / "fake-bin"
        fake_bin.mkdir(parents=True, exist_ok=True)

        (fake_bin / "uname").write_text(
            textwrap.dedent(
                f"""\
                #!/bin/sh
                case "${{1:-}}" in
                  -m) printf '%s\\n' "{uname_m}" ;;
                  *) printf '%s\\n' "{uname_s}" ;;
                esac
                """
            ),
            encoding="utf-8",
        )
        os.chmod(fake_bin / "uname", 0o755)

        for name, target in {
            "dirname": DIRNAME,
            "mkdir": MKDIR,
            "chmod": CHMOD,
        }.items():
            os.symlink(target, fake_bin / name)

        return fake_bin

    def write_stub_python3(self, fake_bin: Path) -> None:
        (fake_bin / "python3").write_text(
            textwrap.dedent(
                f"""\
                #!/bin/sh
                if [ "$1" = "-m" ] && [ "$2" = "venv" ] && [ -n "${{3:-}}" ]; then
                  target="$3"
                  "{MKDIR}" -p "$target/bin"
                  {{
                    printf '%s\\n' '#!/bin/sh'
                    printf '%s\\n' 'printf "%s\\\\n" "$*" >> "${{PYTHON_STUB_LOG:?}}"'
                    printf '%s\\n' 'exit 0'
                  }} > "$target/bin/python"
                  "{CHMOD}" +x "$target/bin/python"
                  exit 0
                fi
                printf '%s\\n' "unexpected python3 args: $*" >> "${{PYTHON3_STUB_LOG:?}}"
                exit 1
                """
            ),
            encoding="utf-8",
        )
        os.chmod(fake_bin / "python3", 0o755)

    def run_script(self, script_path: Path, *args: str, env_overrides=None):
        env = dict(os.environ)
        for key in ("VELO_BIN", "AI_SKILLS_TOOLS_DATA_ROOT", "VELO_LOCAL_VERSION_TAG"):
            env.pop(key, None)
        env["AI_SKILLS_REPO_ROOT"] = str(script_path.parents[4])
        env["HOME"] = str(script_path.parents[5] / "home")
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            [BASH, str(script_path), *args],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def test_help_prints_usage_and_exits_zero(self):
        _, script_path = self.make_temp_repo()

        result = self.run_script(script_path, "-h")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("Usage:", result.stdout)
        self.assertIn("./dfir tools prep [OPTIONS]", result.stdout)
        self.assertIn("Prepare a specific component: venv | plaso | velociraptor | volatility | tsk | all", result.stdout)
        self.assertIn("--init-velociraptor-workspace", result.stdout)

    def test_unknown_tool_is_rejected_before_any_install_work(self):
        _, script_path = self.make_temp_repo()

        result = self.run_script(script_path, "-t", "bogus")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown tool 'bogus'", result.stderr)
        self.assertNotIn("Repo root detected as:", result.stdout)

    def test_venv_tool_fails_cleanly_when_python3_is_unavailable(self):
        repo_root, script_path = self.make_temp_repo()
        fake_bin = self.make_fake_bin(repo_root)

        result = self.run_script(
            script_path,
            "-t",
            "venv",
            env_overrides={"PATH": str(fake_bin)},
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("python3 not found - cannot create repo virtual environment", result.stdout)
        self.assertIn("Failed to prepare repo virtual environment", result.stderr)

    def test_venv_tool_creates_stub_venv_and_reports_success(self):
        repo_root, script_path = self.make_temp_repo()
        fake_bin = self.make_fake_bin(repo_root)
        self.write_stub_python3(fake_bin)
        python_stub_log = repo_root / "python-stub.log"
        python3_stub_log = repo_root / "python3-stub.log"

        result = self.run_script(
            script_path,
            "-t",
            "venv",
            env_overrides={
                "PATH": str(fake_bin),
                "PYTHON_STUB_LOG": str(python_stub_log),
                "PYTHON3_STUB_LOG": str(python3_stub_log),
            },
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn(f"Creating repo virtual environment at: {repo_root / '.venv'}", result.stdout)
        self.assertIn(f"Repo virtual environment ready at: {repo_root / '.venv'}", result.stdout)
        self.assertIn(
            f"Done. Repo virtual environment is prepared at: {repo_root / '.venv'}",
            result.stdout,
        )
        self.assertTrue((repo_root / ".venv" / "bin" / "python").exists())
        self.assertEqual(
            python_stub_log.read_text(encoding="utf-8").strip(),
            "-m pip install --upgrade pip setuptools wheel",
        )
        self.assertFalse(python3_stub_log.exists())

    def write_stub_curl(self, fake_bin):
        curl = fake_bin / "curl"
        curl.write_text('''#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then shift; output="$1"; fi
    shift
done
if [ -n "$output" ]; then
    printf '%s\\n' '#!/bin/sh' 'exit 123' > "$output"
else
    printf '%s\\n' '{"tag_name": "v1.2.3",' '"browser_download_url": "https://fixture.invalid/velociraptor-v1.2.3-darwin-arm64"}'
fi
''')
        curl.chmod(0o755)

    def test_custom_parent_with_spaces_installs_without_starting_a_workspace(self):
        repo_root, script_path = self.make_temp_repo()
        fake_bin = self.make_fake_bin(repo_root)
        self.write_stub_curl(fake_bin)
        parent = (repo_root / "custom home").resolve()
        result = self.run_script(
            script_path, "-t", "velociraptor", "-d", str(parent),
            env_overrides={
                "PATH": f"{fake_bin}{os.pathsep}{os.defpath}",
                "AI_SKILLS_TOOLS_DATA_ROOT": str(repo_root / "other-tools"),
                "VELO_BIN": str(repo_root / "configured/velo"),
                "VELO_LOCAL_VERSION_TAG": "v1.2.3",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = parent / "velociraptor/velociraptor"
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertIn(str(binary), result.stdout)
        self.assertEqual({p.name for p in binary.parent.iterdir()}, {"velociraptor"})
        self.assertFalse((repo_root / "dfir-case-tools").exists())
        self.assertFalse((repo_root / "other-tools").exists())
        self.assertFalse((repo_root / "configured").exists())

    def test_home_default_and_configured_executable_paths(self):
        for configured in (None, "~/custom tools/velo", "$HOME/custom tools/velo",
                           "${HOME}/custom tools/velo", "relative tools/velo", "velo"):
            with self.subTest(configured=configured):
                repo, script = self.make_temp_repo()
                fake_bin = self.make_fake_bin(repo)
                self.write_stub_curl(fake_bin)
                env = {"PATH": f"{fake_bin}{os.pathsep}{os.defpath}",
                       "AI_SKILLS_TOOLS_DATA_ROOT": str(repo / "other-tools")}
                home = repo.parent / "home"
                if configured is None:
                    expected = home / "velociraptor/velociraptor"
                elif configured == "velo":
                    env["VELO_BIN"] = configured
                    expected = fake_bin / configured
                    expected.write_text("#!/bin/sh\nexit 123\n")
                    expected.chmod(0o755)
                else:
                    env["VELO_BIN"] = configured
                    expected = (repo / configured if configured.startswith("relative")
                                else home / "custom tools/velo")
                result = self.run_script(script, "-t", "velociraptor", env_overrides=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(os.access(expected, os.X_OK))
                if configured != "velo":
                    self.assertEqual(list(expected.parent.iterdir()), [expected])
                self.assertFalse((repo / "other-tools").exists())
                self.assertFalse((repo / ".venv").exists())

    def test_missing_configured_command_fails_before_download(self):
        repo, script = self.make_temp_repo()
        fake_bin = self.make_fake_bin(repo)
        self.write_stub_curl(fake_bin)
        result = self.run_script(script, "-t", "velociraptor", env_overrides={
            "PATH": f"{fake_bin}{os.pathsep}{os.defpath}",
            "VELO_BIN": "nonexistent-velociraptor-test-command",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("set workstation.binary", result.stderr)
        self.assertNotIn("Fetching", result.stdout)
        self.assertFalse((repo.parent / "home/velociraptor").exists())

if __name__ == "__main__":
    unittest.main()
