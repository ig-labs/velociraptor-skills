import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ADD_MAPPED_CLIENT_SCRIPT = (
    REPO_ROOT
    / "src/vraptor/resources/scripts/velociraptor/add_mapped_client.sh"
)
SUPERVISE_MAPPED_CLIENT_SCRIPT = (
    REPO_ROOT
    / "src/vraptor/resources/scripts/velociraptor/supervise_mapped_client.sh"
)
ADD_REMOTE_MAPPED_CLIENT_SCRIPT = (
    REPO_ROOT
    / "src/vraptor/resources/scripts/velociraptor/add_remote_mapped_client.sh"
)
MAPPED_CLIENT_STATUS_SCRIPT = (
    REPO_ROOT
    / "src/vraptor/resources/scripts/velociraptor/mapped_client_status.sh"
)


class AddMappedClientShellTest(unittest.TestCase):
    def make_temp_repo(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        repo_root = Path(temp_dir.name) / "ai-skills"
        script_dir = (
            repo_root
            / "dfir-case-tools"
            / "scripts"
            / "velociraptor"
        )
        script_dir.mkdir(parents=True, exist_ok=True)

        add_script = script_dir / "add_mapped_client.sh"
        supervise_script = script_dir / "supervise_mapped_client.sh"
        remote_script = script_dir / "add_remote_mapped_client.sh"
        status_script = script_dir / "mapped_client_status.sh"
        shutil.copy2(ADD_MAPPED_CLIENT_SCRIPT, add_script)
        shutil.copy2(SUPERVISE_MAPPED_CLIENT_SCRIPT, supervise_script)
        shutil.copy2(ADD_REMOTE_MAPPED_CLIENT_SCRIPT, remote_script)
        shutil.copy2(MAPPED_CLIENT_STATUS_SCRIPT, status_script)
        return repo_root, add_script, supervise_script, remote_script, status_script

    def run_script(self, script_path: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(script_path), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_help_prints_usage_and_exits_zero(self):
        _, add_script, _, _, _ = self.make_temp_repo()

        result = self.run_script(add_script, "--help")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("Usage:", result.stdout)
        self.assertIn(
            "./vraptor mapped add-remote [OPTIONS] <evidence-path>",
            result.stdout,
        )
        self.assertIn("--workspace <path>", result.stdout)
        self.assertIn("--velociraptor-bin <path-or-command>", result.stdout)
        self.assertIn("--foreground", result.stdout)
        self.assertIn("--mode <mode>", result.stdout)

    def test_missing_evidence_path_prints_usage_and_exits_zero(self):
        _, add_script, _, _, _ = self.make_temp_repo()

        result = self.run_script(add_script)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("Usage:", result.stdout)

    def test_unknown_argument_fails_before_workspace_checks(self):
        _, add_script, _, _, _ = self.make_temp_repo()

        result = self.run_script(add_script, "--bogus")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown argument: --bogus", result.stderr)
        self.assertNotIn("Velociraptor binary not found", result.stderr)

    def test_supervisor_requires_workspace_argument(self):
        _, _, supervise_script, _, _ = self.make_temp_repo()

        result = self.run_script(supervise_script)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workspace dir required", result.stderr)

    def test_outputs_inside_mounted_evidence_are_rejected_before_writes(self):
        repo, script, _, _, _ = self.make_temp_repo()
        evidence = repo / "mounted"
        evidence.mkdir()
        alias = repo / "alias"
        alias.symlink_to(evidence, target_is_directory=True)
        for extra in (
            ["--workspace", str(evidence / "nested" / "runtime")],
            ["--workspace", str(alias / "runtime")],
            ["--workspace", str(repo / "missing" / ".." / "mounted" / "runtime")],
            ["--workspace", str(repo / "runtime"), "--json-out", str(evidence / "result.json")],
        ):
            with self.subTest(extra=extra):
                result = self.run_script(script, *extra, str(evidence))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside the evidence", result.stderr)
                self.assertEqual(list(evidence.iterdir()), [])
                self.assertFalse((repo / "runtime").exists())

        image = evidence / "disk.E01"
        image.write_bytes(b"original-image")
        image_alias = repo / "image.E01"
        image_alias.symlink_to(image)
        result = self.run_script(script, "--workspace", str(repo / "runtime"),
                                 "--json-out", str(image), str(image_alias))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the evidence", result.stderr)
        self.assertEqual(image.read_bytes(), b"original-image")
        self.assertFalse((repo / "runtime").exists())

    def test_supervisor_requires_api_client_argument(self):
        _, _, supervise_script, _, _ = self.make_temp_repo()

        result = self.run_script(
            supervise_script,
            "/tmp/workspace",
            "client-name",
            "/tmp/client-dir",
            "/tmp/client.config.yaml",
            "/tmp/remap.yaml",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("api client config required", result.stderr)

    def test_remote_wrapper_requires_client_config(self):
        _, _, _, remote_script, _ = self.make_temp_repo()

        result = self.run_script(remote_script, "--api-client", "/tmp/api.yaml", "/tmp/disk.E01")

        self.assertEqual(result.returncode, 1)
        self.assertIn("--client-config is required", result.stderr)

    def test_remote_wrapper_passes_configs_to_shared_engine(self):
        repo_root, add_script, _, remote_script, _ = self.make_temp_repo()
        args_log = repo_root / "engine-args.log"
        add_script.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$@\" > \"${ARGS_LOG:?}\"\n",
            encoding="utf-8",
        )
        os.chmod(add_script, 0o755)

        result = subprocess.run(
            [
                "bash",
                str(remote_script),
                "--client-config",
                "/tmp/client.config.yaml",
                "--api-client",
                "/tmp/api_client.yaml",
                "-n",
                "remote-host",
                "/tmp/disk.E01",
            ],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "ARGS_LOG": str(args_log)},
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            args_log.read_text(encoding="utf-8").splitlines(),
            [
                "--client-config",
                "/tmp/client.config.yaml",
                "--api-client",
                "/tmp/api_client.yaml",
                "-n",
                "remote-host",
                "/tmp/disk.E01",
            ],
        )

    def test_remote_mapping_preserves_incompatible_identity(self):
        repo, add_script, _, _, _ = self.make_temp_repo()
        workspace = repo / "runtime"
        client_dir = workspace / "mapped-clients" / "host"
        client_dir.mkdir(parents=True)
        api, client, evidence = repo / "api.yaml", repo / "client.yaml", repo / "disk.E01"
        for path in (api, client, evidence):
            path.write_text("test data")
        writeback = client_dir / "Velociraptor.writeback.yaml"
        writeback.write_text("client_id: C.existing\n")
        (client_dir / "session.env").write_text(
            f"API_CLIENT_CONFIG={api}\nSOURCE_CLIENT_CONFIG={client}\nEVIDENCE_PATH=/different/disk.E01\n"
        )
        result = self.run_script(add_script, "--workspace", str(workspace), "--api-client", str(api),
                                 "--client-config", str(client), "--velociraptor-bin", "/usr/bin/true",
                                 "-n", "host", str(evidence))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity preserved", result.stderr)
        self.assertEqual(writeback.read_text(), "client_id: C.existing\n")

    def test_status_json_handles_empty_mapped_client_inventory(self):
        repo_root, _, _, _, status_script = self.make_temp_repo()
        workspace = repo_root / "velociraptor"
        workspace.mkdir(parents=True)

        result = self.run_script(
            status_script,
            "--workspace",
            str(workspace),
            "--json",
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, "[\n\n]\n")

    def test_status_json_reports_saved_state_and_live_pids(self):
        repo_root, _, _, _, status_script = self.make_temp_repo()
        workspace = repo_root / "velociraptor"
        client_dir = workspace / "mapped-clients" / "disk01"
        client_dir.mkdir(parents=True)
        (client_dir / "session.env").write_text(
            "CLIENT_NAME=disk01\n"
            "EVIDENCE_PATH=/evidence/disk01.E01\n"
            "MAPPED_CLIENT_MODE=remote_dead_disk\n"
            "SUPERVISOR_MODE=foreground\n",
            encoding="utf-8",
        )
        (client_dir / "client-status.env").write_text(
            "STATE=online\n"
            "DETAIL=healthy\n"
            "CLIENT_ID=C.1234\n"
            "UPDATED_AT=2026-07-13T00:00:00Z\n",
            encoding="utf-8",
        )
        (client_dir / "client.pid").write_text(f"{os.getpid()}\n", encoding="utf-8")
        (client_dir / "supervisor.pid").write_text(f"{os.getpid()}\n", encoding="utf-8")
        identity = subprocess.check_output(
            ["ps", "-p", str(os.getpid()), "-o", "lstart=", "-o", "command="], text=True
        )
        for kind in ("client", "supervisor"):
            (client_dir / f"{kind}.pid.identity").write_text(identity)

        result = self.run_script(
            status_script,
            "--workspace",
            str(workspace),
            "--json",
        )

        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload[0]["client_id"], "C.1234")
        self.assertEqual(payload[0]["state"], "online")
        self.assertTrue(payload[0]["client_process_running"])
        self.assertTrue(payload[0]["supervisor_process_running"])
        (client_dir / "supervisor.pid.identity").write_text("old process identity")
        stale = self.run_script(status_script, "--workspace", str(workspace), "--json")
        self.assertFalse(json.loads(stale.stdout)[0]["supervisor_process_running"])

    def test_supervisor_waits_for_initial_remapped_hostname_update(self):
        repo, _, supervisor, _, _ = self.make_temp_repo()
        client_dir = repo / "mapping"
        client_dir.mkdir()
        config = client_dir / "client.yaml"
        config.write_text("Client: {}\n")
        remap = client_dir / "remap.yaml"
        remap.write_text("remappings:\n- type: mount\n")
        binary = repo / "fake-velociraptor"
        binary.write_text('''#!/bin/bash
if [ "$1" = client ]; then
    printf 'client_id: C.test\\n' >"$(dirname "$4")/Velociraptor.writeback.yaml"
    sleep 60 &
    child="$!"
    trap 'kill "$child" 2>/dev/null; exit 0' TERM INT
    wait "$child"
    exit 0
fi
query="${!#}"
if [[ "$query" == *" AND "* ]]; then
    counter="${TEST_STATE}/identity-count"
    count="$(cat "$counter" 2>/dev/null || echo 0)"
    count=$((count + 1)); echo "$count" >"$counter"
    if [ "$count" -lt 3 ]; then echo '[]'; else echo '[{"client_id":"C.test"}]'; fi
elif [[ "$query" == *"FROM clients()"* ]]; then
    printf '[{"client_id":"C.test","last_seen_at":%s000000}]\\n' "$(date +%s)"
else
    echo '[{"ok":1}]'
fi
''')
        binary.chmod(0o700)
        process = subprocess.Popen(
            ["bash", str(supervisor), str(repo), "mapped-host", str(client_dir), str(config),
             str(remap), str(config), "1", "120", "3", "5", "600", str(repo), "foreground", str(binary)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "TEST_STATE": str(repo)}, start_new_session=True,
        )
        try:
            states = set()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status = client_dir / "client-status.env"
                if status.exists():
                    states.add(status.read_text().splitlines()[0])
                    if "STATE=online" in states:
                        break
                time.sleep(0.1)
            self.assertIn("STATE=waiting_identity", states, status.read_text())
            self.assertIn("STATE=online", states)
            self.assertFalse((client_dir / "supervisor.hold").exists())
            self.assertEqual((client_dir / "client.id").read_text().strip(), "C.test")
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
