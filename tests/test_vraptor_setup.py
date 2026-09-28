"""Setup orchestration must preserve saved intent and never acquire implicitly."""
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from vraptor import cli, context, lifecycle, readiness, readiness_state, settings, setup, workspace


@pytest.fixture
def workstation(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "environ", {"HOME": str(tmp_path), "PATH": os.defpath})
    monkeypatch.setattr("vraptor.resources.repository_root", lambda: tmp_path)
    monkeypatch.setattr(workspace, "configuration_checks", lambda: {})
    monkeypatch.setattr(readiness, "publish_mapped_system_state", lambda *args: None)
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: False)
    return tmp_path


def invoke(root, action="start", *args):
    return cli.main(["setup", action, "--id", "case1", "--case-root", str(root / "cases"), *args])


def saved(root):
    return json.loads((root / "cases/case1/engagement.json").read_text())


def ready(args):
    return {"engagement_id": args.engagement_id, "status": "ready",
            "mode": setup.MODES[args.mode], "connection": {"server_profile": args.server_profile}}


@pytest.mark.parametrize("interactive", [False, True])
def test_live_setup_without_target_does_not_prompt_and_resumes(workstation, monkeypatch, interactive):
    api = workstation / "api.yaml"
    api.touch()
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: interactive)
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("No target prompt")))
    verify = Mock(side_effect=ready)
    monkeypatch.setattr(readiness, "command_live_remote", verify)
    assert invoke(workstation, "start", "--mode", "live-remote", "--api-client", str(api)) == 0
    assert invoke(workstation, "resume") == 0
    assert verify.call_count == 2
    assert not any(getattr(verify.call_args.args[0], name) for name in setup.LIVE_SCOPE)


def test_explicit_live_scope_replaces_saved_selection(workstation, monkeypatch):
    api = workstation / "api.yaml"
    api.touch()
    verify = Mock(side_effect=ready)
    monkeypatch.setattr(readiness, "command_live_remote", verify)
    assert invoke(workstation, "start", "--mode", "live-remote", "--api-client", str(api),
                  "--hostname", "host1") == 0
    selections = [
        ("--host-label", "group1", "--exclude-host-label", "excluded"),
        ("--exclude-host-label", "different"),
        ("--client-id", "C.other"),
        ("--environment-only-ok",),
        ("--hostname", "host2"),
    ]
    for flags in selections:
        assert invoke(workstation, "resume", *flags) == 0
        expected = vars(setup.parser().parse_args(["resume", *flags]))
        actual = saved(workstation)["setup"]
        assert {key: actual[key] for key in setup.LIVE_SCOPE} == {
            key: expected[key] for key in setup.LIVE_SCOPE}
        assert invoke(workstation, "resume") == 0
        assert saved(workstation)["setup"] == actual
    verify.reset_mock()
    assert invoke(workstation, "resume", "--hostname", "host3", "--client-id", "C.other") == 1
    verify.assert_not_called()
    assert saved(workstation)["setup"] == actual


def test_existing_remote_yaml_skips_acquisition_and_resume_pins_connection(workstation, monkeypatch):
    root = workstation
    api = root / "provided.yaml"
    api.touch()
    run = Mock(side_effect=AssertionError("No SSH for supplied config"))
    monkeypatch.setattr(setup.subprocess, "run", run)
    verify = Mock(side_effect=ready)
    monkeypatch.setattr(readiness, "command_live_remote", verify)
    assert invoke(root, "start", "--mode", "live-remote", "--api-client", str(api),
                  "--server-profile", "lab", "--hostname", "host1") == 0
    assert saved(root)["setup"]["api_client"] == str(api)
    assert (root / "cases/case1/AGENTS.md").is_file()
    assert invoke(root, "resume") == 0
    assert verify.call_args.args[0].server_profile == "lab"
    assert verify.call_args.args[0].hostname == "host1"
    run.assert_not_called()


def test_missing_config_does_not_trigger_ssh_or_slack(workstation, monkeypatch):
    run = Mock()
    monkeypatch.setattr(setup.subprocess, "run", run)
    assert invoke(workstation, "start", "--mode", "live-remote", "--hostname", "host1") == 1
    run.assert_not_called()
    assert saved(workstation)["status"] == "needs_attention"


def test_start_and_resume_print_ai_setup_note_without_running_wizard(workstation, monkeypatch, capsys):
    from vraptor.agent import manage
    import shlex

    root = workstation
    config = root / "custom settings.toml"
    config.write_text('schema_version=1\n')
    api = root / "api.yaml"
    api.touch()
    wizard = Mock(side_effect=AssertionError("No implicit AI configuration"))
    monkeypatch.setattr(manage, "main", wizard)
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    assert invoke(root, "start", "--mode", "live-remote", "--hostname", "host1",
                  "--api-client", str(api), "--settings-file", str(config), "--org-id", "O.selected") == 0
    for action in (None, "resume"):
        if action:
            assert invoke(root, action, "--settings-file", str(config)) == 0
        output = capsys.readouterr()
        assert json.loads(output.out)["status"] == "ready"
        assert shlex.split(output.err.strip().removeprefix("To configure AI, run: ")) == [
            "vraptor", "ai", "setup", "--settings-file", str(config)]
        assert saved(root)["setup"]["org_id"] == "O.selected"
    wizard.assert_not_called()
    assert invoke(root, "resume", "--org-id", "O.changed") == 1
    assert saved(root)["setup"]["org_id"] == "O.selected"


def test_fetch_does_not_enable_provisioning(workstation, monkeypatch):
    calls = []

    def fetch(command, **kwargs):
        calls.append(command)
        dest = Path(command[command.index("--output-path") + 1])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.touch()
        assert kwargs["env"]["VRAPTOR_SETTINGS_RESOLVED"] == "1"
        assert kwargs["env"]["VELO_REMOTE_RUN_AS"] == "root"
        return Mock(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", fetch)
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: {"identity": "operator"})
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    assert invoke(workstation, "start", "--mode", "live-remote", "--hostname", "host1",
                  "--fetch-config", "--server-ip", "192.0.2.1", "--run-as", "root", "--api-user", "operator") == 0
    assert len(calls) == 1
    assert "--provision-api" not in calls[0]
    assert "--regenerate-remote-api" not in calls[0]
    assert "fetch_config" not in saved(workstation)["setup"]


@pytest.mark.parametrize("interactive", [False, True])
def test_manual_remote_preparation_requires_continue(workstation, monkeypatch, capsys, interactive):
    calls = []
    instructions = "Run the displayed API creation command in your terminal, then Continue."

    def fetch(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            assert kwargs["stdin"] is (None if interactive else setup.subprocess.DEVNULL)
            assert kwargs["env"]["VRAPTOR_CONFIG_MANUAL_PROMPT"] == "0"
            manifest = Path(command[command.index("--json-out") + 1])
            manifest.write_text(json.dumps({"status": "needs_user_action", "instructions": instructions}))
            return Mock(returncode=3)
        Path(command[command.index("--output-path") + 1]).touch()
        return Mock(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", fetch)
    monkeypatch.setattr(setup.sys.stdin, "isatty", lambda: interactive)
    prompt = Mock(return_value="yes")
    monkeypatch.setattr("builtins.input", prompt)
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: {"identity": "operator"})
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    result = invoke(workstation, "start", "--mode", "live-remote", "--hostname", "host1",
                    "--fetch-config", "--server-ip", "192.0.2.1", "--provision-api", "--api-user", "operator")
    if interactive:
        assert result == 0
        assert len(calls) == 2
        prompt.assert_called_once()
        assert saved(workstation)["status"] == "ready"
    else:
        assert result == 1
        assert len(calls) == 1
        prompt.assert_not_called()
        assert saved(workstation)["status"] == "needs_attention"
    output = capsys.readouterr()
    assert instructions in output.out + output.err


@pytest.mark.parametrize("failure", ["different_server", "copy_failed"])
def test_refresh_preserves_existing_credentials_on_failure(workstation, monkeypatch, failure):
    root = workstation
    api = root / "api.yaml"
    api.write_text("original-credential")
    state = {"engagement_id": "case1", "mode": "live_remote", "server": {"fingerprint": "original"},
             "api": {"identity": "operator"}, "connection": {"server_profile": "lab"}}
    args = setup.parser().parse_args(["start", "--id", "case1", "--mode", "live-remote",
                                     "--server-profile", "lab", "--api-client", str(api),
                                     "--server-ip", "192.0.2.1", "--force", "--fetch-config"])
    snapshot = settings.resolve("lab", vars(args))
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda path: {
        "identity": "operator", "server_fingerprint": path.read_text()})

    def fetch(command, **kwargs):
        candidate = Path(command[command.index("--output-path") + 1])
        candidate.write_text("different")
        return Mock(returncode=1 if failure == "copy_failed" else 0)

    monkeypatch.setattr(setup.subprocess, "run", fetch)
    with pytest.raises((ValueError, RuntimeError)):
        setup._acquire(args, snapshot, state)
    assert api.read_text() == "original-credential"
    assert not list(root.glob(".setup-*"))


def test_resume_preserves_local_ports_and_status_does_not_query(workstation, monkeypatch, capsys):
    root = workstation
    evidence = root / "evidence"
    evidence.mkdir()
    (evidence / "Windows").mkdir()
    config = root / ".config/vraptor/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('schema_version=1\n[local_server]\napi_port=18421\n')
    server = Mock(side_effect=lambda path, *a, **kw: {"api_client": path / "api_client.yaml",
                                                    "client_config": path / "client.config.yaml"})
    monkeypatch.setattr(lifecycle, "ensure_local_server", server)
    monkeypatch.setattr(lifecycle, "ensure_mapping", Mock(return_value={}))
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: {})
    monkeypatch.setattr(readiness, "verify_mapped_readiness", lambda args, *a, **kw: ready(args))
    assert invoke(root, "start", "--mode", "local-deaddisk", "--evidence-path", str(evidence)) == 0
    config.write_text('schema_version=1\n[local_server]\napi_port=18422\n')
    assert invoke(root, "resume") == 0
    assert server.call_args.kwargs["api_port"] == 18421
    assert saved(root)["setup"]["local_server_workspace"] == str(root / "cases/case1/runtime/velociraptor/server")
    assert saved(root)["setup"]["workspace"] == str(root / "cases/case1/runtime/velociraptor/mapping")
    monkeypatch.setattr(setup, "start", Mock(side_effect=AssertionError("Status must be offline")))
    capsys.readouterr()
    assert invoke(root, "status") == 0
    assert json.loads(capsys.readouterr().out)["api_checked"] is False


@pytest.mark.parametrize("mode", ["local-deaddisk", "remote-deaddisk", "live-remote"])
def test_cases_share_connection_files_without_sharing_mapping_or_owning_server(workstation, monkeypatch, mode):
    api, client = workstation / "common/api.yaml", workstation / "common/client.yaml"
    api.parent.mkdir()
    api.write_text("shared-api")
    client.write_text("shared-client")
    config = workstation / "settings.toml"
    config.write_text(f'schema_version=1\n[connections.lab]\napi_client="{api}"\nclient_config="{client}"\n')
    evidence = workstation / "disk.E01"
    evidence.touch()
    server = Mock(side_effect=AssertionError("Shared server must not be adopted"))
    stop_server = Mock(side_effect=AssertionError("Shared server must not be stopped"))
    monkeypatch.setattr(lifecycle, "ensure_local_server", server)
    monkeypatch.setattr(lifecycle, "stop_local_server", stop_server)
    monkeypatch.setattr(lifecycle, "ensure_mapping", Mock(return_value={}))
    monkeypatch.setattr(lifecycle, "stop_mapping", Mock())
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: {})
    monkeypatch.setattr(readiness, "verify_mapped_readiness", lambda args, *a, **kw: ready(args))
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    for root in (workstation / "first", workstation / "second"):
        assert invoke(root, "start", "--mode", mode, "--settings-file", str(config),
                      "--server-profile", "lab", "--evidence-path", str(evidence), "--hostname", "host") == 0
        recipe = saved(root)["setup"]
        assert recipe["api_client"] == str(api)
        assert recipe["client_config"] == str(client)
        assert recipe["local_server_workspace"] is None
        runtime = root / "cases/case1/runtime/velociraptor"
        if mode == "live-remote":
            assert recipe["workspace"] is None
            assert not runtime.exists()
        else:
            assert recipe["workspace"] == str(runtime / "mapping")
            assert invoke(root, "stop", "--stop-server", "--settings-file", str(config)) == 0
        assert not (runtime / "server").exists()
    assert api.read_text() == "shared-api"
    assert client.read_text() == "shared-client"
    server.assert_not_called()
    stop_server.assert_not_called()


def test_explicit_runtime_root_and_saved_paths_survive_default_change(workstation, monkeypatch):
    evidence = workstation / "disk.E01"
    evidence.touch()
    config = workstation / "settings.toml"
    runtime = workstation / "shared-runtime"
    config.write_text(f'schema_version=1\n[workstation]\nruntime_root="{runtime}"\n')
    server = Mock(side_effect=lambda path, *a, **kw: {
        "api_client": path / "api_client.yaml", "client_config": path / "client.config.yaml"})
    monkeypatch.setattr(lifecycle, "ensure_local_server", server)
    monkeypatch.setattr(lifecycle, "ensure_mapping", Mock(return_value={}))
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: {})
    monkeypatch.setattr(readiness, "verify_mapped_readiness", lambda args, *a, **kw: ready(args))
    assert invoke(workstation, "start", "--mode", "local-deaddisk", "--evidence-path", str(evidence),
                  "--settings-file", str(config)) == 0
    before = saved(workstation)["setup"]
    assert before["workspace"] == str(runtime / "mappings/case1")
    assert before["local_server_workspace"] == str(runtime / "servers/local")
    config.write_text('schema_version=1\n')
    assert invoke(workstation, "resume", "--settings-file", str(config)) == 0
    assert saved(workstation)["setup"] == before
    assert server.call_args.args[0] == runtime / "servers/local"
    assert not (workstation / "cases/case1/runtime").exists()
    assert invoke(workstation, "resume", "--workspace", str(workstation / "replacement")) == 1
    assert saved(workstation)["setup"] == before


def test_rebinding_is_rejected_before_overwriting_state(workstation, monkeypatch):
    api = workstation / "provided.yaml"
    api.touch()
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    assert invoke(workstation, "start", "--mode", "live-remote", "--api-client", str(api),
                  "--server-profile", "lab", "--hostname", "host1") == 0
    before = saved(workstation)
    assert invoke(workstation, "resume", "--server-profile", "other") == 1
    assert saved(workstation) == before


def test_concurrent_setup_lock_fails_without_mutation(workstation):
    directory = workstation / "cases/case1"
    with setup.investigation_lock(directory):
        assert invoke(workstation, "start", "--mode", "live-remote", "--hostname", "host1") == 1
    assert not (directory / "engagement.json").exists()


def test_stop_requires_managed_mapping_and_rechecks_ownership(workstation, monkeypatch):
    path = workstation / "cases/case1/engagement.json"
    path.parent.mkdir(parents=True)
    state = {"engagement_id": "case1", "mode": "remote_dead_disk", "status": "ready",
             "setup": {"workspace": str(workstation / "mapping")}}
    path.write_text(json.dumps(state))
    stop = Mock(side_effect=ValueError("Unowned mapping"))
    monkeypatch.setattr(lifecycle, "stop_mapping", stop)
    assert invoke(workstation, "stop") == 1
    assert saved(workstation)["status"] == "ready"


def test_stop_server_recovers_failure_before_mapping_initialization(workstation, monkeypatch):
    evidence = workstation / "mounted"
    evidence.mkdir()
    (evidence / "Windows").mkdir()
    monkeypatch.setattr(lifecycle, "ensure_local_server", lambda path, *a, **kw: {
        "api_client": path / "api_client.yaml", "client_config": path / "client.config.yaml"})
    monkeypatch.setattr(readiness, "validate_api_client_security", Mock(side_effect=ValueError("invalid credential")))
    assert invoke(workstation, "start", "--mode", "local-deaddisk", "--evidence-path", str(evidence)) == 1
    stop = Mock()
    monkeypatch.setattr(lifecycle, "stop_local_server", stop)
    assert invoke(workstation, "stop", "--stop-server") == 0
    stop.assert_called_once_with(Path(saved(workstation)["setup"]["local_server_workspace"]))
    assert saved(workstation)["status"] == "stopped"


@pytest.mark.parametrize("output", ["case", "mapping", "server", "credential"])
def test_setup_outputs_cannot_write_inside_mounted_evidence(workstation, monkeypatch, capsys, output):
    evidence = workstation / "mounted"
    evidence.mkdir()
    server = Mock(side_effect=AssertionError("No server should start"))
    monkeypatch.setattr(lifecycle, "ensure_local_server", server)
    monkeypatch.setattr(setup.subprocess, "run", Mock(side_effect=AssertionError("No credentials should be fetched")))
    config = workstation / "config.toml"
    config.write_text(f'schema_version=1\n[workstation]\nruntime_root="{evidence}"\n')
    extra = {
        "case": ["--case-root", str(evidence)],
        "mapping": ["--workspace", str(evidence / "mapping")],
        "server": ["--settings-file", str(config)],
        "credential": ["--api-client", str(evidence / "api.yaml"), "--fetch-config", "--server-ip", "192.0.2.1"],
    }[output]
    assert invoke(workstation, "start", "--mode", "local-deaddisk", "--evidence-path", str(evidence), *extra) == 1
    assert "outside the mounted evidence" in capsys.readouterr().err
    server.assert_not_called()
    assert not list(evidence.iterdir())


def test_saved_api_path_is_used_by_followup_operations(workstation, monkeypatch):
    root = workstation
    path = root / "cases/case1/engagement.json"
    path.parent.mkdir(parents=True)
    api = root / "nonstandard.yaml"
    api.touch()
    path.write_text(json.dumps({"engagement_id": "case1", "connection": {"server_profile": "lab"},
                                "setup": {"api_client": str(api)}}))
    monkeypatch.setattr(context.engagement_state, "validate", lambda **kwargs: {})
    result = context.resolve(repo_root=root, engagement_id="case1", case_root=str(root / "cases"),
                             server_profile=None, api_client=None)
    assert result.api_client == api


def test_settings_files_read_once_per_setup_command(workstation, monkeypatch):
    api = workstation / "provided.yaml"
    api.touch()
    read = Mock(wraps=settings.read)
    monkeypatch.setattr(settings, "read", read)
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    assert invoke(workstation, "start", "--mode", "live-remote", "--api-client", str(api), "--hostname", "host1") == 0
    assert read.call_count == 1


def test_status_remains_available_when_credentials_file_is_missing(workstation, monkeypatch):
    api = workstation / "api.yaml"
    api.touch()
    monkeypatch.setattr(readiness, "command_live_remote", ready)
    assert invoke(workstation, "start", "--mode", "live-remote", "--api-client", str(api), "--hostname", "host1") == 0
    config = workstation / ".config/vraptor/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('schema_version=1\n[credentials]\nenv_file="missing.env"\n')
    assert invoke(workstation, "status") == 0
    assert invoke(workstation, "resume") == 1


def test_invalid_native_yaml_diagnostics_do_not_echo_credentials(workstation):
    api = workstation / "invalid.yaml"
    api.write_text('client_private_key: [never-print-this-secret\n')
    with pytest.raises(RuntimeError) as error:
        readiness.validate_api_client_security(api)
    assert "never-print-this-secret" not in str(error.value)


@pytest.fixture
def multi_mapping(workstation, monkeypatch):
    root = workstation
    metadata = {"identity": "analyst", "server_fingerprint": "server-one", "org_id": "root",
                "credential_sha256": "credential-one", "credential_security": {
                    "certificate_status": "valid", "private_key_present": True,
                    "group_or_other_access": False, "owner_matches_current_user": True}}
    monkeypatch.setattr(readiness_state, "api_metadata", lambda _: dict(metadata))
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda _: dict(metadata))

    def server(path, *a, **kw):
        path.mkdir(parents=True, exist_ok=True)
        for name in ("api_client.yaml", "client.config.yaml"):
            (path / name).touch()
        return {"api_client": path / "api_client.yaml", "client_config": path / "client.config.yaml"}

    server_call = Mock(side_effect=server)
    monkeypatch.setattr(lifecycle, "ensure_local_server", server_call)
    monkeypatch.setattr(lifecycle, "ensure_mapping", Mock(return_value={}))

    def verify(args, *a, **kw):
        return readiness_state.build_state(
            engagement_id=args.engagement_id, engagement_id_source="explicit",
            server_profile=args.server_profile, mode=setup.MODES[args.mode],
            source_skill="velociraptor-mapped-client", api_client_path=Path(args.api_client),
            verification={"server_reachable": True, "target_visible": True,
                          "client_id": "C." + args.hostname, "hostname": args.hostname,
                          "last_seen": "2026-01-01T00:00:00Z", "scope_type": "client_id"},
            next_step_hint="Analyze the selected host.")

    monkeypatch.setattr(readiness, "verify_mapped_readiness", verify)
    for host in ("host1", "host2", "host3"):
        (root / f"{host}.E01").touch()
    monkeypatch.setattr(lifecycle, "stop_mapping", Mock())
    return root, server_call, metadata


def add_host(root, host, *extra):
    return invoke(root, "start", "--mode", "local-deaddisk", "--mapping-id", host,
                  "--hostname", host, "--evidence-path", str(root / f"{host}.E01"), *extra)


@pytest.mark.parametrize("mode", ["local-deaddisk", "remote-deaddisk"])
def test_two_images_share_case_and_server_but_keep_mapping_identity(multi_mapping, mode):
    root, server, _ = multi_mapping
    extra = []
    if mode == "remote-deaddisk":
        for name in ("api.yaml", "client.yaml"):
            (root / name).touch()
        extra = ["--mode", mode, "--server-profile", "remote", "--api-client", str(root / "api.yaml"),
                 "--client-config", str(root / "client.yaml")]
    assert add_host(root, "host1", *extra) == 0
    first = saved(root)["mappings"]["host1"]
    assert add_host(root, "host2", *extra) == 0
    state = saved(root)
    assert state["mappings"]["host1"] == first
    assert set(state["mappings"]) == {"host1", "host2"}
    assert state["readiness"]["matched_client_count"] == 2
    if mode == "local-deaddisk":
        assert {call.args[0] for call in server.call_args_list} == {root / "cases/case1/runtime/velociraptor/server"}
    else:
        server.assert_not_called()
    for host in state["mappings"]:
        recipe = state["mappings"][host]["setup"]
        assert recipe["workspace"] == str(root / "cases/case1/runtime/velociraptor/mappings" / host)
        assert invoke(root, "resume", "--mapping-id", host) == 0
        assert saved(root)["mappings"][host]["setup"] == recipe
        readiness_state.validate(path=root / "cases/case1/engagement.json", engagement_id="case1",
                                 server_profile=recipe["server_profile"], api_client=Path(recipe["api_client"]),
                                 requested_client_id="C." + host, requested_hostname=None)


def test_multiple_mappings_require_selection_and_preserve_binding(multi_mapping):
    root, _, _ = multi_mapping
    assert add_host(root, "host1") == 0
    assert add_host(root, "host2") == 0
    before = saved(root)
    assert invoke(root, "resume") == 1
    assert invoke(root, "stop") == 1
    assert invoke(root, "resume", "--mapping-id", "host1", "--evidence-path", str(root / "host2.E01")) == 1
    assert add_host(root, "host3", "--server-profile", "another-server") == 1
    assert add_host(root, "host3", "--workspace", before["mappings"]["host1"]["setup"]["workspace"]) == 1
    assert add_host(root, "host3", "--hostname", "host1") == 1
    assert saved(root) == before


def test_stopped_mapping_cannot_inherit_sibling_readiness(multi_mapping, monkeypatch):
    root, _, _ = multi_mapping
    assert add_host(root, "host1") == 0
    assert add_host(root, "host2") == 0
    monkeypatch.setattr(lifecycle, "stop_local_server", Mock(side_effect=ValueError("active sibling")))
    assert invoke(root, "stop", "--mapping-id", "host1", "--stop-server") == 1
    assert saved(root)["mappings"]["host1"]["status"] == "stopped"
    assert saved(root)["mappings"]["host2"]["status"] == "ready"
    assert invoke(root, "resume", "--mapping-id", "host2") == 0
    options = dict(path=root / "cases/case1/engagement.json", engagement_id="case1",
                   server_profile="local", api_client=Path(saved(root)["setup"]["api_client"]))
    readiness_state.validate(**options, requested_client_id="C.host2")
    selected = context.resolve(repo_root=root, engagement_id="case1", case_root=str(root / "cases"),
                               server_profile=None, api_client=None, requested_client_id="C.host2")
    assert selected.state["status"] == "ready"
    assert selected.state["readiness"]["targets"][0]["client_id"] == "C.host2"
    with pytest.raises(RuntimeError, match="status=stopped"):
        readiness_state.validate(**options, requested_client_id="C.host1")
    with pytest.raises(RuntimeError, match="exactly one"):
        readiness_state.validate(**options, requested_client_id="C.unknown")
    with pytest.raises(RuntimeError, match="status=needs_attention"):
        readiness_state.validate(**options)


def test_failed_new_mapping_preserves_ready_sibling(multi_mapping, monkeypatch):
    root, _, _ = multi_mapping
    assert add_host(root, "host1") == 0
    first = saved(root)["mappings"]["host1"]
    monkeypatch.setattr(lifecycle, "ensure_mapping", Mock(side_effect=ValueError("failed enrollment")))
    assert add_host(root, "host2") == 1
    assert saved(root)["mappings"]["host1"] == first
    assert saved(root)["mappings"]["host2"]["status"] == "needs_attention"
    readiness_state.validate(path=root / "cases/case1/engagement.json", engagement_id="case1",
                             server_profile="local", api_client=Path(first["setup"]["api_client"]),
                             requested_client_id="C.host1")


def test_legacy_mapping_is_retained_when_adding_named_host(multi_mapping):
    root, _, _ = multi_mapping
    assert invoke(root, "start", "--mode", "local-deaddisk", "--hostname", "host1",
                  "--evidence-path", str(root / "host1.E01")) == 0
    original = saved(root)
    assert add_host(root, "host2") == 0
    assert saved(root)["mappings"]["default"] == original
    assert invoke(root, "resume", "--mapping-id", "default") == 0
    assert saved(root)["mappings"]["default"]["setup"]["workspace"] == original["setup"]["workspace"]


def test_mapping_credential_refresh_does_not_refresh_other_hosts(multi_mapping):
    root, _, metadata = multi_mapping
    assert add_host(root, "host1") == 0
    assert add_host(root, "host2") == 0
    metadata["credential_sha256"] = "renewed-credential"
    assert invoke(root, "resume", "--mapping-id", "host2") == 0
    options = dict(path=root / "cases/case1/engagement.json", engagement_id="case1",
                   server_profile="local", api_client=Path(saved(root)["setup"]["api_client"]))
    readiness_state.validate(**options, requested_client_id="C.host2")
    with pytest.raises(RuntimeError, match="content hash"):
        readiness_state.validate(**options, requested_client_id="C.host1")
    with pytest.raises(RuntimeError, match="status=needs_attention"):
        readiness_state.validate(**options)
    assert invoke(root, "resume", "--mapping-id", "host1") == 0
    readiness_state.validate(**options)


def test_mapping_resume_reads_case_state_only_twice(multi_mapping, monkeypatch):
    root, _, _ = multi_mapping
    assert add_host(root, "host1") == 0
    read = Mock(wraps=readiness_state.load)
    monkeypatch.setattr(readiness_state, "load", read)
    assert invoke(root, "resume", "--mapping-id", "host1") == 0
    assert read.call_count == 2
