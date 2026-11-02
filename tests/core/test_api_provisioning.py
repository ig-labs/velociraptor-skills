"""Offline provisioning tests: no real SSH, API, credential generation or services."""
import argparse
import hashlib
import json
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from vraptor import api_provisioning as provisioning
from vraptor import readiness, settings, setup


def account(name="selected", org="root", roles=None, policy=None):
    return {"name": name, "org_id": org, "roles": roles or ["administrator", "api"],
            "effective_policy": policy if policy is not None else {"any_query": True, "server_admin": True}}


def request(**changes):
    return {"api_user": "selected", "org_id": "root", "role_profile": "provisioning-admin",
            "bootstrap_user": "bootstrap-admin", "bootstrap_path": "/secure/admin.yaml",
            "server_config": "/secure/server.yaml", "binary": "velociraptor", **changes}


class Server(provisioning.RemoteProvisioner):
    def __init__(self, existing=None, **changes):
        super().__init__(request(**changes))
        self.existing = existing
        self.calls = []
        self.bootstrap = {"identity": "bootstrap-admin", "account": account("bootstrap-admin")}
        self.creation_error = None
        self.concurrent_account = None
        self.lookups = 0

    def query(self, query, **kwargs):
        self.calls.append(query)
        if "whoami()" in query:
            return self.bootstrap, False
        if "user_create(" in query:
            if self.creation_error:
                raise self.creation_error
            self.existing = account()
            return {"created": "selected"}, False
        self.lookups += 1
        if self.lookups == 2 and self.concurrent_account:
            self.existing = self.concurrent_account
        return {"account": self.existing}, self.existing is None

    @property
    def writes(self):
        return [q for q in self.calls if "user_create(" in q]


def test_absent_user_created_once_and_existing_user_is_read_only(tmp_path):
    server = Server()
    assert server.provision(tmp_path, "a" * 64)["status"] == "created"
    assert len(server.writes) == 1
    assert len(server.calls) == 5
    assert 'orgs=["root"]' in server.writes[0]
    assert server.provision(tmp_path, "a" * 64)["status"] == "existing"
    assert len(server.writes) == 1
    assert len(server.calls) == 7
    assert not list(tmp_path.glob("*.pending"))
    assert all("clients(" not in q and "hunt(" not in q for q in server.calls)


@pytest.mark.parametrize("existing", [account(roles=["reader"]), account(org="other"), account(name="different"), account(policy={"any_query": True})])
def test_existing_mismatch_never_changes_account(tmp_path, existing):
    server = Server(existing)
    with pytest.raises(RuntimeError):
        server.provision(tmp_path, "a" * 64)
    assert not server.writes
    assert server.existing == existing


@pytest.mark.parametrize("change", [
    {"identity": "wrong"}, {"account": account("bootstrap-admin", org="other")},
    {"account": account("bootstrap-admin", policy={"any_query": True})},
])
def test_bootstrap_checks_before_target_lookup_or_write(tmp_path, change):
    server = Server()
    server.bootstrap.update(change)
    with pytest.raises(RuntimeError):
        server.provision(tmp_path, "a" * 64)
    assert len(server.calls) == 1
    assert not server.writes


def test_second_lookup_preserves_account_created_by_another_run(tmp_path):
    server = Server()
    server.concurrent_account = account(roles=["reader"])
    with pytest.raises(RuntimeError, match="roles"):
        server.provision(tmp_path, "a" * 64)
    assert not server.writes


def test_uncertain_creation_persists_marker_and_never_replays(tmp_path):
    server = Server()
    server.creation_error = RuntimeError("timeout")
    with pytest.raises(provisioning.ProvisioningError, match="uncertain"):
        server.provision(tmp_path, "a" * 64)
    assert len(list(tmp_path.glob("*.pending"))) == 1
    server.creation_error = None
    with pytest.raises(RuntimeError, match="uncertain"):
        server.provision(tmp_path, "a" * 64)
    assert len(server.writes) == 1
    server.existing = account()
    assert server.provision(tmp_path, "a" * 64)["status"] == "reconciled"
    assert len(server.writes) == 1


def test_failed_post_creation_lookup_reports_uncertain_write(tmp_path, monkeypatch):
    server = Server()
    original_lookup = server.lookup

    def lookup():
        if server.writes:
            raise provisioning.ProvisioningError("absence")
        return original_lookup()

    monkeypatch.setattr(server, "lookup", lookup)
    with pytest.raises(provisioning.ProvisioningError, match="uncertain"):
        server.provision(tmp_path, "a" * 64)
    assert len(server.writes) == 1
    assert len(list(tmp_path.glob("*.pending"))) == 1


@pytest.mark.parametrize("stdout,stderr,code,absent", [
    ('{"account": null}\n', 'user: User not found: selected\n', 0, True),
    ('{"account": null}\n', '[INFO] 2026-01-01T00:00:00Z user: User not found: selected\n', 0, True),
    ('{"account": null}\n', '', 0, False),
    ('{"account": null}\n', 'user: PermissionDenied\n', 0, False),
    ('{"account": null}\n', 'user: User not found: another\n', 0, False),
    ('{"account": null}\n', 'user: User not found: selected\nError: failed\n', 0, False),
    ('{"account": null}\n', 'user: User not found: selected\n', 1, False),
    ('secret-invalid-output', '', 0, False),
])
def test_lookup_requires_exact_confirmed_absence(monkeypatch, stdout, stderr, code, absent):
    run = Mock(return_value=SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code))
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    server = provisioning.RemoteProvisioner(request())
    if absent:
        assert server.lookup() is None
    else:
        with pytest.raises(RuntimeError) as error:
            server.lookup()
        assert "secret-invalid-output" not in str(error.value)
    command = run.call_args.args[0]
    assert command[:5] == ["velociraptor", "--api_config", "/secure/admin.yaml", "--org", "root"]
    assert "--config" not in command


@pytest.mark.parametrize("scenario,status,writes,queries", [
    ("absent", "created", 1, 5),
    ("existing", "existing", 0, 2),
    ("denied", None, 0, 2),
    ("silent", None, 0, 2),
    ("wrong_user", None, 0, 2),
    ("mixed_error", None, 0, 2),
])
def test_native_cli_diagnostics_control_provisioning(tmp_path, capsys, scenario, status, writes, queries):
    """Exercise real subprocess capture with native-style verbosity gating.

    Remote VQL diagnostics are INFO logs, including permission failures. The
    CLI suppresses them without --verbose even when it returns null/exit zero.
    This executable is a local test double; it never opens a network connection.
    """
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "account": account() if scenario == "existing" else None,
        "bootstrap": {"identity": "bootstrap-admin", "account": account("bootstrap-admin")},
        "scenario": scenario, "writes": 0, "queries": 0,
    }))
    binary = tmp_path / "fake-velociraptor"
    binary.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import json
        from pathlib import Path
        import sys

        path = Path(__file__).with_name("state.json")
        state = json.loads(path.read_text())
        state["queries"] += 1
        query = sys.argv[-1]
        messages = []
        if "whoami()" in query:
            row = state["bootstrap"]
        elif "user_create(" in query:
            state["writes"] += 1
            state["account"] = {**state["bootstrap"]["account"], "name": "selected"}
            row = {"created": "selected"}
        else:
            row = {"account": state["account"]}
            if state["account"] is None:
                messages = {
                    "absent": ["user: User not found: selected"],
                    "silent": [],
                    "denied": ["user: PermissionDenied private-diagnostic-sentinel"],
                    "wrong_user": ["user: User not found: another"],
                    "mixed_error": ["user: User not found: selected", "Error: failed private-diagnostic-sentinel"],
                }[state["scenario"]]
        if "--verbose" in sys.argv:
            for message in messages:
                line = "[INFO] 2026-01-01T00:00:00Z " + message
                if "--nocolor" not in sys.argv:
                    line = "\\x1b[32m" + line + "\\x1b[0m"
                print(line, file=sys.stderr)
        path.write_text(json.dumps(state))
        print(json.dumps(row))
    '''))
    binary.chmod(0o700)
    server = provisioning.RemoteProvisioner(request(binary=str(binary)))
    if status:
        receipt = server.provision(tmp_path, "a" * 64)
        assert receipt["status"] == status
    else:
        with pytest.raises(RuntimeError) as error:
            server.provision(tmp_path, "a" * 64)
        assert "private-diagnostic-sentinel" not in str(error.value)
        if scenario != "silent":
            assert "reported a query error" in str(error.value)
    state = json.loads(state_path.read_text())
    assert state["writes"] == writes
    assert state["queries"] == queries
    assert not list(tmp_path.glob("*.pending"))
    captured = capsys.readouterr()
    assert not captured.out and not captured.err


def args(**changes):
    return argparse.Namespace(**{"provision_api": True, "api_user": "selected", "org_id": "root",
                                 "api_role_profile": "provisioning-admin", "server_profile": "lab",
                                 "server_ip": "192.0.2.10", "bootstrap_api_config": None,
                                 "bootstrap_api_user": None, "api_account_ready": False,
                                 "api_account_setup": False, "api_client": None, **changes})


def snapshot(tmp_path):
    return SimpleNamespace(values={"config_root": str(tmp_path), "ssh_user": "root", "ssh_key": "/keys/test"}, environment={})


def test_generic_requires_manual_account_setup_without_ssh(tmp_path, monkeypatch):
    run = Mock(side_effect=AssertionError("No SSH"))
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    monkeypatch.setattr(provisioning.sys.stdin, "isatty", lambda: False)
    selected = args()
    with pytest.raises(RuntimeError, match="Manual API account setup") as error:
        provisioning.prepare_account(selected, snapshot(tmp_path))
    assert "--api-account-ready" in str(error.value)
    selected.api_account_ready = True
    assert provisioning.prepare_account(selected, snapshot(tmp_path))["status"] == "manual"
    run.assert_not_called()


def cached_api(tmp_path, monkeypatch, identity="selected", verify=None):
    api = tmp_path / "api.yaml"
    api.write_text("cached")
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda path: {"identity": identity})
    verify = verify or Mock(return_value={})
    monkeypatch.setattr(readiness, "verify_api_authorization", verify)
    monkeypatch.setattr(provisioning.subprocess, "run", Mock(side_effect=AssertionError("No SSH")))
    return str(api), verify


def test_generic_skips_manual_step_when_cached_yaml_works(tmp_path, monkeypatch, capsys):
    api, verify = cached_api(tmp_path, monkeypatch)
    monkeypatch.setattr(provisioning.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("No prompt")))
    assert provisioning.prepare_account(args(api_client=api), snapshot(tmp_path)) is None
    verify.assert_called_once_with(Path(api), api_user="selected", role_profile="provisioning-admin")
    captured = capsys.readouterr()
    assert not captured.out
    assert "already works" in captured.err and "--api-account-setup" in captured.err


@pytest.mark.parametrize(("answer", "expected"), [("", None), ("n", None), ("yes", "manual")])
def test_interactive_setup_offers_manual_step_when_cached_yaml_works(tmp_path, monkeypatch, capsys,
                                                                     answer, expected):
    api, _ = cached_api(tmp_path, monkeypatch)
    monkeypatch.setattr(provisioning.sys.stdin, "isatty", lambda: True)
    prompt = Mock(side_effect=[answer, "y"])
    monkeypatch.setattr("builtins.input", prompt)
    result = provisioning.prepare_account(args(api_client=api), snapshot(tmp_path))
    assert (result or {}).get("status") == expected
    assert "Run the manual account step anyway?" in prompt.call_args_list[0].args[0]
    shown = "Manual API account setup" in capsys.readouterr().out
    assert shown is (expected == "manual")
    assert prompt.call_count == (2 if expected else 1)


@pytest.mark.parametrize("case", ["api_account_setup", "other_identity", "invalid_credential", "verify_fails",
                                  "missing_file", "force", "regenerate_remote_api"])
def test_generic_runs_manual_step_unless_cached_yaml_works(tmp_path, monkeypatch, case):
    verify = Mock(side_effect=RuntimeError("Live API role profile is missing required roles"))
    api, verify = cached_api(tmp_path, monkeypatch, identity="other" if case == "other_identity" else "selected",
                             verify=verify if case == "verify_fails" else None)
    if case == "invalid_credential":
        monkeypatch.setattr(readiness, "validate_api_client_security",
                            Mock(side_effect=RuntimeError("Velociraptor API credential validation failed: expired")))
    selected = args(api_client=str(tmp_path / "absent.yaml") if case == "missing_file" else api,
                    api_account_setup=case == "api_account_setup", force=case == "force",
                    regenerate_remote_api=case == "regenerate_remote_api")
    monkeypatch.setattr(provisioning.sys.stdin, "isatty", lambda: False)
    with pytest.raises(RuntimeError, match="Manual API account setup"):
        provisioning.prepare_account(selected, snapshot(tmp_path))
    assert verify.call_count == (1 if case == "verify_fails" else 0)


@pytest.mark.parametrize("interactive", [False, True])
def test_account_ready_skips_cached_check_and_prompts(tmp_path, monkeypatch, capsys, interactive):
    api, verify = cached_api(tmp_path, monkeypatch)
    monkeypatch.setattr(provisioning.sys.stdin, "isatty", lambda: interactive)
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("No prompt")))
    selected = args(api_client=api, api_account_ready=True, api_account_setup=True)
    assert provisioning.prepare_account(selected, snapshot(tmp_path)) == {
        "status": "manual", "api_user": "selected", "org_id": "root"}
    verify.assert_not_called()
    assert not capsys.readouterr().err


def test_bootstrap_ignores_cached_check(tmp_path, monkeypatch):
    api, verify = cached_api(tmp_path, monkeypatch)
    monkeypatch.setattr("vraptor.readiness_state.api_metadata", lambda path: {"ca_sha256": "a" * 64})
    receipt = {"status": "existing", "api_user": "selected", "org_id": "root", "ca_sha256": "a" * 64}
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(receipt)))
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    selected = args(api_client=api, bootstrap_api_config="/secure/admin.yaml", bootstrap_api_user="bootstrap-admin")
    assert provisioning.prepare_account(selected, snapshot(tmp_path)) == receipt
    assert run.call_count == 1
    verify.assert_not_called()


def test_account_setup_flag_is_manual_only(tmp_path, monkeypatch):
    selected = args(api_account_setup=True, bootstrap_api_config="/secure/admin.yaml",
                    bootstrap_api_user="bootstrap-admin")
    monkeypatch.setattr(provisioning.subprocess, "run", Mock(side_effect=AssertionError("No SSH")))
    with pytest.raises(ValueError, match="--api-account-setup applies only to manual"):
        provisioning.prepare_account(selected, snapshot(tmp_path))


def test_remote_bootstrap_keeps_key_remote_and_returns_only_receipt(tmp_path, monkeypatch):
    selected = args()
    selected.bootstrap_api_config, selected.bootstrap_api_user = "/secure/admin.yaml", "bootstrap-admin"
    receipt = {"status": "created", "api_user": "selected", "org_id": "root", "ca_sha256": "a" * 64}
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(receipt)))
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    assert provisioning.prepare_account(selected, snapshot(tmp_path)) == receipt
    command = run.call_args.args[0]
    assert command[0] == "ssh"
    assert "StrictHostKeyChecking=yes" in command
    assert json.loads(run.call_args.kwargs["input"])["bootstrap_path"] == "/secure/admin.yaml"
    assert not list(tmp_path.iterdir())
    assert run.call_count == 1


@pytest.mark.parametrize("failure", ["transport", "identity", "org", "missing_ca", "native_failure"])
def test_remote_bootstrap_failures_stop_without_retry(tmp_path, monkeypatch, failure):
    selected = args()
    selected.bootstrap_api_config, selected.bootstrap_api_user = "/secure/admin.yaml", "bootstrap-admin"
    receipt = {"status": "existing", "api_user": "selected", "org_id": "root", "ca_sha256": "a" * 64}
    if failure == "identity": receipt["api_user"] = "different"
    if failure == "org": receipt["org_id"] = "different"
    if failure == "missing_ca": receipt.pop("ca_sha256")
    if failure == "native_failure": receipt = {"status": "failed"}
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(receipt)))
    if failure == "transport": run.side_effect = OSError("secret")
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    with pytest.raises(RuntimeError) as error:
        provisioning.prepare_account(selected, snapshot(tmp_path))
    assert "secret" not in str(error.value)
    assert run.call_count == 1


def test_remote_ca_mismatch_prevents_queries(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    credential, config = tmp_path / "admin.yaml", tmp_path / "server.yaml"
    credential.write_text(yaml.safe_dump({"name": "bootstrap-admin", "ca_certificate": "CA-one", "client_private_key": "private-secret"}))
    credential.chmod(0o600)
    config.write_text(yaml.safe_dump({"Client": {"ca_certificate": "CA-two"}}))
    query = Mock(side_effect=AssertionError("No API call"))
    monkeypatch.setattr(provisioning.RemoteProvisioner, "query", query)
    with pytest.raises(RuntimeError, match="CA bindings"):
        provisioning.remote_main(request(bootstrap_path=str(credential), server_config=str(config)))
    query.assert_not_called()


def test_cached_ca_binding_is_checked_before_remote_queries(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    credential, config = tmp_path / "admin.yaml", tmp_path / "server.yaml"
    credential.write_text(yaml.safe_dump({"name": "bootstrap-admin", "ca_certificate": "CA-wrong"}))
    credential.chmod(0o600)
    config.write_text(yaml.safe_dump({"Client": {"ca_certificate": "CA-wrong"}}))
    query = Mock(side_effect=AssertionError("No API call to a different server"))
    monkeypatch.setattr(provisioning.RemoteProvisioner, "query", query)
    with pytest.raises(RuntimeError, match="CA bindings"):
        provisioning.remote_main(request(
            bootstrap_path=str(credential), server_config=str(config),
            expected_ca_sha256=hashlib.sha256(b"CA-intended").hexdigest(),
        ))
    query.assert_not_called()


def test_bootstrap_request_carries_cached_server_ca(tmp_path, monkeypatch):
    selected = args()
    selected.bootstrap_api_config, selected.bootstrap_api_user = "/secure/admin.yaml", "bootstrap-admin"
    api = tmp_path / "api.yaml"
    api.write_text(yaml.safe_dump({"name": "selected", "ca_certificate": "CA-intended"}))
    selected.api_client = str(api)
    ca_hash = hashlib.sha256(b"CA-intended").hexdigest()
    receipt = {"status": "existing", "api_user": "selected", "org_id": "root", "ca_sha256": ca_hash}
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(receipt)))
    monkeypatch.setattr(provisioning.subprocess, "run", run)
    provisioning.prepare_account(selected, snapshot(tmp_path))
    assert json.loads(run.call_args.kwargs["input"])["expected_ca_sha256"] == ca_hash


@pytest.mark.parametrize("row", [
    {"identity": "selected", **account(name="")},
    {"identity": "wrong", **account()},
    {"identity": "selected", **account(org="other")},
    {"identity": "selected", **account(policy={"server_admin": True})},
])
def test_operational_readiness_rejects_identity_org_and_permission_mismatch(monkeypatch, row):
    monkeypatch.setattr(readiness, "remote_query", lambda *args: [row])
    monkeypatch.setattr(settings, "current", lambda: None)
    monkeypatch.delenv("VELO_LOCAL_ORG_ID", raising=False)
    with pytest.raises(RuntimeError):
        readiness.verify_api_authorization(Path("unused"), api_user="selected", role_profile="provisioning-admin")


@pytest.mark.parametrize("admin_permission", ["server_admin", "super_user"])
def test_investigation_rejects_direct_admin_permissions(monkeypatch, admin_permission):
    row = {"identity": "selected", **account(roles=["investigator", "api"], policy={
        "any_query": True, "read_results": True, "collect_client": True,
        "start_hunt": True, admin_permission: True,
    })}
    monkeypatch.setattr(readiness, "remote_query", lambda *args: [row])
    monkeypatch.setattr(settings, "current", lambda: None)
    monkeypatch.delenv("VELO_LOCAL_ORG_ID", raising=False)
    with pytest.raises(RuntimeError, match="administrator permissions"):
        readiness.verify_api_authorization(Path("unused"), api_user="selected", role_profile="investigation")


def test_generated_yaml_but_live_authentication_failure_preserves_cache(tmp_path, monkeypatch):
    api = tmp_path / "api.yaml"
    api.write_text("original")
    selected = setup.parser().parse_args(["start", "--mode", "live-remote", "--id", "case1",
        "--api-client", str(api), "--api-user", "selected", "--api-role-profile", "provisioning-admin"])
    def fetch(args, snapshot, candidates, replacements, cleanup):
        staged = tmp_path / "staged.yaml"
        staged.write_text("generated")
        candidates.api_client = str(staged)
        replacements.append((staged, api))
    monkeypatch.setattr(setup, "_fetch", fetch)
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda p: {"identity": "selected"})
    verify = Mock(side_effect=RuntimeError("User not found: selected"))
    monkeypatch.setattr(readiness, "verify_api_authorization", verify)
    with pytest.raises(RuntimeError, match="User not found"):
        setup._acquire(selected, None, {})
    assert api.read_text() == "original"
    assert verify.call_count == 1


def test_same_host_lock_prevents_concurrent_queries(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    credential, config = tmp_path / "admin.yaml", tmp_path / "server.yaml"
    credential.write_text(yaml.safe_dump({"name": "bootstrap-admin", "ca_certificate": "CA"}))
    credential.chmod(0o600)
    config.write_text(yaml.safe_dump({"Client": {"ca_certificate": "CA"}}))
    query = Mock(side_effect=AssertionError("No API call"))
    monkeypatch.setattr(provisioning.RemoteProvisioner, "query", query)
    with (tmp_path / ".vraptor-api-provision.lock").open("w") as lock:
        provisioning.fcntl.flock(lock, provisioning.fcntl.LOCK_EX)
        with pytest.raises(RuntimeError, match="Another account"):
            provisioning.remote_main(request(bootstrap_path=str(credential), server_config=str(config)))
    query.assert_not_called()


def test_bootstrap_settings_are_opt_in_and_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(settings.os, "environ", {"HOME": str(tmp_path)})
    config = tmp_path / "config.toml"
    config.write_text('schema_version = 1\n[connections.lab]\napi_user="selected"\n'
                      'bootstrap_api_user="bootstrap-admin"\nbootstrap_api_config="/secure/admin.yaml"\n')
    generic = settings.resolve("other", config_file=str(config), repo_root=tmp_path)
    assert "bootstrap_api_user" not in generic.values
    assert "bootstrap_api_config" not in generic.values
    selected = settings.resolve("lab", config_file=str(config), repo_root=tmp_path)
    assert selected.values["api_user"] == "selected"
    assert selected.environment["VELO_REMOTE_BOOTSTRAP_API_USER"] == "bootstrap-admin"
    assert selected.environment["VELO_REMOTE_API_USER"] == "selected"


def test_cached_bootstrap_yaml_is_rejected_even_without_provisioning(tmp_path, monkeypatch):
    api = tmp_path / "api.yaml"
    api.write_text("bootstrap")
    selected = setup.parser().parse_args(["start", "--mode", "live-remote", "--id", "case1",
        "--api-client", str(api), "--bootstrap-api-user", "bootstrap-admin"])
    monkeypatch.setattr(setup, "_fetch", lambda *a: None)
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda p: {"identity": "bootstrap-admin"})
    query = Mock(side_effect=AssertionError("No operational bootstrap query"))
    monkeypatch.setattr(readiness, "verify_api_authorization", query)
    with pytest.raises(ValueError, match="Bootstrap credentials"):
        setup._acquire(selected, None, {})
    query.assert_not_called()


def test_operational_ca_mismatch_stops_before_authentication(tmp_path, monkeypatch):
    api = tmp_path / "api.yaml"
    api.write_text("selected")
    selected = setup.parser().parse_args(["start", "--mode", "live-remote", "--id", "case1",
        "--api-client", str(api), "--api-user", "selected"])
    monkeypatch.setattr(setup, "_fetch", lambda *a: None)
    monkeypatch.setattr(readiness, "validate_api_client_security", lambda p: {"identity": "selected", "ca_sha256": "other"})
    query = Mock(side_effect=AssertionError("No query to the wrong server"))
    monkeypatch.setattr(readiness, "verify_api_authorization", query)
    with pytest.raises(ValueError, match="different CA"):
        setup._acquire(selected, None, {}, {"ca_sha256": "expected"})
    query.assert_not_called()
