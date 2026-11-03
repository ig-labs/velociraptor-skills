"""Account-only provisioning. Bootstrap credentials never enter the local API client.

The remote runner uses Python 3 and PyYAML already installed on the SSH host.
Its lock serializes this tool, not unrelated GUI/API administrators: coordinate
external user-management writes while provisioning (user_create is an upsert).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROLE_PROFILES = {
    "provisioning-admin": ["administrator", "api"],
    "investigation": ["investigator", "api"],
}

REMOTE_FAILURES = {
    "identity": "Bootstrap authenticated identity mismatch.",
    "organization": "Bootstrap organization mismatch.",
    "permissions": "Bootstrap requires ANY_QUERY and SERVER_ADMIN in the selected organization.",
    "absence": "Account absence was not confirmed; no creation attempted.",
    "pending": "Creation has an uncertain outcome; reconcile the remote pending operation before retrying.",
    "busy": "Another account provisioning operation is running; no creation attempted.",
    "binding": "Bootstrap, selected server, or cached operational configuration have different CA bindings.",
}


class ProvisioningError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(REMOTE_FAILURES[code])


def normalized_org(value):
    return "root" if value in ("", "root") else value


def validate_account(account, username, org_id, role_profile):
    if not isinstance(account, dict) or account.get("name") != username:
        raise RuntimeError("Account verification returned a missing or different identity.")
    if "org_id" not in account or normalized_org(account["org_id"]) != normalized_org(org_id):
        raise RuntimeError("Account verification returned a missing or different organization.")
    roles = set(account.get("roles") or [])
    if not set(ROLE_PROFILES[role_profile]) <= roles:
        raise RuntimeError("Existing account lacks the selected roles; no permissions were changed.")
    policy = account.get("effective_policy") or {}
    required = {"any_query", "read_results", "collect_client", "start_hunt"}
    if role_profile == "provisioning-admin":
        required = {"any_query", "server_admin"}
    elif "administrator" in roles or policy.get("server_admin") or policy.get("super_user"):
        raise RuntimeError("Investigation account has administrator permissions; no permissions were changed.")
    if not all(policy.get(key) is True for key in required):
        raise RuntimeError("Account lacks required effective permissions; no permissions were changed.")


class RemoteProvisioner:
    """Runs on the server. Only fixed account-management queries are supported."""

    def __init__(self, request):
        self.request = request

    def query(self, query, *, allow_absent=False):
        r = self.request
        # Remote VQL diagnostics are INFO logs, suppressed without --verbose.
        # Capture plain-text logs privately: absence checks must see them, but
        # native diagnostics must never enter the provisioning receipt/output.
        result = subprocess.run(
            [r["binary"], "--api_config", r["bootstrap_path"], "--org", r["org_id"],
             "--verbose", "--nocolor", "query", "--format", "jsonl", query],
            capture_output=True, text=True, timeout=45, check=False,
        )
        if result.returncode:
            raise RuntimeError("Bootstrap API query failed; native output withheld.")
        try:
            rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        except ValueError:
            raise RuntimeError("Bootstrap API returned invalid JSON; output withheld.") from None
        # CLI query errors may only appear in logs, despite a zero exit code.
        logs = result.stderr
        absent = False
        if allow_absent:
            pattern = r"user: User not found: " + re.escape(r["api_user"]) + r"\s*$"
            absent = bool(re.search(pattern, logs, re.MULTILINE))
            logs = re.sub(pattern, "", logs, flags=re.MULTILINE)
        if re.search(r"error|denied|not found|failed", logs, re.IGNORECASE):
            raise RuntimeError("Bootstrap API reported a query error; output withheld.")
        if len(rows) != 1 or not isinstance(rows[0], dict):
            raise RuntimeError("Bootstrap API returned an unexpected result count.")
        return rows[0], absent

    def lookup(self):
        row, absent = self.query(
            f'SELECT user(user={json.dumps(self.request["api_user"])}) AS account FROM scope()',
            allow_absent=True,
        )
        account = row.get("account")
        if account is None and absent:
            return None
        if not isinstance(account, dict) or absent:
            raise ProvisioningError("absence")
        return account

    def provision(self, directory, ca_sha256):
        r = self.request
        row, _ = self.query("SELECT whoami() AS identity, user(user=whoami()) AS account FROM scope()")
        account = row.get("account") or {}
        if row.get("identity") != r["bootstrap_user"] or account.get("name") != r["bootstrap_user"]:
            raise ProvisioningError("identity")
        if "org_id" not in account or normalized_org(account["org_id"]) != r["org_id"]:
            raise ProvisioningError("organization")
        policy = account.get("effective_policy") or {}
        if not all(policy.get(key) is True for key in ("any_query", "server_admin")):
            raise ProvisioningError("permissions")
        key = hashlib.sha256(json.dumps([ca_sha256, r["api_user"], r["org_id"]]).encode()).hexdigest()
        pending = directory / (".vraptor-api-" + key + ".pending")
        existing = self.lookup()
        status = "existing"
        if existing is None:
            if pending.exists():
                raise ProvisioningError("pending")
            # Recheck under the host lock immediately before the one write.
            existing = self.lookup()
            if existing is None:
                with pending.open("x") as handle:
                    os.chmod(pending, 0o600)
                    json.dump({"user": r["api_user"], "org_id": r["org_id"], "ca_sha256": ca_sha256}, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                query = (f'SELECT user_create(user={json.dumps(r["api_user"])}, '
                         f'roles={json.dumps(ROLE_PROFILES[r["role_profile"]])}, '
                         f'orgs={json.dumps([r["org_id"]])}) AS created FROM scope()')
                # Keep the pending marker on any uncertain result; never replay.
                try:
                    created, _ = self.query(query)
                    if created.get("created") != r["api_user"]:
                        raise RuntimeError("Creation was not confirmed.")
                    existing = self.lookup()
                    validate_account(existing, r["api_user"], r["org_id"], r["role_profile"])
                except Exception:  # noqa: BLE001 - all failures after submission are uncertain writes
                    # A write was submitted. Even a failed lookup must not claim
                    # that no creation was attempted or expose native output.
                    raise ProvisioningError("pending") from None
                status = "created"
        if status != "created":
            validate_account(existing, r["api_user"], r["org_id"], r["role_profile"])
        if pending.exists():
            pending.unlink()
            if status == "existing":
                status = "reconciled"
        return {"status": status, "api_user": r["api_user"], "org_id": r["org_id"],
                "ca_sha256": ca_sha256}


def remote_main(request):
    """No key material, server configuration, or raw query output leaves this host."""
    import yaml
    os.umask(0o077)
    bootstrap = Path(request["bootstrap_path"])
    directory = bootstrap.parent
    if directory.stat().st_mode & 0o022:
        raise RuntimeError("Bootstrap directory must not be group/other writable.")
    if bootstrap.stat().st_mode & 0o077:
        raise RuntimeError("Bootstrap YAML must not be group/other accessible.")
    credential = yaml.safe_load(bootstrap.read_text())
    server = yaml.safe_load(Path(request["server_config"]).read_text())
    ca = credential.get("ca_certificate")
    if credential.get("name") != request["bootstrap_user"] or request["api_user"].casefold() == request["bootstrap_user"].casefold():
        raise RuntimeError("Bootstrap and operational identities must be distinct and explicitly selected.")
    if not ca or ca != (server.get("Client") or {}).get("ca_certificate"):
        raise ProvisioningError("binding")
    ca_sha256 = hashlib.sha256(ca.encode()).hexdigest()
    if request.get("expected_ca_sha256") and request["expected_ca_sha256"] != ca_sha256:
        raise ProvisioningError("binding")
    lock = os.open(directory / ".vraptor-api-provision.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProvisioningError("busy") from None
        return RemoteProvisioner(request).provision(directory, ca_sha256)


def manual_instructions(username, org_id, role_profile):
    roles = ROLE_PROFILES[role_profile]
    query = (f'SELECT user_create(user={json.dumps(username)}, roles={json.dumps(roles)}, '
             f'orgs={json.dumps([org_id])}) AS Created FROM scope()')
    return (
        "Manual API account setup required. Use an existing administrator in the running server's GUI.\n"
        f"Verify the intended server and organization {org_id!r}; inspect account {username!r}.\n"
        "Preserve existing accounts and permissions. If absent, coordinate other user administrators, "
        "recheck absence, then run this once in an authenticated administrator notebook:\n"
        + query + "\nVerify the resulting account, roles and effective permissions. "
        "If it already exists with different permissions, stop and resolve that separately.\n"
        "In your terminal, rerun the same setup command with --api-account-ready after completion. "
        "Setup will retrieve/generate the selected user's YAML and verify that user's access. "
        "No administrator credential is required locally."
    )


def cached_account_works(args, username, role_profile):
    """True when the kept API YAML already authenticates as the selected user with its roles."""
    # A refresh may fetch from another server; only YAML that setup keeps counts.
    if getattr(args, "force", False) or getattr(args, "regenerate_remote_api", False):
        return False
    cached_api = getattr(args, "api_client", None)
    if not cached_api or not Path(cached_api).is_file():
        return False
    from vraptor import readiness
    try:
        path = Path(cached_api)
        if readiness.validate_api_client_security(path)["identity"] != username:
            return False
        readiness.verify_api_authorization(path, api_user=username, role_profile=role_profile)
    except (OSError, RuntimeError, ValueError, KeyError):
        return False
    return True


def prepare_account(args, snapshot):
    """Called once by setup, before acquisition, including when YAML is cached.

    Generic installs skip the manual step when the cached YAML already works,
    unless --api-account-setup (or the interactive prompt) asks to run it.
    """
    if not getattr(args, "provision_api", False):
        return None
    username = str(getattr(args, "api_user", None) or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", username):
        raise ValueError("Configure api_user or pass --api-user with a valid username before provisioning.")
    from vraptor.api import resolve_org_id
    org_id = normalized_org(resolve_org_id(getattr(args, "org_id", None)))
    role_profile = args.api_role_profile
    bootstrap_path = getattr(args, "bootstrap_api_config", None)
    bootstrap_user = getattr(args, "bootstrap_api_user", None)
    if not bootstrap_path and not bootstrap_user:
        if (not getattr(args, "api_account_ready", False) and not getattr(args, "api_account_setup", False)
                and cached_account_works(args, username, role_profile)):
            note = f"API account {username!r} already works with the cached API YAML."
            if not sys.stdin.isatty():
                print(note + " Skipped the manual account step; rerun with --api-account-setup to run it anyway.",
                      file=sys.stderr, flush=True)
                return None
            if input(note + " Run the manual account step anyway? [y/N]: ").strip().lower() not in {"y", "yes"}:
                return None
        if not getattr(args, "api_account_ready", False):
            instructions = manual_instructions(username, org_id, role_profile)
            if not sys.stdin.isatty():
                raise RuntimeError(instructions)
            print(instructions, flush=True)
            if input("Account setup complete? Continue [y/N]: ").strip().lower() not in {"y", "yes"}:
                raise RuntimeError("Paused for manual API account setup.")
        return {"status": "manual", "api_user": username, "org_id": org_id}
    if not bootstrap_path or not bootstrap_user:
        raise ValueError("Configure both bootstrap_api_config and bootstrap_api_user.")
    for flag in ("api_account_ready", "api_account_setup"):
        if getattr(args, flag, False):
            raise ValueError(f"--{flag.replace('_', '-')} applies only to manual account setup.")
    if username.casefold() == bootstrap_user.casefold():
        raise ValueError("The bootstrap account cannot be the operational API user.")
    values = snapshot.values
    host = str(getattr(args, "server_ip", None) or "")
    ssh_user = str(values.get("ssh_user") or "")
    key = str(values.get("ssh_key") or "")
    if not host or host.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._:-]+", host) or not ssh_user or not key:
        raise ValueError("Remote bootstrap requires a valid server address, SSH user and SSH key.")
    request = {"api_user": username, "org_id": org_id, "role_profile": role_profile,
               "bootstrap_path": bootstrap_path, "bootstrap_user": bootstrap_user,
               "server_config": values.get("server_config") or "/etc/velociraptor/server.config.yaml",
               "binary": values.get("remote_bin") or "velociraptor"}
    cached_api = getattr(args, "api_client", None)
    if cached_api and Path(cached_api).is_file():
        from vraptor.readiness_state import api_metadata
        metadata = api_metadata(Path(cached_api))
        if not metadata.get("ca_sha256"):
            raise ValueError("Cached API configuration has no CA binding; no provisioning attempted.")
        request["expected_ca_sha256"] = metadata["ca_sha256"]
    # No local bootstrap YAML, API client, discovery, query retries or sudo fallback.
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "-i", key,
               ]
    known_hosts = Path(values["config_root"]) / (args.server_profile + "_known_hosts")
    if known_hosts.is_file():
        command += ["-o", "UserKnownHostsFile=" + str(known_hosts), "-o", "GlobalKnownHostsFile=/dev/null"]
    command += [f"{ssh_user}@{host}", "python3 -c " + shlex.quote(Path(__file__).read_text())]
    try:
        result = subprocess.run(command, input=json.dumps(request), env=dict(snapshot.environment),
                                capture_output=True, text=True, timeout=240, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Bootstrap transport failed or timed out. Reconcile account state before retrying; no credentials were fetched.") from None
    try:
        receipt = json.loads(result.stdout)
    except ValueError:
        receipt = {}
    if not isinstance(receipt, dict):
        receipt = {}
    if result.returncode or receipt.get("status") not in {"created", "existing", "reconciled"}:
        if receipt.get("error_code") in REMOTE_FAILURES:
            raise ProvisioningError(receipt["error_code"])
        raise RuntimeError("Bootstrap account setup failed; no operational fallback or credential generation. "
                           "Check SSH trust, remote Python 3/PyYAML, bootstrap access, permissions and any pending operation.")
    if receipt.get("api_user") != username or receipt.get("org_id") != org_id or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("ca_sha256") or "")):
        raise RuntimeError("Bootstrap receipt identity, organization or server binding mismatch.")
    return receipt


if __name__ == "__main__":
    try:
        print(json.dumps(remote_main(json.load(sys.stdin))))
    except ProvisioningError as exc:
        print(json.dumps({"status": "failed", "error_code": exc.code}))
        raise SystemExit(1)
    except Exception:  # noqa: BLE001 - sanitize every remote failure before returning output
        # Logs and exceptions may contain native config/key material. Never relay them.
        print(json.dumps({"status": "failed"}))
        raise SystemExit(1)
