from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vraptor.artifacts import linux as linux_host_profile


class LinuxHostProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = linux_host_profile.load_contract()

    def inventory_rows(self, *, omit: set[str] | None = None):
        omitted = omit or set()
        rows = []
        seen = set()
        for capability in self.contract["capabilities"].values():
            for candidate in capability["candidates"]:
                artifact = candidate["artifact"]
                if artifact in omitted or artifact in seen:
                    continue
                seen.add(artifact)
                parameters = sorted(
                    set(candidate.get("fixed_env", {}))
                    | set(candidate.get("parameter_map", {}).values())
                )
                rows.append(
                    {
                        "name": artifact,
                        "parameter_names": parameters,
                    }
                )
        return rows

    def test_contract_defines_modes_focuses_and_safe_artifacts(self):
        self.assertEqual(
            set(self.contract["modes"]),
            {"triage", "standard", "deep", "timeline"},
        )
        self.assertTrue(
            {
                "persistence",
                "execution",
                "authentication",
                "web-server",
                "container",
                "filesystem",
            }.issubset(self.contract["focuses"])
        )
        artifacts = {
            candidate["artifact"]
            for capability in self.contract["capabilities"].values()
            for candidate in capability["candidates"]
        }
        self.assertIn("Linux.Forensics.Journal", artifacts)
        self.assertIn("Linux.Search.FileFinder", artifacts)
        self.assertIn("Linux.Sys.Crontab", artifacts)
        self.assertNotIn("Linux.Sys.Logs", artifacts)

    def test_standard_plan_uses_inventory_and_per_artifact_reuse_commands(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="standard",
            include_optional=["packages"],
            distro="debian",
            investigation_id="IR1234",
            client_id="C.1234",
            contract=self.contract,
        )

        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["source_inventory_sha256"], "abc123")
        self.assertEqual(len(plan["profile_sha256"]), 64)
        selected = {item["capability"]: item for item in plan["selected"]}
        self.assertEqual(
            selected["packages"]["artifact"],
            "Linux.Debian.Packages",
        )
        for item in plan["selected"]:
            with self.subTest(artifact=item["artifact"]):
                self.assertIn(" collect check ", item["check_command"])
                self.assertIn(" collect ensure ", item["ensure_command"])
                self.assertNotIn("--force-run", item["ensure_command"])
                self.assertNotIn(" export ", item["ensure_command"])

    def test_optional_capabilities_require_explicit_selection(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="triage",
            contract=self.contract,
        )
        selected = {item["capability"] for item in plan["selected"]}
        self.assertFalse(
            {"authorized_keys", "ssh_logins", "live_process", "live_network"}
            & selected
        )
        self.assertIn("live_process", plan["available_optional_capabilities"])
        self.assertEqual(plan["included_optional_capabilities"], [])

        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="triage",
            include_optional=["live_process"],
            contract=self.contract,
        )
        self.assertIn(
            "live_process",
            {item["capability"] for item in plan["selected"]},
        )

    def test_missing_required_inventory_capability_fails_closed(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(omit={"Linux.Sys.Crontab"}),
            inventory_sha256="abc123",
            mode="triage",
            contract=self.contract,
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertTrue(
            any("cron: no validated candidate" in item for item in plan["blockers"])
        )

    def test_deep_mode_requires_focus(self):
        with self.assertRaisesRegex(RuntimeError, "requires at least one --focus"):
            linux_host_profile.build_plan(
                inventory_rows=self.inventory_rows(),
                inventory_sha256="abc123",
                mode="deep",
                contract=self.contract,
            )

    def test_timeline_requires_bounds_and_binds_supported_parameters(self):
        with self.assertRaisesRegex(RuntimeError, "requires --date-after"):
            linux_host_profile.build_plan(
                inventory_rows=self.inventory_rows(),
                inventory_sha256="abc123",
                mode="timeline",
                contract=self.contract,
            )

        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="timeline",
            include_optional=["file_timeline"],
            inputs={
                "date_after": "2026-08-01T10:00:00Z",
                "date_before": "2026-08-01T12:00:00Z",
                "path_glob": "/var/www/**",
            },
            contract=self.contract,
        )

        self.assertEqual(plan["status"], "ready")
        selected = {item["capability"]: item for item in plan["selected"]}
        self.assertEqual(
            selected["journal"]["env"],
            {
                "AlsoUpload": "N",
                "DateAfter": "2026-08-01T10:00:00Z",
                "DateBefore": "2026-08-01T12:00:00Z",
            },
        )
        self.assertEqual(
            selected["file_timeline"]["env"]["SearchFilesGlob"],
            "/var/www/**",
        )

    def test_unused_optional_input_fails_closed(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "not used by the selected capabilities: path_glob",
        ):
            linux_host_profile.build_plan(
                inventory_rows=self.inventory_rows(),
                inventory_sha256="abc123",
                mode="timeline",
                inputs={
                    "date_after": "2026-08-01T10:00:00Z",
                    "date_before": "2026-08-01T12:00:00Z",
                    "path_glob": "/var/www/**",
                },
                contract=self.contract,
            )

    def test_web_server_focus_requires_bounded_inputs(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="deep",
            focuses=["web-server"],
            inputs={
                "server_role": "nginx-php",
                "application_context": "vhost=app.example app=wordpress",
                "document_root": "/var/www/html",
                "log_timezone": "UTC",
                "log_format": "nginx-combined-xff",
            },
            contract=self.contract,
        )
        self.assertEqual(plan["status"], "incomplete")
        self.assertTrue(any("web_logs: missing inputs" in x for x in plan["blockers"]))
        self.assertTrue(any("web_files: missing inputs" in x for x in plan["blockers"]))

        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="deep",
            focuses=["web-server"],
            inputs={
                "date_after": "2026-08-01T10:00:00Z",
                "date_before": "2026-08-01T12:00:00Z",
                "log_glob": "/var/log/nginx/*.log",
                "search_regex": "wp-login|xmlrpc|cmd=",
                "server_role": "nginx-php",
                "application_context": "vhost=app.example app=wordpress",
                "document_root": "/var/www/html",
                "log_timezone": "UTC",
                "log_format": "nginx-combined-xff",
                "estimated_log_bytes": "25000000",
                "max_log_bytes": "100000000",
                "web_root": "/var/www/html/**",
            },
            contract=self.contract,
        )
        self.assertEqual(plan["status"], "ready")
        selected = {item["capability"]: item for item in plan["selected"]}
        self.assertIn(
            "deterministically post-filter",
            selected["web_logs"]["limitations"],
        )
        self.assertEqual(
            selected["web_logs"]["analysis_inputs"]["date_after"],
            "2026-08-01T10:00:00Z",
        )
        self.assertEqual(
            selected["web_logs"]["analysis_inputs"]["estimated_log_bytes"],
            "25000000",
        )
        self.assertIn(
            "--analysis-input date_after=2026-08-01T10:00:00Z",
            selected["web_logs"]["ensure_command"],
        )
        self.assertEqual(
            selected["web_log_inventory"]["env"]["SearchFilesGlob"],
            "/var/log/nginx/*.log",
        )
        self.assertEqual(
            selected["web_files"]["env"]["Upload_File"],
            "N",
        )

    def test_unbounded_paths_and_searches_are_rejected(self):
        for inputs, message in (
            ({"path_glob": "/**"}, "bounded path"),
            ({"path_glob": "var/www/**"}, "bounded path"),
            ({"search_regex": ".*"}, "unbounded"),
            ({"search_regex": "GET"}, "low-selectivity"),
            ({"search_regex": "/"}, "low-selectivity"),
            ({"search_regex": "^POST$"}, "low-selectivity"),
            ({"search_regex": "(?i)post"}, "low-selectivity"),
            ({"search_regex": "200|404"}, "low-selectivity"),
        ):
            with self.subTest(inputs=inputs):
                with self.assertRaisesRegex(RuntimeError, message):
                    linux_host_profile.build_plan(
                        inventory_rows=self.inventory_rows(),
                        inventory_sha256="abc123",
                        mode="deep",
                        focuses=["filesystem"],
                        inputs=inputs,
                        contract=self.contract,
                    )

    def test_web_focus_requires_server_context(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="deep",
            focuses=["web-server"],
            inputs={
                "date_after": "2026-08-01T10:00:00Z",
                "date_before": "2026-08-01T12:00:00Z",
                "log_glob": "/var/log/nginx/*.log",
                "search_regex": "wp-login|xmlrpc|cmd=",
                "web_root": "/var/www/html/**",
                "estimated_log_bytes": "25000000",
                "max_log_bytes": "100000000",
            },
            contract=self.contract,
        )
        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "web-server: missing context inputs server_role, application_context, "
            "document_root, log_timezone, log_format",
            " ".join(plan["blockers"]),
        )

    def test_web_preflight_byte_limit_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "exceed"):
            linux_host_profile.build_plan(
                inventory_rows=self.inventory_rows(),
                inventory_sha256="abc123",
                mode="deep",
                focuses=["web-server"],
                inputs={
                    "date_after": "2026-08-01T10:00:00Z",
                    "date_before": "2026-08-01T12:00:00Z",
                    "log_glob": "/var/log/nginx/*.log",
                    "search_regex": "wp-login",
                    "web_root": "/var/www/html/**",
                    "server_role": "nginx-php",
                    "application_context": "vhost=app.example app=wordpress",
                    "document_root": "/var/www/html",
                    "log_timezone": "UTC",
                    "log_format": "nginx-combined-xff",
                    "estimated_log_bytes": "200",
                    "max_log_bytes": "100",
                },
                contract=self.contract,
            )

    def test_web_preflight_first_pass_withholds_loghunter(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(),
            inventory_sha256="abc123",
            mode="deep",
            focuses=["web-server"],
            inputs={
                "date_after": "2026-08-01T10:00:00Z",
                "date_before": "2026-08-01T12:00:00Z",
                "log_glob": "/var/log/nginx/*.log",
                "search_regex": "wp-login",
                "web_root": "/var/www/html/**",
                "server_role": "nginx-php",
                "application_context": "vhost=app.example app=wordpress",
                "document_root": "/var/www/html",
                "log_timezone": "UTC",
                "log_format": "nginx-combined-xff",
            },
            contract=self.contract,
        )
        selected = {item["capability"] for item in plan["selected"]}
        self.assertEqual(plan["status"], "incomplete")
        self.assertIn("web_log_inventory", selected)
        self.assertNotIn("web_logs", selected)
        self.assertTrue(
            any(
                "web_logs: missing inputs estimated_log_bytes, max_log_bytes"
                in blocker
                for blocker in plan["blockers"]
            )
        )

    def test_loghunter_reuse_identity_is_separate_from_analysis_bounds(self):
        base_inputs = {
            "log_glob": "/var/log/nginx/*.log",
            "search_regex": "wp-login",
            "web_root": "/var/www/html/**",
            "server_role": "nginx-php",
            "application_context": "vhost=app.example app=wordpress",
            "document_root": "/var/www/html",
            "log_timezone": "UTC",
            "log_format": "nginx-combined-xff",
            "estimated_log_bytes": "25000000",
            "max_log_bytes": "100000000",
        }
        plans = []
        for after, before in (
            ("2026-08-01T10:00:00Z", "2026-08-01T11:00:00Z"),
            ("2026-08-01T11:00:00Z", "2026-08-01T12:00:00Z"),
        ):
            plans.append(
                linux_host_profile.build_plan(
                    inventory_rows=self.inventory_rows(),
                    inventory_sha256="abc123",
                    mode="deep",
                    focuses=["web-server"],
                    inputs={
                        **base_inputs,
                        "date_after": after,
                        "date_before": before,
                    },
                    contract=self.contract,
                )
            )
        web_logs = [
            next(
                item
                for item in plan["selected"]
                if item["capability"] == "web_logs"
            )
            for plan in plans
        ]
        self.assertEqual(web_logs[0]["env"], web_logs[1]["env"])
        self.assertNotEqual(
            web_logs[0]["check_command"],
            web_logs[1]["check_command"],
        )
        self.assertNotEqual(
            web_logs[0]["analysis_inputs"],
            web_logs[1]["analysis_inputs"],
        )

    def test_server_context_rejects_placeholders(self):
        with self.assertRaisesRegex(RuntimeError, "placeholder"):
            linux_host_profile.build_plan(
                inventory_rows=self.inventory_rows(),
                inventory_sha256="abc123",
                mode="deep",
                focuses=["web-server"],
                inputs={
                    "server_role": "x",
                    "application_context": "x",
                    "document_root": "/var/www/html",
                    "log_timezone": "UTC",
                    "log_format": "x",
                },
                contract=self.contract,
            )

    def test_requested_optional_capability_is_enforced(self):
        plan = linux_host_profile.build_plan(
            inventory_rows=self.inventory_rows(omit={"Linux.Sys.Pslist"}),
            inventory_sha256="abc123",
            mode="triage",
            include_optional=["live_process"],
            contract=self.contract,
        )
        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "live_process: no validated candidate is available",
            plan["blockers"],
        )

    def test_time_bounds_require_timezone_and_order(self):
        for inputs, message in (
            (
                {
                    "date_after": "2026-08-01T10:00:00",
                    "date_before": "2026-08-01T12:00:00Z",
                },
                "explicit timezone",
            ),
            (
                {
                    "date_after": "2026-08-01T12:00:00Z",
                    "date_before": "2026-08-01T10:00:00Z",
                },
                "earlier than",
            ),
            (
                {
                    "date_after": "not-a-date",
                    "date_before": "2026-08-01T12:00:00Z",
                },
                "ISO-8601",
            ),
        ):
            with self.subTest(inputs=inputs):
                with self.assertRaisesRegex(RuntimeError, message):
                    linux_host_profile.build_plan(
                        inventory_rows=self.inventory_rows(),
                        inventory_sha256="abc123",
                        mode="timeline",
                        inputs=inputs,
                        contract=self.contract,
                    )

    def test_inventory_parameter_mismatch_blocks_required_capability(self):
        rows = self.inventory_rows()
        journal = next(
            item for item in rows if item["name"] == "Linux.Forensics.Journal"
        )
        journal["parameter_names"].remove("DateBefore")
        plan = linux_host_profile.build_plan(
            inventory_rows=rows,
            inventory_sha256="abc123",
            mode="timeline",
            inputs={
                "date_after": "2026-08-01T10:00:00Z",
                "date_before": "2026-08-01T12:00:00Z",
            },
            contract=self.contract,
        )
        self.assertEqual(plan["status"], "incomplete")
        self.assertTrue(
            any("lacks parameters DateBefore" in item for item in plan["blockers"])
        )
        self.assertTrue(
            any("journal: no validated candidate" in item for item in plan["blockers"])
        )

    def test_cli_returns_two_for_incomplete_inventory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact_definitions_inventory.json"
            path.write_text(
                json.dumps(self.inventory_rows(omit={"Linux.Sys.Crontab"})),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = linux_host_profile.main(
                    [
                        "--inventory",
                        str(path),
                        "--mode",
                        "triage",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertTrue(Path(payload["plan_file"]).is_file())
        self.assertEqual(result, 2)
        self.assertEqual(payload["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
