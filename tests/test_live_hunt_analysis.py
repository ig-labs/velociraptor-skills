import base64
import copy
import gzip
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.artifacts import policy as artifact_policy
from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import golden as autoruns_golden
from vraptor.collect import requests as collection
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.hunt import live


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = "DetectRaptor.Windows.Detection.Evtx"
AUTORUNS_ARTIFACT = "IG.Windows.Sysinternals.Autoruns"
UPSTREAM_AUTORUNS_ARTIFACT = "Windows.Sysinternals.Autoruns"


def golden_lookup_configuration(
    *,
    tool="Autoruns.GoldenDB",
    version="20260728",
    inventory_hash="b" * 64,
):
    keys = ["a" * 40]
    serialized = json.dumps(
        keys,
        separators=(",", ":"),
    ).encode("utf-8")
    configuration = live.configured_autoruns_golden(
        tool=tool,
        version=version,
    )
    configuration.update(
        {
            "database": "/tmp/golden.sqlite",
            "database_sha256": inventory_hash,
            "identity_count": 1,
            "record_count": 1,
            "lookup_key_count": 1,
            "lookup_payload_sha256": "c" * 64,
            "lookup_gzip_base64": base64.b64encode(
                gzip.compress(serialized, mtime=0)
            ).decode("ascii"),
            "lookup_transport": "gzip-base64-json",
        }
    )
    return configuration


def create_golden_database(path):
    result = autoruns_golden.promote_records(
        path,
        [
            {
                "EntryLocation": r"hkcu\software\vendor\run",
                "Entry": "Vendor App",
                "Category": "Logon",
                "Signer": "(Verified) Vendor",
                "ImagePath": r"C:\Program Files\Vendor\App.exe",
                "LaunchString": (
                    r'"C:\Program Files\Vendor\App.exe" /quiet'
                ),
            }
        ],
        modified_time="2026-07-28T07:32:47Z",
    )
    return result["validation"]


def consume_classification(result):
    """Model stubs must finish the streamed evidence before returning a manifest."""
    def classify(rows, **kwargs):
        list(rows)
        return copy.deepcopy(result)

    return classify


def accounted_autoruns_batches(groups, *, source_rows, residual_rows):
    """Mirror the server protocol across response batch boundaries."""
    records = []
    for group in groups:
        identity = {key: group[key] for key in ("ImagePath", "LaunchString", "Signer")}
        sort_key = f"{group['Total']:020d}|" + json.dumps(
            identity, ensure_ascii=False, separators=(",", ":"),
        )
        records.append({"_AutorunsStream": "group", **group, "SortKey": sort_key})
    yield [{
        "_AutorunsStream": "summary",
        "SourceRows": source_rows,
        "MatchedRows": source_rows - residual_rows,
        "ResidualRows": residual_rows,
        "PopulatedRows": sum(group["Total"] for group in groups),
        "GroupCount": len(groups),
    }]
    yield sorted(records, key=lambda row: row["SortKey"], reverse=True)
    yield [{"_AutorunsStream": "complete"}]


class FakeDirectApi:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "count() AS RowCount" in vql:
            if any(key.startswith("FilterValue") for key in env):
                return []
            return [{"RowCount": len(self.rows)}] if self.rows else []
        return self._selected(vql, env)

    def query_batches(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        yield self._selected(vql, dict(env or {}))

    def _selected(self, vql, env):
        limit_match = re.search(r"\bLIMIT\s+(\d+)", vql)
        limit = int(limit_match.group(1)) if limit_match else len(self.rows)
        return list(self.rows[:limit])


class FakePivotApi:
    def __init__(self):
        self.calls = []

    def query(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "count() AS RowCount" in vql:
            return [{"RowCount": 2000}]
        if "GROUP BY Pivot1" in vql and "Detection.Name AS Pivot1" in vql:
            return [
                {"Pivot1": "Detection A", "Count": 1500},
                {"Pivot1": "Detection B", "Count": 500},
            ]
        if "GROUP BY Pivot1" in vql and "DisplayName AS Pivot1" in vql:
            return [
                {"Pivot1": "Remote Management Tool", "Count": 1500},
                {"Pivot1": "Suspicious Utility", "Count": 500},
            ]
        if "GROUP BY Pivot1" in vql and "Category AS Pivot1" in vql:
            return [
                {"Pivot1": "Remote Access", "Count": 1400},
                {"Pivot1": "Other", "Count": 100},
            ]
        if "GROUP BY Pivot1" in vql and "hash(accessor=" in vql:
            return [
                {"Pivot1": "sig-common", "Count": 1300},
                {"Pivot1": "sig-secondary", "Count": 100},
                {"Pivot1": "sig-rare", "Count": 100},
            ]
        return []

    def query_batches(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        limit = int(re.search(r"\bLIMIT\s+(\d+)", vql).group(1))
        detection = env.get("PivotScope1", "")
        signature = next(
            (
                value
                for key, value in env.items()
                if key.startswith("Signature") and key.endswith("Value1")
            ),
            "",
        )
        shape = signature or ("tail" if any(key.startswith("Tail") for key in env) else "scope")
        yield [
            {
                "Detection": detection,
                "Evidence": f"evidence-{detection}-{shape}-{index}",
            }
            for index in range(limit)
        ]


class FakeAutorunsUseCaseApi:
    def __init__(self):
        self.calls = []

    def query(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "count() AS RowCount" in vql:
            return [{"RowCount": 3}]
        if "Category AS Pivot1" in vql:
            return [{"Pivot1": "Logon", "Count": 3}]
        if "hash(accessor=" in vql and "AS Pivot6" in vql:
            return [
                {
                    "Pivot1": r"hkcu\software\microsoft\windows\run",
                    "Pivot2": "cmd.exe",
                    "Pivot3": r"c:\windows\system32\cmd.exe",
                    "Pivot4": "cmd.exe /c whoami",
                    "Pivot5": "",
                    "Pivot6": "exact-one",
                    "Count": 3,
                }
            ]
        if "lowcase(string=`Entry Location`) AS Pivot1" in vql:
            return [
                {
                    "Pivot1": r"hkcu\software\microsoft\windows\run",
                    "Pivot2": "cmd.exe",
                    "Pivot3": r"c:\windows\system32\cmd.exe",
                    "Pivot4": "cmd.exe /c whoami",
                    "Pivot5": "",
                    "Count": 3,
                }
            ]
        if "hash(accessor=" in vql and "AS Pivot1" in vql:
            return [{"Pivot1": "exact-one", "Count": 3}]
        return []

    def query_batches(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        if "FROM AutorunsResidualRows" in vql:
            yield [
                {
                    "ImagePath": r"c:\windows\system32\cmd.exe",
                    "LaunchString": "cmd.exe /c whoami",
                    "Signer": "",
                    "ExampleCategory": "Logon",
                    "Total": 3,
                }
            ]
            return
        if "AS HashKey" in vql:
            yield [
                {
                    "EntryLocation": (
                        r"hkcu\software\microsoft\windows\run"
                    ),
                    "Entry": "cmd.exe",
                    "Category": "Logon",
                    "Signer": "",
                    "ImagePath": r"c:\windows\system32\cmd.exe",
                    "LaunchString": "cmd.exe /c whoami",
                    "Profile": "System",
                    "Description": "Windows Command Processor",
                    "Version": "10.0",
                    "SHA256": "a" * 64,
                    "Fqdn": "host-one.example.test",
                    "ClientId": "C.1",
                    "_AutorunsIdentity": autoruns.trusted_key_payload(
                        signer="", image_path=r"c:\windows\system32\cmd.exe",
                        launch_string="cmd.exe /c whoami"),
                    "HashKey": autoruns.trusted_key(
                        signer="",
                        image_path=r"c:\windows\system32\cmd.exe",
                        launch_string="cmd.exe /c whoami",
                    ),
                }
            ]
            return
        yield []


class FakeAutorunsGoldenResidualApi:
    def __init__(self, residual_rows=3, inventory_hash="a" * 64):
        self.calls = []
        self.residual_rows = residual_rows
        self.inventory_hash = inventory_hash

    def query(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "AS Inventory" in vql:
            return [
                {
                    "Inventory": {
                        "Definition": {
                            "hash": self.inventory_hash,
                            "filestore_path": "inventory/golden.sqlite",
                        }
                    }
                }
            ]
        if "CountSql" in env:
            return [{"IdentityCount": 100, "RecordCount": 100}]
        if "count() AS RowCount" in vql:
            if any(
                key.startswith("AutorunsSuspicious")
                for key in env
            ):
                return [{"RowCount": 1}]
            if "AutorunsGoldenKeys" in vql:
                return [{"RowCount": self.residual_rows}]
            return [{"RowCount": 10}]
        return []

    def residual_groups(self):
        return [
            {
                "ImagePath": rf"c:\users\user\residual-{index}.exe",
                "LaunchString": f"residual-{index}.exe",
                "Signer": "",
                "Total": 1,
            }
            for index in range(self.residual_rows)
        ]

    def query_batches(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "LET AutorunsCountedGroups" in vql:
            yield from accounted_autoruns_batches(
                self.residual_groups(), source_rows=10,
                residual_rows=self.residual_rows,
            )
            return
        if "LET AutorunsResidualRows" in vql:
            yield self.residual_groups()
            return
        suspicious_image = next(
            (
                value
                for key, value in env.items()
                if key.startswith("AutorunsSuspicious")
                and key.endswith("Value1")
            ),
            "",
        )
        if env.get("AutorunsSelectedHashesGzipBase64"):
            suspicious_image = r"c:\users\user\residual-0.exe"
        if suspicious_image:
            index_match = re.search(r"residual-(\d+)", suspicious_image)
            index = int(index_match.group(1)) if index_match else 0
            image_path = rf"c:\users\user\residual-{index}.exe"
            launch_string = f"residual-{index}.exe"
            yield [
                {
                    "EntryLocation": r"hkcu\software\vendor\run",
                    "Entry": f"residual-{index}",
                    "Category": "Logon",
                    "Signer": "",
                    "ImagePath": image_path,
                    "LaunchString": launch_string,
                    "Profile": "",
                    "Description": "Residual test item",
                    "Version": "",
                    "SHA256": f"{index:064x}",
                    "Fqdn": f"host-{index}.example.test",
                    "ClientId": f"C.{index}",
                    "_AutorunsIdentity": autoruns.trusted_key_payload(
                        signer="", image_path=image_path, launch_string=launch_string),
                    "HashKey": autoruns.trusted_key(
                        signer="",
                        image_path=image_path,
                        launch_string=launch_string,
                    ),
                }
            ]
            return
        yield [
            {
                "EntryLocation": r"hkcu\software\vendor\run",
                "Entry": f"residual-{index}",
                "Category": "Logon",
                "Signer": "",
                "ImagePath": rf"c:\users\user\residual-{index}.exe",
                "LaunchString": rf"residual-{index}.exe",
                "Fqdn": f"host-{index}.example.test",
                "ClientId": f"C.{index}",
            }
            for index in range(self.residual_rows)
        ]


class FakeSafeBootAutorunsApi(FakeAutorunsGoldenResidualApi):
    def residual_groups(self):
        return [{
            "ImagePath": r"c:\windows\system32\cmd.exe",
            "LaunchString": "cmd.exe",
            "Signer": "(verified) microsoft windows",
            "ExampleCategory": "Logon",
            "Total": 1,
        }]

    def query_batches(self, vql, env=None, **kwargs):
        if "LET AutorunsCountedGroups" in vql or "LET AutorunsResidualRows" in vql:
            yield from super().query_batches(vql, env, **kwargs)
            return
        resolved_env = dict(env or {})
        self.calls.append((vql, resolved_env, kwargs))
        image_path = r"c:\windows\system32\cmd.exe"
        launch_string = "cmd.exe"
        if resolved_env.get("AutorunsSelectedHashesGzipBase64"):
            yield [
                {
                    "EntryLocation": (
                        r"HKLM\SYSTEM\CurrentControlSet\Control"
                        r"\SafeBoot\AlternateShell"
                    ),
                    "Entry": "cmd.exe",
                    "Category": "Logon",
                    "Signer": "(Verified) Microsoft Windows",
                    "ImagePath": image_path,
                    "LaunchString": launch_string,
                    "Profile": "System-wide",
                    "Description": "Windows Command Processor",
                    "Version": "10",
                    "SHA256": "a" * 64,
                    "Fqdn": "host.example.test",
                    "ClientId": "C.1",
                    "_AutorunsIdentity": autoruns.trusted_key_payload(
                        signer="(Verified) Microsoft Windows", image_path=image_path,
                        launch_string=launch_string),
                    "HashKey": autoruns.trusted_key(
                        signer="(Verified) Microsoft Windows",
                        image_path=image_path,
                        launch_string=launch_string,
                    ),
                }
            ]
            return
        yield []


class FakeMismatchedPivotApi(FakePivotApi):
    def query(self, vql, env=None, **kwargs):
        env = dict(env or {})
        self.calls.append((vql, env, kwargs))
        if "count() AS RowCount" in vql:
            return [{"RowCount": 2000}]
        if "GROUP BY Pivot1" in vql and "Detection.Name AS Pivot1" in vql:
            return [{"Pivot1": "Broken scope", "Count": 500}]
        return []

    def query_batches(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        yield []


def request(artifact=ARTIFACT):
    return collection.CollectionRequest(
        target_collection_type="test",
        requested_groups=[],
        requested_artifacts=[artifact],
        expected_specs=[
            collection.ArtifactSpec(
                label=artifact,
                artifact=artifact,
                env={},
            )
        ],
    )


class LiveHuntAnalysisTest(unittest.TestCase):
    def test_reviewed_autoruns_stack_can_promote_to_local_golden_db(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.golden-promote",
            group="",
            hunt_state="FINISHED",
        )
        pending = {
            "review_id": "review-golden",
            "kind": "normalized_stack",
            "scope": {"Category": "Logon"},
            "scope_row_count": 10,
            "exhaustive": False,
            "closure_eligible": True,
            "exact_variant_count_lower_bound": 1,
            "non_promotable_reasons": [],
            "review_match": {
                "type": "normalized_signature",
                "scope": {"Category": "Logon"},
                "stack_id": "autorun_path_entry",
                "logical_dimensions": [
                    "EntryLocation",
                    "Entry",
                    "NormalizedImagePath",
                    "NormalizedLaunchString",
                    "Signer",
                ],
                "server_dimensions": ["a", "b", "c", "d", "e"],
                "values": [
                    (
                        r"hku\s-1-5-21-111-222-333-1001"
                        r"\software\microsoft\windows\run"
                    ),
                    "Vendor App",
                    r"c:\program files\vendor\app.exe",
                    r'"c:\program files\vendor\app.exe" /quiet',
                    "(verified) vendor",
                ],
                "row_count": 10,
            },
        }
        state["artifacts"][AUTORUNS_ARTIFACT] = {
            "pending_reviews": [pending],
            "reviewed_signatures": [],
            "row_accounting": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "golden.sqlite"
            live.apply_decisions(
                state,
                [
                    {
                        "review_id": "review-golden",
                        "complete": True,
                        "disposition": "expected",
                        "reason": "Reviewed vendor persistence.",
                        "hijack_risk_reviewed": True,
                        "promote_to_golden": True,
                        "golden_context": {
                            "Description": "Vendor application",
                            "Company": "Vendor",
                        },
                    }
                ],
                profiles=profiles,
                source="test",
                golden_db_path=database,
            )
            promoted_hash = state["golden_promotions"][0]["hash_key"]
            lookup = autoruns_golden.lookup_hashes(
                database,
                [promoted_hash],
            )

        self.assertTrue(lookup[0]["known_good"])
        self.assertNotIn("categories", lookup[0])
        self.assertEqual(
            lookup[0]["context"],
            {
                "example_entry_location": "",
                "example_entry": "",
                "example_description": "Vendor application",
                "example_company": "",
            },
        )

    def test_default_safeboot_alternate_shell_is_contextually_excluded(self):
        row = {
            "EntryLocation": (
                r"HKLM\SYSTEM\CurrentControlSet\Control"
                r"\SafeBoot\AlternateShell"
            ),
            "Entry": "cmd.exe",
            "Category": "Logon",
            "ImagePath": r"C:\Windows\System32\cmd.exe",
            "LaunchString": "cmd.exe",
            "Signer": "(Verified) Microsoft Windows",
        }

        self.assertEqual(
            live.autoruns_context_exclusion_reason(row),
            "windows-default-safeboot-alternate-shell",
        )
        self.assertEqual(
            live.autoruns_context_exclusion_reason(
                {
                    **row,
                    "EntryLocation": (
                        r"HKLM\Software\Microsoft\Windows"
                        r"\CurrentVersion\Run"
                    ),
                }
            ),
            "",
        )
        self.assertEqual(
            live.autoruns_context_exclusion_reason(
                {**row, "LaunchString": "cmd.exe /c payload.cmd"}
            ),
            "",
        )

    def test_safeboot_context_exclusion_survives_analysis_resume(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeSafeBootAutorunsApi(
                residual_rows=1,
                inventory_hash=validation["sha256"],
            )
            hunt_root = Path(temp_dir) / "H.safeboot"
            classification = {
                "suspicious_rows": [
                    {
                        "ImagePath": r"c:\windows\system32\cmd.exe",
                        "LaunchString": "cmd.exe",
                        "Signer": "(verified) microsoft windows",
                        "Total": 1,
                        "Severity": "high",
                        "Reason": "Bare command shell persistence.",
                    }
                ],
                "potential_golden_rows": [],
                "manifest": {
                    "source_stack_sha256": "c" * 64,
                    "model": "test",
                    "reviewed_group_count": 1,
                    "represented_row_count": 1,
                    "model_reviewed_group_count": 1,
                    "script_excluded_group_count": 0,
                    "part_count": 1,
                },
            }
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=consume_classification(classification),
            ) as classify:
                first = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={
                        "hunt_id": "H.safeboot",
                        "state": "FINISHED",
                    },
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    autoruns_golden_tool="Autoruns.GoldenDB",
                    autoruns_golden_version="20260728",
                    autoruns_golden_db=database,
                    autoruns_ai_review_enabled=True,
                )
                second = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={
                        "hunt_id": "H.safeboot",
                        "state": "FINISHED",
                    },
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    autoruns_golden_tool="Autoruns.GoldenDB",
                    autoruns_golden_version="20260728",
                    autoruns_golden_db=database,
                    autoruns_ai_review_enabled=True,
                )

        self.assertEqual(classify.call_count, 2)
        for result in (first, second):
            workflow = result["autoruns_residual_workflow"][
                AUTORUNS_ARTIFACT
            ]
            self.assertEqual(
                workflow["classification"]["suspicious_count"],
                0,
            )
            self.assertEqual(
                workflow["suspicious_context"][
                    "contextual_exclusion_count"
                ],
                1,
            )

    def test_autoruns_trusted_key_uses_signer_and_user_normalized_paths(self):
        key = autoruns.trusted_key(
            signer="(Verified) Microsoft",
            image_path=r"C:\Users\Alice\App.exe",
            launch_string=r"C:\Users\Bob\App.exe /c TEST",
        )

        self.assertEqual(
            autoruns.trusted_key_payload(
                signer="(Verified) Microsoft",
                image_path=r"C:\Users\Alice\App.exe",
                launch_string=r"C:\Users\Bob\App.exe /c TEST",
            ),
            {
                "ImagePath": r"c:\users\user\app.exe",
                "LaunchString": r"c:\users\user\app.exe /c test",
                "Signer": "(verified) microsoft",
            },
        )
        self.assertRegex(key, r"^[0-9a-f]{40}$")
        self.assertEqual(
            key,
            "d45a537211ce08541a21a1e4fb343ea1fa652a25",
        )
        self.assertEqual(
            key,
            autoruns.trusted_key(
                signer="(verified) microsoft",
                image_path=r"C:\Users\Different\App.exe",
                launch_string=r"C:\Users\Another\App.exe /c test",
            ),
        )
        self.assertEqual(
            autoruns.normalize_user_path(
                r"%SystemRoot%\System32\cmd.exe /c "
                r"%WinDir%\Temp\job.cmd"
            ),
            (
                r"c:\windows\system32\cmd.exe /c "
                r"c:\windows\temp\job.cmd"
            ),
        )
        self.assertEqual(
            autoruns.normalize_user_path(
                r"\SystemRoot\System32\drivers\example.sys"
            ),
            r"c:\windows\system32\drivers\example.sys",
        )
        self.assertEqual(
            autoruns.normalize_user_path(
                r"HKU\S-1-5-21-111-222-333-1001\Software\Vendor"
            ),
            r"hku\sid\software\vendor",
        )
        self.assertEqual(
            autoruns.normalize_user_path(
                r"%LOCALAPPDATA%\Vendor\App.exe "
                r"%APPDATA%\Vendor\Config"
            ),
            (
                r"c:\users\user\appdata\local\vendor\app.exe "
                r"c:\users\user\appdata\roaming\vendor\config"
            ),
        )
        self.assertEqual(
            autoruns.normalize_user_path(
                r"C:\Documents and Settings\Alice\Vendor\App.exe"
            ),
            r"c:\users\user\vendor\app.exe",
        )
        record = autoruns.trusted_record(
            category="Logon",
            signer="(Verified) Microsoft",
            image_path=r"C:\Users\Alice\App.exe",
            launch_string=r"C:\Users\Bob\App.exe /c TEST",
        )
        self.assertEqual(record["hash_key"], key)
        self.assertEqual(record["category"], "logon")
        self.assertEqual(record["image_path"], r"c:\users\user\app.exe")
        self.assertEqual(
            record["launch_string"],
            r"c:\users\user\app.exe /c test",
        )

    def test_autoruns_trusted_key_matches_velociraptor_html_escaping(self):
        self.assertEqual(
            autoruns.trusted_key(
                signer="s",
                image_path="p&g",
                launch_string="2>&1",
            ),
            "9d266988536f34f17b03c3f5e7621e193d530d24",
        )
        env = {}
        where, selected = live.autoruns_selected_hash_where(
            [
                {
                    "ImagePath": "p&g",
                    "LaunchString": "2>&1",
                    "Signer": "s",
                }
            ],
            env=env,
        )
        payload = json.loads(
            gzip.decompress(
                base64.b64decode(
                    env["AutorunsSelectedHashesGzipBase64"]
                )
            )
        )
        self.assertEqual(
            payload,
            [
                {
                    "ImagePath": "p&g",
                    "LaunchString": "2>&1",
                    "Signer": "s",
                }
            ],
        )
        self.assertIn("AutorunsSelectedHashes", where)
        self.assertEqual(len(selected), 1)
        self.assertIn(
            "ImagePath=ImagePath",
            live.autoruns_golden_query_preamble(where),
        )

    def test_autoruns_known_good_schema_is_category_free(self):
        schema_path = (
            REPO_ROOT
            / "src/vraptor/resources"
            / "autoruns"
            / "windows-autoruns-known-good-schema.sql"
        )
        schema = schema_path.read_text(encoding="utf-8")
        self.assertEqual(autoruns_golden.SCHEMA_SQL, schema)
        self.assertIn("hash_key TEXT NOT NULL", schema)
        for column in (
            "signer",
            "image_path",
            "launch_string",
            "description",
            "modified_time",
        ):
            self.assertIn(f"{column} TEXT NOT NULL", schema)
        self.assertIn("PRIMARY KEY (hash_key)", schema)
        self.assertNotIn("category TEXT", schema)
        self.assertNotIn("autoruns_known_good_categories", schema)
        self.assertNotIn("autoruns_known_good_context", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS metadata", schema)
        connection = sqlite3.connect(":memory:")
        try:
            autoruns_golden.initialize_database(
                connection,
                built_at="2026-08-07T00:00:00Z",
            )
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' AND name = 'autoruns_known_good'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertIn("modified_time TEXT NOT NULL DEFAULT", table_sql)
        for excluded in (
            "confidence",
            "first_seen",
            "last_seen",
            "reason",
            "status",
            "version",
        ):
            self.assertNotIn(excluded, schema.casefold())
        self.assertNotIn("fqdn", schema.casefold())
        self.assertNotIn("clientid", schema.casefold())
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(schema)
            values = (
                key := "a" * 40,
                r"c:\windows\system32\cmd.exe",
                "cmd.exe /c test",
                "(verified) microsoft",
                "Windows command processor",
            )
            insert = """
                INSERT INTO autoruns_known_good (
                    hash_key, image_path, launch_string, signer, description
                ) VALUES (?, ?, ?, ?, ?)
            """
            connection.execute(insert, values)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(insert, values)
            connection.execute(
                "DELETE FROM autoruns_known_good WHERE hash_key = ?",
                (key,),
            )
            remaining = connection.execute(
                """
                SELECT count(*)
                FROM autoruns_known_good
                """
            ).fetchone()[0]
            self.assertEqual(remaining, 0)
        finally:
            connection.close()

    def test_autoruns_lolbin_use_case_is_imagepath_first_and_launch_aware(self):
        env = {}

        use_case = live.autoruns_use_case(
            AUTORUNS_ARTIFACT,
            "autoruns-lolbin",
            env=env,
        )

        self.assertEqual(use_case["output_name"], "suspicious_lolbins.json")
        self.assertEqual(len(use_case["reference_hash"]), 64)
        self.assertIn("`Image Path`", use_case["where"])
        self.assertEqual(
            use_case["family_stack"]["dimensions"],
            [
                "EntryLocation",
                "Entry",
                "ImagePath",
                "LaunchString",
                "Signer",
            ],
        )
        regex = env["UseCaseLolbinRegex1"]
        self.assertRegex(r"c:\windows\system32\cmd.exe", regex)
        self.assertNotRegex(r"c:\windows\system32\cmd.exe.bak", regex)
        self.assertNotRegex(r"cmd.exe /c whoami", regex)

    def test_analysis_output_paths_are_scoped_by_use_case(self):
        root = Path("/case/H.1")
        paths = live.analysis_paths(root)

        self.assertEqual(
            live.analysis_output_paths(paths, use_case=""),
            {"filters": root / "analysis" / "filters.json"},
        )
        self.assertEqual(
            live.analysis_output_paths(
                paths,
                use_case="autoruns-lolbin",
            ),
            {"filters": root / "analysis" / "filters-lolbin.json"},
        )

    def test_output_state_keeps_only_matching_use_case_records(self):
        state = {
            "case_filters": [
                {"id": "general", "use_case": ""},
                {"id": "lolbin", "use_case": "autoruns-lolbin"},
            ],
            "findings": [
                {"summary": "general", "use_case": ""},
                {"summary": "lolbin", "use_case": "autoruns-lolbin"},
            ],
            "normalization_candidates": [],
            "autoruns_mode_coverage": {
                AUTORUNS_ARTIFACT: {
                    "general-golden-residual": {
                        "mode": "general-golden-residual",
                    },
                    "autoruns-lolbin": {
                        "mode": "autoruns-lolbin",
                    },
                }
            },
            "artifacts": {
                AUTORUNS_ARTIFACT: {
                    "autoruns_residual_workflow": {
                        "stage": "complete",
                    },
                    "autoruns_focused_workflows": {
                        "autoruns-lolbin": {"stage": "complete"},
                        "autoruns-unverified": {"stage": "complete"},
                    },
                    "pending_reviews": [],
                    "pending_review_files": [],
                    "row_accounting": [],
                    "reviewed_signatures": [],
                    "drilldown_requests": [],
                }
            },
        }

        scoped = live.output_state_for_use_case(
            state,
            use_case="autoruns-lolbin",
        )

        self.assertEqual(
            [item["id"] for item in scoped["case_filters"]],
            ["lolbin"],
        )
        self.assertEqual(
            [item["summary"] for item in scoped["findings"]],
            ["lolbin"],
        )
        artifact_state = scoped["artifacts"][AUTORUNS_ARTIFACT]
        self.assertNotIn("autoruns_residual_workflow", artifact_state)
        self.assertEqual(
            list(artifact_state["autoruns_focused_workflows"]),
            ["autoruns-lolbin"],
        )

    def test_autoruns_unverified_use_case_requires_populated_context(self):
        env = {}

        use_case = live.autoruns_use_case(
            AUTORUNS_ARTIFACT,
            "autoruns-unverified",
            env=env,
        )

        self.assertEqual(
            use_case["output_name"],
            "suspicious_unverified.json",
        )
        self.assertIn("NOT (string=Signer =~", use_case["where"])
        self.assertIn("`Image Path`", use_case["where"])
        self.assertIn("`Launch String`", use_case["where"])
        self.assertEqual(env["UseCaseVerifiedRegex1"], r"(?i)verified")
        self.assertEqual(
            use_case["family_stack"]["dimensions"],
            [
                "EntryLocation",
                "Entry",
                "ImagePath",
                "LaunchString",
                "Signer",
            ],
        )

    def test_autoruns_rmm_use_case_matches_paths_and_launch_strings(self):
        env = {}

        use_case = live.autoruns_use_case(
            AUTORUNS_ARTIFACT,
            "autoruns-rmm",
            env=env,
        )

        self.assertEqual(use_case["output_name"], "suspicious_rmm.json")
        self.assertEqual(len(use_case["reference_hash"]), 64)
        self.assertIn("`Image Path`", use_case["where"])
        self.assertIn("`Launch String`", use_case["where"])
        regex = env["UseCaseRmmRegex1"]
        self.assertRegex(
            r"c:\program files\anydesk\anydesk.exe",
            regex,
        )
        self.assertEqual(
            use_case["family_stack"]["dimensions"],
            [
                "EntryLocation",
                "Entry",
                "ImagePath",
                "LaunchString",
                "Signer",
            ],
        )

    def test_autoruns_golden_lookup_can_preserve_priority_use_cases(self):
        configuration = golden_lookup_configuration()
        env = live.query_env("H.golden", AUTORUNS_ARTIFACT)

        where = live.autoruns_golden_where(
            AUTORUNS_ARTIFACT,
            configuration=configuration,
            env=env,
            preserve_priority=True,
        )

        self.assertNotIn("inventory_get", where)
        self.assertIn("AutorunsGoldenKeys", where)
        count_query = live.count_vql(where)
        self.assertIn("memoize", count_query)
        self.assertIn("parse_json_array", count_query)
        self.assertIn("gunzip", count_query)
        self.assertIn("base64decode", count_query)
        self.assertNotIn("Category", where)
        self.assertIn("`Image Path`", where)
        self.assertIn("`Launch String`", where)
        self.assertIn("Signer", where)
        self.assertTrue(env["AutorunsGoldenLookupGzipBase64"])

    def test_autoruns_golden_lookup_is_strict_by_default(self):
        configuration = golden_lookup_configuration()
        env = live.query_env("H.golden", AUTORUNS_ARTIFACT)

        where = live.autoruns_golden_where(
            AUTORUNS_ARTIFACT,
            configuration=configuration,
            env=env,
        )

        self.assertNotIn("inventory_get", where)
        self.assertNotIn("memoize(", where)
        self.assertTrue(where.startswith("(NOT (get("))
        self.assertNotIn(" OR ", where)
        self.assertEqual(live.count_vql(where).count("memoize("), 1)
        self.assertFalse(
            any(key.startswith("AutorunsGoldenLolbinRegex") for key in env)
        )
        self.assertFalse(
            any(key.startswith("AutorunsGoldenRmmRegex") for key in env)
        )

    def test_autoruns_golden_disable_ignores_environment_defaults(self):
        configuration = live.configured_autoruns_golden(
            disabled=True,
            environ={
                "VELO_AUTORUNS_GOLDEN_TOOL": "Autoruns.GoldenDB",
                "VELO_AUTORUNS_GOLDEN_VERSION": "20260728-deadbeef",
            },
        )

        self.assertFalse(configuration["enabled"])
        self.assertEqual(configuration["tool"], "")
        self.assertEqual(configuration["version"], "")

    def test_autoruns_golden_candidate_build_uses_strict_server_diff(self):
        configuration = golden_lookup_configuration()
        env = live.query_env("H.golden", AUTORUNS_ARTIFACT)

        where = live.autoruns_golden_where(
            AUTORUNS_ARTIFACT,
            configuration=configuration,
            env=env,
            preserve_priority=False,
        )

        self.assertNotIn("inventory_get", where)
        self.assertTrue(where.startswith("(NOT (get("))
        self.assertNotIn(" OR ", where)

    def test_autoruns_golden_inventory_is_pinned_by_server_hash(self):
        class FakeInventoryApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env=None, **kwargs):
                self.calls.append((vql, dict(env or {}), kwargs))
                return [
                    {
                        "Inventory": {
                            "Definition": {
                                "hash": "b" * 64,
                                "filestore_path": "inventory/golden.sqlite",
                            }
                        }
                    }
                ]

        resolved = live.resolve_autoruns_golden_inventory(
            api := FakeInventoryApi(),
            golden_lookup_configuration(),
        )

        self.assertEqual(resolved["inventory_hash"], "b" * 64)
        self.assertNotIn("filestore_path", resolved)
        self.assertEqual(resolved["identity_count"], 1)
        self.assertEqual(resolved["record_count"], 1)
        self.assertEqual(len(api.calls), 1)
        self.assertNotIn("sqlite(", api.calls[0][0])

    def test_autoruns_golden_inventory_must_match_shared_database(self):
        class FakeInventoryApi:
            def query(self, vql, env=None, **kwargs):
                return [
                    {
                        "Inventory": {
                            "Definition": {
                                "hash": "d" * 64,
                            }
                        }
                    }
                ]

        with self.assertRaisesRegex(
            RuntimeError,
            "does not match the shared local SQLite database",
        ):
            live.resolve_autoruns_golden_inventory(
                FakeInventoryApi(),
                golden_lookup_configuration(
                    inventory_hash="b" * 64,
                ),
            )

    def test_autoruns_golden_inventory_syncs_missing_server_tool(self):
        class FakeInventoryApi:
            def query(self, vql, env=None, **kwargs):
                return [{"Inventory": None}]

        configuration = golden_lookup_configuration()
        configuration["database"] = "/tmp/golden.sqlite"
        with mock.patch.object(
            live.autoruns_golden,
            "publish_database",
            return_value={"database_sha256": "b" * 64},
        ) as publish:
            resolved = live.resolve_autoruns_golden_inventory(
                FakeInventoryApi(),
                configuration,
                sync_missing_or_stale=True,
            )

        publish.assert_called_once()
        self.assertEqual(resolved["inventory_hash"], "b" * 64)
        self.assertEqual(
            resolved["inventory_sync"]["status"],
            "updated",
        )
        self.assertEqual(
            resolved["inventory_sync"]["reason"],
            "missing",
        )

    def test_autoruns_golden_inventory_recovers_exact_missing_error(self):
        api = mock.Mock()
        api.query.side_effect = live.InventoryNotFoundError("missing inventory")
        with mock.patch.object(
            live.autoruns_golden, "publish_database",
            return_value={"database_sha256": "b" * 64},
        ) as publish:
            resolved = live.resolve_autoruns_golden_inventory(
                api, golden_lookup_configuration(), sync_missing_or_stale=True,
            )
        publish.assert_called_once()
        self.assertEqual(resolved["inventory_sync"]["reason"], "missing")
        self.assertEqual(resolved["inventory_hash"], "b" * 64)

    def test_autoruns_golden_inventory_missing_error_respects_disabled_sync(self):
        api = mock.Mock()
        api.query.side_effect = live.InventoryNotFoundError("missing inventory")
        with mock.patch.object(live.autoruns_golden, "publish_database") as publish:
            with self.assertRaisesRegex(RuntimeError, "Publish the current database"):
                live.resolve_autoruns_golden_inventory(api, golden_lookup_configuration())
        publish.assert_not_called()

    def test_autoruns_golden_inventory_other_errors_never_publish(self):
        api = mock.Mock()
        error = RuntimeError("permission denied or unrelated not_found")
        api.query.side_effect = error
        with mock.patch.object(live.autoruns_golden, "publish_database") as publish:
            with self.assertRaises(RuntimeError) as raised:
                live.resolve_autoruns_golden_inventory(
                    api, golden_lookup_configuration(), sync_missing_or_stale=True,
                )
        self.assertIs(raised.exception, error)
        publish.assert_not_called()

    def test_autoruns_golden_inventory_missing_error_still_verifies_upload(self):
        api = mock.Mock()
        api.query.side_effect = live.InventoryNotFoundError("missing inventory")
        with mock.patch.object(
            live.autoruns_golden, "publish_database",
            return_value={"database_sha256": "d" * 64},
        ):
            with self.assertRaisesRegex(RuntimeError, "publication verification"):
                live.resolve_autoruns_golden_inventory(
                    api, golden_lookup_configuration(), sync_missing_or_stale=True,
                )

    def test_autoruns_golden_inventory_syncs_stale_server_tool(self):
        class FakeInventoryApi:
            def query(self, vql, env=None, **kwargs):
                return [
                    {
                        "Inventory": {
                            "Definition": {
                                "hash": "d" * 64,
                            }
                        }
                    }
                ]

        configuration = golden_lookup_configuration()
        configuration["database"] = "/tmp/golden.sqlite"
        with mock.patch.object(
            live.autoruns_golden,
            "publish_database",
            return_value={"database_sha256": "b" * 64},
        ) as publish:
            resolved = live.resolve_autoruns_golden_inventory(
                FakeInventoryApi(),
                configuration,
                sync_missing_or_stale=True,
            )

        publish.assert_called_once()
        self.assertEqual(resolved["inventory_hash"], "b" * 64)
        self.assertEqual(
            resolved["inventory_sync"]["reason"],
            "stale",
        )

    def test_autoruns_golden_configuration_changes_analysis_watermark(self):
        first = live.analysis_input_hash(
            profile_hash="profile",
            filters=[],
            known_bad=[],
            autoruns_golden_configuration={
                "enabled": True,
                "tool": "Autoruns.GoldenDB",
                "version": "one",
            },
        )
        second = live.analysis_input_hash(
            profile_hash="profile",
            filters=[],
            known_bad=[],
            autoruns_golden_configuration={
                "enabled": True,
                "tool": "Autoruns.GoldenDB",
                "version": "two",
            },
        )

        self.assertNotEqual(first, second)

    def test_autoruns_golden_sync_status_does_not_change_watermark(self):
        common = {
            "enabled": True,
            "tool": "Autoruns.GoldenDB",
            "version": "20260728-bbbbbbbb",
            "inventory_hash": "b" * 64,
            "database_sha256": "b" * 64,
        }
        first = live.analysis_input_hash(
            profile_hash="profile",
            filters=[],
            known_bad=[],
            autoruns_golden_configuration={
                **common,
                "inventory_sync": {
                    "status": "updated",
                    "reason": "missing",
                },
            },
        )
        second = live.analysis_input_hash(
            profile_hash="profile",
            filters=[],
            known_bad=[],
            autoruns_golden_configuration={
                **common,
                "inventory_sync": {
                    "status": "current",
                    "reason": "",
                },
            },
        )

        self.assertEqual(first, second)

    def test_general_autoruns_analysis_applies_strict_golden_diff_first(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                inventory_hash=validation["sha256"],
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.golden-residual",
                    "state": "FINISHED",
                },
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.golden-residual",
                autoruns_golden_tool="Autoruns.GoldenDB",
                autoruns_golden_version="20260728",
                autoruns_golden_db=database,
            )
            state = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            summary = Path(result["analysis_file"]).read_text(
                encoding="utf-8"
            )
            state_size = Path(result["state_file"]).stat().st_size

        artifact_state = state["artifacts"][AUTORUNS_ARTIFACT]
        golden = artifact_state["autoruns_golden"]
        self.assertTrue(golden["strict_subtraction"])
        self.assertEqual(golden["source_rows"], 10)
        self.assertEqual(golden["matched_rows"], 7)
        self.assertEqual(golden["residual_rows"], 3)
        self.assertEqual(golden["identity_count"], 1)
        self.assertEqual(golden["record_count"], 1)
        self.assertEqual(golden["warnings"], [])
        self.assertFalse(
            any(
                key.startswith("AutorunsGoldenLolbinRegex")
                or key.startswith("AutorunsGoldenRmmRegex")
                or key.startswith("AutorunsGoldenVerifiedRegex")
                for _, env, _ in api.calls
                for key in env
            )
        )
        mode = result["autoruns_mode_coverage"][AUTORUNS_ARTIFACT]
        self.assertEqual(mode["mode"], "general-golden-residual")
        self.assertEqual(mode["source_rows"], 10)
        self.assertEqual(mode["scope_rows"], 3)
        self.assertEqual(mode["golden_db"]["matched_rows"], 7)
        self.assertIn("### Autoruns GoldenDB reduction", summary)
        self.assertIn("### Streaming review", summary)
        self.assertIn("general-golden-residual", summary)
        self.assertEqual(result["status"], "awaiting_ai_classification")
        self.assertEqual(result["review_item_count"], 0)
        self.assertEqual(
            artifact_state["pending_reviews"],
            [],
        )
        self.assertFalse(
            (Path(result["state_file"]).parent / "autoruns_residual_stack.csv").exists()
        )
        self.assertEqual(Path(result["state_file"]).name, "hunt-analysis-state.json")
        self.assertLess(
            state_size,
            50_000,
        )

    def test_combined_autoruns_stack_requires_exact_review_accounting(self):
        for represented in (3, 4, 2):
            with self.subTest(represented=represented), tempfile.TemporaryDirectory() as temp_dir:
                database = Path(temp_dir) / "golden.sqlite"
                validation = create_golden_database(database)
                api = FakeAutorunsGoldenResidualApi(inventory_hash=validation["sha256"])
                classification = {
                    "suspicious_rows": [], "potential_golden_rows": [],
                    "manifest": {
                        "source_stack_sha256": "a" * 64,
                        "model": "test-model", "reviewed_group_count": 3,
                        "represented_row_count": represented,
                        "model_reviewed_group_count": 3,
                        "script_excluded_group_count": 0, "part_count": 1,
                        "runtime_files_persisted": False,
                    },
                }
                with (
                    mock.patch.object(live.autoruns_ai_review, "classify_streaming_rows",
                                      side_effect=consume_classification(classification)),
                    mock.patch.object(live.operation_log, "emit") as emit,
                ):
                    kwargs = dict(
                        investigation_id="IR1",
                        hunt_row={"hunt_id": "H.growth", "state": "FINISHED",
                                  "review_scope": "ad_hoc_review"},
                        request=request(AUTORUNS_ARTIFACT),
                        hunt_root=Path(temp_dir) / "H.growth",
                        autoruns_golden_tool="Autoruns.GoldenDB",
                        autoruns_golden_version="20260728",
                        autoruns_golden_db=database, autoruns_ai_review_enabled=True,
                    )
                    if represented != 3:
                        with self.assertRaisesRegex(RuntimeError, "accounting mismatch"):
                            live.analyze_live_hunt(api, **kwargs)
                        continue
                    result = live.analyze_live_hunt(api, **kwargs)
                self.assertEqual(result["status"], "complete")
                state = json.loads(Path(result["state_file"]).read_text())["specialized_analysis"]
                stack = state["artifacts"][AUTORUNS_ARTIFACT]["autoruns_residual_workflow"]["stack"]
                self.assertEqual(stack["represented_rows"], represented)
                self.assertEqual(stack["expected_rows"], 3)
                self.assertEqual(stack["additional_rows"], 0)
                warnings = [call for call in emit.call_args_list
                            if call.args == ("autoruns_accounting_growth",)]
                self.assertEqual(warnings, [])

    def test_focused_autoruns_stack_growth_continues_but_shortfall_fails(self):
        for represented in (3, 4, 2):
            with self.subTest(represented=represented), tempfile.TemporaryDirectory() as temp_dir:
                api = FakeAutorunsUseCaseApi()
                classification = {
                    "suspicious_rows": [], "potential_golden_rows": [],
                    "manifest": {
                        "source_stack_sha256": "a" * 64,
                        "model": "test-model", "reviewed_group_count": 1,
                        "represented_row_count": represented,
                        "model_reviewed_group_count": 1,
                        "script_excluded_group_count": 0, "part_count": 1,
                        "runtime_files_persisted": False,
                    },
                }
                with (
                    mock.patch.object(
                        live.autoruns_ai_review, "classify_streaming_rows",
                        side_effect=consume_classification(classification),
                    ),
                    mock.patch.object(live.operation_log, "emit") as emit,
                ):
                    kwargs = dict(
                        investigation_id="IR1",
                        hunt_row={"hunt_id": "H.focused-growth", "state": "FINISHED",
                                  "review_scope": "ad_hoc_review"},
                        request=request(AUTORUNS_ARTIFACT),
                        hunt_root=Path(temp_dir) / "H.focused-growth",
                        use_case="autoruns-lolbin", autoruns_ai_review_enabled=True,
                    )
                    if represented < 3:
                        with self.assertRaisesRegex(RuntimeError, "accounting mismatch"):
                            live.analyze_live_hunt(api, **kwargs)
                        continue
                    result = live.analyze_live_hunt(api, **kwargs)
                self.assertEqual(result["status"], "complete")
                workflow = result["autoruns_focused_workflows"][AUTORUNS_ARTIFACT][
                    "autoruns-lolbin"
                ]
                stack = workflow["stack"]
                self.assertEqual(stack["represented_rows"], represented)
                self.assertEqual(stack["expected_rows"], 3)
                self.assertEqual(stack["additional_rows"], represented - 3)
                warnings = [call for call in emit.call_args_list
                            if call.args == ("autoruns_accounting_growth",)]
                self.assertEqual(len(warnings), int(represented > 3))
                if represented > 3:
                    self.assertEqual(warnings[0].kwargs["level"], "warning")
                    self.assertIn("Continuing with all reviewed rows", stack["warnings"][0])

    def test_autoruns_residual_classification_drills_down_suspicious(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                inventory_hash=validation["sha256"],
            )
            hunt_root = Path(temp_dir) / "H.golden-review"
            classification = {
                "suspicious_rows": [{
                    "ImagePath": r"c:\users\user\residual-0.exe",
                    "LaunchString": "residual-0.exe",
                    "Signer": "",
                    "Total": 1,
                    "Severity": "high",
                    "Reason": "Unexpected user-path persistence.",
                }],
                "potential_golden_rows": [{
                    "ImagePath": r"c:\users\user\residual-1.exe",
                    "LaunchString": "residual-1.exe",
                    "Signer": "",
                    "Total": 1,
                    "Reason": "Reviewed test candidate.",
                }],
                "manifest": {
                    "source_stack_sha256": "a" * 64,
                    "model": "test-model",
                    "reviewed_group_count": 3,
                    "represented_row_count": 3,
                    "model_reviewed_group_count": 2,
                    "script_excluded_group_count": 1,
                    "part_count": 1,
                    "runtime_files_persisted": False,
                },
            }
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=consume_classification(classification),
            ):
                result = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={
                        "hunt_id": "H.golden-review",
                        "state": "FINISHED",
                        "review_scope": "ad_hoc_review",
                    },
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    autoruns_golden_tool="Autoruns.GoldenDB",
                    autoruns_golden_version="20260728",
                    autoruns_golden_db=database,
                    autoruns_ai_review_enabled=True,
                )
            state = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            generated_files = {
                path.name
                for path in (hunt_root / "analysis").iterdir()
                if path.is_file()
            }
            ai_review_directory_exists = (
                hunt_root / "analysis" / "autoruns_ai_review"
            ).exists()
            potential_metadata, potential_rows, _ = live.parse_csv_with_metadata(
                hunt_root / "analysis" / "autoruns_potential_golden.csv"
            )
            analysis_report = Path(result["analysis_file"]).read_text(
                encoding="utf-8"
            )
            canonical_state_size = Path(result["state_file"]).stat().st_size
            regenerated_report = (
                flow_analysis_coordinator.render_canonical_hunt_report(
                    hunt_root=hunt_root,
                    question="Review persistence",
                    specialized_state=state,
                )
            )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["coverage"], "complete")
        workflow_state = state["artifacts"][AUTORUNS_ARTIFACT][
            "autoruns_residual_workflow"
        ]
        self.assertEqual(workflow_state["stage"], "complete")
        self.assertEqual(
            workflow_state["suspicious_context"]["row_count"],
            1,
        )
        self.assertEqual(
            workflow_state["suspicious_context"]["host_count"],
            1,
        )
        representative = workflow_state["suspicious_context"][
            "representative_items"
        ][0]
        self.assertEqual(
            representative["endpoints"],
            [{
                "fqdn": "host-0.example.test",
                "client_id": "C.0",
                "row_count": 1,
            }],
        )
        self.assertEqual(
            representative["persistence"],
            [{
                "category": "Logon",
                "entry_location": r"hkcu\software\vendor\run",
                "entry": "residual-0",
            }],
        )
        self.assertEqual(
            representative["source"]["hunt_id"],
            "H.golden-review",
        )
        self.assertEqual(
            len(representative["source"]["query_sha256"]),
            64,
        )
        self.assertEqual(
            workflow_state["ai_review"]["model_reviewed_group_count"],
            2,
        )
        self.assertIn("autoruns_potential_golden.csv", generated_files)
        self.assertFalse(ai_review_directory_exists)
        self.assertEqual(potential_metadata["SchemaVersion"], "2")
        self.assertEqual(potential_metadata["EngagementId"], "IR1")
        self.assertEqual(potential_metadata["HuntId"], "H.golden-review")
        self.assertEqual(potential_metadata["Artifact"], AUTORUNS_ARTIFACT)
        self.assertEqual(potential_metadata["ReviewComplete"], "true")
        self.assertEqual(potential_metadata["ReviewedGroupCount"], "3")
        self.assertEqual(potential_metadata["GoldenDBSHA256"], validation["sha256"])
        self.assertEqual(len(potential_rows), 1)
        self.assertEqual(
            workflow_state["classification"]["potential_golden"]["row_count"],
            1,
        )
        self.assertEqual(
            workflow_state["classification"]["potential_golden"]["path"],
            "analysis/autoruns_potential_golden.csv",
        )
        self.assertEqual(
            workflow_state["candidate_output"]["action"],
            "published",
        )
        self.assertTrue(workflow_state["candidate_output"]["current_run"])
        self.assertIn(
            "Potential GoldenDB output: status `complete`; action `published`",
            analysis_report,
        )
        self.assertIn("host-0.example.test", analysis_report)
        self.assertIn("host-0.example.test", regenerated_report)
        self.assertIn("C.0", analysis_report)
        self.assertIn(r"hkcu\software\vendor\run", analysis_report)
        self.assertIn("suspicious Autoruns identity/identities", analysis_report)
        self.assertNotIn(
            "No specialized finding summaries have been recorded.",
            analysis_report,
        )
        self.assertLess(canonical_state_size, 64 * 1024)

    def test_failed_autoruns_rerun_preserves_last_verified_candidate_set(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                inventory_hash=validation["sha256"],
            )
            hunt_root = Path(temp_dir) / "H.golden-preserve"
            completed_classification = {
                "suspicious_rows": [],
                "potential_golden_rows": [{
                    "ImagePath": r"c:\users\user\residual-1.exe",
                    "LaunchString": "residual-1.exe",
                    "Signer": "",
                    "Total": 1,
                    "Reason": "Reviewed test candidate.",
                }],
                "manifest": {
                    "source_stack_sha256": "c" * 64,
                    "model": "test-model",
                    "reviewed_group_count": 3,
                    "represented_row_count": 3,
                    "model_reviewed_group_count": 3,
                    "script_excluded_group_count": 0,
                    "part_count": 1,
                    "runtime_files_persisted": False,
                },
            }
            common = {
                "investigation_id": "IR1",
                "hunt_row": {
                    "hunt_id": "H.golden-preserve",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                "request": request(AUTORUNS_ARTIFACT),
                "hunt_root": hunt_root,
                "autoruns_golden_tool": "Autoruns.GoldenDB",
                "autoruns_golden_version": "20260728",
                "autoruns_golden_db": database,
                "autoruns_ai_review_enabled": True,
            }
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=consume_classification(completed_classification),
            ):
                first = live.analyze_live_hunt(api, **common)
            candidate_path = (
                hunt_root / "analysis" / "autoruns_potential_golden.csv"
            )
            original_bytes = candidate_path.read_bytes()
            original_reference = first["autoruns_residual_workflow"][
                AUTORUNS_ARTIFACT
            ]["classification"]["potential_golden"]

            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=RuntimeError("provider request failed"),
            ):
                result = live.analyze_live_hunt(api, **common)
            workflow = result["autoruns_residual_workflow"][
                AUTORUNS_ARTIFACT
            ]
            analysis_report = Path(result["analysis_file"]).read_text(
                encoding="utf-8"
            )
            preserved_bytes = candidate_path.read_bytes()

        self.assertEqual(preserved_bytes, original_bytes)
        self.assertEqual(workflow["stage"], "ai_classification_failed")
        self.assertEqual(workflow["classification"], {})
        self.assertEqual(workflow["candidate_output"]["status"], "failed")
        self.assertEqual(
            workflow["candidate_output"]["action"],
            "preserved_stale",
        )
        self.assertFalse(workflow["candidate_output"]["current_run"])
        retained = workflow["candidate_output"]["retained_previous"]
        self.assertTrue(retained["verified"])
        self.assertEqual(retained["sha256"], original_reference["sha256"])
        self.assertIn(
            "Potential GoldenDB output: status `failed`; action `preserved_stale`",
            analysis_report,
        )

    def test_disabled_autoruns_review_preserves_last_verified_candidate_set(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                inventory_hash=validation["sha256"],
            )
            hunt_root = Path(temp_dir) / "H.golden-disabled"
            completed_classification = {
                "suspicious_rows": [],
                "potential_golden_rows": [],
                "manifest": {
                    "source_stack_sha256": "d" * 64,
                    "model": "test-model",
                    "reviewed_group_count": 3,
                    "represented_row_count": 3,
                    "model_reviewed_group_count": 3,
                    "script_excluded_group_count": 0,
                    "part_count": 1,
                    "runtime_files_persisted": False,
                },
            }
            common = {
                "investigation_id": "IR1",
                "hunt_row": {
                    "hunt_id": "H.golden-disabled",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                "request": request(AUTORUNS_ARTIFACT),
                "hunt_root": hunt_root,
                "autoruns_golden_tool": "Autoruns.GoldenDB",
                "autoruns_golden_version": "20260728",
                "autoruns_golden_db": database,
            }
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=consume_classification(completed_classification),
            ):
                live.analyze_live_hunt(
                    api,
                    **common,
                    autoruns_ai_review_enabled=True,
                )
            candidate_path = (
                hunt_root / "analysis" / "autoruns_potential_golden.csv"
            )
            original_bytes = candidate_path.read_bytes()

            result = live.analyze_live_hunt(
                api,
                **common,
                autoruns_ai_review_enabled=False,
            )
            preserved_bytes = candidate_path.read_bytes()
            workflow = result["autoruns_residual_workflow"][
                AUTORUNS_ARTIFACT
            ]

        self.assertEqual(preserved_bytes, original_bytes)
        self.assertEqual(workflow["stage"], "awaiting_ai_classification")
        self.assertEqual(
            workflow["candidate_output"]["status"],
            "not_produced",
        )
        self.assertEqual(
            workflow["candidate_output"]["action"],
            "preserved_stale",
        )
        self.assertFalse(workflow["candidate_output"]["current_run"])
        self.assertTrue(
            workflow["candidate_output"]["retained_previous"]["verified"]
        )

    def test_autoruns_residual_ai_review_runs_and_drills_down_in_one_pass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                inventory_hash=validation["sha256"],
            )
            hunt_root = Path(temp_dir) / "H.golden-ai"
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=consume_classification({
                    "suspicious_rows": [
                        {
                            "ImagePath": (
                                r"c:\users\user\residual-0.exe"
                            ),
                            "LaunchString": "residual-0.exe",
                            "Signer": "",
                            "Total": 1,
                            "Severity": "high",
                            "Reason": "Unexpected user-path persistence.",
                        }
                    ],
                    "potential_golden_rows": [],
                    "manifest": {
                        "source_stack_sha256": "b" * 64,
                        "model": "gpt-5.6-luna",
                        "reviewed_group_count": 3,
                        "represented_row_count": 3,
                        "model_reviewed_group_count": 3,
                        "script_excluded_group_count": 0,
                        "part_count": 1,
                        "runtime_files_persisted": False,
                    },
                }),
            ) as classify:
                result = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={
                        "hunt_id": "H.golden-ai",
                        "state": "FINISHED",
                        "review_scope": "ad_hoc_review",
                    },
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    autoruns_golden_tool="Autoruns.GoldenDB",
                    autoruns_golden_version="20260728",
                    autoruns_golden_db=database,
                    autoruns_ai_review_enabled=True,
                )
            potential_metadata, potential_rows, potential_fields = (
                live.parse_csv_with_metadata(
                    hunt_root
                    / "analysis"
                    / "autoruns_potential_golden.csv"
                )
            )

        classify.assert_called_once()
        # General GoldenDB accounting and grouping share one source query.
        self.assertEqual(sum("LET AutorunsCountedGroups" in q for q, _, _ in api.calls), 1)
        self.assertFalse(any("count() AS RowCount" in q for q, _, _ in api.calls))
        self.assertEqual(result["status"], "complete")
        workflow = result["autoruns_residual_workflow"][
            AUTORUNS_ARTIFACT
        ]
        self.assertEqual(workflow["stage"], "complete")
        self.assertEqual(workflow["ai_review"]["part_count"], 1)
        self.assertEqual(
            workflow["suspicious_context"]["host_count"],
            1,
        )
        self.assertEqual(workflow["candidate_output"]["action"], "published_empty")
        self.assertTrue(workflow["candidate_output"]["current_run"])
        self.assertEqual(potential_metadata["ReviewComplete"], "true")
        self.assertEqual(
            potential_fields,
            list(live.AUTORUNS_POTENTIAL_GOLDEN_FIELDS),
        )
        self.assertEqual(potential_rows, [])

    def test_autoruns_chat_summary_uses_bounded_in_memory_context(self):
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.context",
            group="",
            hunt_state="FINISHED",
        )
        state["artifacts"] = {
            AUTORUNS_ARTIFACT: {
                "status": "complete",
                "autoruns_golden": {
                    "source_rows": 12,
                    "matched_rows": 0,
                    "residual_rows": 12,
                },
                "autoruns_residual_workflow": {
                    "stack": {"group_count": 1, "represented_rows": 12},
                    "classification": {
                        "suspicious_count": 1,
                        "potential_golden_count": 0,
                    },
                    "ai_review": {"model_reviewed_group_count": 1},
                    "suspicious_context": {
                        "row_count": 12,
                        "host_count": 3,
                        "items": [
                            {
                                "Severity": "high",
                                "Reason": "Unexpected persistence.",
                                "ImagePath": r"c:\users\user\suspicious.exe",
                                "LaunchString": "suspicious.exe -silent",
                                "row_count": 12,
                                "host_count": 3,
                            }
                        ],
                    },
                },
            }
        }

        details = live.autoruns_context_items_for_state(state)
        summary = live.render_autoruns_chat_summary(
            state,
            autoruns_context_details=details,
            selected_artifacts=[AUTORUNS_ARTIFACT],
        )

        self.assertIn("Exact rows represented: 12", summary)
        self.assertIn("Endpoints: 3 endpoint(s)", summary)
        self.assertIn("identities unavailable in legacy compact state", summary)
        self.assertIn("suspicious.exe", summary)

    def test_autoruns_context_renderer_bounds_named_endpoints(self):
        endpoints = [
            {
                "fqdn": f"host-{index}.example.test",
                "client_id": f"C.{index}",
                "row_count": 1,
            }
            for index in range(12)
        ]

        rendered = "\n".join(
            live.render_bounded_autoruns_context(
                [{
                    "Severity": "high",
                    "Reason": "Unexpected persistence.",
                    "ImagePath": "suspicious.exe",
                    "row_count": 12,
                    "host_count": 12,
                    "endpoints": endpoints,
                }],
                heading_level=4,
                context_group_count=1,
            )
        )

        self.assertIn("host-0.example.test", rendered)
        self.assertNotIn("host-8.example.test", rendered)
        self.assertNotIn("host-9.example.test", rendered)
        self.assertIn("plus 2 more endpoint(s)", rendered)

    def test_compact_autoruns_context_preserves_omission_accounting(self):
        workflow = {
            "suspicious_context": {
                "items": [{
                    "ImagePath": "suspicious.exe",
                    "row_count": 12,
                    "host_count": 12,
                    "endpoints": [
                        {
                            "fqdn": f"host-{index}.example.test",
                            "client_id": f"C.{index}",
                            "row_count": 1,
                        }
                        for index in range(12)
                    ],
                    "persistence": [
                        {
                            "category": "Logon",
                            "entry_location": f"location-{index}",
                            "entry": f"entry-{index}",
                        }
                        for index in range(12)
                    ],
                }],
            },
        }

        context = live.compact_autoruns_workflow(workflow)[
            "suspicious_context"
        ]
        representative = context["representative_items"][0]

        self.assertEqual(len(representative["endpoints"]), 10)
        self.assertEqual(representative["omitted_endpoint_count"], 2)
        self.assertEqual(len(representative["persistence"]), 10)
        self.assertEqual(representative["omitted_persistence_count"], 2)

    def test_non_empty_golden_db_zero_match_is_recorded_as_warning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "autoruns-golden.sqlite"
            validation = create_golden_database(database)
            api = FakeAutorunsGoldenResidualApi(
                residual_rows=10,
                inventory_hash=validation["sha256"],
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.golden-zero",
                    "state": "FINISHED",
                },
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.golden-zero",
                autoruns_golden_tool="Autoruns.GoldenDB",
                autoruns_golden_db=database,
            )

        golden = result["autoruns_mode_coverage"][AUTORUNS_ARTIFACT][
            "golden_db"
        ]
        self.assertIn("## Autoruns hunt summary", result["chat_summary"])
        self.assertEqual(
            result["chat_summary"].strip(),
            result["autoruns_chat_summary"].strip(),
        )
        self.assertEqual(golden["matched_rows"], 0)
        self.assertEqual(
            golden["warnings"],
            ["non_empty_golden_db_produced_zero_matches"],
        )

    def test_use_case_is_rejected_for_non_autoruns_artifact(self):
        with self.assertRaisesRegex(RuntimeError, "only supported"):
            live.autoruns_use_case(
                ARTIFACT,
                "autoruns-unverified",
                env={},
            )

    def test_suspicious_use_case_output_contains_hosts_and_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = live.analysis_paths(Path(temp_dir) / "H.output")
            written = live.write_suspicious_use_case_outputs(
                paths,
                hunt_id="H.output",
                review_items=[
                    {
                        "review_id": "review-one",
                        "artifact": AUTORUNS_ARTIFACT,
                        "kind": "drilldown",
                        "scope": {"Category": "Logon"},
                        "scope_row_count": 2,
                        "exhaustive": True,
                        "evidence_hash": "abc",
                        "use_case": "autoruns-lolbin",
                        "output_name": "suspicious_lolbins.json",
                        "source_disposition": "suspicious",
                        "drilldown": {"reason": "Suspicious launch string."},
                        "rows": [
                            {
                                "Entry": "cmd.exe",
                                "ImagePath": (
                                    r"c:\windows\system32\cmd.exe"
                                ),
                                "LaunchString": "cmd.exe /c whoami",
                                "Fqdn": "host-one.example.test",
                                "ClientId": "C.1",
                            },
                            {
                                "Entry": "cmd.exe",
                                "ImagePath": (
                                    r"c:\windows\system32\cmd.exe"
                                ),
                                "LaunchString": "cmd.exe /c whoami",
                                "Fqdn": "host-one.example.test",
                                "ClientId": "C.1",
                            },
                        ],
                    },
                    {
                        "kind": "drilldown",
                        "exhaustive": False,
                        "output_name": "suspicious_lolbins.json",
                        "source_disposition": "suspicious",
                        "rows": [{"Fqdn": "must-not-persist"}],
                    },
                ],
            )
        self.assertEqual(written, [])

    def test_suspicious_use_case_output_rejects_unknown_filename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "Unsupported"):
                live.write_suspicious_use_case_outputs(
                    live.analysis_paths(Path(temp_dir) / "H.output"),
                    hunt_id="H.output",
                    review_items=[
                        {
                            "kind": "drilldown",
                            "exhaustive": True,
                            "source_disposition": "suspicious",
                            "output_name": "../outside.json",
                            "rows": [],
                        }
                    ],
                )

    def test_unverified_use_case_writes_complete_stack_without_review_queue(self):
        api = FakeAutorunsUseCaseApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.use-case"
            (hunt_root / "analysis").mkdir(parents=True)
            expected_filters_path = (
                hunt_root / "analysis" / "filters-unverified.json"
            )
            expected_filters_path.write_text(
                '{"filters": ["stale"]}\n',
                encoding="utf-8",
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.use-case", "state": "FINISHED"},
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=hunt_root,
                use_case="autoruns-unverified",
            )

            workflow = result["autoruns_focused_workflows"][
                AUTORUNS_ARTIFACT
            ]["autoruns-unverified"]
            stack_path = hunt_root / "analysis" / "autoruns_unverified_stack.csv"
            analysis_path = Path(result["analysis_file"])
            analysis_exists = analysis_path.is_file()
            analysis_text = analysis_path.read_text(encoding="utf-8")
            general_filters_exists = (
                hunt_root / "analysis" / "filters.json"
            ).exists()
            focused_filters_exists = expected_filters_path.exists()

        self.assertEqual(result["review_item_count"], 0)
        self.assertEqual(result["review_files"], [])
        self.assertNotIn("summary_file", result)
        self.assertEqual(result["filters_file"], "")
        self.assertFalse(focused_filters_exists)
        self.assertTrue(analysis_exists)
        self.assertEqual(analysis_path, hunt_root / "analysis-hunt.md")
        self.assertIn("## Specialized analysis", analysis_text)
        self.assertIn("autoruns-unverified", analysis_text)
        self.assertFalse(general_filters_exists)
        self.assertEqual(workflow["stage"], "awaiting_ai_classification")
        self.assertFalse(stack_path.exists())
        self.assertFalse(workflow["stack"]["persisted"])
        self.assertTrue(
            any(
                any(
                    key.startswith("UseCaseVerifiedRegex")
                    for key in env
                )
                for _, env, _ in api.calls
            )
        )
        coverage = result["autoruns_mode_coverage"][AUTORUNS_ARTIFACT]
        self.assertEqual(coverage["mode"], "autoruns-unverified")
        self.assertEqual(coverage["source_rows"], 3)
        self.assertEqual(coverage["scope_rows"], 3)

    def test_rmm_review_uses_metadata_manifest_not_editable_csv(self):
        api = FakeAutorunsUseCaseApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.review-csv"
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.review-csv",
                    "state": "FINISHED",
                },
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=hunt_root,
                use_case="autoruns-rmm",
            )
            persisted = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            manifest = json.loads(
                Path(result["review_items_file"]).read_text(encoding="utf-8")
            )

        self.assertEqual(result["review_files"], [])
        self.assertFalse(
            (hunt_root / "analysis" / "autoruns_rmm_review.csv").exists()
        )
        self.assertEqual(manifest["review_item_count"], 1)
        self.assertFalse(manifest["raw_rows_persisted"])
        artifact_state = persisted["artifacts"][AUTORUNS_ARTIFACT]
        self.assertEqual(artifact_state["pending_review_count"], 1)

    def test_rmm_ai_review_streams_into_metadata_without_runtime_files(self):
        api = FakeAutorunsUseCaseApi()

        def review_rows(rows, **kwargs):
            supplied = list(rows)
            return {
                "recommendations": [
                    {
                        "review_id": row["ReviewId"],
                        "disposition": "notable",
                        "severity": "low",
                        "confidence": "high",
                        "drilldown_recommended": True,
                        "reason": "Confirm the remote-management owner.",
                    }
                    for row in supplied
                ],
                "manifest": {
                    "schema_version": 1,
                    "streaming": True,
                    "use_case": "autoruns-rmm",
                    "model": "test-model",
                    "reviewed_group_count": len(supplied),
                    "part_count": 1,
                    "runtime_files_persisted": False,
                },
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.rmm-ai"
            with mock.patch.object(
                live.autoruns_ai_review,
                "review_focused_rows_streaming",
                side_effect=review_rows,
            ) as review:
                result = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={"hunt_id": "H.rmm-ai", "state": "FINISHED"},
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    use_case="autoruns-rmm",
                    autoruns_ai_review_enabled=True,
                )
            review_manifest = json.loads(
                Path(result["review_items_file"]).read_text(encoding="utf-8")
            )
            canonical = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )

        review.assert_called_once()
        self.assertEqual(
            review_manifest["review_items"][0]["ai_review"]["disposition"],
            "notable",
        )
        self.assertFalse(
            (hunt_root / "analysis" / "autoruns_ai_review").exists()
        )
        self.assertFalse(
            canonical["specialized_analysis"]["artifacts"][AUTORUNS_ARTIFACT]
            ["rmm_ai_review"]["runtime_files_persisted"]
        )

    def test_focused_autoruns_ai_selects_and_drills_context_in_one_pass(self):
        api = FakeAutorunsUseCaseApi()
        observed_rows_iterable = []

        def classify_stack(rows, **kwargs):
            observed_rows_iterable.append(hasattr(rows, "__iter__"))
            return {
                "suspicious_rows": [
                    {
                        "ImagePath": r"c:\windows\system32\cmd.exe",
                        "LaunchString": "cmd.exe /c whoami",
                        "Signer": "",
                        "Total": 3,
                        "Severity": "high",
                        "Reason": "Unexpected command-shell persistence.",
                    }
                ],
                "potential_golden_rows": [],
                "manifest": {
                    "source_stack_sha256": "d" * 64,
                    "model": "test-model",
                    "review_mode": "autoruns-lolbin",
                    "reviewed_group_count": 1,
                    "represented_row_count": 3,
                    "model_reviewed_group_count": 1,
                    "script_excluded_group_count": 0,
                    "suspicious_count": 1,
                    "part_count": 1,
                    "runtime_files_persisted": False,
                },
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.focused-ai"
            candidate_path = (
                hunt_root / "analysis" / "autoruns_potential_golden.csv"
            )
            candidate_path.parent.mkdir(parents=True, exist_ok=True)
            candidate_path.write_text(
                live.render_csv_with_metadata(
                    metadata={
                        "SchemaVersion": 2,
                        "SourceStackSHA256": "e" * 64,
                        "SourceQuerySHA256": "f" * 64,
                        "GoldenDBSHA256": "",
                        "GoldenDBVersion": "",
                        "SourceGroupCount": 0,
                        "ReviewedGroupCount": 0,
                        "ReviewComplete": "true",
                    },
                    fieldnames=live.AUTORUNS_POTENTIAL_GOLDEN_FIELDS,
                    rows=[],
                ),
                encoding="utf-8",
            )
            original_candidate_bytes = candidate_path.read_bytes()
            with mock.patch.object(
                live.autoruns_ai_review,
                "classify_streaming_rows",
                side_effect=classify_stack,
            ) as classify:
                result = live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={
                        "hunt_id": "H.focused-ai",
                        "state": "FINISHED",
                    },
                    request=request(AUTORUNS_ARTIFACT),
                    hunt_root=hunt_root,
                    use_case="autoruns-lolbin",
                    autoruns_ai_review_enabled=True,
                )
            workflow = result["autoruns_focused_workflows"][
                AUTORUNS_ARTIFACT
            ]["autoruns-lolbin"]
            summary = Path(result["analysis_file"]).read_text(
                encoding="utf-8"
            )
            summary_name = Path(result["analysis_file"]).name
            focused_filters_exists = (
                hunt_root
                / "analysis"
                / "filters-lolbin.json"
            ).exists()
            preserved_candidate_bytes = candidate_path.read_bytes()

        classify.assert_called_once()
        self.assertEqual(observed_rows_iterable, [True])
        self.assertEqual(result["review_item_count"], 0)
        self.assertEqual(result["review_files"], [])
        self.assertEqual(workflow["stage"], "complete")
        self.assertEqual(
            workflow["candidate_output"]["status"],
            "not_applicable",
        )
        self.assertEqual(
            workflow["candidate_output"]["action"],
            "not_applicable",
        )
        self.assertEqual(preserved_candidate_bytes, original_candidate_bytes)
        self.assertEqual(workflow["classification"]["suspicious_count"], 1)
        self.assertEqual(workflow["suspicious_context"]["row_count"], 1)
        self.assertFalse(workflow["suspicious_context"]["persisted"])
        self.assertEqual(summary_name, "analysis-hunt.md")
        self.assertEqual(result["filters_file"], "")
        self.assertFalse(focused_filters_exists)
        self.assertIn("### Streaming review", summary)
        self.assertIn("autoruns-lolbin", summary)
        self.assertFalse(result["raw_evidence_persisted"])
        self.assertFalse(result["raw_result_exported"])

    def test_rmm_use_case_bypasses_golden_inventory_and_stacks_candidates(self):
        api = FakeAutorunsUseCaseApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.rmm", "state": "FINISHED"},
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.rmm",
                use_case="autoruns-rmm",
                autoruns_golden_tool="Autoruns.GoldenDB",
                autoruns_golden_version="20260728",
            )

        self.assertEqual(result["review_item_count"], 1)
        self.assertEqual(
            result["review_items"][0]["use_case"],
            "autoruns-rmm",
        )
        self.assertTrue(
            any(
                any(key.startswith("UseCaseRmmRegex") for key in env)
                for _, env, _ in api.calls
            )
        )
        self.assertFalse(
            any("inventory_get(" in vql for vql, _, _ in api.calls)
        )
        self.assertEqual(
            result["autoruns_mode_coverage"][AUTORUNS_ARTIFACT]["mode"],
            "autoruns-rmm",
        )

    def test_autoruns_mode_coverage_is_retained_across_focused_passes(self):
        api = FakeAutorunsUseCaseApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.mode-coverage"
            live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.mode-coverage",
                    "state": "FINISHED",
                },
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=hunt_root,
                use_case="autoruns-unverified",
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.mode-coverage",
                    "state": "FINISHED",
                },
                request=request(AUTORUNS_ARTIFACT),
                hunt_root=hunt_root,
                use_case="autoruns-rmm",
            )
            state = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            hydrated = live.load_state(
                Path(result["state_file"]),
                investigation_id="IR1",
                hunt_id="H.mode-coverage",
                group="",
                hunt_state="FINISHED",
            )
            unverified_queue_exists = (
                hunt_root
                / "analysis"
                / "autoruns_unverified_stack.csv"
            ).is_file()
            rmm_queue_exists = (
                hunt_root
                / "analysis"
                / "autoruns_rmm_review.csv"
            ).is_file()

        modes = state["autoruns_mode_coverage"][AUTORUNS_ARTIFACT]
        self.assertIn("autoruns-unverified", modes)
        self.assertIn("autoruns-rmm", modes)
        self.assertFalse(unverified_queue_exists)
        self.assertFalse(rmm_queue_exists)
        self.assertEqual(
            {
                item["use_case"]
                for item in hydrated["artifacts"][AUTORUNS_ARTIFACT][
                    "pending_reviews"
                ]
            },
            {"autoruns-rmm"},
        )
        self.assertIn(
            "autoruns-unverified",
            state["artifacts"][AUTORUNS_ARTIFACT][
                "autoruns_focused_workflows"
            ],
        )

    def test_scoped_select_applies_where_before_projection_aliases(self):
        vql = live.select_vql(
            ["Detection.Name AS Detection", "Message AS Evidence"],
            "(Detection.Name = PivotScope1)",
            100,
        )

        self.assertIn(
            "LET ReviewRows = SELECT * FROM "
            "hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
            vql,
        )
        self.assertLess(
            vql.index("WHERE (Detection.Name = PivotScope1)"),
            vql.index("Detection.Name AS Detection"),
        )
        self.assertIn("FROM ReviewRows", vql)

    def test_detectraptor_live_projection_includes_full_direct_evidence(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        projection = live.profile_projection(profiles[ARTIFACT])
        rendered = "\n".join(projection)

        self.assertNotIn("EvidenceLength", rendered)
        self.assertNotIn("EvidenceSHA256", rendered)
        self.assertNotIn("EvidencePreview", rendered)
        self.assertIn("EventData.ScriptBlockText", rendered)
        self.assertIn(" AS Evidence", rendered)
        self.assertIn("EvidencePath", rendered)
        self.assertIn("Computer", projection)
        self.assertIn("ClientId", projection)
        self.assertNotIn(
            "if(condition=Message, then=Message, else=EventData) AS Evidence",
            projection,
        )
        self.assertNotIn(
            "EvidenceSHA256",
            profiles[ARTIFACT]["review"]["filter_fields"],
        )
        self.assertNotIn(
            "EvidenceLength",
            profiles[ARTIFACT]["review"]["sample_fields"],
        )
        self.assertNotIn(
            "EvidencePreview",
            profiles[ARTIFACT]["review"]["sample_fields"],
        )

    def test_ig_autoruns_uses_category_scope_and_requested_projection(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        profile = profiles[AUTORUNS_ARTIFACT]
        projection = live.profile_projection(profile)
        scope_id, scope = live.stack_for_role(profile, "scope")
        signature_id, signature = live.stack_for_role(profile, "signature")
        normalized_id, normalized = live.stack_for_role(
            profile,
            "family_signature",
        )

        self.assertEqual(scope_id, "category")
        self.assertEqual(scope["server_dimensions"], ["Category"])
        self.assertEqual(scope["server_scope_aliases"], ["Category"])
        self.assertEqual(signature_id, "autorun_signature")
        self.assertEqual(len(signature["server_dimensions"]), 1)
        self.assertEqual(
            signature["dimensions"],
            [
                "NormalizedImagePath",
                "NormalizedLaunchString",
                "Signer",
            ],
        )
        self.assertEqual(normalized_id, "autorun_path_entry")
        self.assertEqual(
            normalized["dimensions"],
            [
                "EntryLocation",
                "Entry",
                "NormalizedImagePath",
                "NormalizedLaunchString",
                "Signer",
            ],
        )
        self.assertEqual(
            normalized["server_dimensions"],
            [
                autoruns.user_path_vql("`Entry Location`"),
                autoruns.ascii_lower_vql("Entry"),
                autoruns.user_path_vql("`Image Path`"),
                autoruns.user_path_vql("`Launch String`"),
                autoruns.ascii_lower_vql("Signer"),
            ],
        )
        signature_expression = signature["server_dimensions"][0]
        self.assertIn("ImagePath=" + autoruns.user_path_vql("`Image Path`"), signature_expression)
        self.assertIn("LaunchString=" + autoruns.user_path_vql("`Launch String`"), signature_expression)
        self.assertIn("Signer=" + autoruns.ascii_lower_vql("Signer"), signature_expression)
        self.assertLess(
            signature_expression.index("ImagePath="),
            signature_expression.index("LaunchString="),
        )
        self.assertLess(
            signature_expression.index("LaunchString="),
            signature_expression.index("Signer="),
        )
        self.assertNotIn("Entry=Entry", signature_expression)
        self.assertNotIn("Category=Category", signature_expression)
        self.assertEqual(
            projection,
            [
                "`Entry Location` AS EntryLocation",
                "Entry",
                "Category",
                "Signer",
                "`Image Path` AS ImagePath",
                "`Launch String` AS LaunchString",
                "Profile",
                "Description",
                "Version",
                "`SHA-256` AS SHA256",
                "Fqdn",
                "ClientId",
            ],
        )

    def test_autoruns_compound_filter_matches_category_path_and_signer(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        profile = profiles[AUTORUNS_ARTIFACT]
        candidate = live.validate_filter(
            {
                "scope": {"Category": "Logon"},
                "conditions": [
                    {
                        "field": "ImagePath",
                        "operator": "regex",
                        "pattern": (
                            r"(?i)^c:\\windows\\system32\\"
                            r"securityhealthsystray\.exe$"
                        ),
                    },
                    {
                        "field": "Signer",
                        "operator": "regex",
                        "pattern": r"(?i)^\(verified\).*microsoft",
                    },
                ],
                "reason": "noise-reduction",
                "status": "case-approved",
            },
            artifact=AUTORUNS_ARTIFACT,
            profile=profile,
            source="test",
            default_status="candidate",
        )
        env = live.query_env("H.autoruns-filter", AUTORUNS_ARTIFACT)
        where = live.remaining_where(
            profile=profile,
            filters=[candidate],
            reviewed_scopes=[],
            reviewed_matches=[],
            reviewed_signatures=[],
            known_bad=[
                {
                    "field": "ImagePath",
                    "operator": "regex",
                    "pattern": r"(?i)\\temp\\",
                    "enabled": True,
                }
            ],
            env=env,
        )

        self.assertEqual(len(candidate["conditions"]), 2)
        self.assertNotIn("field", candidate)
        self.assertIn("Category", where)
        self.assertIn("`Image Path`", where)
        self.assertIn("Signer", where)
        self.assertIn(" AND ", where)
        self.assertIn("NOT", where)
        self.assertIn("AND NOT", where)
        self.assertIn(
            r"(?i)^c:\\windows\\system32\\securityhealthsystray\.exe$",
            env.values(),
        )
        self.assertIn(
            r"(?i)^\(verified\).*microsoft",
            env.values(),
        )

    def test_autoruns_artifact_variants_share_the_same_artifact_profile(self):
        profiles = artifact_policy.load_artifact_policy().profiles

        self.assertEqual(
            profiles[UPSTREAM_AUTORUNS_ARTIFACT],
            profiles[AUTORUNS_ARTIFACT],
        )

    def test_small_hunt_reviews_in_memory_and_persists_no_raw_rows(self):
        rows = [
            {
                "Detection": "Managed service execution",
                "Evidence": f"RAW-SECRET-{index}",
                "Fqdn": "host.example.test",
            }
            for index in range(3)
        ]
        api = FakeDirectApi(rows)
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "IR1" / "hunts" / "H.1"
            stale_filters = hunt_root / "analysis" / "filters.json"
            stale_filters.parent.mkdir(parents=True)
            stale_filters.write_text(
                '{"filters": ["stale"]}\n',
                encoding="utf-8",
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.1",
                    "hunt_description": "dfir-group=DR-test",
                    "state": "FINISHED",
                },
                request=request(),
                hunt_root=hunt_root,
                include_review_rows=True,
            )
            state_text = Path(result["state_file"]).read_text(encoding="utf-8")
            files = sorted(
                path.relative_to(hunt_root).as_posix()
                for path in hunt_root.rglob("*")
                if path.is_file()
            )

        self.assertEqual(result["status"], "awaiting_review")
        self.assertEqual(result["coverage"], "unknown")
        self.assertEqual(result["review_item_count"], 1)
        item = result["review_items"][0]
        self.assertEqual(item["kind"], "direct")
        self.assertTrue(item["exhaustive"])
        self.assertEqual(item["rows"], rows)
        self.assertFalse(result["raw_evidence_persisted"])
        self.assertFalse(result["raw_result_exported"])
        self.assertFalse(result["snapshot_created"])
        self.assertEqual(result["filters_file"], "")
        self.assertEqual(
            result["persistence_manifest"]["raw_result_export_count"],
            0,
        )
        persisted_state = json.loads(state_text)
        persisted_state = persisted_state["specialized_analysis"]
        self.assertTrue(persisted_state["source_identifiers"])
        self.assertEqual(
            persisted_state["coverage_state"]["source_type"],
            "hunt",
        )
        self.assertIn("persistence_manifest", persisted_state)
        self.assertNotIn("RAW-SECRET", state_text)
        self.assertEqual(
            files,
            [
                "analysis-hunt.md",
                "analysis/hunt-analysis-state.json",
                "analysis/review-items.json",
            ],
        )
        select_calls = [vql for vql, _, _ in api.calls if "LIMIT" in vql]
        self.assertEqual(len(select_calls), 1)
        self.assertIn("Detection.Name AS Detection", select_calls[0])
        self.assertIn("AS Evidence", select_calls[0])

    def test_specialized_debug_writes_only_bounded_validation_metadata(self):
        api = FakeDirectApi(
            [{"Detection": "Example", "Evidence": "sensitive-value"}]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.debug", "state": "FINISHED"},
                request=request(),
                hunt_root=Path(temp_dir) / "H.debug",
                debug_validation=True,
            )
            debug_path = (
                Path(result["state_file"]).parent
                / "hunt-analysis-validation-debug.json"
            )
            debug_text = debug_path.read_text(encoding="utf-8")
            state = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            debug_bytes = debug_path.read_bytes()
            non_debug = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.debug", "state": "FINISHED"},
                request=request(),
                hunt_root=Path(temp_dir) / "H.debug",
            )
            non_debug_state = json.loads(
                Path(non_debug["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]
            debug_after_non_debug = debug_path.read_bytes()

        self.assertNotIn("sensitive-value", debug_text)
        self.assertIn("last_validation_debug", state)
        self.assertLess(len(debug_text), 1_048_576)
        self.assertEqual(debug_after_non_debug, debug_bytes)
        self.assertTrue(state["last_validation_debug"]["current_run"])
        self.assertFalse(
            non_debug_state["last_validation_debug"]["current_run"]
        )

    def test_default_review_response_is_bounded_and_referenced(self):
        rows = [
            {
                "Detection": "Managed service execution",
                "Evidence": f"RAW-SECRET-{index}",
                "Fqdn": "host.example.test",
            }
            for index in range(5)
        ]
        api = FakeDirectApi(rows)
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.compact", "state": "FINISHED"},
                request=request(),
                hunt_root=Path(temp_dir) / "H.compact",
            )
            manifest_text = Path(result["review_items_file"]).read_text(
                encoding="utf-8"
            )

        item = result["review_items"][0]
        self.assertFalse(result["review_rows_included"])
        self.assertFalse(
            result["finding_consolidation"]["manager"]["attempted"]
        )
        self.assertNotIn("rows", item)
        self.assertEqual(len(item["representative_rows"]), 3)
        self.assertEqual(item["rows_omitted_from_response"], 2)
        self.assertEqual(item["row_reference"]["type"], "velociraptor_live_query")
        self.assertEqual(Path(result["review_items_file"]).name, "review-items.json")
        self.assertNotIn("RAW-SECRET", manifest_text)
        self.assertIn('"raw_rows_persisted": false', manifest_text)

    def test_filter_candidate_is_validated_before_it_closes_watermark(self):
        rows = [
            {
                "Detection": "Managed service execution",
                "Evidence": "expected management agent",
                "Fqdn": "host.example.test",
            }
        ]
        api = FakeDirectApi(rows)
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "IR1" / "hunts" / "H.2"
            first = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.2",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                request=request(),
                hunt_root=hunt_root,
            )
            review_id = first["review_items"][0]["review_id"]
            decisions_path = Path(temp_dir) / "decisions.json"
            decisions_path.write_text(
                json.dumps(
                    {
                        "reviews": [
                            {
                                "review_id": review_id,
                                "complete": True,
                                "disposition": "expected",
                                "reason": "Approved management-agent activity.",
                                "findings": [
                                    {"summary": "No malicious activity identified."}
                                ],
                                "filters": [
                                    {
                                        "scope": {
                                            "Detection": "Managed service execution"
                                        },
                                        "conditions": [
                                            {
                                                "field": "Evidence",
                                                "operator": "regex",
                                                "pattern": "expected management agent",
                                            }
                                        ],
                                        "reason": "Approved management tooling.",
                                        "status": "promoted",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            validation = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.2",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                request=request(),
                hunt_root=hunt_root,
                decisions_path=decisions_path,
            )
            validation_item = validation["review_items"][0]
            decisions_path.write_text(
                json.dumps(
                    {
                        "reviews": [
                            {
                                "review_id": validation_item["review_id"],
                                "complete": True,
                                "filter_status": "case-approved",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            complete = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.2",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                request=request(),
                hunt_root=hunt_root,
                decisions_path=decisions_path,
            )
            filters = json.loads(
                Path(complete["filters_file"]).read_text(encoding="utf-8")
            )
            summary = Path(complete["analysis_file"]).read_text(encoding="utf-8")
            profiles = artifact_policy.load_artifact_policy().profiles
            reusable, _ = live.load_reusable_filters(
                [Path(complete["filters_file"])],
                profiles=profiles,
            )

        self.assertEqual(validation["status"], "awaiting_review")
        self.assertEqual(validation["review_item_count"], 1)
        self.assertEqual(validation_item["kind"], "filter_validation")
        self.assertEqual(validation_item["scope_row_count"], 1)
        self.assertEqual(
            validation_item["decision_template"]["filter_status"],
            "case-approved",
        )
        self.assertEqual(validation_item["filter"]["status"], "candidate")
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(complete["coverage"], "complete")
        self.assertEqual(complete["review_item_count"], 0)
        self.assertEqual(len(filters["case_filters"]), 1)
        self.assertEqual(len(filters["filters"]), 1)
        candidate = filters["case_filters"][0]
        self.assertEqual(filters["filters"][0]["id"], candidate["id"])
        self.assertEqual(reusable[0]["id"], candidate["id"])
        self.assertEqual(candidate["conditions"][0]["field"], "Evidence")
        self.assertEqual(
            candidate["scope"],
            {"Detection": "Managed service execution"},
        )
        self.assertEqual(candidate["status"], "case-approved")
        self.assertEqual(candidate["matched_rows"], 1)
        self.assertTrue(candidate["validation_review_id"])
        self.assertIn("Approved management tooling", summary)
        self.assertIn("No malicious activity identified", summary)

    def test_stale_review_decision_is_rejected(self):
        api = FakeDirectApi([{"Evidence": "one"}])
        with tempfile.TemporaryDirectory() as temp_dir:
            decisions_path = Path(temp_dir) / "decisions.json"
            decisions_path.write_text(
                json.dumps(
                    {
                        "reviews": [
                            {
                                "review_id": "review-stale",
                                "complete": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "unknown or stale"):
                live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={"hunt_id": "H.3", "state": "FINISHED"},
                    request=request(),
                    hunt_root=Path(temp_dir) / "H.3",
                    decisions_path=decisions_path,
                )

    def test_single_exact_variant_normalized_group_can_close_after_hijack_review(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        profile = profiles[AUTORUNS_ARTIFACT]
        normalized_stack = profile["review"]["stacks"]["autorun_path_entry"]
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.autoruns-close",
            group="",
            hunt_state="FINISHED",
        )
        pending = {
            "review_id": "review-normalized",
            "kind": "normalized_stack",
            "scope": {"Category": "Logon"},
            "scope_row_count": 12,
            "exhaustive": False,
            "closure_eligible": True,
            "review_match": {
                "type": "normalized_signature",
                "scope": {"Category": "Logon"},
                "stack_id": "autorun_path_entry",
                "server_dimensions": normalized_stack["server_dimensions"],
                "values": ["normalized-value"],
                "row_count": 12,
            },
        }
        state["artifacts"][AUTORUNS_ARTIFACT] = {
            "pending_reviews": [pending],
            "reviewed_signatures": [],
            "row_accounting": [],
        }

        with self.assertRaisesRegex(RuntimeError, "hijack_risk_reviewed"):
            live.apply_decisions(
                state,
                [
                    {
                        "review_id": "review-normalized",
                        "complete": True,
                        "disposition": "expected",
                        "reason": "Known signed vendor autorun.",
                    }
                ],
                profiles=profiles,
                source="test",
            )

        with self.assertRaisesRegex(RuntimeError, "variant_risk_reviewed"):
            live.apply_decisions(
                state,
                [
                    {
                        "review_id": "review-normalized",
                        "complete": True,
                        "disposition": "expected",
                        "reason": "Known signed vendor autorun.",
                        "hijack_risk_reviewed": True,
                    }
                ],
                profiles=profiles,
                source="test",
            )

        live.apply_decisions(
            state,
            [
                {
                    "review_id": "review-normalized",
                    "complete": True,
                    "disposition": "expected",
                    "reason": (
                        "Single exact signer/hash/launch variant is expected; "
                        "DLL and .NET hijack risk reviewed."
                    ),
                    "hijack_risk_reviewed": True,
                    "variant_risk_reviewed": True,
                }
            ],
            profiles=profiles,
            source="test",
        )

        accounting = state["artifacts"][AUTORUNS_ARTIFACT]["row_accounting"]
        self.assertEqual(
            accounting[0]["basis"],
            "normalized_stack_review",
        )
        self.assertEqual(accounting[0]["row_count"], 12)

    def test_completed_stack_page_compacts_group_predicates_to_category_scope(self):
        scope = {"Category": "Drivers"}
        artifact_state = {
            "reviewed_scopes": [],
            "reviewed_signatures": [
                {"id": "accounting-one", "scope": scope},
                {"id": "accounting-two", "scope": scope},
                {
                    "id": "accounting-other",
                    "scope": {"Category": "Services"},
                },
            ],
            "scope_stack_pages": [
                {
                    "id": "scope-page-drivers",
                    "scope": scope,
                    "accounting_ids": [
                        "accounting-one",
                        "accounting-two",
                    ],
                    "exhaustive": True,
                    "status": "pending",
                }
            ],
        }

        live.compact_completed_scope_pages(artifact_state)

        self.assertEqual(artifact_state["reviewed_scopes"], [scope])
        self.assertEqual(
            [item["id"] for item in artifact_state["reviewed_signatures"]],
            ["accounting-other"],
        )
        self.assertEqual(
            artifact_state["scope_stack_pages"][0]["status"],
            "compacted",
        )

    def test_signature_shape_classifies_mixed_evidence(self):
        reduction = live.signature_reduction(
            [
                {"Pivot1": "one", "Count": 250},
                {"Pivot1": "two", "Count": 100},
                {"Pivot1": "three", "Count": 50},
            ],
            scope_count=1000,
        )

        self.assertEqual(reduction["classification"], "mixed")
        self.assertEqual(reduction["leading_coverage_percent"], 40.0)
        self.assertEqual(reduction["rows_per_pattern"], 5)

    def test_stack_vql_orders_high_prevalence_groups_first(self):
        vql = live.stack_vql(
            [autoruns.ascii_lower_vql("Entry"), "lowcase(string=`Image Path`)"],
            "Category = ScopeValue",
            1001,
        )

        self.assertIn("ORDER BY Count DESC", vql)

    def test_family_stack_continuation_skips_accounted_keys_in_memory(self):
        scope = {"Category": "Drivers"}
        stack_id = "autorun_path_entry"
        reviewed = [
            {
                "id": live.accounting_id_for(
                    artifact=AUTORUNS_ARTIFACT,
                    scope=scope,
                    stack_id=stack_id,
                    values=[
                        "driver-one",
                        "c:\\windows\\system32\\drivers\\one.sys",
                        "(verified) microsoft windows",
                    ],
                ),
                "scope": scope,
                "stack_id": stack_id,
                "row_count": 20,
            }
        ]
        groups = [
            {
                "Pivot1": "driver-one",
                "Pivot2": "c:\\windows\\system32\\drivers\\one.sys",
                "Pivot3": "(verified) microsoft windows",
                "Count": 20,
            },
            {
                "Pivot1": "driver-two",
                "Pivot2": "c:\\windows\\system32\\drivers\\two.sys",
                "Pivot3": "(verified) microsoft windows",
                "Count": 3,
            },
        ]

        remaining = live.unreviewed_family_groups(
            groups,
            artifact=AUTORUNS_ARTIFACT,
            scope=scope,
            stack_id=stack_id,
            dimension_count=3,
            reviewed_signatures=reviewed,
        )

        self.assertEqual(
            [item["Pivot1"] for item in remaining],
            ["driver-two"],
        )
        self.assertEqual(live.accounted_signature_rows(reviewed), 20)
        self.assertEqual(
            live.accounted_signature_rows(
                reviewed,
                excluded_scopes=[scope],
            ),
            0,
        )

    def test_normalized_stack_keeps_blank_signer_groups(self):
        reduction = live.signature_reduction(
            [
                {
                    "Pivot1": "driver-name",
                    "Pivot2": "c:\\windows\\system32\\drivers\\driver.sys",
                    "Pivot3": "",
                    "Count": 3,
                }
            ],
            scope_count=3,
            dimension_count=3,
            allow_empty_dimensions=True,
        )

        self.assertEqual(reduction["signature_groups_returned"], 1)
        self.assertEqual(
            reduction["leading_signatures"][0]["values"],
            [
                "driver-name",
                "c:\\windows\\system32\\drivers\\driver.sys",
                "",
            ],
        )

    def test_normalized_stack_keeps_all_blank_dimension_groups(self):
        reduction = live.signature_reduction(
            [
                {
                    "Pivot1": "",
                    "Pivot2": "",
                    "Pivot3": "",
                    "Count": 2,
                }
            ],
            scope_count=2,
            dimension_count=3,
            allow_empty_dimensions=True,
        )

        self.assertEqual(reduction["signature_groups_returned"], 1)
        self.assertEqual(
            reduction["leading_signatures"][0]["values"],
            ["", "", ""],
        )

    def test_dimension_match_expression_requeries_empty_nested_values(self):
        env = {}

        expression = live.dimension_match_expression(
            ["Name", "Authenticode.Trusted"],
            ["srvany.exe", ""],
            env=env,
            prefix="TrustStack",
        )

        self.assertEqual(
            expression,
            "((Name = TrustStack1Value1) AND "
            "(NOT (Authenticode.Trusted)))",
        )
        self.assertEqual(env, {"TrustStack1Value1": "srvany.exe"})

    def test_generic_stack_summary_prefers_configured_profile_dimensions(self):
        summary = live.render_generic_stack_chat_summary(
            {
                "artifacts": {
                    "Windows.System.Pslist": {
                        "current_total": 10,
                        "pending_reviews": [],
                        "stack_discovery": {
                            "validated_signature_fields": ["Name", "Exe"],
                        },
                        "streaming_stack": {
                            "represented_row_count": 10,
                            "reviewed_group_count": 2,
                            "signature_logical_dimensions": [
                                "Name",
                                "Exe",
                                "AuthenticodeTrusted",
                            ],
                            "suspicious_group_count": 0,
                            "notable_group_count": 0,
                        },
                    }
                }
            }
        )

        self.assertIn(
            "- Fields: `Name`, `Exe`, `AuthenticodeTrusted`",
            summary,
        )

    def test_generic_stack_summary_recovers_dimensions_from_review_match(self):
        summary = live.render_generic_stack_chat_summary(
            {
                "artifacts": {
                    "Windows.System.Pslist": {
                        "current_total": 10,
                        "pending_reviews": [
                            {
                                "review_match": {
                                    "logical_dimensions": [
                                        "Name",
                                        "Exe",
                                        "AuthenticodeTrusted",
                                    ]
                                }
                            }
                        ],
                        "stack_discovery": {
                            "validated_signature_fields": ["Name", "Exe"],
                        },
                        "streaming_stack": {
                            "represented_row_count": 10,
                            "reviewed_group_count": 2,
                            "suspicious_group_count": 0,
                            "notable_group_count": 0,
                        },
                    }
                }
            }
        )

        self.assertIn(
            "- Fields: `Name`, `Exe`, `AuthenticodeTrusted`",
            summary,
        )

    def test_generic_stack_summary_separates_follow_up_from_disposition(self):
        summary = live.render_generic_stack_chat_summary(
            {
                "artifacts": {
                    "Windows.System.Pslist": {
                        "current_total": 1,
                        "pending_reviews": [
                            {
                                "query": {"outcome": "complete"},
                                "review_match": {
                                    "logical_dimensions": ["Name"],
                                    "rows_exhaustive": True,
                                },
                            }
                        ],
                        "streaming_stack": {
                            "represented_row_count": 1,
                            "reviewed_group_count": 1,
                        },
                    }
                }
            }
        )

        self.assertIn(
            "- Evidentiary closure: `pending operator disposition`",
            summary,
        )

    def test_positive_scope_with_empty_branch_fails_as_profile_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(
                RuntimeError,
                "reported 500 row\\(s\\), but its review query returned none",
            ):
                live.analyze_live_hunt(
                    FakeMismatchedPivotApi(),
                    investigation_id="IR1",
                    hunt_row={"hunt_id": "H.mismatch", "state": "FINISHED"},
                    request=request(),
                    hunt_root=Path(temp_dir) / "H.mismatch",
                )

    def test_live_review_token_budget_has_hard_ceiling(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "may not exceed 200000"):
                live.analyze_live_hunt(
                    FakeDirectApi([{"Evidence": "one"}]),
                    investigation_id="IR1",
                    hunt_row={"hunt_id": "H.tokens", "state": "FINISHED"},
                    request=request(),
                    hunt_root=Path(temp_dir) / "H.tokens",
                    max_review_tokens=200_001,
                )

    def test_depleted_shared_budget_is_not_an_oversized_row(self):
        rows = [{"Evidence": "x" * 100}]
        encoding = "cl100k_base"
        row_tokens = live.token_budget.estimate_tokens(
            live.stable_json(rows[0]),
            encoding,
        )
        api = FakeDirectApi(rows)

        returned, meta = live.query_rows_bounded(
            api,
            vql="SELECT * FROM scope() LIMIT 1",
            env={},
            row_limit=1,
            token_limit=max(1, row_tokens - 1),
            max_item_tokens=row_tokens + 10,
            token_encoding=encoding,
        )

        self.assertEqual(returned, [])
        self.assertEqual(
            meta["outcome"],
            live.QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED,
        )
        self.assertFalse(meta["oversized_row"])
        self.assertFalse(live.query_emits_review(meta))
        self.assertTrue(live.query_stops_pass(meta))

    def test_true_oversized_first_row_is_explicit(self):
        rows = [{"Evidence": "x" * 1000}]
        encoding = "cl100k_base"
        api = FakeDirectApi(rows)

        returned, meta = live.query_rows_bounded(
            api,
            vql="SELECT * FROM scope() LIMIT 1",
            env={},
            row_limit=1,
            token_limit=10,
            max_item_tokens=10,
            token_encoding=encoding,
        )

        self.assertEqual(returned, [])
        self.assertEqual(
            meta["outcome"],
            live.QUERY_OUTCOME_FIRST_ROW_OVERSIZED,
        )
        self.assertTrue(meta["oversized_row"])
        self.assertTrue(live.query_emits_review(meta))

    def test_transient_exhaustive_query_requires_exact_row_accounting(self):
        rows = [{"Evidence": "one"}, {"Evidence": "two"}]
        returned, meta = live.query_rows_exhaustive_transient(
            FakeDirectApi(rows),
            vql="SELECT * FROM scope()",
            env={},
            expected_count=2,
            maximum_rows=10,
            token_encoding="cl100k_base",
        )
        self.assertEqual(returned, rows)
        self.assertTrue(meta["transient_exhaustive"])
        self.assertFalse(meta["truncated"])

        with self.assertRaisesRegex(RuntimeError, "row-count mismatch"):
            live.query_rows_exhaustive_transient(
                FakeDirectApi(rows),
                vql="SELECT * FROM scope()",
                env={},
                expected_count=3,
                maximum_rows=10,
                token_encoding="cl100k_base",
            )

    def test_transient_exhaustive_query_enforces_explicit_row_ceiling(self):
        with self.assertRaisesRegex(RuntimeError, "maximum_rows=1"):
            live.query_rows_exhaustive_transient(
                FakeDirectApi([{"Evidence": "one"}, {"Evidence": "two"}]),
                vql="SELECT * FROM scope()",
                env={},
                expected_count=2,
                maximum_rows=1,
                token_encoding="cl100k_base",
            )

    def test_large_applications_hunt_uses_application_scope_stack(self):
        artifact = "DetectRaptor.Windows.Detection.Applications"
        api = FakePivotApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.sample", "state": "FINISHED"},
                request=request(artifact),
                hunt_root=Path(temp_dir) / "H.sample",
                direct_row_limit=1000,
                sample_rows=25,
            )

        self.assertEqual(result["review_item_count"], 3)
        self.assertEqual(
            [item["kind"] for item in result["review_items"]],
            ["signature", "signature", "pivot"],
        )
        self.assertTrue(
            any(
                "GROUP BY Pivot1" in vql and "DisplayName AS Pivot1" in vql
                for vql, _, _ in api.calls
            )
        )

    def test_suppression_preserves_known_bad_matches(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        profile = profiles[ARTIFACT]
        suppression = live.validate_filter(
            {
                "scope": {"Detection": "Example"},
                "conditions": [
                    {
                        "field": "Evidence",
                        "operator": "regex",
                        "pattern": "management agent",
                    }
                ],
                "reason": "Expected management activity.",
            },
            artifact=ARTIFACT,
            profile=profile,
            source="test",
            default_status="case-approved",
        )
        known_bad = {
            "id": "known-bad",
            "artifact": ARTIFACT,
            "scope": {},
            "field": "Evidence",
            "operator": "regex",
            "pattern": "malicious",
            "reason": "Known malicious value.",
            "enabled": True,
        }
        env = live.query_env("H.1", ARTIFACT)

        where = live.remaining_where(
            profile=profile,
            filters=[suppression],
            reviewed_scopes=[],
            reviewed_matches=[],
            reviewed_signatures=[],
            known_bad=[known_bad],
            env=env,
        )

        self.assertIn("Detection.Name", where)
        self.assertIn("if(condition=Message", where)
        self.assertIn("AND NOT", where)
        self.assertIn("KnownBadValue1", env)
        self.assertEqual(env["KnownBadValue1"], "malicious")

    def test_filter_reference_requires_approved_profile_field(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "filters.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": live.FILTER_SCHEMA_VERSION,
                        "filters": [
                            {
                                "artifact": ARTIFACT,
                                "conditions": [
                                    {
                                        "field": "Detection",
                                        "operator": "regex",
                                        "pattern": "anything",
                                    }
                                ],
                                "reason": "Detection names are not filter fields.",
                                "status": "promoted",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "not approved"):
                live.load_reusable_filters([path], profiles=profiles)

    def test_filter_requires_conditions_list(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        with self.assertRaisesRegex(RuntimeError, "conditions must be a list"):
            live.validate_filter(
                {
                    "field": "Evidence",
                    "operator": "regex",
                    "pattern": "anything",
                    "reason": "Invalid filter shape.",
                },
                artifact=ARTIFACT,
                profile=profiles[ARTIFACT],
                source="test",
                default_status="candidate",
            )

    def test_changed_watermark_resets_prior_coverage(self):
        artifact_state = {
            "current_total": 100,
            "analysis_input_hash": "old-inputs",
            "completed_at_total": 100,
            "reviewed_scopes": [{"Detection": "Example"}],
            "reviewed_matches": [{"id": "known-bad"}],
            "pending_reviews": [{"review_id": "review-old"}],
        }

        reasons = live.update_analysis_watermark(
            artifact_state,
            total=101,
            input_hash="new-inputs",
        )

        self.assertEqual(
            reasons,
            ["row_count_changed:100->101", "analysis_inputs_changed"],
        )
        self.assertIsNone(artifact_state["completed_at_total"])
        self.assertEqual(artifact_state["reviewed_scopes"], [])
        self.assertEqual(artifact_state["reviewed_matches"], [])
        self.assertEqual(artifact_state["pending_reviews"], [])
        self.assertEqual(artifact_state["coverage_watermark_total"], 101)

    def test_unsupported_specialized_state_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            path.write_text(
                json.dumps(
                    {
                        "analysis_version": 1,
                        "hunt_id": "H.migrate",
                        "artifacts": {
                            ARTIFACT: {
                                "completed_at_total": 10,
                                "reviewed_scopes": [{"Detection": "unsupported"}],
                                "reviewed_matches": [{"id": "unsupported"}],
                                "pending_reviews": [{"review_id": "unsupported"}],
                            }
                        },
                        "case_filters": [{"id": "filter-preserved"}],
                        "findings": [{"summary": "preserved"}],
                        "query_ledger": [{"row_count": 10}],
                    }
                ),
                encoding="utf-8",
            )

            state = live.load_state(
                path,
                investigation_id="IR1",
                hunt_id="H.migrate",
                group="",
                hunt_state="FINISHED",
            )

        self.assertEqual(state["analysis_version"], live.ANALYSIS_VERSION)
        self.assertEqual(state["artifacts"], {})
        self.assertEqual(state["findings"], [])
        self.assertNotIn("migration", state)

    def test_missing_target_baseline_prevents_complete_coverage(self):
        self.assertEqual(
            live.target_execution_coverage(
                {
                    "baseline_scope_available": False,
                    "strict_complete": False,
                },
                hunt_state="FINISHED",
            ),
            "unknown",
        )

    def test_ad_hoc_review_does_not_require_target_execution_coverage(self):
        self.assertEqual(
            live.target_execution_coverage(
                {
                    "review_scope": "ad_hoc_review",
                    "baseline_scope_available": False,
                    "strict_complete": False,
                },
                hunt_state="RUNNING",
            ),
            "not_assessed",
        )
        self.assertTrue(
            live.target_execution_satisfies_review("not_assessed")
        )

    def test_analysis_reports_responding_host_completion_without_baseline(self):
        api = FakeDirectApi(
            [
                {
                    "Detection": "Managed service execution",
                    "Evidence": "review me",
                    "Fqdn": "host.example.test",
                }
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.responding-host-stats",
                    "state": "RUNNING",
                    "baseline_scope_available": False,
                    "client_count": 90,
                    "responded_client_count": 90,
                    "completed_client_count": 87,
                    "terminal_client_count": 90,
                    "failed_client_count": 3,
                    "open_client_count": 0,
                },
                request=request(),
                hunt_root=Path(temp_dir) / "H.responding-host-stats",
            )
            summary = Path(result["analysis_file"]).read_text(
                encoding="utf-8"
            )
            state = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]

        self.assertEqual(
            result["host_execution"],
            state["host_execution"],
        )
        self.assertEqual(
            state["host_execution"]["denominator_basis"],
            "responding_hosts",
        )
        self.assertIn(
            "Successfully completed: 87/90 responding hosts (96.7%)",
            summary,
        )
        self.assertIn(
            "Terminal execution: 90/90 responding hosts (100.0%)",
            summary,
        )
        self.assertIn("Failed: 3; open: 0", summary)
        self.assertIn("Total targeted hosts: unknown", summary)

    def test_filter_validation_requires_explicit_nonzero_approval(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        profile = profiles[ARTIFACT]
        candidate = live.validate_filter(
            {
                "conditions": [
                    {
                        "field": "Evidence",
                        "operator": "regex",
                        "pattern": "expected",
                    }
                ],
                "reason": "Expected activity.",
            },
            artifact=ARTIFACT,
            profile=profile,
            source="test",
            default_status="candidate",
        )
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.validation",
            group="",
            hunt_state="FINISHED",
        )
        state["case_filters"] = [candidate]
        state["artifacts"][ARTIFACT] = {
            "pending_reviews": [
                {
                    "review_id": "review-filter",
                    "kind": "filter_validation",
                    "filter_id": candidate["id"],
                    "scope_row_count": 0,
                    "query": {
                        "row_count": 0,
                        "oversized_row": False,
                    },
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "explicit filter_status"):
            live.apply_decisions(
                state,
                [{"review_id": "review-filter", "complete": True}],
                profiles=profiles,
                source="test",
            )
        with self.assertRaisesRegex(RuntimeError, "zero-match"):
            live.apply_decisions(
                state,
                [
                    {
                        "review_id": "review-filter",
                        "complete": True,
                        "filter_status": "case-approved",
                    }
                ],
                profiles=profiles,
                source="test",
            )
        state["artifacts"][ARTIFACT]["pending_reviews"][0].update(
            {
                "scope_row_count": 1,
                "query": {
                    "row_count": 0,
                    "oversized_row": True,
                },
            }
        )
        with self.assertRaisesRegex(RuntimeError, "reviewable validation row"):
            live.apply_decisions(
                state,
                [
                    {
                        "review_id": "review-filter",
                        "complete": True,
                        "filter_status": "case-approved",
                    }
                ],
                profiles=profiles,
                source="test",
            )

    def test_non_exhaustive_review_cannot_close_without_progress(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.sample",
            group="",
            hunt_state="FINISHED",
        )
        state["artifacts"][ARTIFACT] = {
            "pending_reviews": [
                {
                    "review_id": "review-sample",
                    "kind": "pivot",
                    "exhaustive": False,
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "non-exhaustive"):
            live.apply_decisions(
                state,
                [{"review_id": "review-sample", "complete": True}],
                profiles=profiles,
                source="test",
            )

    def test_partial_decisions_preserve_unsubmitted_pending_reviews(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        state = live.initial_state(
            investigation_id="IR1",
            hunt_id="H.partial",
            group="",
            hunt_state="FINISHED",
        )
        state["artifacts"][ARTIFACT] = {
            "pending_reviews": [
                {
                    "review_id": "review-one",
                    "kind": "pattern",
                    "exhaustive": False,
                },
                {
                    "review_id": "review-two",
                    "kind": "tail",
                    "exhaustive": False,
                },
            ]
        }

        live.apply_decisions(
            state,
            [{"review_id": "review-one", "complete": False}],
            profiles=profiles,
            source="test",
        )

        self.assertEqual(
            state["artifacts"][ARTIFACT]["pending_reviews"],
            [
                {
                    "review_id": "review-two",
                    "kind": "tail",
                    "exhaustive": False,
                }
            ],
        )

    def test_selected_artifact_response_ignores_unrelated_incomplete_state(self):
        api = FakeDirectApi(
            [{"Detection": "Example", "Evidence": "reviewed evidence"}]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.selected"
            first = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.selected",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                request=request(),
                hunt_root=hunt_root,
            )
            state_path = Path(first["state_file"])
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["specialized_analysis"]["artifacts"]["Unrelated.Artifact"] = {
                "status": "awaiting_review",
            }
            state_path.write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            decision_path = Path(temp_dir) / "decisions.json"
            decision_path.write_text(
                json.dumps(
                    {
                        "reviews": [
                            {
                                "review_id": first["review_items"][0][
                                    "review_id"
                                ],
                                "complete": True,
                                "disposition": "expected",
                                "reason": "Selected artifact evidence reviewed.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.selected",
                    "state": "FINISHED",
                    "review_scope": "ad_hoc_review",
                },
                request=request(),
                hunt_root=hunt_root,
                decisions_path=decision_path,
            )
            persisted = json.loads(
                Path(result["state_file"]).read_text(encoding="utf-8")
            )["specialized_analysis"]

        self.assertEqual(result["selected_artifacts"], [ARTIFACT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["result_review_coverage"], "complete")
        self.assertEqual(persisted["status"], "incomplete")

    def test_specialized_only_checkpoint_mirrors_effective_coverage(self):
        state = {
            "hunt_id": "H.specialized",
            "review_scope": "ad_hoc_review",
            "status": "complete",
            "coverage": "complete",
            "result_review_coverage": "complete",
            "target_execution_coverage": "not_assessed",
            "analysis_memory": {"path": "/case/H.specialized/analysis-hunt.md"},
            "analysis_outputs": {
                "general": {
                    "report": "/case/H.specialized/analysis-hunt.md"
                }
            },
            "artifacts": {},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "hunt-analysis-state.json"
            live.write_canonical_specialized_state(path, state)
            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(persisted["analysis_method"], "specialized")
        self.assertEqual(persisted["review_scope"], "ad_hoc_review")
        self.assertEqual(
            persisted["coverage"],
            {
                "result_review": "complete",
                "target_execution": "not_assessed",
                "overall": "complete",
            },
        )
        output = persisted["specialized_analysis"]["analysis_outputs"]["general"]
        self.assertEqual(
            output["report"], "/case/H.specialized/analysis-hunt.md"
        )


if __name__ == "__main__":
    unittest.main()
