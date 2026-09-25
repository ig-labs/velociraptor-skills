import argparse
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from vraptor import query as client_query


class FakeQueryApi:
    def __init__(self, batches):
        self.batches = batches
        self.calls = []

    def query_batches(self, vql, env=None, *, timeout=0, max_wait=1, max_row=1000):
        self.calls.append(
            {
                "vql": vql,
                "env": env,
                "timeout": timeout,
                "max_wait": max_wait,
                "max_row": max_row,
            }
        )
        yield from self.batches


class FakeClientApi:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def query(self, vql, env=None, *, timeout=0, max_wait=1, max_row=1000):
        self.queries.append(vql)
        return list(self.rows)


class VelociraptorClientQueryTest(unittest.TestCase):
    def test_build_client_vql_supports_exact_name_search_and_os_filter(self):
        vql = client_query.build_client_vql(
            name="host01.example",
            search="srv|dc",
            os_filters=["windows"],
            ignore_case=True,
        )

        self.assertIn("labels AS Labels", vql)
        self.assertIn("os_info.hostname =~ '(?i)^host01\\\\.example$'", vql)
        self.assertIn("client_id =~ '(?i)srv|dc'", vql)
        self.assertIn("os_info.system =~ '(?i)^(?:windows)$'", vql)
        self.assertTrue(vql.endswith("ORDER BY last_seen_at DESC"))

    def test_filter_client_rows_matches_required_labels_and_online_window(self):
        evaluated_at = datetime(2026, 8, 5, 13, 30, tzinfo=timezone.utc)
        rows = [
            {
                "client_id": "C.online",
                "Hostname": "major",
                "Labels": '["ir9004", "Linux"]',
                "LastSeen": "2026-08-05T13:28:30Z",
            },
            {
                "client_id": "C.stale",
                "Hostname": "stale",
                "Labels": ["ir9004"],
                "LastSeen": "2026-08-05T12:00:00Z",
            },
            {
                "client_id": "C.other",
                "Hostname": "other",
                "Labels": ["ir9999"],
                "LastSeen": "2026-08-05T13:29:00Z",
            },
        ]

        matched, match_count = client_query.filter_client_rows(
            rows,
            required_labels=["IR9004"],
            online_within_minutes=5,
            ignore_case=True,
            evaluated_at=evaluated_at,
        )

        self.assertEqual(match_count, 1)
        self.assertEqual([row["client_id"] for row in matched], ["C.online"])
        self.assertEqual(matched[0]["Labels"], ["Linux", "ir9004"])
        self.assertEqual(matched[0]["LastSeenAgeSeconds"], 90.0)

    def test_filter_client_rows_reports_truncated_match_count(self):
        rows = [
            {
                "client_id": f"C.{index}",
                "Labels": ["prod"],
                "LastSeen": "2026-08-05T13:29:00Z",
            }
            for index in range(3)
        ]

        matched, match_count = client_query.filter_client_rows(
            rows,
            required_labels=["prod"],
            limit=2,
            evaluated_at=datetime(2026, 8, 5, 13, 30, tzinfo=timezone.utc),
        )

        self.assertEqual(match_count, 3)
        self.assertEqual(len(matched), 2)

    def test_run_vql_query_stops_after_bounded_extra_row(self):
        api = FakeQueryApi(
            [
                [{"row": 1}, {"row": 2}],
                [{"row": 3}, {"row": 4}],
            ]
        )

        rows, truncated = client_query.run_vql_query(
            api,
            "SELECT * FROM scope()",
            env={"Needle": "value"},
            max_rows=3,
            timeout=30,
            batch_size=2,
        )

        self.assertEqual(rows, [{"row": 1}, {"row": 2}, {"row": 3}])
        self.assertTrue(truncated)
        self.assertEqual(api.calls[0]["env"], {"Needle": "value"})
        self.assertEqual(api.calls[0]["timeout"], 30)
        self.assertEqual(api.calls[0]["max_row"], 2)

    def test_read_vql_accepts_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "query.vql"
            path.write_text("SELECT 1 AS ok FROM scope()\n", encoding="utf-8")
            args = argparse.Namespace(vql=None, vql_file=str(path))

            query, source = client_query.read_vql(args)

        self.assertEqual(query, "SELECT 1 AS ok FROM scope()")
        self.assertEqual(source, str(path.resolve()))

    def test_command_clients_returns_all_matching_tagged_clients(self):
        rows = [
            {
                "client_id": "C.1",
                "Hostname": "major",
                "Fqdn": "major.example",
                "OSType": "linux",
                "Labels": ["ir9004", "Linux"],
                "LastSeen": "2026-08-05T13:29:00Z",
            },
            {
                "client_id": "C.2",
                "Hostname": "other",
                "Fqdn": "other.example",
                "OSType": "windows",
                "Labels": ["ir9999"],
                "LastSeen": "2026-08-05T13:29:00Z",
            },
        ]
        fake_api = FakeClientApi(rows)
        args = argparse.Namespace(
            api_client="/tmp/lab7.yaml",
            investigation_id="lab7",
            org_id="root",
            client_command="list",
            name=None,
            client_id=None,
            search="",
            os=[],
            label=["ir9004"],
            exclude_label=[],
            online_within_minutes=None,
            ignore_case=False,
            limit=1000,
            batch_size=1000,
        )

        with (
            mock.patch.object(
                client_query,
                "resolve_connection",
                return_value=(Path("/tmp/lab7.yaml"), "root"),
            ),
            mock.patch.object(client_query, "VeloApiClient", return_value=fake_api),
        ):
            payload = client_query.command_clients(args)

        self.assertEqual(payload["match_count"], 1)
        self.assertEqual(payload["returned_count"], 1)
        self.assertEqual(payload["clients"][0]["Hostname"], "major")
        self.assertFalse(payload["truncated"])
        self.assertIn("FROM clients()", fake_api.queries[0])

    def test_parse_env_rejects_invalid_key(self):
        with self.assertRaisesRegex(ValueError, "Invalid VQL environment key"):
            client_query.parse_env(["bad-key=value"])


if __name__ == "__main__":
    unittest.main()
