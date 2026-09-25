"""Single-pass Autoruns VQL parity and fail-closed stream validation."""
import base64
import copy
import gzip
import json
import subprocess
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import regex as autoruns_regex
from vraptor.analyze import source as review_source
from vraptor.hunt import live

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


def encode(value):
    return base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()


def stream_rows():
    return [
        {"_AutorunsStream": "summary", "SourceRows": 5, "MatchedRows": 2,
         "ResidualRows": 3, "PopulatedRows": 2, "GroupCount": 1},
        {"_AutorunsStream": "group", "ImagePath": "a", "LaunchString": "",
         "Signer": "", "ExampleCategory": "Logon", "Total": 2, "SortKey": "2|a"},
        {"_AutorunsStream": "complete"},
    ]


class AutorunsAccountedStackTest(unittest.TestCase):
    def test_complete_stream(self):
        stream = live.AutorunsAccountedStack(stream_rows())
        self.assertFalse(stream.complete)
        self.assertEqual(list(stream), [{"ImagePath": "a", "LaunchString": "",
                                        "Signer": "", "ExampleCategory": "Logon", "Total": 2}])
        self.assertTrue(stream.complete)
        self.assertEqual(stream.counts["SourceRows"], 5)

    def test_missing_malformed_duplicate_and_incomplete_streams(self):
        valid = stream_rows()
        bad = [[], valid[1:], valid[:1], valid[:2], valid[:1] + valid[2:],
               valid + [None], valid + [valid[-1]], valid[:1] + [None],
               valid[:1] + [valid[0]] + valid[1:], valid[:2] + [valid[1]] + valid[2:]]
        for field, values in {
            "SourceRows": [None, True, -1, "5", 5.0, 6],
            "MatchedRows": [None, True, -1, 3],
            "ResidualRows": [None, True, -1, 4],
            "PopulatedRows": [None, True, -1, 1, 3, 4],
            "GroupCount": [None, True, -1, 0, 2, 4],
        }.items():
            for value in values:
                rows = copy.deepcopy(valid)
                rows[0][field] = value
                bad.append(rows)
        for field, values in {"Total": [None, True, "2", 2.0, 0, -1, 1, 3],
                              "ImagePath": [None, 12], "Signer": [None],
                              "LaunchString": [False], "SortKey": [None],
                              "_AutorunsStream": [None, "unknown"]}.items():
            for value in values:
                rows = copy.deepcopy(valid)
                rows[1][field] = value
                bad.append(rows)
        for rows in bad:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                list(live.AutorunsAccountedStack(rows))

    def test_duplicate_and_order_validation_with_consistent_counts(self):
        for second in ({"ImagePath": "a", "SortKey": "1|a"},
                       {"ImagePath": "b", "SortKey": "9|b"}):
            rows = stream_rows()
            rows[0].update(SourceRows=6, ResidualRows=4, PopulatedRows=3, GroupCount=2)
            rows.insert(2, {**rows[1], "Total": 1, **second})
            with self.subTest(second=second), self.assertRaises(RuntimeError):
                list(live.AutorunsAccountedStack(rows))

    def test_transport_failure_after_complete_is_not_swallowed(self):
        def rows():
            yield from stream_rows()
            raise RuntimeError("transport failed")
        stream = live.AutorunsAccountedStack(rows())
        with self.assertRaisesRegex(RuntimeError, "transport failed"):
            list(stream)
        self.assertFalse(stream.complete)

    def test_source_binding(self):
        source = review_source.flow_source(client_id="C.test", flow_id="F.test", artifact="A")
        query = live.autoruns_accounted_stack_vql("", source=source)
        self.assertEqual(query.count("FROM source("), 1)
        self.assertNotIn("hunt_results(", query)

    @unittest.skipUnless(BINARY.exists(), "Configured Velociraptor unavailable")
    def test_native_source_and_predicate_are_each_evaluated_once_per_row(self):
        rows = [{"Image Path": path, "Launch String": "", "Signer": "", "Category": "Logon",
                 "Keep": keep} for path, keep in (("a", True), ("a", True), ("b", False), ("", True))]
        with mock.patch.object(live, "source_vql", return_value="TestRows"):
            query = live.autoruns_accounted_stack_vql(
                'set(item=Visits, field="Matching", value=Visits.Matching+1) AND Keep')
        query = (
            "LET Visits <= dict(Source=0, Matching=0)\n"
            "LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows)) "
            'WHERE set(item=Visits, field="Source", value=Visits.Source+1)\n'
            + query + "\nSELECT Visits.Source AS SourceVisits, Visits.Matching AS MatchingVisits FROM scope()"
        )
        run = subprocess.run([str(BINARY), "query", "--format=jsonl", "--env", "Rows=" + json.dumps(rows), query],
                             text=True, capture_output=True, check=True, timeout=30)
        self.assertEqual(run.stderr, "")
        received = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(received.pop(), {"SourceVisits": 4, "MatchingVisits": 4})
        stream = live.AutorunsAccountedStack(received)
        self.assertEqual(sum(row["Total"] for row in stream), 2)
        self.assertTrue(stream.complete)

    @unittest.skipUnless(BINARY.exists(), "Configured Velociraptor unavailable")
    def test_native_vql_parity_unicode_categories_blank_and_matching(self):
        def row(image, launch="", signer="", category="Logon"):
            return {"Image Path": image, "Launch String": launch, "Signer": signer, "Category": category}
        source_rows = [row(r"C:\exact.exe"), row(r"C:\exact.exe", category="Services"),
                       row(r"C:\regex7.exe", "run7"), row(r"C:\regex7.exe", "wrong"),
                       row(""), row("", "launch-only"), row(" "),
                       row(r"C:\Users\Alice\app.exe", category="Services"),
                       row(r"%USERPROFILE%\app.exe", category="Logon")]
        source_rows += [row("C:\\" + value, signer=value) for value in
                        ("Straße", "STRASSE", "CAFÉ", "café", "é", "e\u0301", "İ", "i", "日本語😀", "<&>\u2028")]
        key = autoruns.trusted_key(image_path=r"C:\exact.exe", launch_string="", signer="")
        env = {}
        where = live.autoruns_golden_where("Windows.Sysinternals.Autoruns", configuration={
            "enabled": True, "lookup_gzip_base64": encode([key]), "regex_rule_count": 1,
            "regex_lookup_gzip_base64": encode([{
                "ImagePathRegex": autoruns_regex.full_pattern(r"c:\\regex[0-9]+\.exe"),
                "LaunchStringRegex": autoruns_regex.full_pattern("run[0-9]+"),
            }]),
        }, env=env)
        with mock.patch.object(live, "source_vql", return_value="TestRows"):
            queries = [live.autoruns_accounting_vql(where), live.autoruns_residual_stack_vql(where),
                       live.autoruns_accounted_stack_vql(where)]
        self.assertEqual(queries[2].count("FROM TestRows"), 1)
        for rows in (source_rows, list(reversed(source_rows)), [], [row(""), row("")],
                     [row(r"C:\exact.exe")]):
            outputs = []
            for query in queries:
                command = [str(BINARY), "query", "--format=jsonl"]
                for name, value in {**env, "Rows": json.dumps(rows)}.items():
                    command += ["--env", f"{name}={value}"]
                run = subprocess.run(command + [
                    "LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows))\n" + query],
                    text=True, capture_output=True, check=True, timeout=30)
                self.assertEqual(run.stderr, "")
                outputs.append([json.loads(line) for line in run.stdout.splitlines()])
            counts = outputs[0][0] if outputs[0] else dict(SourceRows=0, ResidualRows=0, PopulatedRows=0)
            stream = live.AutorunsAccountedStack(outputs[2])
            self.assertEqual({key: stream.counts[key] for key in counts}, counts)
            expected = [{key: value for key, value in item.items() if key != "SortKey"} for item in outputs[1]]
            self.assertEqual(list(stream), expected)
            self.assertTrue(stream.complete)
            self.assertEqual(stream.counts["MatchedRows"], len(rows) - counts["ResidualRows"])


if __name__ == "__main__":
    unittest.main()
