"""Counts-only workflow, native VQL parity and transport failure regressions."""
import copy
import hashlib
import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import regex as autoruns_regex
from vraptor.autoruns import testing as test
from vraptor.autoruns import test_store as autoruns_test_db
from vraptor.analyze import source as review_source
from vraptor.hunt import operations as hunting
from vraptor.analyze import cli_output as analysis_cli_output
from tests.test_autoruns_accounted_stack import stream_rows

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


def config():
    payload = autoruns.trusted_key_serialized(image_path=r"C:\Users\Alice\exact.exe", launch_string="", signer="Vendor")
    return {
        "exact_hashes": [autoruns.trusted_key(image_path=r"C:\Users\Alice\exact.exe", launch_string="", signer="Vendor")],
        "exact_patterns": autoruns_test_db.exact_patterns([payload]),
        "regex_rules": [{"ImagePathRegex": autoruns_regex.full_pattern(r"c:\\vendor\\known\.dll"),
                         "LaunchStringRegex": autoruns_regex.full_pattern("")}],
        "signer_rules": [],
        "metadata": {"purpose": "autoruns_test_only"}, "database_sha256": "0" * 64,
    }


class AutorunsTestVQLDisplayTest(unittest.TestCase):
    def test_render_preserves_each_query_and_hashes_bound_values_without_disclosure(self):
        cfg = config()
        source = review_source.hunt_source("H.test", "IG.Windows.Sysinternals.Autoruns")
        for mode in ("hash-baseline", "regex-equivalent"):
            with self.subTest(mode=mode):
                query, env, _ = test.build_query(cfg, mode=mode, source=source)
                env["HuntId"] = 'H.test\n-- untrusted "source"'
                env["AutorunsTestVeto"] = "private-veto-É"
                rendered = test.render_vql(query, env, mode=mode, database_sha256=cfg["database_sha256"])
                comments, body = rendered.split("\n\n", 1)
                self.assertEqual(body, query)
                self.assertTrue(all(line.startswith("-- ") for line in comments.splitlines()))
                self.assertIn(f"-- autoruns_test mode={json.dumps(mode)}", comments)
                self.assertIn(f"-- HuntId={json.dumps(env['HuntId'])}", comments)
                self.assertIn(f"-- ArtifactName={json.dumps(env['ArtifactName'])}", comments)
                self.assertIn(f"-- database_sha256={json.dumps(cfg['database_sha256'])}", comments)
                self.assertIn(f"-- query_sha256={hashlib.sha256(query.encode('utf-8')).hexdigest()}", comments)
                identity = json.dumps({"query": query, "env": env}, sort_keys=True, ensure_ascii=False).encode("utf-8")
                self.assertIn(f"-- query_environment_sha256={hashlib.sha256(identity).hexdigest()}", comments)
                self.assertIn("separately bound API environment parameters; values omitted", comments)
                self.assertIn("does not establish live signature-source verification", comments)
                for name, value in env.items():
                    if name.startswith("AutorunsTest"):
                        payload = value.encode("utf-8")
                        self.assertIn(
                            f"-- env {json.dumps(name)}: utf8_bytes={len(payload)} sha256={hashlib.sha256(payload).hexdigest()}",
                            comments,
                        )
                        self.assertNotIn(value, rendered)

    def test_show_vql_matches_acquisition_and_is_printed_even_when_stream_fails(self):
        cfg = config()
        for mode, broken in (("hash-baseline", False), ("regex-equivalent", False), ("hash-baseline", True)):
            with self.subTest(mode=mode, broken=broken):
                api = mock.Mock(org_id="root")
                output, error = io.StringIO(), io.StringIO()
                expected = {"Hashes": 1 if mode == "hash-baseline" else 0,
                            "Exact": 0 if mode == "hash-baseline" else 1, "Regex": 1, "Signer": 0}
                def batches(query, env, **kwargs):
                    self.assertEqual(error.getvalue(), test.render_vql(
                        query, env, mode=mode, database_sha256=cfg["database_sha256"]) + "\n")
                    if broken:
                        raise TimeoutError("stream failed after VQL display")
                    yield [{"_AutorunsTest": "rules_ready", "Ready": True, **expected}, *stream_rows()]
                api.query_batches.side_effect = batches
                with mock.patch.object(test, "validate_request", return_value=cfg), \
                     mock.patch.object(test.time, "monotonic", side_effect=[100.0, 150.0, 155.0]), \
                     redirect_stdout(output), redirect_stderr(error):
                    if broken:
                        with self.assertRaisesRegex(TimeoutError, "stream failed"):
                            test.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                     database=Path("unused"), mode=mode, show_vql=True)
                    else:
                        result = test.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                          database=Path("unused"), mode=mode, show_vql=True)
                        self.assertEqual(result["stream_seconds"], 5.0)
                        self.assertEqual(result["preparation_seconds"], 50.0)
                        self.assertIn(f"query_environment_sha256={result['query_environment_sha256']}", error.getvalue())
                self.assertEqual(output.getvalue(), "")
                api.query.assert_not_called()
                self.assertEqual(api.query_batches.call_count, 1)


class AutorunsTestStreamTest(unittest.TestCase):
    def test_complete_consumption_returns_counts_only(self):
        expected = {"Hashes": 0, "Exact": 1, "Regex": 1, "Signer": 0}
        header = {"_AutorunsTest": "rules_ready", "Ready": True, **expected}
        self.assertEqual(test.consume_stream(iter([header, *stream_rows()]), expected),
                         {key: value for key, value in stream_rows()[0].items() if key != "_AutorunsStream"})
        for mutation in ({"Ready": False}, {"Exact": 0}, {"Exact": True}, {"_AutorunsTest": "wrong"}):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                test.consume_stream(iter([{**header, **mutation}, *stream_rows()]), expected)

    def test_truncation_errors_and_rows_after_completion_fail(self):
        header = {"_AutorunsTest": "rules_ready", "Ready": True}
        for tail in ([], stream_rows()[:-1], stream_rows() + [None]):
            with self.subTest(tail=tail), self.assertRaises(RuntimeError):
                test.consume_stream(iter([header, *tail]), {})
        def interrupted():
            yield header
            yield from stream_rows()
            raise TimeoutError("test timeout after marker")
        with self.assertRaises(TimeoutError):
            test.consume_stream(interrupted(), {})

    def test_runner_has_no_rows_and_closes_transport(self):
        cfg = config()
        expected = {"Hashes": 0, "Exact": 1, "Regex": 1, "Signer": 0}
        api = mock.Mock(org_id="root")
        closed = []
        def batches(*args, **kwargs):
            try:
                yield [{"_AutorunsTest": "rules_ready", "Ready": True, **expected}]
                yield stream_rows()
            finally:
                closed.append(True)
        api.query_batches.side_effect = batches
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(test, "validate_request", return_value=cfg), redirect_stdout(output), redirect_stderr(error):
            result = test.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns", database=Path("unused"), mode="regex-equivalent")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(), "")
        self.assertEqual(closed, [True])
        self.assertEqual(result["counts"]["GroupCount"], 1)
        self.assertEqual(result["stack_rows_saved"], 0)
        self.assertEqual(result["review_status"], "not_performed")
        self.assertNotIn("ExampleCategory", json.dumps(result))
        rendered = analysis_cli_output.render_final_text(result)
        self.assertIn("H.test", rendered)
        self.assertIn("IG.Windows.Sysinternals.Autoruns", rendered)
        self.assertNotIn("Hunt analysis: unknown", rendered)
        api.query.assert_not_called()
        self.assertEqual(api.query_batches.call_count, 1)

    def test_malformed_batch_and_oversized_request_fail_closed(self):
        api = mock.Mock(org_id="root")
        api.query_batches.return_value = iter([{}])
        with mock.patch.object(test, "validate_request", return_value=config()):
            with self.assertRaisesRegex(RuntimeError, "malformed row batch"):
                test.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns", database=Path("unused"))
            api.query_batches.reset_mock()
            with mock.patch.object(test, "MAX_REQUEST_BYTES", 1), self.assertRaisesRegex(RuntimeError, "request is"):
                test.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns", database=Path("unused"))
            api.query_batches.assert_not_called()


@unittest.skipUnless(BINARY.exists(), "Configured Velociraptor unavailable")
class AutorunsTestNativeTest(unittest.TestCase):
    def execute(self, rows, cfg, mode):
        source = review_source.ReviewSource("test", "synthetic", "IG.Windows.Sysinternals.Autoruns", "TestRows", {})
        query, env, expected = test.build_query(cfg, mode=mode, source=source)
        prefix = "LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=gunzip(string=base64decode(string=TestRowsGzip))))\n"
        args = [str(BINARY), "--logfile", "/dev/null", "query", "--format", "jsonl"]
        for name, value in {**env, "TestRowsGzip": test._encode(rows)}.items():
            args.extend(["--env", f"{name}={value}"])
        args.append(prefix + query)
        result = subprocess.run(args, capture_output=True, text=True, timeout=90, check=True)
        self.assertNotIn("ERROR", result.stderr)
        parsed = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return test.consume_stream(iter(parsed), expected)

    def test_native_baseline_parity_unicode_and_no_tuple_cross_products(self):
        cfg = config()
        known = [dict(image_path="C:\\Vendor\\É.dll", launch_string="a&b<z>\u2028", signer="VENDOR"),
                 dict(image_path="C:\\Vendor\\b.dll", launch_string="other", signer="VENDOR")]
        cfg["exact_hashes"] += [autoruns.trusted_key(**row) for row in known]
        cfg["exact_patterns"] += autoruns_test_db.exact_patterns(autoruns.trusted_key_serialized(**row) for row in known)
        rows = [{"Image Path": r"C:\Users\Bob\exact.exe", "Launch String": "", "Signer": "Vendor", "Category": "Services"},
                {"Image Path": r"C:\Vendor\known.dll", "Launch String": "", "Signer": "Unverified", "Category": "Logon"},
                {"Image Path": "", "Launch String": "", "Signer": "", "Category": "Logon"}]
        for row in known + [{**known[0], "image_path": "C:\\Vendor\\é.dll"},
                            {**known[0], "launch_string": "other"}, {**known[1], "signer": "wrong"}]:
            rows.append({"Image Path": row["image_path"], "Launch String": row["launch_string"], "Signer": row["signer"], "Category": "Logon"})
        baseline = self.execute(rows, cfg, "hash-baseline")
        equivalent = self.execute(rows, cfg, "regex-equivalent")
        self.assertEqual(baseline, equivalent)
        self.assertEqual(baseline, dict(SourceRows=8, MatchedRows=4, ResidualRows=4, PopulatedRows=3, GroupCount=3))

    def test_more_than_1000_scalar_rules_match_the_last_rule(self):
        cfg = config()
        cfg["exact_hashes"] = []
        cfg["exact_patterns"] = [r"(?-i)\Anever" + str(n) + r"\z" for n in range(1201)]
        cfg["regex_rules"] = [{"ImagePathRegex": rf"(?-i)\Ac:\\never{n}\.dll\z", "LaunchStringRegex": r"(?-i)\A\z"} for n in range(1201)]
        cfg["regex_rules"].append({"ImagePathRegex": r"(?-i)\Ac:\\last\.dll\z", "LaunchStringRegex": r"(?-i)\A\z"})
        cfg["exact_patterns"] += autoruns_test_db.exact_patterns([autoruns.trusted_key_serialized(image_path=r"C:\Exact.dll", launch_string="", signer="")])
        rows = [{"Image Path": path, "Launch String": "", "Signer": "", "Category": "Logon"}
                for path in (r"C:\last.dll", r"C:\Exact.dll", r"C:\unknown.dll")]
        self.assertEqual(self.execute(rows, cfg, "regex-equivalent"),
                         dict(SourceRows=3, MatchedRows=2, ResidualRows=1, PopulatedRows=1, GroupCount=1))

    def test_signer_experiment_requires_exact_verified_subject_path_and_launch(self):
        cfg = config()
        item = dict(image_path=r"C:\Windows\System32\approved.dll",
                    launch_string=r"C:\Windows\System32\approved.dll", signer="(Verified) Microsoft Windows")
        cfg["signer_rules"] = autoruns_test_db.signer_rules([
            (autoruns.trusted_key(**item), autoruns.trusted_key_serialized(**item))])
        path = r"C:\Windows\SysWOW64\approved.dll"
        rows = [{"Image Path": path, "Launch String": path, "Signer": signer, "Category": "Services"}
                for signer in ("(Verified) Microsoft Windows", "(Not verified) Microsoft Windows",
                               "Microsoft Windows", "(Verified) Microsoft Windows Evil")]
        rows += [{**rows[0], "Launch String": path + " /extra"},
                 {**rows[0], "Image Path": r"C:\Windows\SysWOW64\unknown.dll"},
                 {**rows[0], "Image Path": r"C:\Users\Bob\approved.dll"}]
        self.assertEqual(self.execute(rows, cfg, "regex-equivalent")["MatchedRows"], 0)
        self.assertEqual(self.execute(rows, cfg, "signer-experimental")["MatchedRows"], 1)


class AutorunsProfileTest(unittest.TestCase):
    def test_profile_resolves_real_collector_and_stable_marker(self):
        request = hunting.build_request_for_profile("autoruns", validate_target=False)
        self.assertEqual([s.artifact for s in request.expected_specs], ["IG.Windows.Sysinternals.Autoruns"])
        tags = hunting.build_hunt_tags("ir-test", "autoruns", "sig", "windows")
        self.assertTrue(hunting.is_autoruns_hunt({"tags": tags}))
        self.assertTrue(hunting.is_autoruns_hunt({"hunt_description": hunting.build_hunt_description("ir-test", "autoruns", "sig", "windows")}))
        self.assertFalse(hunting.is_autoruns_hunt({"hunt_description": "ordinary hunt question=autoruns"}))

    def test_profile_and_ordinary_hunts_reuse_compatible_results(self):
        request = hunting.build_request_for_profile("autoruns", validate_target=False)
        base = {"hunt_id": "H.test", "state": "RUNNING", "tags": ["dfir-engagement:ir-test"],
                "start_request": {"artifacts": ["IG.Windows.Sysinternals.Autoruns"], "os": "windows"}}
        for target, tagged, allowed in (("autoruns", False, True), ("ordinary", True, True),
                                        ("autoruns", True, True), ("ordinary", False, True)):
            row = copy.deepcopy(base)
            if tagged:
                row["tags"].append("dfir-analysis:autoruns")
            with self.subTest(target=target, tagged=tagged), mock.patch.object(hunting, "query_hunts", return_value=[row]):
                matches = hunting.find_matching_hunts(object(), "ir-test", target, request, "windows", [], [])
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["reuse_allowed"], allowed)
            self.assertEqual(matches[0]["selection_compatible"], allowed)


if __name__ == "__main__":
    unittest.main()
