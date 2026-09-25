"""Production regex migration, native matching and host-free AI cache contracts."""
import csv
import copy
import hashlib
import io
import json
import tempfile
import sqlite3
from dataclasses import replace
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vraptor.autoruns import dedup_ai as dedup
from vraptor.autoruns import golden
from vraptor.autoruns import regex_store as db
from vraptor.autoruns import review
from vraptor.analyze import host as collection_analysis
from vraptor.autoruns import testing as autoruns_test
from vraptor.analyze import source as review_source
from vraptor.hunt import command as hunt_workflow
from vraptor.artifacts import persistence as persistence_policy
from tests import test_autoruns_regex as legacy_tests
from tests.test_autoruns_regex import EXACT, RULE
from tests.test_autoruns_regex_review import execute, row
from tests.test_autoruns_ai_review import _test_execution


class MigrationTest(unittest.TestCase):
    rows = legacy_tests.AutorunsRegexTest.rows
    expected_ids = legacy_tests.AutorunsRegexTest.expected_ids
    generated_query = legacy_tests.AutorunsRegexTest.generated_query
    run_vql = legacy_tests.AutorunsRegexTest.run_vql
    test_local_filters_agree_and_do_not_modify_database = legacy_tests.AutorunsRegexTest.test_local_filters_agree_and_do_not_modify_database
    test_native_single_pass_any_matches_local = legacy_tests.AutorunsRegexTest.test_native_single_pass_any_matches_local
    # Reuse native and single-host parity fixtures, with schema 9 as the target.
    def setUp(self):
        legacy_tests.AutorunsRegexTest.setUp(self)
        self.legacy = self.root / "legacy.sqlite"
        self.legacy.write_bytes(self.database.read_bytes())
        self.migration = db.migrate(self.database, self.database, backup_dir=self.root/"backups")

    # The inherited hash-short-circuit instrumentation is specific to schema 6.
    def test_hash_hit_skips_any_and_any_stops_at_first_match(self):
        query, env = self.generated_query()
        self.assertNotIn("hash(", query)
        self.assertEqual(self.migration["identity_count"], 0)
        self.assertEqual(Path(self.migration["backup"]).read_bytes(), self.legacy.read_bytes())

    def test_generated_vql_with_more_than_1000_rules(self):
        with sqlite3.connect(self.database) as conn:
            for index in range(1105):
                conn.execute("INSERT INTO autoruns_regex_rules VALUES (?,?,?,?,?,?)",
                    (".",f"never{index}",".*",".*","Synthetic","2026-01-01"))
            conn.execute("UPDATE metadata SET value=? WHERE key='rule_count'",("1108",))
        self.test_native_single_pass_any_matches_local()


class DedupAiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root/"golden.sqlite"
        golden.promote_records(self.database, [EXACT], regex_rows=[RULE])
        db.migrate(self.database, self.database, backup_dir=self.root/"backup")

    def export(self, name="source", host="PRIVATE_HOST", total=2, extra_rows=(), max_total_rows=None):
        folder = self.root/name
        folder.mkdir()
        cfg = db.load(self.database)
        rows = [row(host, image=r"C:\unknown.exe")]*total + list(extra_rows) + [row("known", **EXACT)]
        selected = dedup.template()
        stream = execute(rows, original=True, config=cfg, vql_file=selected, max_total_rows=max_total_rows)
        self.assertEqual(stream[-1]["MatchedRows"], 1)
        with (folder/"review.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f,fieldnames=review.CSV_FIELDS);writer.writeheader()
            counts = review.consume(iter(stream),writer,rule_count=len(cfg["rules"]),
                max_hostnames=20,expect_cache_metrics=False, pre_golden_cutoff=True, max_total_rows=max_total_rows)
        query, env, _ = review.build_query(cfg,source=review_source.hunt_source("H.test", golden.DEFAULT_AUTORUNS_ARTIFACT),vql_file=selected, max_hostnames=20, max_total_rows=max_total_rows)
        stats = dict(action="autoruns_dedup", status="complete", stream_complete=True, mode="regex-review", hunt_id="H.test",
            artifact=golden.DEFAULT_AUTORUNS_ARTIFACT, database_sha256=cfg["database_sha256"],
            vql_file={"sha256":selected.sha256}, max_example_hosts=20, counts=counts,
            source_contract=review.SOURCE_CONTRACT, max_total_rows=max_total_rows,
            query_environment_sha256=autoruns_test._query_environment_sha256(query,env),
            review_csv_sha256=hashlib.sha256((folder/"review.csv").read_bytes()).hexdigest())
        (folder/"stats.json").write_text(json.dumps(stats))
        return folder/"stats.json"

    def run_review(self, source, name, executor, **options):
        return dedup.review_saved(source,database=self.database,hunt_id="H.test",
            artifact=golden.DEFAULT_AUTORUNS_ARTIFACT,hunt_root=self.root/"hunts/H.test",executor=executor,**options)

    def state(self):
        return dedup.publication.load_state(self.root / "hunts/H.test")

    def test_skip_ai_publishes_canonical_outputs_without_model(self):
        source = self.export()
        executor = Mock(side_effect=AssertionError("AI must not run"))
        result = self.run_review(source, "prepared", executor, skip_ai=True)
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["ai_review_status"], "skipped")
        self.assertFalse(result["review_complete"])
        self.assertTrue(result["canonical_analysis_written"])
        root = self.root / "hunts/H.test"
        self.assertEqual(sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()), [
            "analysis-hunt.md", "analysis/autoruns_potential_golden.csv",
            "analysis/autoruns_review.csv", "analysis/hunt-analysis-state.json"])
        self.assertEqual(Path(result["analysis_review_csv"]).read_bytes(), source.with_name("review.csv").read_bytes())
        self.assertEqual(len(Path(result["potential_golden_csv"]).read_text().splitlines()), 1)
        self.assertIn("AI review is incomplete", Path(result["report_markdown"]).read_text())
        executor.assert_not_called()
        persistence_policy.preflight_analysis_tree(root / "analysis", ["hunt:H.test"])
        executor.side_effect = None
        executor.return_value = ("END", {})
        self.assertFalse(self.run_review(source, "reviewed", executor)["cache_hit"])
        executor.assert_called_once()

    def test_stack_threshold_boundary_retention_and_cache_change(self):
        source = self.export(total=20, extra_rows=[row("host", image=r"C:\frequent.exe")]*21, max_total_rows=20)
        argv = ["analyze", "--id", "fixture", "--hunt-id", "H.test",
                "--artifact", golden.DEFAULT_AUTORUNS_ARTIFACT, "--profile", "autoruns"]
        threshold = hunt_workflow.parse_args(argv).stack_max_total_rows
        seen = []
        def execute(**kwargs):
            seen.append(kwargs["prompt"])
            return "END", {}
        selected = self.run_review(source, "selected", execute, max_total_rows=threshold)
        self.assertIn("unknown.exe", seen[0])
        self.assertNotIn("frequent.exe", seen[0])
        self.assertEqual(selected["source_selection"], dict(stage="before_golden", max_total_rows=20,
            excluded_group_count=1, excluded_row_count=21))
        self.assertEqual(selected["result_review"], "partial")
        self.assertEqual(selected["manifest"]["model_reviewed_group_count"], 1)
        self.assertEqual(Path(selected["analysis_review_csv"]).read_bytes(), source.with_name("review.csv").read_bytes())
        self.assertIn("21 records", selected["chat_summary"])
        self.assertIn("Source records: 42; GoldenDB matched: 1", selected["chat_summary"])
        self.assertIn("representing 20 records", selected["chat_summary"])
        self.assertIn("GoldenDB not evaluated; absent from review CSV", selected["chat_summary"])
        self.assertNotIn("frequent.exe", Path(selected["analysis_review_csv"]).read_text())
        self.assertTrue(self.run_review(source, "cached", execute, max_total_rows=threshold)["cache_hit"])
        disabled = hunt_workflow.parse_args([*argv, "--stack-max-total-rows", "0"]).stack_max_total_rows
        with self.assertRaisesRegex(RuntimeError, "contract/database/scope"):
            self.run_review(source, "mismatched", execute, max_total_rows=disabled)
        unlimited = self.export("unlimited", total=20, extra_rows=[row("host", image=r"C:\frequent.exe")]*21)
        expanded = self.run_review(unlimited, "expanded", execute, max_total_rows=disabled)
        self.assertIsNone(expanded["source_selection"]["max_total_rows"])
        self.assertEqual(expanded["source_selection"]["excluded_group_count"], 0)
        self.assertFalse(expanded["cache_hit"])
        self.assertEqual(expanded["manifest"]["model_reviewed_group_count"], 2)
        self.assertEqual(expanded["result_review"], "complete")
        self.assertIn("frequent.exe", seen[-1])
        self.assertEqual(len(seen), 2)

    def test_all_stacks_excluded_does_not_call_model(self):
        executor = Mock(side_effect=AssertionError("AI must not run"))
        result = self.run_review(self.export(total=101, max_total_rows=100), "excluded", executor, max_total_rows=100)
        executor.assert_not_called()
        self.assertEqual(result["manifest"]["model_reviewed_group_count"], 0)
        self.assertEqual(result["result_review"], "partial")
        self.assertEqual(result["source_selection"]["excluded_row_count"], 101)
        self.assertEqual(len(Path(result["potential_golden_csv"]).read_text().splitlines()), 1)
        self.assertEqual(len(Path(result["analysis_review_csv"]).read_text().splitlines()), 1)

    def test_native_cutoff_precedes_matching_and_uses_final_counts(self):
        cfg = db.load(self.database)
        known, frequent, rare = row("known", **EXACT), row(image=r"C:\frequent.exe"), row(image=r"C:\rare.exe")
        # Interleaving ensures the predicate sees completed, not incremental counts.
        rows = [known, frequent, rare] * 25 + [known, frequent, row(Enabled="disabled")]
        build = review.build_query

        def instrument(*args, **kwargs):
            query, env, expected = build(*args, **kwargs)
            query = query.replace("LET retained =", 'LET MatchProbe <= dict(Calls=0)\n'
                'LET ProbeMatch(Value) = if(condition=set(item=MatchProbe, field="Calls", value=MatchProbe.Calls + 1), then=Value)\nLET retained =')
            query = query.replace('condition=ApplyMatching AND any(items=GoldenRules,',
                                  'condition=ApplyMatching AND ProbeMatch(Value=any(items=GoldenRules,')
            query = query.replace('Signer =~ rule.Signer"),', 'Signer =~ rule.Signer")),')
            return query + '\nSELECT MatchProbe.Calls AS Calls, len(list=DedupState) AS StoredGroups FROM scope()\n', env, expected

        with patch.object(review, "build_query", side_effect=instrument):
            filtered = execute(rows, original=True, config=cfg, vql_file=dedup.template(), max_total_rows=25)
            unlimited = execute(rows, original=True, config=cfg, vql_file=dedup.template())
        self.assertEqual(filtered[-1], {"Calls": 1, "StoredGroups": 3})
        self.assertEqual(unlimited[-1], {"Calls": 3, "StoredGroups": 3})
        self.assertEqual(filtered[-2], dict(_Review="summary", SourceRows=78, EligibleRows=77,
            EligibleGroups=3, HighCountExcludedRows=52, HighCountExcludedGroups=2,
            MatchedRows=0, MatchedGroups=0, ResidualRows=25, GroupCount=1))
        self.assertEqual(unlimited[-2]["MatchedRows"], 26)
        self.assertEqual(unlimited[-2]["HighCountExcludedRows"], 0)
        self.assertEqual(filtered[1]["TotalRows"], 25)

    def test_native_clears_only_over_limit_samples_and_preserves_output(self):
        cfg = db.load(self.database)
        # Interleave groups so even an LRU of one must evict and re-emit keys.
        rows = [row(f"host{i}", image=f"c:\\fixture\\count{total}.exe")
                for i in range(45) for total in (20, 21, 45) if i < total]
        build = review.build_query

        def baseline(query):
            return query.replace(
                'AND if(condition=MaxTotalRows > 0 AND State.TotalRows > MaxTotalRows,\n'
                '        then=if(condition=State.TotalRows = MaxTotalRows + 1,\n'
                '            then=set(item=State, field="Names", value=dict()), else=State),\n'
                '        else=SampleHost(State=State, Name=Name))',
                'AND SampleHost(State=State, Name=Name)')

        def instrument(query):
            instrumented = query.replace('LET DedupSize = 100000', 'LET DedupSize = 1')
            instrumented = ('LET SampleProbe <= dict(Clears=0)\n'
                'LET ClearNames(State) = set(item=SampleProbe, field="Clears", value=SampleProbe.Clears + 1) '
                'AND set(item=State, field="Names", value=dict())\n' + instrumented)
            instrumented = instrumented.replace(
                'then=set(item=State, field="Names", value=dict()), else=State)',
                'then=ClearNames(State=State), else=State)')
            instrumented += ('\nSELECT "samples" AS _Review, _value.TotalRows AS TotalRows, '
                'len(list=_value.Names) AS StoredHosts FROM items(item=DedupState)\n'
                'SELECT "clears" AS _Review, SampleProbe.Clears AS Clears FROM scope()\n')
            return instrumented

        for limit in (20, None):
            for cap in (20, 0):
                with self.subTest(limit=limit, cap=cap):
                    def run(transform):
                        def modified(*args, **kwargs):
                            query, env, expected = build(*args, **kwargs)
                            return transform(query), env, expected
                        with patch.object(review, "build_query", side_effect=modified):
                            return execute(rows, cap=cap, original=True, config=cfg,
                                vql_file=dedup.template(), max_total_rows=limit)
                    before, after = run(baseline), run(instrument)
                    self.assertEqual(after[:-4], before)
                    samples = {item["TotalRows"]: item["StoredHosts"] for item in after[-4:-1]}
                    self.assertEqual(samples, {20: cap, 21: 0 if limit else cap, 45: 0 if limit else cap})
                    self.assertEqual(after[-1]["Clears"], 2 if limit else 0)

    def test_cutoff_stream_rejects_bad_accounting_truncation_and_over_limit_rows(self):
        cfg = db.load(self.database)
        stream = execute([row()]*25 + [row(image=r"C:\frequent.exe")]*26,
            original=True, config=cfg, vql_file=dedup.template(), max_total_rows=25)

        def consume(value, limit=25):
            return review.consume(iter(value), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                rule_count=len(cfg["rules"]), max_hostnames=20, pre_golden_cutoff=True,
                max_total_rows=limit, expect_cache_metrics=False)

        counts = consume(stream)
        self.assertEqual(counts["HighCountExcludedRows"], 26)
        for field in (*review.COUNT_FIELDS, *review.CUTOFF_COUNT_FIELDS):
            for value in (None, -1, True):
                with self.subTest(field=field, value=value):
                    broken = copy.deepcopy(stream)
                    broken[-1][field] = value
                    with self.assertRaises(RuntimeError):
                        consume(broken)
        for field in ("EligibleRows", "EligibleGroups", "HighCountExcludedRows", "HighCountExcludedGroups", "MatchedGroups", "ResidualRows", "GroupCount"):
            with self.subTest(field=field):
                broken = copy.deepcopy(stream)
                broken[-1][field] += 1
                with self.assertRaises(RuntimeError):
                    consume(broken)
        for broken in (stream[:-1], stream + [stream[1]], [stream[0], stream[-1]]):
            with self.assertRaises(RuntimeError):
                consume(broken)
        with self.assertRaisesRegex(RuntimeError, "exceeds"):
            consume(stream, limit=24)
        with self.assertRaisesRegex(RuntimeError, "Unlimited"):
            consume(stream, limit=None)

    def test_skip_ai_unlimited_exports_high_count_residuals(self):
        source = self.export(total=26)
        executor = Mock(side_effect=AssertionError("AI must not run"))
        result = self.run_review(source, "unlimited", executor, skip_ai=True)
        self.assertEqual(result["counts"]["ResidualRows"], 26)
        self.assertEqual(result["source_selection"]["excluded_group_count"], 0)
        self.assertIn("unknown.exe", Path(result["analysis_review_csv"]).read_text())
        executor.assert_not_called()

    def test_source_run_binds_cutoff_and_publishes_accounted_empty_csv(self):
        cfg = db.load(self.database)
        stream = execute([row()]*26, original=True, config=cfg, vql_file=dedup.template(), max_total_rows=25)
        with patch.object(autoruns_test, "_stream_rows", return_value=(r for r in stream)):
            result = review.run(Mock(org_id="root"), hunt_id="H.test",
                artifact=golden.DEFAULT_AUTORUNS_ARTIFACT, database=self.database,
                output_dir=self.root/"exported", vql_file=dedup.template(),
                workflow="autoruns", max_total_rows=25)
        self.assertEqual(result["source_contract"], review.SOURCE_CONTRACT)
        self.assertEqual(result["max_total_rows"], 25)
        self.assertEqual(result["counts"]["HighCountExcludedGroups"], 1)
        self.assertEqual(len(Path(result["review_csv"]).read_text().splitlines()), 1)
        stats, rows, _ = dedup.load_source(result["stats_json"], database=self.database,
            hunt_id="H.test", artifact=golden.DEFAULT_AUTORUNS_ARTIFACT, max_total_rows=25)
        self.assertEqual(rows, [])
        self.assertEqual(stats["counts"]["EligibleRows"], 26)
        published = self.run_review(result["stats_json"], "prepared", Mock(), skip_ai=True, max_total_rows=25)
        self.assertEqual(published["result_review"], "not_reviewed")
        self.assertIn("GoldenDB not evaluated", published["chat_summary"])

    def test_historical_ai_only_cutoff_report_retains_csv_wording(self):
        record = dict(counts=dict(SourceRows=52, MatchedRows=1, GroupCount=2, ResidualRows=51),
            review_complete=False, result_review="not_reviewed",
            ai_selection=dict(max_total_rows=25, excluded_group_count=1, excluded_row_count=26))
        summary = dedup.publication.render_summary(record, {})
        self.assertIn("retained in review CSV", summary)
        self.assertNotIn("GoldenDB not evaluated", summary)

    def test_threshold_binds_query_and_cache_even_when_residuals_are_identical(self):
        executor = Mock(return_value=("END", {}))
        first = self.export("first", max_total_rows=25)
        second = self.export("second", max_total_rows=100)
        self.assertEqual(first.with_name("review.csv").read_bytes(), second.with_name("review.csv").read_bytes())
        self.assertNotEqual(json.loads(first.read_text())["query_environment_sha256"],
                            json.loads(second.read_text())["query_environment_sha256"])
        self.run_review(first, "first", executor, max_total_rows=25)
        result = self.run_review(second, "second", executor, max_total_rows=100)
        self.assertFalse(result["cache_hit"])
        self.assertEqual(executor.call_count, 2)
        stats = json.loads(first.read_text())
        stats["max_total_rows"] = 100
        first.write_text(json.dumps(stats))
        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            self.run_review(first, "changed", executor, max_total_rows=100)

    def test_historical_pre_golden_v4_publication_remains_readable(self):
        result = self.run_review(self.export(max_total_rows=20), "historical", Mock(), skip_ai=True, max_total_rows=20)
        path = Path(result["state_file"])
        state = json.loads(path.read_text())
        record = state["specialized_analysis"]["autoruns_review"]
        record["source_contract"] = review.SOURCE_CONTRACT
        record["source_selection"]["stage"] = "before_golden"
        record["counts"].update(EligibleGroups=2, MatchedGroups=1)
        path.write_text(json.dumps(state))
        persistence_policy.preflight_analysis_tree(path.parent, ["hunt:H.test"])
        record["source_contract"] = review.GOLDEN_FIRST_SOURCE_CONTRACT
        record["source_selection"]["stage"] = "after_golden"
        record["counts"].update(EligibleGroups=None, MatchedGroups=None)
        path.write_text(json.dumps(state))
        persistence_policy.preflight_analysis_tree(path.parent, ["hunt:H.test"])

    def test_historical_v3_publication_still_passes_persistence_policy(self):
        result = self.run_review(self.export(), "prepared", Mock(), skip_ai=True)
        path = Path(result["state_file"])
        state = json.loads(path.read_text())
        record = state["specialized_analysis"]["autoruns_review"]
        record.update(schema="autoruns-review-v3", content="complete_residual_stacks", contract="autoruns-dedup-ai-v1")
        for name in ("source_selection", "source_contract", "max_total_rows"):
            record.pop(name)
        for name in review.CUTOFF_COUNT_FIELDS:
            record["counts"].pop(name)
        path.write_text(json.dumps(state))
        persistence_policy.preflight_analysis_tree(path.parent, ["hunt:H.test"])

    def test_native_empty_and_all_matched_cutoff_accounting(self):
        cfg = db.load(self.database)
        for rows, matched, excluded in (([], 0, 0), ([row(**EXACT)]*25, 25, 0),
                                        ([row(**EXACT)]*26, 0, 26)):
            with self.subTest(rows=len(rows)):
                stream = execute(rows, cap=0, original=True, config=cfg,
                    vql_file=dedup.template(), max_total_rows=25)
                counts = review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                    rule_count=len(cfg["rules"]), max_hostnames=0, pre_golden_cutoff=True,
                    max_total_rows=25, expect_cache_metrics=False)
                self.assertEqual(counts["GroupCount"], 0)
                self.assertEqual(counts["MatchedRows"], matched)
                self.assertEqual(counts["HighCountExcludedRows"], excluded)

    def test_native_materialization_threshold_preserves_disk_and_memory_results(self):
        from tests.test_autoruns_regex_review import subprocess as native_subprocess
        cfg = db.load(self.database)
        rows = [row("early", image=f"c:\\fixture\\item{i}.exe") for i in range(1105)]
        rows += [row(f"late{i}", image="c:\\fixture\\item0.exe") for i in range(20)]
        rows += [row("last", image="c:\\fixture\\item1.exe")]
        build, run_native = review.build_query, native_subprocess.run
        results = []
        for limit in (100000, 1000):
            with self.subTest(limit=limit):
                messages = []
                def configured(*args, **kwargs):
                    query, env, expected = build(*args, **kwargs)
                    self.assertIn("LET VQL_MATERIALIZE_ROW_LIMIT <= 100000", query)
                    return query.replace("LET VQL_MATERIALIZE_ROW_LIMIT <= 100000",
                        f"LET VQL_MATERIALIZE_ROW_LIMIT <= {limit}"), env, expected
                def capture(*args, **kwargs):
                    command = list(args[0])
                    command.insert(1, "--verbose")
                    output = run_native(command, *args[1:], **kwargs)
                    messages.append(output.stderr)
                    return output
                with patch.object(review, "build_query", side_effect=configured), \
                     patch.object(native_subprocess, "run", side_effect=capture):
                    results.append(execute(rows, cap=10, original=True, config=cfg,
                        vql_file=dedup.template(), max_total_rows=20))
                self.assertEqual("Materialize of LET deduplicated_keys" in "".join(messages), limit == 1000)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][-1]["HighCountExcludedRows"], 21)
        self.assertEqual(results[0][-1]["EligibleGroups"], 1105)

    def test_native_many_groups_keep_late_counts_and_host_samples(self):
        cfg = db.load(self.database)
        rows = [row("early", image=f"c:\\fixture\\item{i}.exe") for i in range(1105)]
        # Revisit early groups after exceeding the old 1,000-row materialization limit.
        rows += [row(f"late{i}", image="c:\\fixture\\item0.exe") for i in range(25)]
        rows += [row("last", image="c:\\fixture\\item1.exe")]
        for limit, cap in ((25, 20), (None, 20), (None, 0)):
            with self.subTest(limit=limit, cap=cap):
                stream = execute(rows, cap=cap, original=True, config=cfg,
                    vql_file=dedup.template(), max_total_rows=limit)
                counts = review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                    rule_count=len(cfg["rules"]), max_hostnames=cap, pre_golden_cutoff=True,
                    max_total_rows=limit, expect_cache_metrics=False)
                stacks = {dedup.identity(r): r for r in stream[1:-1]}
                self.assertEqual(len(stacks), len(stream)-2)
                self.assertEqual(counts["SourceRows"], 1131)
                self.assertEqual(counts["EligibleGroups"], 1105)
                self.assertEqual(counts["HighCountExcludedRows"], 26 if limit else 0)
                self.assertEqual(counts["GroupCount"], 1104 if limit else 1105)
                second = next(r for r in stacks.values() if r["ImagePath"] == "c:\\fixture\\item1.exe")
                self.assertEqual(second["TotalRows"], 2)
                self.assertEqual(second["ExampleHosts"], ["early", "last"] if cap else [])
                if limit is None:
                    first = next(r for r in stacks.values() if r["ImagePath"] == "c:\\fixture\\item0.exe")
                    self.assertEqual(first["TotalRows"], 26)
                    self.assertEqual(first["ExampleHosts"], ["early", *[f"late{i}" for i in range(19)]] if cap else [])

    def test_cli_summary_reports_findings_duration_and_paths(self):
        executor = Mock(return_value=("SUSPICIOUS\t1\thigh\tSuspicious launch\nEND", {}))
        result = self.run_review(self.export(), "summary", executor)
        summary = result["chat_summary"]
        for expected in ("Suspicious identities: 1 (0 critical, 1 high", "GoldenDB prospects: 0",
                         "HIGH |", "unknown.exe", "Suspicious launch", "Elapsed:"):
            self.assertIn(expected, summary)
        self.assertEqual(result["report_file"], result["report_markdown"])
        self.assertEqual(result["state_file"], result["report_json"])
        self.assertIn(summary, Path(result["report_file"]).read_text())
        from vraptor.analyze.cli_output import render_final_text
        terminal = render_final_text(result)
        self.assertIn(summary, terminal)
        self.assertIn(result["report_file"], terminal)
        self.assertIn(result["state_file"], terminal)

    def test_partial_source_preserves_previous_publication(self):
        source = self.export()
        self.run_review(source, "first", Mock(return_value=("END", {})))
        before = {p: p.read_bytes() for p in (self.root/"hunts/H.test").rglob("*") if p.is_file()}
        stats = json.loads(source.read_text()); stats["stream_complete"] = False
        source.write_text(json.dumps(stats))
        with self.assertRaises(RuntimeError):
            self.run_review(source, "partial", Mock(), skip_ai=True)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_hosts_never_reach_ai_or_state_and_fresh_samples_are_joined(self):
        executor = Mock(return_value=("SUSPICIOUS\t1\thigh\tSuspicious launch\nEND", {}))
        first = self.run_review(self.export(), "first", executor)
        self.assertFalse(first["cache_hit"])
        self.assertNotIn("PRIVATE_HOST", executor.call_args.kwargs["prompt"])
        self.assertNotIn("ExampleHosts", executor.call_args.kwargs["prompt"])
        self.assertNotIn("private_host", Path(first["report_json"]).read_text())
        second = self.run_review(self.export("source2", "FRESH_HOST"), "second", executor)
        self.assertTrue(second["cache_hit"])
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(second["suspicious_rows"][0]["ExampleHosts"], ["fresh_host"])
        self.assertIn("fresh_host", Path(second["report_markdown"]).read_text())
        self.run_review(self.export("source3", total=3), "third", executor)
        self.assertEqual(executor.call_count, 2)

    def test_potential_golden_omits_hosts_and_report_rebuild_matches(self):
        executor = Mock(return_value=("POTENTIAL_GOLDEN\t1\tStable benign persistence\nEND", {}))
        for index, host in enumerate(("PRIVATE_HOST", "FRESH_HOST")):
            result = self.run_review(self.export(f"source{index}", host), "review", executor)
            self.assertEqual(result["cache_hit"], bool(index))
            with Path(result["potential_golden_csv"]).open() as stream:
                reader = csv.DictReader(stream)
                self.assertEqual(reader.fieldnames, list(dedup.publication.CANDIDATE_FIELDS))
                self.assertEqual(next(reader)["Reason"], "Stable benign persistence")
            report = Path(result["report_markdown"])
            before = report.read_bytes()
            dedup.publication.coordinator.refresh_canonical_hunt_report(
                self.root/"hunts/H.test", question="Review Autoruns persistence")
            self.assertEqual(report.read_bytes(), before)
            self.assertNotIn(host.lower(), report.read_text())
        executor.assert_called_once()

    def test_failed_ai_retains_csv_and_explicit_failed_state(self):
        with self.assertRaises(RuntimeError):
            self.run_review(self.export(), "failed", Mock(return_value=("SUSPICIOUS\t999\thigh\tUnknown\nEND", {})))
        record = dedup.publication.saved_review(self.state())
        self.assertEqual(record["ai_review_status"], "failed")
        self.assertFalse(record["review_complete"])
        self.assertTrue((self.root/"hunts/H.test/analysis/autoruns_review.csv").is_file())

    def test_publication_failure_rolls_back_all_outputs(self):
        source = self.export()
        report = self.run_review(source, "first", Mock(return_value=("END", {})))
        before = {p: p.read_bytes() for p in (self.root/"hunts/H.test").rglob("*") if p.is_file()}
        original = dedup.publication.atomic_io.write_text_atomic
        state_path = Path(report["report_json"])
        def fail_state(path, *args, **kwargs):
            if path == state_path:
                raise OSError("fixture state commit failure")
            return original(path, *args, **kwargs)
        fresh = self.export("fresh", "FRESH_HOST")
        with patch.object(dedup.publication.atomic_io, "write_text_atomic", side_effect=fail_state):
            with self.assertRaisesRegex(OSError, "commit"):
                self.run_review(fresh, "second", Mock(), skip_ai=True)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_state_and_csv_tampering_fail_closed(self):
        source = self.export()
        result = self.run_review(source, "first", Mock(return_value=("END", {})))
        destination = Path(result["analysis_review_csv"])
        destination.write_text(destination.read_text()+"extra")
        with self.assertRaises(persistence_policy.PersistencePolicyError):
            persistence_policy.classify_analysis_file(destination, analysis_root=destination.parent, source_ids=["hunt:H.test"])
        with self.assertRaisesRegex(RuntimeError, "different publications"):
            dedup.publication.coordinator.refresh_canonical_hunt_report(self.root/"hunts/H.test", question="fixture")

    def test_preserves_other_hunt_checkpoint_and_rejects_incompatible_state(self):
        source = self.export()
        first = self.run_review(source, "first", Mock(), skip_ai=True)
        state = self.state()
        state["checkpoint"] = {"result": {}, "generation": 3}
        state["specialized_analysis"]["other_metadata"] = {"fixture": True}
        path = Path(first["report_json"])
        path.write_text(json.dumps(state))
        self.run_review(source, "second", Mock(), skip_ai=True)
        self.assertEqual(self.state()["checkpoint"], state["checkpoint"])
        self.assertEqual(self.state()["specialized_analysis"]["other_metadata"], {"fixture": True})
        state["schema_version"] = 5; path.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.run_review(source, "third", Mock(), skip_ai=True)

    def test_command_runs_native_stream_through_canonical_publisher(self):
        cfg = db.load(self.database)
        stream = execute([row(f"PRIVATE_HOST_{i}", image=r"C:\unknown.exe") for i in range(15)], cap=10,
                         original=True, config=cfg, vql_file=dedup.template(), max_total_rows=20)
        self.assertEqual(stream[1]["TotalRows"], 15)
        self.assertEqual(len(stream[1]["ExampleHosts"]), 10)
        api = Mock(org_id="root")
        api.query.return_value = [{"Definition": {"hash": cfg["database_sha256"]}}]
        original_classify = dedup.ai.classify_streaming_rows_async
        executor = Mock(return_value=("POTENTIAL_GOLDEN\t1\tKnown benign fixture\nEND", {}))
        async def classify(*args, **kwargs):
            kwargs["executor"] = executor
            return await original_classify(*args, **kwargs)
        from vraptor.results import operation_policy
        for skip, existing_only in ((False, False), (True, False), (True, True)):
            args = hunt_workflow.parse_args(["analyze", "--id", "fixture", "--profile", "autoruns",
                "--hunt-id", "H.test", "--artifact", golden.DEFAULT_AUTORUNS_ARTIFACT,
                "--case-root", str(self.root / "live"), "--autoruns-golden-db", str(self.database),
                *(["--skip-ai"] if skip else [])])
            args.existing_only = existing_only
            api.query.reset_mock()
            api.query_batches.return_value = iter([stream])
            with patch.object(hunt_workflow, "resolve_api_client", return_value=self.root/"api.yaml"), \
                 patch.object(hunt_workflow, "resolve_agent_execution", return_value=None), \
                 patch.object(hunt_workflow, "VeloApiClient") as client, \
                 patch.object(hunt_workflow.generic, "query_single_hunt", return_value={"artifacts": [golden.DEFAULT_AUTORUNS_ARTIFACT]}), \
                 patch.object(dedup.ai, "classify_streaming_rows_async", side_effect=classify), \
                 operation_policy(existing_only=existing_only):
                client.return_value.__enter__.return_value = api
                result = hunt_workflow.command_autoruns(args)
            self.assertEqual(api.query.call_count, 0 if existing_only else 1)
            self.assertTrue(result["canonical_analysis_written"])
            with Path(result["analysis_review_csv"]).open() as stream_file:
                exported = list(csv.DictReader(stream_file))
            self.assertEqual(int(exported[0]["TotalRows"]), 15)
            self.assertEqual(len(json.loads(exported[0]["ExampleHosts"])), 10)
            self.assertEqual(result["ai_review_status"], "skipped" if skip else "complete")
            self.assertEqual(len(Path(result["potential_golden_csv"]).read_text().splitlines()), 1 if skip else 2)
            self.assertFalse(list((self.root/"live/fixture/hunts").glob(".autoruns-runtime-*")))
        executor.assert_called_once()

    def test_hunt_directory_lock_excludes_another_publisher(self):
        root = self.root/"hunts/H.test"
        with dedup.publication.hunt_lock(root):
            with self.assertRaisesRegex(RuntimeError, "Another Autoruns"):
                with dedup.publication.hunt_lock(root):
                    self.fail("second writer entered")

    def test_changed_csv_or_missing_completion_fails_before_ai(self):
        source=self.export()
        executor=Mock()
        source.with_name("review.csv").write_text("changed")
        with self.assertRaisesRegex(RuntimeError,"checksum"):
            self.run_review(source,"failed",executor)
        executor.assert_not_called()
        self.assertFalse((self.root/"failed").exists())

    def test_unknown_model_id_does_not_publish_cache_or_report(self):
        executor=Mock(return_value=("SUSPICIOUS\t999\thigh\tUnknown\nEND",{}))
        with self.assertRaises(RuntimeError): self.run_review(self.export(),"failed",executor)
        self.assertFalse((self.root/"failed").exists())
        self.assertFalse((self.root/".autoruns-ai-cache").exists())

    def test_unicode_signer_and_extra_arguments_preserve_exact_matching(self):
        legacy=self.root/"unicode.sqlite"
        item={**EXACT,"Signer":"VÉNDOR","Launch String":"fixed /service\n"}
        golden.promote_records(legacy,[item])
        target=self.root/"unicode-regex.sqlite"
        db.migrate(legacy,target,backup_dir=self.root/"backup")
        samples=[item,{**item,"Signer":"Véndor"},{**item,"Launch String":"fixed /service\nextra"}]
        old=collection_analysis.reduce_autoruns_with_golden_db(samples,database=legacy)[0]
        new=collection_analysis.reduce_autoruns_with_golden_db(samples,database=target)[0]
        self.assertEqual(old,new)
        stream=execute([row(**r) for r in samples],original=True,config=db.load(target),vql_file=dedup.template())
        self.assertEqual(stream[-1]["MatchedRows"],1)

    def test_default_cli_requires_live_readiness(self):
        args=["analyze","--id","fixture","--profile","autoruns","--hunt-id","H.test",
            "--artifact",golden.DEFAULT_AUTORUNS_ARTIFACT,"--autoruns-golden-db",str(self.database),"--no-progress"]
        with patch.object(hunt_workflow,"validate_live_engagement",return_value=None) as readiness, patch.object(hunt_workflow,"command_autoruns",return_value={"status":"complete","chat_summary":"test"}), patch("sys.stdout",io.StringIO()):
            self.assertEqual(hunt_workflow.main(args),0)
        readiness.assert_called_once()


    def test_regex_import_backup_dry_run_and_legacy_write_guard(self):
        incoming=self.root/"rules.json"
        incoming.write_text(json.dumps([dict(Category=".", ImagePath=r"c:\\vendor\\new\.exe",
            LaunchString=r"c:\\vendor\\new\.exe", Signer="vendor", Notes="Reviewed vendor entry")]))
        before=self.database.read_bytes()
        result=db.import_rules(self.database,incoming,backup_dir=self.root/"backups",dry_run=True)
        self.assertEqual(result["added_rules"],1)
        self.assertEqual(before,self.database.read_bytes())
        result=db.import_rules(self.database,incoming,backup_dir=self.root/"backups")
        self.assertEqual(Path(result["backup"]).read_bytes(),before)
        self.assertEqual(db.import_rules(self.database,incoming,backup_dir=self.root/"backups")["added_rules"],0)
        with self.assertRaisesRegex(RuntimeError,"regex-import"):
            golden.promote_records(self.database,[EXACT])

    def test_large_scalar_rule_set_and_late_match(self):
        cfg=db.load(self.database)
        rule=cfg["rules"][0]
        cfg["rules"]=[{**rule,"ImagePath":f"never{i}"} for i in range(1105)]+cfg["rules"]
        stream=execute([row(**EXACT)],original=True,config=cfg,vql_file=dedup.template())
        self.assertEqual(stream[-1]["MatchedRows"],1)


    def test_exclude_exact_retains_only_existing_regex(self):
        source=self.root/"legacy.sqlite"
        golden.promote_records(source,[EXACT],regex_rows=[RULE])
        target=self.root/"existing-only.sqlite"
        result=db.migrate(source,target,backup_dir=self.root/"backup",exclude_exact=True)
        self.assertEqual(result["removed_exact_count"],1)
        self.assertEqual(result["converted_exact_count"],0)
        self.assertEqual(result["regex_rule_count"],1)
        residual,_=collection_analysis.reduce_autoruns_with_golden_db([EXACT],database=target)
        self.assertEqual(len(residual),1)
        self.assertEqual(Path(result["backup"]).read_bytes(),source.read_bytes())


    def test_schema9_rejects_experimental_templates(self):
        cfg=db.load(self.database)
        with self.assertRaisesRegex(RuntimeError,"pinned production"):
            review.build_query(cfg,source=review_source.hunt_source("H.test",golden.DEFAULT_AUTORUNS_ARTIFACT))

    def test_unsupported_artifact_is_rejected_before_queries(self):
        with self.assertRaises(SystemExit), patch("sys.stderr",io.StringIO()):
            hunt_workflow.parse_args(["analyze","--profile","autoruns","--hunt-id","H.test",
                "--artifact","Custom.Autoruns.Report"])

    def test_route_query_setting_invalidates_cache(self):
        source=self.export()
        executor=Mock(return_value=("END",{}))
        first=_test_execution()
        second=replace(first,route=replace(first.route,default_query={"mode":"new"}))
        for index,execution in enumerate((first,second,second)):
            result=dedup.review_saved(source,database=self.database,hunt_id="H.test",
                artifact=golden.DEFAULT_AUTORUNS_ARTIFACT,hunt_root=self.root/"hunts/H.test",
                execution=execution,executor=executor)
            self.assertEqual(result["cache_hit"],index==2)
        self.assertEqual(executor.call_count,2)

    def test_category_cache_and_raw_pattern_whole_field_parity(self):
        with sqlite3.connect(self.database) as conn:
            conn.execute("DELETE FROM autoruns_regex_rules")
            conn.execute("INSERT INTO autoruns_regex_rules VALUES (?,?,?,?,?,?)",
                (".", r"c:\\vendor\\fixed\.exe", "fixed /service", "vendor", "Fixture", "2026-01-01"))
            conn.execute("UPDATE metadata SET value='1' WHERE key='rule_count'")
        samples=[{**EXACT,"Category":"Logon"},{**EXACT,"Category":"Services"},
            {**EXACT,"Category":"Logon","Launch String":"prefix fixed /service"}]
        expected=collection_analysis.reduce_autoruns_with_golden_db(samples,database=self.database)[0]
        self.assertEqual(len(expected),1)
        target=self.root/"filtered.csv"
        golden.filter_autoruns_rows(self.database,samples,output=target)
        with target.open() as stream:
            self.assertEqual(len(list(csv.DictReader(stream))),1)
        output=execute([row(**r) for r in samples],original=True,config=db.load(self.database),vql_file=dedup.template())
        self.assertEqual(output[-1]["MatchedRows"],2)

    def test_legacy_schema9_baseline_mutation_rejected(self):
        before=self.database.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"regex-import"):
            golden.promote_records(self.root/"delta.sqlite",[EXACT],baseline_databases=[self.database])
        self.assertEqual(before,self.database.read_bytes())
