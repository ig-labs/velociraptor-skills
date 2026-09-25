"""Native VQL and fail-closed CSV publication tests for regex review."""
import csv
import io
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest.mock import Mock, patch

from vraptor.autoruns import review
from vraptor.autoruns import testing as parent
from vraptor.analyze import source as review_source

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


def configuration():
    return {"rules": [{"Category": "Logon", "ImagePath": r"^c:\\known\.exe$",
                       "LaunchString": ".", "Signer": r"^\(Verified\) Microsoft"}],
            "metadata": {}, "database_sha256": "0"*64}


def execute(rows, cap=20, config=None, original=False, **query_options):
    if not original and not query_options.get("single_lru", False):
        query_options.setdefault("cache_max_entries", review.CACHE_MAX_ENTRIES)
    source = review_source.ReviewSource("test", "test", "IG.Windows.Sysinternals.Autoruns",
        "foreach(row=parse_json_array(data=gunzip(string=base64decode(string=TestRowsGzip))))", {})
    query, env, _ = review.build_query(config or configuration(), source=source, max_hostnames=cap, **query_options)
    args = [str(BINARY), "query", "--format", "jsonl"]
    for name, value in {**env, "TestRowsGzip": parent._encode(rows)}.items():
        args += ["--env", f"{name}={value}"]
    output = subprocess.run([*args, query], text=True, capture_output=True, check=True, timeout=30)
    if "ERROR" in output.stderr:
        raise AssertionError(output.stderr)
    return [json.loads(line) for line in output.stdout.splitlines() if line.strip()]


def row(host="a", image=r"C:\Users\Alice\tool.exe", **changes):
    return {"Category": "Logon", "Image Path": image, "Launch String": image,
            "Signer": "Vendor", "Enabled": "enabled", "Fqdn": host, **changes}


class RegexReviewTest(unittest.TestCase):
    def test_normalized_groups_bounded_samples_counts_and_all_fields(self):
        rows = [row(f"host{i}") for i in range(25)] + [row("host0"), row("")]
        rows += [row("other", image=r"C:\Users\Bob\tool.exe")]
        rows += [row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")]
        rows += [row(image=r"C:\known.exe")]  # signer mismatch stays
        rows += [row(Enabled="disabled"), row(image="File not found: missing.exe")]
        stream = execute(rows)
        out = io.StringIO()
        counts = review.consume(iter(stream), csv.DictWriter(out, fieldnames=review.CSV_FIELDS),
                                rule_count=1, max_hostnames=20)
        self.assertEqual(counts, dict(SourceRows=32, EligibleRows=30, MatchedRows=1,
                                     ResidualRows=29, GroupCount=2, ExcludedRows=2))
        stack = next(item for item in stream[1:-1] if item["TotalRows"] == 28)
        self.assertEqual(stack["ImagePath"], r"c:\users\user\tool.exe")
        self.assertEqual(stack["TotalRows"], 28)
        self.assertEqual(len(stack["ExampleHosts"]), 20)
        self.assertNotIn("Seen", parent.build_query(configuration(), mode="regex-review",
            source=review_source.hunt_source("H.test", "IG.Windows.Sysinternals.Autoruns"))[0])

    def test_empty_zero_cap_and_all_matched(self):
        for rows in ([], [row()], [row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")]):
            stream = execute(rows, 0)
            for item in stream[1:-1]:
                self.assertEqual(item["ExampleHosts"], [])
            review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                           rule_count=1, max_hostnames=0)

    def test_unsorted_stacks_preserve_counts_and_csv_order(self):
        stream = execute([row(image=r"C:\small.exe"), row(), row()])
        stacks = sorted(stream[1:-1], key=lambda item: item["TotalRows"])
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=review.CSV_FIELDS)
        writer.writeheader()
        counts = review.consume(iter([stream[0], *stacks, stream[-1]]), writer,
                                rule_count=1, max_hostnames=20)
        self.assertEqual(counts["ResidualRows"], 3)
        self.assertEqual(counts["GroupCount"], 2)
        self.assertEqual([int(r["TotalRows"]) for r in csv.DictReader(
            io.StringIO(output.getvalue()))], [1, 2])
        query, _, _ = review.build_query(configuration(), source=review_source.hunt_source(
            "H.test", "IG.Windows.Sysinternals.Autoruns"), cache_max_entries=review.CACHE_MAX_ENTRIES)
        self.assertNotIn("ORDER BY", query.upper())

    def test_incomplete_or_forged_stream_rejected(self):
        stream = execute([row()])
        for broken in (stream[:-1], [*stream, stream[-1]],
                       [stream[0], {**stream[1], "ExampleHosts": ["a", "a"]}, stream[-1]],
                       [stream[0], stream[1], {**stream[-1], "ResidualRows": 999}]):
            with self.assertRaises(RuntimeError):
                review.consume(iter(broken), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                               rule_count=1, max_hostnames=20)

    def test_loader_roundtrip_schema_and_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"db.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE metadata(key TEXT,value TEXT); CREATE TABLE GoldenRules(RuleId INTEGER,Category TEXT,ImagePath TEXT,LaunchString TEXT,Signer TEXT);")
                db.executemany("INSERT INTO metadata VALUES (?,?)",
                               [("schema_version", review.SCHEMA), ("rule_count", "1")])
                db.execute("INSERT INTO GoldenRules VALUES (1,?,?,?,?)",
                           tuple(configuration()["rules"][0].values()))
            self.assertEqual(review.load_database(path)["rules"], configuration()["rules"])
            with sqlite3.connect(path) as db:
                db.execute("UPDATE metadata SET value='2' WHERE key='rule_count'")
            with self.assertRaises(RuntimeError):
                review.load_database(path)

    def test_loader_without_rule_id_ignores_descriptive_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"db.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE metadata(key TEXT,value TEXT); CREATE TABLE GoldenRules(Category TEXT,ImagePath TEXT,LaunchString TEXT,Signer TEXT,Notes TEXT,LastModified TEXT);")
                db.executemany("INSERT INTO metadata VALUES (?,?)",
                               [("schema_version", review.SCHEMA), ("rule_count", "1")])
                db.execute("INSERT INTO GoldenRules VALUES (?,?,?,?,?,?)",
                           (*configuration()["rules"][0].values(), "Descriptive only", "2026-09-12"))
            before = path.read_bytes()
            self.assertEqual(review.load_database(path)["rules"], configuration()["rules"])
            self.assertEqual(path.read_bytes(), before)

    def test_publication_only_after_complete_stream(self):
        stream = execute([row()], original=True)
        with tempfile.TemporaryDirectory() as temp, patch.object(
                review, "load_database", return_value=configuration()):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([stream[:-1]])
            with self.assertRaises(RuntimeError):
                parent.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), mode="regex-review", output_dir=target)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])
            api.query_batches.return_value = iter([stream])
            result = parent.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                database=Path("unused"), mode="regex-review", output_dir=target)
            with (target/"review.csv").open() as f:
                saved = list(csv.DictReader(f))
            self.assertEqual(json.loads(saved[0]["ExampleHosts"]), ["a"])
            self.assertEqual(result["stack_rows_saved"], 1)
            self.assertEqual(json.loads((target/"stats.json").read_text()), result)
            with self.assertRaises(RuntimeError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target)



    def test_category_launch_and_case_semantics(self):
        known = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        cfg = configuration()
        cfg["rules"][0]["LaunchString"] = r"^c:\\known\.exe$"
        source = review_source.ReviewSource("test", "test", "artifact",
            "foreach(row=parse_json_array(data=gunzip(string=base64decode(string=TestRowsGzip))))", {})
        rows = [known, {**known, "Category": "Services"}, {**known, "Launch String": "bad"},
                row("host.example.org"), row("host.example.org")]
        query, env, _ = review.build_query(cfg, source=source, cache_max_entries=review.CACHE_MAX_ENTRIES)
        args = [str(BINARY), "query", "--format", "jsonl"]
        for k,v in {**env, "TestRowsGzip": parent._encode(rows)}.items():
            args += ["--env", k+"="+v]
        result = subprocess.run([*args, query], capture_output=True, text=True, check=True)
        stream = [json.loads(x) for x in result.stdout.splitlines()]
        counts = review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                                rule_count=1, max_hostnames=20)
        self.assertEqual(counts["MatchedRows"], 1)
        stack = next(item for item in stream[1:-1] if item["TotalRows"] == 2)
        self.assertEqual(stack["ExampleHosts"], ["host.example.org"])

    def test_transport_error_after_summary_does_not_publish(self):
        stream = execute([row()], original=True)
        def batches(*args, **kwargs):
            yield stream
            raise TimeoutError("transport ended abnormally")
        with tempfile.TemporaryDirectory() as temp, patch.object(
                review, "load_database", return_value=configuration()):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.side_effect = batches
            with self.assertRaises(TimeoutError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])


class RestoredUncachedReviewTest(unittest.TestCase):
    def consume(self, stream):
        return review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                              rule_count=1, max_hostnames=20, expect_cache_metrics=False)

    def test_default_uses_original_sorted_uncached_query_and_accounts_all_rows(self):
        source = review_source.hunt_source("H.test", "IG.Windows.Sysinternals.Autoruns")
        query, _, _ = review.build_query(configuration(), source=source)
        self.assertNotIn("cache(", query)
        self.assertNotIn("CacheCategoryMetrics", query)
        self.assertIn("ORDER BY TotalRows DESC", query)
        known = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        stream = execute([row(), known, row(), row(image=r"C:\other.exe"), row(Enabled="disabled")], original=True)
        self.assertEqual(self.consume(stream), dict(SourceRows=5, EligibleRows=4, MatchedRows=1,
                         ResidualRows=3, GroupCount=2, ExcludedRows=1))
        self.assertEqual([r["TotalRows"] for r in stream[1:-1]], [2, 1])

    def test_original_schema_order_and_accounting_fail_closed(self):
        stream = execute([row(), row(), row(image=r"C:\other.exe")], original=True)
        for broken in (stream[:-1], [*stream, stream[-1]],
                       [stream[0], *reversed(stream[1:-1]), stream[-1]],
                       [*stream[:-1], {**stream[-1], "ResidualRows": 999}],
                       [*stream[:-1], {**stream[-1], "CacheBypasses": 0}]):
            with self.assertRaises(RuntimeError):
                self.consume(broken)
        with self.assertRaises(RuntimeError):
            review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                           rule_count=1, max_hostnames=20)

    def test_default_publication_marks_cache_metrics_unavailable(self):
        stream = execute([row()], original=True)
        with tempfile.TemporaryDirectory() as temp, patch.object(review, "load_database", return_value=configuration()):
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([stream])
            result = review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                database=Path("unused"), output_dir=Path(temp)/"review")
            self.assertEqual(result["decision_cache"], dict(mode="uncached-restored", enabled=False, metrics_available=False))
            self.assertTrue(result["stream_complete"])
            self.assertNotIn("cache(", api.query_batches.call_args.args[0])


class RegexReviewCacheTest(unittest.TestCase):
    def compare(self, rows, **options):
        cached = execute(rows, **options)
        plain = execute(rows, config=options.get("config"), cache_max_entries=0)
        def result(stream):
            return sorted(stream[1:-1], key=lambda r: tuple(r[f] for f in review.FIELDS))
        self.assertEqual(result(cached), result(plain))
        for field in ("SourceRows", "EligibleRows", "MatchedRows", "ResidualRows", "GroupCount"):
            self.assertEqual(cached[-1][field], plain[-1][field])
        return cached

    def test_full_identity_true_false_and_every_field(self):
        known = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        variants = [known, {**known, "Category": "Services"},
                    {**known, "Image Path": r"C:\other.exe"},
                    {**known, "Launch String": ""}, {**known, "Signer": "Other"}]
        rows = [dict(item, Fqdn=f"host{i}") for i in range(5) for item in variants]
        cfg = configuration()
        cfg["rules"][0]["LaunchString"] = r"^c:\\known\.exe$"
        stream = self.compare(rows, config=cfg)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 5)
        self.assertEqual(stream[-1]["MatchedRows"], 5)
        self.assertEqual(stream[-1]["CacheBypasses"], 0)
        self.assertTrue(all(len(r["ExampleHosts"]) == 5 for r in stream[1:-1]))

    def test_lru_eviction_is_safe(self):
        a = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        b, c = row(image=r"C:\b.exe"), row(image=r"C:\c.exe")
        stream = self.compare([a, b, a, c, b], cache_max_entries=2)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 4)

    def test_long_keys_bypass_and_unicode_is_not_merged(self):
        rows = [row(image="C:\\" + "é"*3000 + ".exe")]*2
        rows += [row(image="C:\\" + p + ".exe") for p in ("é", "e\u0301", "Straße", "STRASSE", "a|b", 'a"b')]*2
        stream = self.compare(rows)
        self.assertEqual(stream[-1]["CacheBypasses"], 2)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 8)
        self.assertEqual(stream[-1]["GroupCount"], 7)

    def test_normalization_shares_decision_but_preserves_hosts(self):
        stream = self.compare([row("a", image=r"C:\Users\Alice\tool.exe"),
                               row("b", image=r"C:\Users\Bob\tool.exe")])
        self.assertEqual(stream[-1]["MatchingEvaluations"], 1)
        self.assertEqual(stream[1]["TotalRows"], 2)
        self.assertEqual(set(stream[1]["ExampleHosts"]), {"a", "b"})

    def test_changed_rules_and_next_query_do_not_reuse_decisions(self):
        rows = [row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")]*2
        self.assertEqual(execute(rows)[-1]["MatchedRows"], 2)
        cfg = configuration()
        cfg["rules"][0]["Signer"] = "^Different$"
        stream = execute(rows, config=cfg)
        self.assertEqual(stream[-1]["MatchedRows"], 0)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 1)

    def test_cache_diagnostics_and_bounds_validate(self):
        stream = execute([row(), row()])
        stats = {}
        review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                       rule_count=1, max_hostnames=20, cache_stats=stats)
        self.assertEqual({key: stats[key] for key in ("matching_evaluations", "bypasses", "hits", "misses",
                                                   "dedicated_categories", "overflow_cache_used")},
                         dict(matching_evaluations=1, bypasses=0, hits=1, misses=1,
                              dedicated_categories=1, overflow_cache_used=False))
        for changes in ({"MatchingEvaluations": 3}, {"CacheBypasses": 2},
                        {"MatchingEvaluations": True}, {"MatchingEvaluations": 0},
                        {"CacheErrors": 1}, {"CacheErrors": False},
                        {"CacheCategories": 20}, {"CacheOverflowUsed": "false"}):
            with self.assertRaises(RuntimeError):
                review.consume(iter([*stream[:-1], {**stream[-1], **changes}]),
                               csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                               rule_count=1, max_hostnames=20)
        for options in ({"cache_max_entries": -1}, {"cache_max_entries": True},
                        {"cache_max_entries": 501}, {"cache_max_key_bytes": 0},
                        {"cache_max_key_bytes": 4097}):
            with self.assertRaises(RuntimeError):
                review.build_query(configuration(), source=review_source.hunt_source("H.test", "artifact"),
                                   **options)

    def test_invalid_cache_value_rejects_publication(self):
        original = review.build_query
        def broken(*args, **kwargs):
            query, env, counts = original(*args, **kwargs)
            query = query.replace('func=ReviewFullMatch()', 'func=NULL')
            return query, env, counts
        with patch.object(review, "build_query", side_effect=broken):
            stream = execute([row()])
        self.assertGreater(stream[-1]["CacheErrors"], 0)
        with self.assertRaises(RuntimeError):
            review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                           rule_count=1, max_hostnames=20)

    def test_busy_category_does_not_evict_other_category(self):
        a = row(image=r"C:\quiet.exe", Category="Quiet")
        busy = [row(image=f"C:\\busy{i}.exe", Category="Busy") for i in range(10)]
        stream = self.compare([a, *busy, a], cache_max_entries=2)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 11)
        self.assertEqual(stream[-1]["CacheCategories"], 2)
        self.assertFalse(stream[-1]["CacheOverflowUsed"])

    def test_unbounded_categories_use_bounded_overflow(self):
        rows = [row(Category=f"Category{i}") for i in range(25)]
        stream = self.compare([*rows, rows[0], rows[-1]], cache_max_entries=2)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 25)
        self.assertEqual(stream[-1]["CacheCategories"], 19)
        self.assertTrue(stream[-1]["CacheOverflowUsed"])

    def test_empty_and_quoted_category_keys(self):
        rows = [row(Category=value) for value in ("", 'a"b', "a.b", "a|b")]*2
        stream = self.compare(rows)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 4)
        self.assertEqual(stream[-1]["CacheCategories"], 4)


class RegexReviewCategoryMetricsTest(unittest.TestCase):
    def stats(self, stream):
        stats = {}
        review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                       rule_count=1, max_hostnames=20, cache_stats=stats)
        return stats

    def test_matched_and_residual_hits_are_separate_by_category(self):
        known = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        stream = execute([known, known, row(), row(), row(Category="Services"), row(Enabled="disabled")])
        stats = self.stats(stream)
        self.assertEqual(stats["matched"], dict(rows=2, hits=1, misses=1, bypasses=0, matching_evaluations=1))
        self.assertEqual(stats["residual"], dict(rows=3, hits=1, misses=2, bypasses=0, matching_evaluations=2))
        by_category = {item["category"]: item for item in stats["by_category"]}
        self.assertEqual(by_category["Logon"]["matched"], stats["matched"])
        self.assertEqual(by_category["Logon"]["residual"]["hits"], 1)
        self.assertEqual(by_category["Services"]["residual"]["misses"], 1)
        self.assertEqual(stats["hits"], 2)

    def test_bypasses_split_by_result(self):
        long = row(image="c:\\" + "x"*5000, Signer="(Verified) Microsoft Windows")
        for matched in (True, False):
            cfg = configuration()
            if matched:
                cfg["rules"][0]["ImagePath"] = "."
            stats = self.stats(execute([long, long], config=cfg))
            outcome = stats["matched" if matched else "residual"]
            self.assertEqual(outcome, dict(rows=2, hits=0, misses=0, bypasses=2, matching_evaluations=2))

    def test_metrics_overflow_is_bounded_and_reconciles(self):
        rows = [row(Category=f"cat{i}") for i in range(130)]
        rows += [row(Category="é"*200)]*2
        stats = self.stats(execute(rows))
        self.assertEqual(len(stats["by_category"]), 128)
        overflow = stats["category_overflow"]
        self.assertIsNone(overflow["category"])
        self.assertEqual(overflow["residual"], dict(rows=4, hits=1, misses=3, bypasses=0, matching_evaluations=3))
        self.assertEqual(stats["residual"]["rows"], 132)
        self.assertEqual(stats["dedicated_categories"], 19)

    def test_missing_duplicate_or_inconsistent_metrics_fail(self):
        import copy
        good = execute([row(), row()])
        changes = [
            lambda summary: summary.pop("CacheCategoryMetrics"),
            lambda summary: summary["CacheCategoryMetrics"].append(copy.deepcopy(summary["CacheCategoryMetrics"][0])),
            lambda summary: summary["CacheCategoryMetrics"][0].update(ResidualRows=3),
            lambda summary: summary["CacheCategoryMetrics"][0].update(ResidualEvaluations=True),
            lambda summary: summary["CacheCategoryMetrics"][0].update(ResidualBypasses=2),
            lambda summary: summary["CacheCategoryMetricsOverflow"].update(Category="forged"),
        ]
        for change in changes:
            broken = copy.deepcopy(good)
            change(broken[-1])
            with self.assertRaises(RuntimeError):
                self.stats(broken)
        # Valid global totals must not allow a malformed category summary to publish.
        with tempfile.TemporaryDirectory() as temp, patch.object(review, "load_database", return_value=configuration()):
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([broken])
            target = Path(temp)/"review"
            with self.assertRaises(RuntimeError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target)
            self.assertFalse(target.exists())
