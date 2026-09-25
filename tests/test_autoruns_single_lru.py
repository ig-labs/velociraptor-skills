"""Opt-in shared LRU correctness, diagnostics, routing and publication."""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vraptor.autoruns import review
from vraptor.autoruns import testing as parent
from vraptor.analyze import source as review_source
from tests.test_autoruns_regex_review import configuration, execute, row


class SingleLRUTest(unittest.TestCase):
    def consume(self, stream):
        stats = {}
        counts = review.consume(iter(stream), csv.DictWriter(io.StringIO(), fieldnames=review.CSV_FIELDS),
                                rule_count=1, max_hostnames=20, cache_stats=stats, single_lru=True)
        return counts, stats

    def test_full_identity_bypass_hosts_and_accounting_match_uncached(self):
        known = row(image=r"C:\known.exe", Signer="(Verified) Microsoft Windows")
        variants = [known, {**known, "Category": "Services"},
                    {**known, "Image Path": r"C:\other.exe"},
                    {**known, "Launch String": ""}, {**known, "Signer": "Other"},
                    row(image="C:\\" + "é"*3000), row(image="C:\\é.exe"),
                    row(image="C:\\e\u0301.exe")]
        rows = [dict(item, Fqdn=f"host{i}") for i in range(25) for item in variants]
        rows += [row(Enabled="disabled")]
        cfg = configuration()
        cfg["rules"][0]["LaunchString"] = r"^c:\\known\.exe$"
        cached = execute(rows, config=cfg, single_lru=True)
        plain = execute(rows, config=cfg, cache_max_entries=0)
        normalize = lambda stream: sorted(stream[1:-1], key=lambda r: tuple(r[f] for f in review.FIELDS))
        self.assertEqual(normalize(cached), normalize(plain))
        counts, stats = self.consume(cached)
        self.assertEqual(counts, dict(SourceRows=201, EligibleRows=200, MatchedRows=25,
                                     ResidualRows=175, GroupCount=7, ExcludedRows=1))
        self.assertEqual(stats["bypasses"], 25)
        self.assertEqual(stats["matching_evaluations"], 32)
        self.assertEqual(stats["matched"]["hits"], 24)
        self.assertEqual(stats["residual"]["rows"], 175)
        self.assertEqual(stats["dedicated_categories"], 0)
        self.assertFalse(stats["overflow_cache_used"])

    def test_single_lru_default_capacity_is_1000_and_bounded(self):
        rows = [row(image=f"C:\\item{i}.exe") for i in range(750)]
        stream = execute(rows*2, single_lru=True)
        self.assertEqual(stream[-1]["MatchingEvaluations"], 750)
        self.assertEqual(stream[-1]["ResidualRows"], 1500)
        source = review_source.hunt_source("H.test", "artifact")
        query, _, _ = review.build_query(configuration(), source=source, single_lru=True)
        self.assertIn("max_size=1000", query)
        with self.assertRaises(RuntimeError):
            review.build_query(configuration(), source=source, single_lru=True, cache_max_entries=1001)

    def test_cross_category_eviction_keeps_all_occurrences(self):
        a = row(image=r"C:\quiet.exe", Category="Quiet")
        rows = [a, *[row(image=f"C:\\busy{i}.exe", Category="Busy") for i in range(10)], a]
        single = execute(rows, single_lru=True, cache_max_entries=2)
        category = execute(rows, cache_max_entries=2)
        self.assertEqual(single[-1]["MatchingEvaluations"], 12)
        self.assertEqual(category[-1]["MatchingEvaluations"], 11)
        counts, stats = self.consume(single)
        self.assertEqual(counts["ResidualRows"], 12)
        self.assertEqual(counts["GroupCount"], 11)
        self.assertEqual(stats["hits"], 0)

    def test_metrics_overflow_remains_independent_of_cache_routing(self):
        rows = [row(Category=f"Category{i}") for i in range(130)] + [row(Category="x"*300)]
        stream = execute(rows*2, single_lru=True)
        counts, stats = self.consume(stream)
        self.assertEqual(counts["ResidualRows"], 262)
        self.assertEqual(stats["matching_evaluations"], 131)
        self.assertEqual(len(stats["by_category"]), 128)
        self.assertEqual(stats["category_overflow"]["residual"]["rows"], 6)
        self.assertEqual(stats["dedicated_categories"], 0)
        self.assertFalse(stats["overflow_cache_used"])

    def test_publication_requires_summary_and_normal_transport(self):
        stream = execute([row(), row()], single_lru=True)
        with tempfile.TemporaryDirectory() as temp, patch.object(review, "load_database", return_value=configuration()):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([stream[:-1]])
            with self.assertRaises(RuntimeError):
                parent.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), mode="regex-review", output_dir=target, single_lru=True)
            self.assertFalse(target.exists())
            def broken(*args, **kwargs):
                yield stream
                raise ConnectionError("transport reset after summary")
            api.query_batches.side_effect = broken
            with self.assertRaises(ConnectionError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target, single_lru=True)
            self.assertFalse(target.exists())
            api.query_batches.side_effect = None
            api.query_batches.return_value = iter([stream])
            result = parent.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                database=Path("unused"), mode="regex-review", output_dir=target, single_lru=True)
            self.assertEqual(result["decision_cache"]["mode"], "single-lru")
            self.assertEqual(result["decision_cache"]["max_total_entries"], 1000)
            self.assertEqual(result["decision_cache"]["max_caches"], 1)
            self.assertIsNone(result["decision_cache"]["max_entries_per_category"])
            self.assertEqual(json.loads((target/"stats.json").read_text()), result)
            self.assertIn('cache(name="autoruns-regex-review-single-lru"', api.query_batches.call_args.args[0])

    def test_category_cache_allocation_is_rejected_in_single_mode(self):
        with self.assertRaisesRegex(RuntimeError, "unexpectedly allocated"):
            self.consume(execute([row()]))

