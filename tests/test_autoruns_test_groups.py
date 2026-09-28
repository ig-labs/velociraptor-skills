"""Finite-language, category-evidence and presentation grouping regressions."""

import hashlib
import json
import unittest

import re2

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import test_groups as grouping


def identity(image, launch="", signer="Vendor"):
    payload = autoruns.trusted_key_serialized(image_path=image, launch_string=launch, signer=signer)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest(), payload


def matches(pattern, value):
    options = re2.Options()
    options.log_errors = False
    return re2.compile(pattern, options=options).search(value) is not None


class AutorunsTestGroupsTest(unittest.TestCase):
    def test_system32_svchost_dlls_share_group_without_category_inference(self):
        rows = [identity(r"C:\Windows\System32\alpha.dll", r"C:\Windows\System32\svchost.exe -k a"),
                identity(r"C:\Windows\System32\beta.dll", r'"C:\Windows\System32\svchost.exe" -k b')]
        groups = grouping.grouped_patterns(rows)
        self.assertEqual(len(groups), 1)
        self.assertIn("svchost executable launch", groups[0]["Group"])
        self.assertNotIn("services", groups[0]["Group"].lower())
        self.assertEqual(groups[0]["CategoryRegex"], ".*")
        self.assertEqual(groups[0]["SourceHashes"], sorted(key for key, _ in rows))
        for _, payload in rows:
            self.assertTrue(matches(groups[0]["IdentityRegex"], payload))

    def test_grouping_separates_parent_extension_and_launch_family(self):
        rows = [identity(r"C:\Windows\System32\alpha.dll", r"C:\Windows\System32\svchost.exe -k a"),
                identity(r"C:\Windows\System32\beta.dll"),
                identity(r"C:\Windows\System32\gamma.dll", r"C:\Windows\System32\gamma.dll"),
                identity(r"C:\Windows\System32\delta.dll", r"C:\Vendor\helper.exe -k a"),
                identity(r"C:\Windows\System32\echo.dll", "unparsed launch"),
                identity(r"C:\Windows\SysWOW64\alpha.dll", r"C:\Windows\System32\svchost.exe -k a"),
                identity(r"C:\Windows\System32\alpha.exe", r"C:\Windows\System32\svchost.exe -k a"),
                identity(r"C:\Windows\System32\zeta.dll", r"C:\Vendor\svchost.exe -k a")]
        groups = grouping.grouped_patterns(rows)
        self.assertEqual(len(groups), len(rows))
        self.assertEqual(sorted(key for group in groups for key in group["SourceHashes"]),
                         sorted(key for key, _ in rows))

    def test_observed_categories_preserve_all_associations_and_ascii_case_only(self):
        rows = [identity(r"C:\Windows\System32\alpha.dll"), identity(r"C:\Windows\System32\beta.dll")]
        categories = {rows[0][0]: ["Services", "Print [Monitor]", "services", "Σ"],
                      rows[1][0]: ["Services"]}
        groups = grouping.grouped_patterns(rows, categories)
        self.assertEqual(len(groups), 2)
        pattern = next(group["CategoryRegex"] for group in groups if rows[0][0] in group["SourceHashes"])
        self.assertNotIn("[sS]", pattern)
        for category in ("Services", "SERVICES", "print [monitor]", "Σ"):
            self.assertTrue(matches(pattern, autoruns.ascii_lower(category)), category)
        for category in ("", "Other", "Services extra", "xServices", "Print M", "σ"):
            self.assertFalse(matches(pattern, autoruns.ascii_lower(category)), category)

    def test_unknown_category_matches_empty_and_arbitrary_values(self):
        rows = [identity(r"C:\Vendor\alpha.dll"), identity(r"C:\Vendor\beta.dll")]
        groups = grouping.grouped_patterns(rows, {rows[1][0]: []})
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["CategoryRegex"], ".*")
        for value in ("", "Services", "\n", "Σ", "arbitrary"):
            self.assertTrue(matches(groups[0]["CategoryRegex"], value))

    def test_exact_tuples_do_not_mix_or_unicode_fold(self):
        rows = [identity(r"C:\Vendor\Straße.dll", "launch one", "Σ"),
                identity(r"C:\Vendor\STRASSE.dll", "launch two", "σ")]
        groups = grouping.grouped_patterns(rows)
        self.assertEqual(len(groups), 1)
        pattern = groups[0]["IdentityRegex"]
        for _, payload in rows:
            self.assertTrue(matches(pattern, payload))
        for row in [identity(r"C:\Vendor\Straße.dll", "launch two", "Σ"),
                    identity(r"C:\Vendor\Straße.dll", "launch one", "σ"),
                    identity(r"C:\Vendor\STRAẞE.dll", "launch one", "Σ")]:
            self.assertFalse(matches(pattern, row[1]))

    def test_field_regex_rules_remain_correlated_and_anchored(self):
        rows = [identity(r"C:\Vendor\Straße.dll", "launch one", "Σ"),
                identity(r"C:\Vendor\STRASSE.dll", "launch two", "σ")]
        groups = grouping.grouped_patterns(rows, {rows[0][0]: ["Services"]})
        def accepts(payload, category):
            item = json.loads(payload)
            return any(matches(rule["CategoryRegex"], autoruns.ascii_lower(category))
                       and all(matches(rule[field + "Regex"], item[field])
                               for field in ("ImagePath", "LaunchString", "Signer"))
                       for group in groups for rule in group["Rules"])
        for _, payload in rows:
            self.assertTrue(accepts(payload, "SERVICES"))
        self.assertFalse(accepts(rows[0][1], ""))
        self.assertTrue(accepts(rows[1][1], ""))
        for row in [identity(r"C:\Vendor\Straße.dll", "launch two", "Σ"),
                    identity(r"C:\Vendor\Straße.dll", "launch one", "σ"),
                    identity(r"C:\Vendor\STRAẞE.dll", "launch one", "Σ"),
                    identity(r"C:\Vendor\Straße.dll", "launch one\n", "Σ")]:
            self.assertFalse(accepts(row[1], "Services"))
        self.assertEqual(sorted(rule["HashKey"] for group in groups for rule in group["Rules"]),
                         sorted(key for key, _ in rows))
        self.assertTrue(all(set(rule) == {"HashKey", "CategoryRegex", "ImagePathRegex",
                                         "LaunchStringRegex", "SignerRegex"}
                            for group in groups for rule in group["Rules"]))

    def test_field_literals_preserve_regex_punctuation_and_controls(self):
        row = identity(r"C:\Vendor\a+b[1].dll", "launch | (one)?\n\x00\r\t", "Σ.*$\\")
        group = grouping.grouped_patterns([row])[0]
        rule = group["Rules"][0]
        item = json.loads(row[1])
        for field in ("ImagePath", "LaunchString", "Signer"):
            self.assertTrue(matches(rule[field + "Regex"], item[field]))
            self.assertFalse(matches(rule[field + "Regex"], item[field] + "extra"))
        self.assertTrue(matches(group["IdentityRegex"], row[1]))

    def test_deterministic_order_and_pattern_caps_preserve_one_membership(self):
        rows = [identity(fr"C:\Vendor\{index:04d}.dll") for index in range(600)]
        categories = {key: ["Services", "Known"] for key, _ in rows}
        groups = grouping.grouped_patterns(rows, categories, max_pattern_bytes=1024)
        reverse_categories = {key: list(reversed(value)) for key, value in reversed(list(categories.items()))}
        self.assertEqual(groups, grouping.grouped_patterns(list(reversed(rows)), reverse_categories,
                                                          max_pattern_bytes=1024))
        self.assertGreater(len(groups), 1)
        for group in groups:
            self.assertLessEqual(len(group["IdentityRegex"].encode("utf-8")), 1024)
            self.assertLessEqual(len(group["SourceHashes"]), 256)
        self.assertEqual(sorted(key for group in groups for key in group["SourceHashes"]),
                         sorted(key for key, _ in rows))
        for key, payload in rows:
            matching = [group for group in groups if matches(group["IdentityRegex"], payload)]
            self.assertEqual(len(matching), 1)
            self.assertIn(key, matching[0]["SourceHashes"])

    def test_review_has_one_identity_per_line_and_group_pattern_provenance(self):
        rows = [identity(r"C:\Vendor\one.dll", "line\nsecond", "Vendor`name"),
                identity(r"C:\Vendor\two.dll", "literal\\n", "Vendor")]
        groups = grouping.grouped_patterns(rows)
        before = json.dumps(groups)
        review = grouping.render_grouped_review(rows, groups,
                                               {rows[0][0]: "review | only\nsecond ` line"})
        self.assertEqual(json.dumps(groups), before)
        self.assertIn("## Group 001", review)
        self.assertIn("### Pattern 001 (global position 001)", review)
        self.assertIn("| HashKey | Category | ImagePath | LaunchString | Signer | Notes |", review)
        lines = [line for line in review.splitlines() if any(key in line for key, _ in rows)]
        self.assertEqual(len(lines), len(rows))
        for key, _ in rows:
            self.assertEqual(sum(key in line for line in lines), 1)
        self.assertIn(r"review \| only\nsecond ` line", review)
        self.assertNotIn(groups[0]["IdentityRegex"], review)

    def test_invalid_associations_and_incomplete_review_fail_closed(self):
        rows = [identity(r"C:\Vendor\one.dll")]
        for categories in ({"unknown": ["Services"]}, {rows[0][0]: [""]},
                           {rows[0][0]: ["Services", ""]}, {rows[0][0]: "Services"},
                           {rows[0][0]: [" Services"]}, {rows[0][0]: ["Services "]}):
            with self.assertRaises(RuntimeError):
                grouping.grouped_patterns(rows, categories)
        with self.assertRaisesRegex(RuntimeError, "Duplicate"):
            grouping.grouped_patterns(rows * 2)
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            grouping.grouped_patterns([("0" * 40, rows[0][1])])
        with self.assertRaisesRegex(RuntimeError, "budget"):
            grouping.grouped_patterns([], max_pattern_bytes=1)
        with self.assertRaisesRegex(RuntimeError, "omitted"):
            grouping.render_grouped_review(rows, [])
        groups = grouping.grouped_patterns(rows)
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            grouping.render_grouped_review(rows, groups * 2)

    def test_review_includes_approved_paired_rules_with_wildcards(self):
        rule = {"ImagePathRegex": r"(?-i)\A(?:c:\\vendor\\(?:one|two)\.dll)\z",
                "LaunchStringRegex": r"(?-i)\A(?:)\z",
                "Description": "Original | note\nwith `markup`"}
        review = grouping.render_grouped_review([], [], paired_rules=[rule])
        self.assertIn("## Existing paired regex rules", review)
        self.assertIn("approved paired rules match directly", review)
        self.assertNotIn("veto", review)
        self.assertIn("original review-only Description", review)
        rows = [line for line in review.splitlines() if line.startswith("| ` 001 ` |")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count("` .* `"), 2)
        self.assertIn(r"Original \| note\nwith `markup`", rows[0])
        self.assertIn(r"(?:one\|two)", rows[0])
        self.assertEqual(rule["Description"], "Original | note\nwith `markup`")


if __name__ == "__main__":
    unittest.main()
