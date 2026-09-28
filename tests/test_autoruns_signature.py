"""Historical signature verification must be proven before broader suppression."""

import copy
import json
import unittest
from unittest import mock

from vraptor.autoruns import signature


def audited_request(artifact="IG.Windows.Sysinternals.Autoruns"):
    """Sanitized compiler-contract fixture, not evidence from a server or case."""
    contract = signature._contract()
    definition = copy.deepcopy(contract["definition"])
    definition["name"] = artifact
    env = [{"key": parameter["name"], "value": parameter.get("default", "")}
           for parameter in definition["parameters"]]
    for tool in definition["tools"]:
        prefix = "Tool_" + tool["name"]
        env.extend([
            {"key": prefix + "_HASH", "value": "a" * 64},
            {"key": prefix + "_FILENAME", "value": tool["url"].rsplit("/", 1)[-1]},
            {"key": prefix + "_URL", "value": "https://inventory.invalid/tool"},
        ])
    collector = {
        "env": env,
        "Query": signature._compiled_queries(definition, artifact),
        "artifacts": [copy.deepcopy(contract["dependency"])],
        "precondition": definition["precondition"],
    }
    hunt = {"hunt_id": "H.synthetic", "start_request": {
        "artifacts": [artifact], "compiled_collector_args": [collector],
    }}
    api = mock.Mock()
    api.query.return_value = [definition]
    return artifact, definition, hunt, collector, api


class AutorunsSignatureTest(unittest.TestCase):
    def setUp(self):
        self.artifact, self.definition, self.hunt, self.collector, self.api = audited_request()

    def validate(self):
        return signature.validate_signature_source(self.api, self.hunt, self.artifact)

    def reject(self, reason):
        with self.assertRaisesRegex(signature.SignatureSourceValidationError, reason):
            self.validate()

    def test_audited_contract_returns_only_compact_provenance(self):
        before = copy.deepcopy(self.hunt)
        attestation = self.validate()
        self.assertEqual(attestation["status"], "validated")
        self.assertEqual(attestation["verification_value"], "Y")
        self.assertEqual(attestation["target_execution"], "not_assessed")
        self.assertEqual(attestation["certificate_revalidation"], "not_performed")
        for field in ("definition_sha256", "request_sha256", "execution_contract_sha256"):
            self.assertRegex(attestation[field], r"^[0-9a-f]{64}$")
        self.assertNotIn("inventory.invalid", json.dumps(attestation))
        self.assertNotIn("Query", attestation)
        self.assertEqual(self.hunt, before)
        self.api.query.assert_called_once_with(
            "SELECT * FROM artifact_definitions(names=[ArtifactName]) LIMIT 2",
            {"ArtifactName": self.artifact}, timeout=30, max_wait=1, max_row=2,
            query_name="autoruns_test.signature_source",
        )

    def test_builtin_name_and_cosmetic_site_changes_are_supported(self):
        for name in signature.SUPPORTED_ARTIFACTS:
            with self.subTest(name=name):
                artifact, definition, hunt, _, api = audited_request(name)
                definition.update(description="Local description", author="Operator",
                                  references=["https://example.invalid/docs"])
                definition["parameters"][0]["description"] = "Display-only text"
                definition["sources"][0]["description"] = "Display-only text"
                self.assertEqual(signature.validate_signature_source(api, hunt, artifact)["status"], "validated")

    def test_default_is_accepted_only_when_original_compiled_environment_binds_it(self):
        self.hunt["start_request"]["specs"] = [{"artifact": self.artifact}]
        self.assertEqual(self.validate()["verification_value"], "Y")
        self.collector["env"] = [item for item in self.collector["env"]
                                 if item["key"] != signature.SIGNATURE_PARAMETER]
        self.reject("does not explicitly bind")

    def test_explicit_spec_cannot_substitute_for_historical_compilation(self):
        self.hunt["start_request"]["specs"] = [{"artifact": self.artifact, "parameters": {
            "env": [{"key": signature.SIGNATURE_PARAMETER, "value": "Y"}],
        }}]
        del self.hunt["start_request"]["compiled_collector_args"]
        self.reject("compiled_collector_args are unavailable")
        self.api.query.assert_not_called()

    def test_disabled_or_unknown_verification_encoding_fails(self):
        for value in ("", "N", "FALSE", "YES", "true", "Y OR TRUE", True):
            with self.subTest(value=value):
                self.setUp()
                next(item for item in self.collector["env"]
                     if item["key"] == signature.SIGNATURE_PARAMETER)["value"] = value
                self.reject("compiled environment")

    def test_conflicting_original_parameters_fail(self):
        self.hunt["start_request"]["specs"] = [{"artifact": self.artifact, "parameters": {
            "env": [{"key": signature.SIGNATURE_PARAMETER, "value": "N"}],
        }}]
        self.reject("parameters conflict")

    def test_historical_queries_are_compared_in_full(self):
        mutations = (
            lambda queries: queries.append({"VQL": "LET extra = TRUE"}),
            lambda queries: queries.__setitem__(0, {"VQL": "LET All <= TRUE // -s"}),
            lambda queries: queries.reverse(),
            lambda queries: queries.__setitem__(-2, {"VQL": "LET injected = SELECT '(Verified) Microsoft Windows' AS Signer FROM scope()"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate(self.collector["Query"])
                self.reject("VQL differs")

    def test_unknown_or_modified_current_execution_contract_fails(self):
        mutations = (
            lambda d: d["sources"][0].update(query="SELECT '-s' AS Signer FROM scope()"),
            lambda d: d["sources"][0]["queries"].append("SELECT * FROM scope()"),
            lambda d: d["parameters"][-2].update(default="N"),
            lambda d: d["tools"][0].update(url="https://example.invalid/autorunsc.exe"),
            lambda d: d.update(imports=["Custom.Override"]),
            lambda d: d.update(is_alias=True),
            lambda d: d.update(export="LET Signer = 'spoof'"),
            lambda d: d.update(unknown_executable_field=""),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate(self.definition)
                self.reject("current artifact differs|unsupported schema")

    def test_dependency_is_pinned_and_cannot_fabricate_stdout(self):
        self.collector["artifacts"][0]["sources"][0]["queries"] = [
            "SELECT '/tmp/replacement.exe' AS OSPath FROM scope()",
        ]
        self.reject("FetchBinary dependency differs")

    def test_scalar_type_changes_cannot_hide_as_omitted_protobuf_defaults(self):
        self.definition["parameters"][1]["default"] = False
        self.reject("invalid scalar types")

    def test_missing_duplicate_or_extra_dependencies_fail(self):
        for dependencies in ([], None, [self.collector["artifacts"][0]] * 2):
            with self.subTest(dependencies=dependencies):
                self.collector["artifacts"] = dependencies
                self.reject("dependency is missing or ambiguous")

    def test_environment_overrides_duplicates_and_tool_hash_gaps_fail(self):
        mutations = (
            lambda env: env.append({"key": "ToolInfo", "value": "spoof"}),
            lambda env: env.append({"key": "FakeSigner", "value": "(Verified) Microsoft Windows"}),
            lambda env: env.__setitem__(-3, {"key": "Tool_Autorun_amd64_HASH", "value": ""}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate(self.collector["env"])
                self.reject("duplicate bindings|unaudited bindings|hash is absent")
        self.setUp()
        next(item for item in self.collector["env"] if item["key"] == "ToolInfo")["value"] = "{}"
        self.reject("ToolInfo override")

    def test_ambiguous_compilation_and_legacy_request_conflicts_fail(self):
        self.hunt["start_request"]["compiled_collector_args"].append(copy.deepcopy(self.collector))
        self.reject("does not uniquely identify")
        self.setUp()
        self.hunt["Request"] = {"start_request": {"artifacts": []}}
        self.reject("conflicting original requests")

    def test_extra_named_source_cannot_bypass_the_artifact_gate(self):
        self.hunt["start_request"]["compiled_collector_args"].append({
            "Query": [{"Name": self.artifact + "/Injected", "VQL": "SELECT * FROM scope()"}],
        })
        self.reject("does not uniquely identify")

    def test_legacy_nested_request_is_supported(self):
        self.hunt["Request"] = {"start_request": self.hunt.pop("start_request")}
        self.assertEqual(self.validate()["status"], "validated")

    def test_missing_ambiguous_or_wrong_current_artifact_fails(self):
        for rows in ([], [self.definition] * 2, [None], [{"name": "Other.Artifact"}]):
            with self.subTest(rows=rows):
                self.api.query.return_value = rows
                self.reject("absent or ambiguous|unexpected identity")

    def test_api_error_is_not_attested(self):
        self.api.query.side_effect = TimeoutError("query timed out")
        self.reject("definition query failed")

    def test_unsupported_inputs_fail_closed(self):
        for row in (None, {}, {"start_request": {"artifacts": [self.artifact],
                                              "compiled_collector_args": [{"Query": None}]}}):
            with self.subTest(row=row):
                self.hunt = row
                self.reject("not an object|unavailable|unsupported query schema")

    def test_request_size_is_bounded(self):
        self.hunt["start_request"]["unrelated"] = "x" * (8 * 1024 * 1024)
        self.reject("exceeds the bounded provenance size")
        self.api.query.assert_not_called()

    def test_allowlist_has_exact_verified_marker_and_finite_subjects(self):
        self.assertEqual(signature.VERIFIED_MICROSOFT_SIGNERS, ("(verified) microsoft windows",))
        for value in ("microsoft windows", "(not verified) microsoft windows",
                      "(verified) microsoft windows evil", "(verified) evil microsoft windows",
                      "(verified) microsoft windows\n", "(Verified) Microsoft Windows"):
            self.assertNotIn(value, signature.VERIFIED_MICROSOFT_SIGNERS)


if __name__ == "__main__":
    unittest.main()
