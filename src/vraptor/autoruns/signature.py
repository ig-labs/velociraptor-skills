"""Fail-closed provenance gate for experimental Autoruns signer rules.

Only the pinned built-in Autorunsc execution contract is supported. A cosmetic
site rename is accepted; arbitrary IG artifacts are not. Current definitions
cannot establish historical collection flags: the original compiled collector
must contain the exact audited VQL, injected FetchBinary implementation, and a
bound verification parameter. This attests the collection request, not endpoint
execution, a present-day certificate check, or the safety of a signed program.

The resource records the local binary and primary sources used for the audit.
Unknown compiler layouts require another audit, never a substring fallback.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from typing import Any


VERIFIED_MICROSOFT_SIGNERS = ("(verified) microsoft windows",)
SIGNATURE_PARAMETER = "Verify digital signatures"
SUPPORTED_ARTIFACTS = (
    "Windows.Sysinternals.Autoruns", "IG.Windows.Sysinternals.Autoruns",
)
_RESOURCE = resources.files("vraptor").joinpath(
    "resources/autoruns/builtin-signature-contract.json"
)
_COSMETIC = {
    "description", "author", "reference", "references", "raw", "compiled",
    "built_in", "compiled_in", "metadata",
}
_ARTIFACT_FIELDS = {
    "name", "aliases", "description", "author", "reference", "references",
    "required_permissions", "implied_permissions", "impersonate", "resources",
    "tools", "precondition", "parameters", "type", "sources", "imports",
    "export", "reports", "column_types", "raw", "compiled", "built_in",
    "compiled_in", "is_alias", "is_inherited", "metadata",
}
_PARAMETER_FIELDS = {
    "name", "default", "description", "type", "choices", "friendly_name",
    "validating_regex", "artifact_type", "sources",
}
_SOURCE_FIELDS = {"name", "description", "precondition", "query", "queries", "notebook"}
_TOOL_FIELDS = {
    "name", "url", "github_project", "github_asset_regex", "serve_locally",
    "admin_override", "expected_hash", "version", "materialize", "artifact",
    "filestore_path", "serve_url", "serve_urls", "serve_path", "filename",
    "hash", "invalid_hash", "versions",
}
_RESOURCE_FIELDS = {
    "timeout", "ops_per_second", "cpu_limit", "iops_limit", "max_rows",
    "max_upload_bytes", "max_batch_wait", "max_batch_rows", "max_batch_rows_buffer",
}
_COLLECTOR_FIELDS = {
    "query_id", "total_queries", "expiry", "precondition", "principal",
    "effective_principal", "env", "Query", "max_row", "max_row_buffer_size",
    "max_wait", "ops_per_second", "cpu_limit", "iops_limit", "progress_timeout",
    "artifacts", "timeout", "heartbeat", "tools", "org_id",
}


class SignatureSourceValidationError(RuntimeError):
    """Historical signature-verification provenance could not be established."""


def _fail(reason: str) -> None:
    raise SignatureSourceValidationError(
        "Signer experiment blocked: " + reason + ". "
        "Use the semantics-equivalent test baseline until the exact artifact "
        "and collection-time compiled request have been audited."
    )


def _encoded(value: Any, *, limit: int, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail(label + " is not a valid JSON object")
    if len(encoded) > limit:
        _fail(label + " exceeds the bounded provenance size")
    return encoded


def _fields(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - allowed:
        _fail(label + " has an unsupported schema")
    return value


def _canonical(value: Any) -> Any:
    """Ignore catalog prose and omitted protobuf defaults, preserving VQL bytes."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in _COSMETIC:
                continue
            item = _canonical(item)
            if item not in (None, "", False, [], {}):
                result[key] = item
        return result
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _definition(value: Any) -> dict[str, Any]:
    value = _fields(value, _ARTIFACT_FIELDS, "artifact definition")
    for key in ("name", "type", "precondition", "export", "impersonate"):
        if key in value and not isinstance(value[key], str):
            _fail("artifact definition has invalid scalar types")
    for label, allowed in (
        ("parameters", _PARAMETER_FIELDS), ("sources", _SOURCE_FIELDS),
        ("tools", _TOOL_FIELDS),
    ):
        items = value.get(label, [])
        if not isinstance(items, list) or len(items) > 64:
            _fail("artifact " + label + " has an unsupported schema")
        for item in items:
            _fields(item, allowed, "artifact " + label)
            text_fields = {
                "parameters": ("name", "type", "default"),
                "sources": ("name", "precondition", "query"),
                "tools": ("name", "url", "hash", "expected_hash"),
            }[label]
            if any(key in item and not isinstance(item[key], str) for key in text_fields):
                _fail("artifact " + label + " has invalid scalar types")
            if label == "sources" and "queries" in item and (
                not isinstance(item["queries"], list)
                or not all(isinstance(query, str) for query in item["queries"])
            ):
                _fail("artifact source queries have invalid types")
    if "resources" in value:
        _fields(value["resources"], _RESOURCE_FIELDS, "artifact resources")
    return _canonical(value)


def _contract() -> dict[str, Any]:
    contract = json.loads(_RESOURCE.read_text(encoding="utf-8"))
    if contract.get("schema") != 1:
        _fail("installed signature contract has an unsupported version")
    contract["definition"] = _canonical(contract["definition"])
    contract["dependency"] = _canonical(contract["dependency"])
    return contract


def _compiled_queries(definition: dict[str, Any], artifact: str) -> list[dict[str, str]]:
    """Exact single-source compiler layout; no parsing or '-s' token heuristics.

    This is deliberately limited to the inspected bool/hidden parameters and
    built-in source. The compiler wraps the final SELECT and Windows precondition
    and binds bool parameters before evaluating the source's option table.
    """
    result = []
    for parameter in definition["parameters"]:
        if parameter["type"] == "bool":
            name = parameter["name"]
            escaped = name if name.isalnum() else "`" + name + "`"
            result.append({"VQL": (
                f"LET {escaped} <= get(field='{name}') = TRUE OR "
                f"get(field='{name}') =~ '^(Y|TRUE|YES|OK)$'"
            )})
    prefix = artifact.replace(".", "_") + "_0"
    result.append({"VQL": f"LET precondition_{prefix} = {definition['precondition']}"})
    queries = definition["sources"][0]["queries"]
    result.extend({"VQL": query} for query in queries[:-1])
    final = f"{prefix}_{len(queries) - 1}"
    result.append({"VQL": f"LET {final} = {queries[-1]}"})
    result.append({"Name": artifact, "VQL": (
        f"SELECT * FROM if(then={final}, condition=precondition_{prefix}, "
        "else={SELECT * FROM scope() WHERE log(message='Query skipped due to "
        "precondition') AND FALSE})"
    )})
    return result


def _query_contract(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 64:
        _fail("compiled query list is missing or unsupported")
    result = []
    for query in value:
        query = _fields(query, {"Name", "VQL"}, "compiled query")
        if not isinstance(query.get("VQL"), str) or not isinstance(query.get("Name", ""), str):
            _fail("compiled query has invalid name or VQL")
        result.append({key: val.strip() if key == "VQL" else val
                       for key, val in query.items() if val})
    return result


def _environment(value: Any) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > 128:
        _fail("compiled environment is missing or unsupported")
    result = {}
    for item in value:
        item = _fields(item, {"key", "value", "comment"}, "compiled environment")
        key, val = item.get("key"), item.get("value", "")
        if not isinstance(key, str) or not key or not isinstance(val, str) or key in result:
            _fail("compiled environment contains invalid or duplicate bindings")
        result[key] = val
    return result


def _validate_collector(collector: Any, contract: dict[str, Any], artifact: str) -> None:
    collector = _fields(collector, _COLLECTOR_FIELDS, "compiled collector")
    definition = contract["definition"]
    if _query_contract(collector.get("Query")) != _compiled_queries(definition, artifact):
        _fail("collection-time VQL differs from the audited execution contract")
    if collector.get("precondition", definition["precondition"]) != definition["precondition"]:
        _fail("collection-time precondition differs from the audited contract")
    if collector.get("effective_principal"):
        _fail("collection-time impersonation is outside the audited contract")
    dependencies = collector.get("artifacts")
    if not isinstance(dependencies, list) or len(dependencies) != 1:
        _fail("collection-time FetchBinary dependency is missing or ambiguous")
    if _definition(dependencies[0]) != contract["dependency"]:
        _fail("collection-time FetchBinary dependency differs from the audited contract")
    env = _environment(collector.get("env"))
    parameters = {item["name"] for item in definition["parameters"]}
    if not parameters <= env.keys() or env[SIGNATURE_PARAMETER] != "Y":
        _fail("collection-time compiled environment does not explicitly bind signature verification to Y")
    if env["ToolInfo"]:
        _fail("collection-time ToolInfo override is outside the audited contract")
    for parameter in definition["parameters"]:
        if parameter["type"] == "bool" and env[parameter["name"]] not in ("", "Y"):
            _fail("collection-time bool parameter has an unaudited encoding")
    tool_keys = set()
    for tool in definition["tools"]:
        prefix = "Tool_" + tool["name"]
        tool_keys.update(prefix + suffix for suffix in ("_HASH", "_FILENAME", "_URL", "_URLs"))
        if not re.fullmatch(r"[0-9a-fA-F]{64}", env.get(prefix + "_HASH", "")):
            _fail("collection-time Autorunsc tool hash is absent or invalid")
        if env.get(prefix + "_FILENAME") != tool["url"].rsplit("/", 1)[-1]:
            _fail("collection-time Autorunsc tool filename differs from the audited contract")
        if not env.get(prefix + "_URL"):
            _fail("collection-time Autorunsc tool URL is absent")
    if env.keys() - parameters - tool_keys:
        _fail("collection-time environment contains unaudited bindings")
    if collector.get("tools") and collector["tools"] != [tool["name"] for tool in definition["tools"]]:
        _fail("collection-time tool list differs from the audited contract")


def validate_signature_source(api: Any, hunt_row: dict[str, Any], artifact: str) -> dict[str, Any]:
    """Validate a bounded current definition and original compiled hunt request.

    Makes at most one read-only ``artifact_definitions(names=[ArtifactName])`` query.
    Does not read result rows, launch collection, use local case state, or write
    files. A missing historical compiled request cannot be reconstructed from
    current defaults and raises ``SignatureSourceValidationError``.
    """
    if artifact not in SUPPORTED_ARTIFACTS:
        _fail("artifact name is outside the audited Autoruns contract")
    if not isinstance(hunt_row, dict):
        _fail("hunt metadata is not an object")
    request = hunt_row.get("start_request")
    nested = hunt_row.get("Request")
    legacy = nested.get("start_request") if isinstance(nested, dict) else None
    if request is not None and legacy is not None and request != legacy:
        _fail("hunt metadata contains conflicting original requests")
    request = request if request is not None else legacy
    if not isinstance(request, dict):
        _fail("original hunt start_request is unavailable")
    request_bytes = _encoded(request, limit=8 * 1024 * 1024, label="original request")
    artifacts = request.get("artifacts")
    if not isinstance(artifacts, list) or artifacts.count(artifact) != 1:
        _fail("original request does not uniquely name the requested artifact")
    compiled = request.get("compiled_collector_args")
    if not isinstance(compiled, list) or not compiled or len(compiled) > 64:
        _fail("collection-time compiled_collector_args are unavailable")
    collectors = []
    for item in compiled:
        if not isinstance(item, dict) or not isinstance(item.get("Query"), list):
            _fail("compiled collector has an unsupported query schema")
        if any(isinstance(query, dict) and isinstance(query.get("Name"), str)
               and (query["Name"] == artifact or query["Name"].startswith(artifact + "/"))
               for query in item["Query"]):
            collectors.append(item)
    if len(collectors) != 1:
        _fail("compiled request does not uniquely identify this artifact's output")
    contract = _contract()
    _validate_collector(collectors[0], contract, artifact)
    specs = request.get("specs", [])
    if not isinstance(specs, list) or len(specs) > 64:
        _fail("original request specs have an unsupported schema")
    matching_specs = [spec for spec in specs if isinstance(spec, dict)
                      and spec.get("artifact") == artifact]
    if len(matching_specs) > 1:
        _fail("original request contains duplicate artifact specs")
    if matching_specs:
        parameters = matching_specs[0].get("parameters", {})
        if not isinstance(parameters, dict) or set(parameters) - {"env"}:
            _fail("original request parameters have an unsupported schema")
        supplied = _environment(parameters.get("env", []))
        actual = _environment(collectors[0]["env"])
        if any(key not in actual or actual[key] != value for key, value in supplied.items()):
            _fail("original request parameters conflict with the compiled environment")
    try:
        rows = api.query(
            "SELECT * FROM artifact_definitions(names=[ArtifactName]) LIMIT 2",
            {"ArtifactName": artifact}, timeout=30, max_wait=1, max_row=2,
            query_name="autoruns_test.signature_source",
        )
    except Exception as exc:
        raise SignatureSourceValidationError(
            "Signer experiment blocked: current artifact definition query failed."
        ) from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        _fail("current artifact definition is absent or ambiguous")
    current = rows[0]
    definition_bytes = _encoded(current, limit=1024 * 1024, label="current definition")
    if current.get("name") != artifact:
        _fail("current artifact definition has an unexpected identity")
    expected = {**contract["definition"], "name": artifact}
    if _definition(current) != expected:
        _fail("current artifact differs from the audited builtin execution contract")
    return {
        "status": "validated", "contract_id": contract["contract_id"],
        "artifact": artifact, "definition_sha256": hashlib.sha256(definition_bytes).hexdigest(),
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "execution_contract_sha256": hashlib.sha256(_encoded(
            contract, limit=1024 * 1024, label="installed contract",
        )).hexdigest(),
        "verification_parameter": SIGNATURE_PARAMETER, "verification_value": "Y",
        "signer_field": "Signer", "verified_marker": "(Verified) ",
        "allowed_canonical_signers": list(VERIFIED_MICROSOFT_SIGNERS),
        "provenance": "original_compiled_collector_args",
        "target_execution": "not_assessed", "certificate_revalidation": "not_performed",
    }
