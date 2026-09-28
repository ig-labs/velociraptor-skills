"""Offline request packing, streamed validation, and VQL identity regressions."""

import base64
import gzip
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from types import SimpleNamespace
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.hunt import live
from vraptor.api import VeloApiClient
from vraptor.api import build_vql_request
from vraptor.api import org_id_candidates


BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
ARTIFACT = "Windows.Sysinternals.Autoruns"


def selected_rows(count=166):
    return [
        {
            "ImagePath": f"c:\\apps\\{index:04d}\\café_日本語😀.exe",
            "LaunchString": hashlib.sha256(str(index).encode()).hexdigest(),
            "Signer": "",
            "Severity": "high",
            "Reason": "Synthetic selected identity",
        }
        for index in range(count)
    ]


def decode_identities(env):
    return json.loads(gzip.decompress(base64.b64decode(
        env["AutorunsSelectedHashesGzipBase64"])))


def context_row(identity, category="Logon"):
    return {
        "_AutorunsIdentity": identity,
        "HashKey": autoruns.trusted_key(
            image_path=identity["ImagePath"],
            launch_string=identity["LaunchString"],
            signer=identity["Signer"],
        ),
        "Category": category,
        "ClientId": "C.synthetic",
        "Fqdn": "synthetic.invalid",
    }


class StreamingApi:
    org_id = "root"
    query_timeout_seconds = 0

    def __init__(self):
        self.requests = []

    def query_batches(self, query, env, **kwargs):
        self.requests.append((query, dict(env), kwargs))
        rows = [context_row(identity) for identity in decode_identities(env)]
        for offset in range(0, len(rows), 17):
            yield rows[offset:offset + 17]

    def query(self, *args, **kwargs):
        raise AssertionError("Drill-down must stream responses")


def review(api, selected, **kwargs):
    return live.review_autoruns_suspicious_context_streaming(
        api, hunt_id="H.synthetic", artifact=ARTIFACT,
        profile={}, suspicious_rows=selected, state={"query_ledger": []}, **kwargs,
    )


def plan(selected, api=None, **kwargs):
    return live.autoruns_suspicious_request_batches(
        api or StreamingApi(), projection=["*"], suspicious_rows=selected,
        env={"HuntId": "H.synthetic", "ArtifactName": ARTIFACT}, **kwargs,
    )


class AutorunsRequestBatchesTest(unittest.TestCase):
    def test_default_packs_more_than_100_and_retains_streaming(self):
        api = StreamingApi()
        context, accepted = review(api, selected_rows())
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(context["query_count"], 1)
        self.assertEqual(context["identity_count"], 166)
        self.assertEqual(context["row_count"], 166)
        self.assertEqual(len(accepted), 166)
        self.assertEqual(api.requests[0][2], {"max_wait": 30, "max_row": 100})

    def test_explicit_count_cap_compatibility(self):
        api = StreamingApi()
        context, accepted = review(api, selected_rows(), identity_batch_size=100)
        self.assertEqual([len(decode_identities(env)) for _, env, _ in api.requests], [100, 66])
        self.assertEqual(context["query_count"], 2)
        self.assertEqual(len(accepted), 166)

    def test_request_boundary_includes_all_protobuf_fields(self):
        selected = selected_rows(30)
        api = StreamingApi()
        api.org_id = "组织"
        api.query_timeout_seconds = 16384
        initial = plan(selected, api)[0]
        query, env, _, size = initial
        actual_sizes = [len(build_vql_request(
            query, env, org_id=org, timeout=16384, max_wait=30, max_row=100,
        ).SerializeToString()) for org in org_id_candidates(api.org_id)]
        self.assertEqual(size, max(actual_sizes))
        self.assertGreater(size, len(env["AutorunsSelectedHashesGzipBase64"]))
        self.assertEqual(len(plan(selected, api, request_max_bytes=size)), 1)
        split = plan(selected, api, request_max_bytes=size - 1)
        self.assertGreater(len(split), 1)
        self.assertTrue(all(batch[3] <= size - 1 for batch in split))
        self.assertEqual(sum(len(batch[2]) for batch in split), len(selected))
        capped = plan(selected, api, request_max_bytes=size - 1, identity_batch_size=7)
        self.assertTrue(all(len(batch[2]) <= 7 and batch[3] <= size - 1 for batch in capped))

    def test_singleton_exact_boundary_and_oversize_rejected(self):
        selected = selected_rows(1)
        size = plan(selected)[0][3]
        self.assertEqual(plan(selected, request_max_bytes=size)[0][3], size)
        with self.assertRaisesRegex(RuntimeError, "One Autoruns identity exceeds"):
            plan(selected, request_max_bytes=size - 1)

    def test_oversized_later_identity_fails_before_any_query(self):
        selected = selected_rows(2)
        selected[1]["ImagePath"] = "z" + "".join(
            hashlib.sha256(str(index).encode()).hexdigest() for index in range(500)
        )
        small_api = StreamingApi()
        review(small_api, selected[:1], request_max_bytes=20_000)
        self.assertEqual(len(small_api.requests), 1)
        api = StreamingApi()
        with self.assertRaisesRegex(RuntimeError, "no drill-down queries issued"):
            review(api, selected, identity_batch_size=1, request_max_bytes=20_000)
        self.assertEqual(api.requests, [])

    def test_unicode_order_and_cross_category_dedup_are_deterministic(self):
        selected = selected_rows(30)
        selected.append({**selected[0], "Category": "Services"})
        first = plan(selected, identity_batch_size=7)
        second = plan(list(reversed(selected)), identity_batch_size=7)
        self.assertEqual([(batch[0], batch[1], batch[3]) for batch in first],
                         [(batch[0], batch[1], batch[3]) for batch in second])
        identities = [identity for batch in first for identity in decode_identities(batch[1])]
        self.assertEqual(len(identities), 30)
        self.assertIn("café_日本語😀", identities[0]["ImagePath"])

    def test_cross_category_context_remains_one_identity(self):
        selected = selected_rows(1)
        identity = {key: selected[0][key] for key in ("ImagePath", "LaunchString", "Signer")}
        api = mock.Mock(query_batches=mock.Mock(return_value=iter([
            [context_row(identity, "Logon")], [context_row(identity, "Services")],
        ])))
        context, accepted = review(api, selected)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(context["row_count"], 2)
        self.assertEqual(context["items"][0]["categories"], ["Logon", "Services"])

    def test_invalid_limits_fail_without_queries(self):
        for field in ("identity_batch_size", "request_max_bytes"):
            for value in (0, -1, True, 1.5, "100"):
                with self.subTest(field=field, value=value):
                    api = StreamingApi()
                    with self.assertRaises(RuntimeError):
                        review(api, selected_rows(1), **{field: value})
                    self.assertEqual(api.requests, [])

    def test_malformed_batches_and_rows_fail_closed(self):
        for batch in (None, {}, "", "malformed", [None], ["malformed"]):
            with self.subTest(batch=batch):
                api = mock.Mock(query_batches=mock.Mock(return_value=iter([batch])))
                with self.assertRaisesRegex(RuntimeError, "malformed"):
                    review(api, selected_rows(1))

    def test_incomplete_or_failed_stream_never_reports_success(self):
        selected = selected_rows(2)
        identity = {key: selected[0][key] for key in ("ImagePath", "LaunchString", "Signer")}
        api = mock.Mock(query_batches=mock.Mock(return_value=iter([[context_row(identity)]])))
        with self.assertRaisesRegex(RuntimeError, "1 missing"):
            review(api, selected)

        def failed_stream():
            yield [context_row(identity)]
            raise RuntimeError("synthetic transport failure")

        api.query_batches.return_value = failed_stream()
        with self.assertRaisesRegex(RuntimeError, "synthetic transport failure"):
            review(api, selected)

    def test_server_identity_and_hash_validation_retained(self):
        selected = selected_rows(1)
        identity = {key: selected[0][key] for key in ("ImagePath", "LaunchString", "Signer")}
        valid = context_row(identity)
        invalid_streams = [
            ([{**valid, "_AutorunsIdentity": None}], "omitted its server identity"),
            ([{**valid, "_AutorunsIdentity": {**identity, "Signer": "unexpected"}}], "unexpected"),
            ([{**valid, "HashKey": "invalid"}], "invalid server HashKey"),
            ([valid, {**valid, "HashKey": "a" * 40}], "inconsistent"),
        ]
        for rows, message in invalid_streams:
            with self.subTest(message=message):
                api = mock.Mock(query_batches=mock.Mock(return_value=iter([rows])))
                with self.assertRaisesRegex(RuntimeError, message):
                    review(api, selected)

    def test_request_builder_matches_actual_transport(self):
        client = VeloApiClient(Path("unused-api-config"), org_id="组织", query_timeout_seconds=16384)
        client._stub = mock.Mock()
        client._stub.Query.return_value = [SimpleNamespace(Response="[]", log="", part=0)]
        query = "SELECT 日本語 FROM scope()"
        env = {"z": "😀", "a": "café"}
        list(client.query_batches(query, env, max_wait=30, max_row=100))
        request = client._stub.Query.call_args.args[0]
        expected = build_vql_request(
            query, env, org_id="组织", timeout=16384, max_wait=30, max_row=100,
        )
        self.assertEqual(request.SerializeToString(), expected.SerializeToString())
        self.assertEqual(expected.ByteSize(), len(request.SerializeToString()))

    def test_transport_rejects_falsey_malformed_json_payloads(self):
        for payload in ("{}", "null", '""', "false", "0", '"bad"'):
            with self.subTest(payload=payload):
                client = VeloApiClient(Path("unused-api-config"))
                client._stub = mock.Mock()
                client._stub.Query.return_value = [
                    SimpleNamespace(Response=payload, log="", part=0),
                ]
                with self.assertRaisesRegex(RuntimeError, "not a row array"):
                    list(client.query_batches("SELECT * FROM scope()"))

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor binary unavailable")
    def test_local_vql_more_than_100_unicode_blank_and_cross_category_rows(self):
        selected = selected_rows()
        selected.append({"ImagePath": "", "LaunchString": "", "Signer": "",
                         "Severity": "high", "Reason": "Synthetic blank identity"})
        raw_rows = [
            {"Image Path": row["ImagePath"], "Launch String": row["LaunchString"],
             "Signer": row["Signer"], "Category": "Logon"}
            for row in selected
        ]
        raw_rows.append({**raw_rows[0], "Category": "Services"})

        class LocalVqlApi(StreamingApi):
            def query_batches(self, query, env, **kwargs):
                self.requests.append((query, dict(env), kwargs))
                prefix = "LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows))\n"
                args = [str(BINARY), "query", "--format=jsonl", "--env", "Rows=" + json.dumps(raw_rows)]
                for key, value in env.items():
                    args.extend(["--env", key + "=" + value])
                result = subprocess.run(args + [prefix + query], check=True, capture_output=True,
                                        text=True, timeout=30)
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                for offset in range(0, len(rows), 17):
                    yield rows[offset:offset + 17]

        api = LocalVqlApi()
        with mock.patch.object(live, "source_vql", return_value="TestRows"):
            context, accepted = review(api, selected)
        self.assertEqual(len(api.requests), 1)
        self.assertEqual(len(accepted), 167)
        self.assertEqual(context["row_count"], 168)


if __name__ == "__main__":
    unittest.main()
