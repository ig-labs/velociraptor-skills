from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.agent.runtime import AgentRequest, AgentResult
from vraptor.analyze import command, coordinator, host, prompt_debug, runtime
from vraptor.analyze.limits import resolve_analysis_limits
from vraptor.hunt import command as hunt

from tests.core.test_core_collection_analysis_cli import (
    args,
    collection_payload,
    run_analysis,
)

LIMITS = resolve_analysis_limits({})
CSV = '_SourceRef,Command\nS0001-R1,"cmd /c echo test"\n'
SOURCES = {
    "source-1": {
        "alias": "S0001",
        "scope_type": "collection",
        "scope_id": "r1",
        "org_id": "root",
        "client_id": "C.1",
        "flow_id": "F.1",
        "artifact": "Artifact.Test",
        "source": "Artifact.Test",
    },
    "source-2": {"alias": "S0002", "scope_id": "unrelated"},
}
PLAN = {"collection_type": "custom", "request_id": "r1", "source_aliases": SOURCES}
CHUNK = {
    "artifact": "Artifact.Test",
    "task_chunk_index": 0,
    "task_chunk_count": 1,
    "row_start": 0,
    "row_end": 1,
    "row_count": 1,
}


def render():
    return runtime.render_chunk_prompt(
        plan=PLAN,
        chunk=CHUNK,
        question="What executed?",
        csv_evidence=CSV,
    )


def result(task, output, status="succeeded"):
    return AgentResult(
        task_id=task.task_id,
        status=status,
        output=output,
        output_file="",
        events_file="",
        manifest_file="",
        elapsed_seconds=0.01,
    )


class ChunkPromptDebugTests(unittest.TestCase):
    def test_cli_defaults_and_positive_count(self):
        for parser in (command.build_parser(),):
            self.assertEqual(
                parser.parse_args(["--client-id", "C.1"]).debug_chunk_prompts, 0
            )
            self.assertEqual(
                parser.parse_args(
                    ["--client-id", "C.1", "--debug"]
                ).debug_chunk_prompts,
                0,
            )
            self.assertEqual(
                parser.parse_args(
                    ["--client-id", "C.1", "--debug-chunk-prompts"]
                ).debug_chunk_prompts,
                1,
            )
            self.assertEqual(
                parser.parse_args(
                    ["--client-id", "C.1", "--debug-chunk-prompts=3"]
                ).debug_chunk_prompts,
                3,
            )
            for invalid in ("0", "-1", "invalid"):
                with self.assertRaises(SystemExit):
                    parser.parse_args(
                        ["--client-id", "C.1", "--debug-chunk-prompts", invalid]
                    )
        self.assertEqual(
            hunt.parse_args(
                [
                    "analyze",
                    "--id",
                    "test",
                    "--hunt-id",
                    "H.1",
                    "--debug-chunk-prompts",
                    "2",
                ]
            ).debug_chunk_prompts,
            2,
        )
        with self.assertRaises(SystemExit):
            hunt.parse_args(
                ["analyze", "--snapshot", "snapshot.json", "--debug-chunk-prompts"]
            )

    def test_disabled_has_no_io_or_evidence_reparse(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                prompt_debug.session(Path(directory)),
                mock.patch.object(
                    prompt_debug, "_write_new", side_effect=AssertionError("write")
                ),
                mock.patch.object(
                    prompt_debug.PromptDump,
                    "capture",
                    side_effect=AssertionError("capture"),
                ),
            ):
                self.assertIn("cmd /c echo test", render())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_exact_content_provenance_permissions_and_one_file_limit(self):
        expected = render()
        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 1) as dump:
                self.assertEqual(render(), expected)
                for _ in range(10):
                    render()
            files = sorted(dump.directory.iterdir())
            self.assertEqual(
                [p.name for p in files], ["chunk-001.prompt.txt", "manifest.json"]
            )
            self.assertEqual(files[0].read_bytes(), expected.encode())
            for path in files:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(dump.directory.stat().st_mode), 0o700)
            manifest = json.loads(files[1].read_text())
            record = manifest["prompts"][0]
            self.assertEqual(
                record["sha256"], hashlib.sha256(expected.encode()).hexdigest()
            )
            self.assertEqual(
                record["source_aliases"], {"source-1": SOURCES["source-1"]}
            )
            self.assertEqual(record["first_reference"], "S0001-R1")
            self.assertEqual(record["row_count"], 1)
            self.assertTrue(record["persistence"]["explicit_export"])
            self.assertNotIn("cmd /c echo test", files[1].read_text())

    def test_limit_is_shared_across_concurrent_writers(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                prompt_debug.session(Path(directory), 3) as dump,
                ThreadPoolExecutor(max_workers=8) as pool,
            ):
                list(
                    pool.map(
                        lambda _: dump.capture("prompt", PLAN, CHUNK, CSV),
                        range(100),
                    )
                )
            self.assertEqual(dump.summary()["saved_count"], 3)
            self.assertEqual(len(list(dump.directory.glob("*.prompt.txt"))), 3)

    def test_async_context_propagates_and_resets(self):
        async def exercise(directory):
            with prompt_debug.session(Path(directory), 2) as dump:
                await asyncio.gather(
                    asyncio.to_thread(render), asyncio.to_thread(render)
                )
            render()
            return dump

        with tempfile.TemporaryDirectory() as directory:
            dump = asyncio.run(exercise(directory))
            self.assertEqual(dump.summary()["saved_count"], 2)

    def test_empty_run_creates_nothing_and_reruns_preserve_previous_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with prompt_debug.session(root, 1) as empty:
                pass
            self.assertEqual(empty.summary()["saved_count"], 0)
            self.assertEqual(list(root.iterdir()), [])
            with prompt_debug.session(root, 1) as first:
                render()
            with prompt_debug.session(root, 1) as second:
                render()
            self.assertNotEqual(first.directory, second.directory)
            self.assertTrue((first.directory / "manifest.json").is_file())

    def test_failure_preserves_manifest_and_resets_context(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                self.assertRaisesRegex(RuntimeError, "model failed"),
                prompt_debug.session(Path(directory), 1) as dump,
            ):
                render()
                raise RuntimeError("model failed")
            self.assertTrue((dump.directory / "manifest.json").is_file())
            with mock.patch.object(
                prompt_debug.PromptDump, "capture", side_effect=AssertionError("leaked")
            ):
                render()

    def test_symlink_destination_is_rejected(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as other,
        ):
            (Path(directory) / "debug").symlink_to(other, target_is_directory=True)
            with (
                self.assertRaisesRegex(ValueError, "symlinks"),
                prompt_debug.session(Path(directory), 1),
            ):
                render()
            self.assertEqual(list(Path(other).iterdir()), [])

    def test_hunt_streaming_prompt_keeps_source_mapping(self):
        chunk = coordinator._streaming_chunk(
            [
                {
                    "unit_id": "unit-1",
                    "revision": "rev-1",
                    "source_id": "source-1",
                    "segment_id": "segment-1",
                    "artifact": "Artifact.Test",
                    "compatibility_key": "Artifact.Test/profile",
                    "row_count": 1,
                    "input_tokens": 10,
                    "rows": [{"_SourceRef": "S0001-R1", "Command": "test"}],
                }
            ],
            analysis_id="analysis-1",
        )
        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 1) as dump:
                work = next(
                    coordinator.iter_streaming_chunk_work(
                        [chunk],
                        source_aliases=SOURCES,
                        scope_type="hunt",
                        scope_id="H.1",
                        analysis_id="analysis-1",
                        question="What executed?",
                        limits=LIMITS.as_dict(),
                        encoding_name=LIMITS.token_encoding,
                    )
                )
            self.assertEqual(
                (dump.directory / "chunk-001.prompt.txt").read_text(),
                work["task"].prompt,
            )

    def test_skip_ai_host_renders_prompt_without_model_or_credentials(self):
        payload = collection_payload()
        payload["artifact_flows"] = [
            {
                "artifact": "Artifact.Test",
                "artifact_name": "Artifact.Test",
                "flow_id": "F.1",
                "flow_state": "FINISHED",
                "total_rows": 1,
                "matching_flow_found": True,
                "is_finished": True,
                "available_result_components": ["Artifact.Test"],
            }
        ]
        plan, chunks = host.build_analysis_workload(
            object(),
            payload,
            collection_type="custom",
            limits=LIMITS,
            profiles={
                "Artifact.Test": {
                    "enabled": True,
                    "review": {"analysis_fields": ["Command"]},
                }
            },
            query_rows=lambda *_args: [{"Command": "test"}],
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(command.collection, "CASE_ROOT", Path(directory)),
            mock.patch.object(
                command,
                "resolve_collection",
                return_value=("host01", payload, "reused_existing_flows"),
            ),
            mock.patch.object(command, "build_workload", return_value=(plan, chunks)),
            mock.patch.object(
                command,
                "resolve_agent_execution",
                side_effect=AssertionError("credentials"),
            ),
            mock.patch.object(
                command,
                "execute_incremental_analysis_async",
                side_effect=AssertionError("model"),
            ),
        ):
            with prompt_debug.session(Path(directory), 1) as dump:
                result = run_analysis(
                    object(), args(skip_ai=True, debug_chunk_prompts=1)
                )
            self.assertEqual(result["ai_review_status"], "skipped")
            self.assertFalse(result["review_complete"])
            self.assertEqual(dump.summary()["saved_count"], 1)
            self.assertEqual(dump.summary()["response_count"], 0)

    def test_host_responses_and_correction_prompt_are_paired_exactly(self):
        outputs = ["malformed\tresponse\n", "RESULT\tno_reportable_findings\nEND\n"]
        sent = []

        def execute(task):
            sent.append(task.prompt)
            return result(task, outputs[len(sent) - 1])

        def validate(task, output):
            if output == outputs[0]:
                raise ValueError("Invalid result header")
            return {"accepted": True}

        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 1) as dump:
                task = AgentRequest("task-1", render(), "chunk.txt", {"stage": "chunk"})
                accepted, _ = asyncio.run(
                    runtime._validated_pool_async(
                        [task],
                        max_concurrency=1,
                        execute=execute,
                        validate=validate,
                    )
                )
            self.assertEqual(accepted["task-1"], {"accepted": True})
            manifest = json.loads((dump.directory / "manifest.json").read_text())
            attempts = manifest["prompts"][0]["attempts"]
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["response_count"], 2)
            self.assertEqual(
                [a["validation_status"] for a in attempts], ["rejected", "accepted"]
            )
            for i, attempt in enumerate(attempts):
                prompt = (dump.directory / attempt["prompt_file"]).read_bytes()
                response_path = dump.directory / attempt["response_file"]
                response = response_path.read_bytes()
                self.assertEqual(prompt, sent[i].encode())
                self.assertEqual(response, outputs[i].encode())
                self.assertEqual(
                    hashlib.sha256(response).hexdigest(), attempt["response_sha256"]
                )
                self.assertEqual(stat.S_IMODE(response_path.stat().st_mode), 0o600)
            self.assertIn("RETRY CORRECTION", sent[1])

    def test_response_limit_excludes_uncaptured_chunks_and_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 1) as dump:
                first = AgentRequest("first", render(), "1.txt", {"stage": "chunk"})
                second = AgentRequest("second", render(), "2.txt", {"stage": "chunk"})
                synthesis = AgentRequest(
                    "synthesis", first.prompt, "s.txt", {"stage": "host-synthesis"}
                )
                asyncio.run(
                    runtime._validated_pool_async(
                        [synthesis, first, second],
                        max_concurrency=1,
                        execute=lambda task: result(task, task.task_id),
                        validate=lambda *_: {"accepted": True},
                    )
                )
                with mock.patch.object(
                    prompt_debug.hashlib,
                    "sha256",
                    side_effect=AssertionError("unneeded hash"),
                ):
                    self.assertIsNone(prompt_debug.track_task(second))
            files = list(dump.directory.glob("*.response.txt"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_text(), "first")

    def test_concurrent_responses_remain_paired_when_completion_order_changes(self):
        async def run_tasks(tasks):
            second_completed = asyncio.Event()

            async def execute(task):
                if task.task_id == "first":
                    await second_completed.wait()
                else:
                    second_completed.set()
                return result(task, task.task_id)

            return await runtime._validated_pool_async(
                tasks,
                max_concurrency=2,
                execute=execute,
                validate=lambda *_: {"accepted": True},
            )

        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 2) as dump:
                tasks = [
                    AgentRequest(
                        name,
                        runtime.render_chunk_prompt(
                            plan=PLAN,
                            chunk=CHUNK,
                            question=name,
                            csv_evidence=CSV,
                        ),
                        name + ".txt",
                        {"stage": "chunk"},
                    )
                    for name in ("first", "second")
                ]
                asyncio.run(run_tasks(tasks))
            for record in dump.records:
                response = dump.directory / record["attempts"][0]["response_file"]
                self.assertEqual(response.read_text(), record["task_id"])

    def test_failed_call_without_output_is_distinct_from_empty_response(self):
        for status, expected_files in (("failed", 0), ("succeeded", 3)):
            with (
                self.subTest(status=status),
                tempfile.TemporaryDirectory() as directory,
            ):
                with prompt_debug.session(Path(directory), 1) as dump:
                    task = AgentRequest(
                        "task", render(), "chunk.txt", {"stage": "chunk"}
                    )
                    asyncio.run(
                        runtime._validated_pool_async(
                            [task],
                            max_concurrency=1,
                            execute=lambda task, status=status: result(
                                task, "", status
                            ),
                            validate=lambda *_: (_ for _ in ()).throw(
                                ValueError("Empty response")
                            ),
                        )
                    )
                self.assertEqual(dump.summary()["response_count"], expected_files)
                for attempt in dump.records[0]["attempts"]:
                    self.assertEqual(attempt["runner_status"], status)
                    self.assertEqual(
                        attempt["response_bytes"], 0 if status == "succeeded" else None
                    )

    def test_streaming_retry_saves_rejected_and_accepted_outputs(self):
        chunk = coordinator._streaming_chunk(
            [
                {
                    "unit_id": "u1",
                    "revision": "rev1",
                    "source_id": "source-1",
                    "segment_id": "s1",
                    "artifact": "Artifact.Test",
                    "compatibility_key": "Artifact.Test/profile",
                    "row_count": 1,
                    "input_tokens": 10,
                    "rows": [{"_SourceRef": "S0001-R1", "Command": "test"}],
                }
            ],
            analysis_id="a1",
        )
        sent = []

        async def execute(task, **_kwargs):
            sent.append(task.prompt)
            return result(
                task,
                "INVALID\n"
                if len(sent) == 1
                else "RESULT\tno_reportable_findings\nEND\n",
            )

        with tempfile.TemporaryDirectory() as directory:
            with prompt_debug.session(Path(directory), 1) as dump:
                work = next(
                    coordinator.iter_streaming_chunk_work(
                        [chunk],
                        source_aliases=SOURCES,
                        scope_type="hunt",
                        scope_id="H.1",
                        analysis_id="a1",
                        question="What executed?",
                        limits=LIMITS.as_dict(),
                        encoding_name=LIMITS.token_encoding,
                    )
                )
                outcome = asyncio.run(
                    coordinator._execute_streaming_chunk_work_async(
                        work,
                        runner=SimpleNamespace(run=execute),
                        workdir=Path(directory),
                        runtime_dir=Path(directory),
                    )
                )
            self.assertEqual(outcome["status"], "accepted")
            self.assertEqual(dump.summary()["response_count"], 2)
            self.assertEqual(
                [a["validation_status"] for a in dump.records[0]["attempts"]],
                ["rejected", "accepted"],
            )
            self.assertNotIn("task", work)


if __name__ == "__main__":
    unittest.main()
