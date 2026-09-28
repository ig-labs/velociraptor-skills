from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from vraptor.agent.config import HydratedProviderInputs
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.diagnostics import DebugSession
from vraptor.agent.runtime import AgentError
from vraptor.agent.runtime import AgentProviderException
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentUsage
from vraptor.agent.runtime import ApiAgentRunner
from vraptor.agent.runtime import ProviderCapabilities
from vraptor.agent.runtime import ProviderResponse
from vraptor.agent.runtime import RetryPolicy
from vraptor.agent.runtime import run_item_pool


class FakeAdapter:
    def __init__(self, configuration, outcome):
        self.configuration = configuration
        self.outcome = outcome
        self.last_request = None

    def capabilities(self):
        return ProviderCapabilities(
            structured_output=True,
            json_mode=True,
            request_output_token_limit=True,
        )

    async def execute(self, request, **_kwargs):
        self.last_request = request
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class AgentDiagnosticsTest(unittest.TestCase):
    def configuration(self, provider="azure_openai"):
        return ResolvedAgentExecution(
            route=ResolvedAgentRoute(
                provider=provider,
                model="gpt-5.6-sol",
                protocol="responses",
                base_url="https://resource.openai.azure.com/openai/v1/?api-key=SECRET",
                auth_mode="api_key",
                credential_variable="AZURE_OPENAI_API_KEY",
                field_sources={
                    "provider": "environment:AI_SKILLS_ANALYST_AGENT_PROVIDER",
                    "model": "codex:/safe/config.toml",
                },
            ),
            inputs=HydratedProviderInputs(
                api_key="SECRET",
                credential_present=True,
            ),
        )

    def request(self):
        return AgentRequest(
            task_id="artifact-1",
            prompt="RAW-EVIDENCE SECRET",
            output_name="result.txt",
            metadata={"stage": "artifact-analysis"},
            max_output_tokens=64000,
        )

    def test_success_records_provider_resolution_without_payloads(self):
        for provider in ("openai", "azure_openai"):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                debug_path = root / "analysis" / "validation-debug.json"
                adapter = FakeAdapter(
                    self.configuration(provider),
                    ProviderResponse("accepted", f"req-{provider}"),
                )
                with DebugSession(
                    debug_path,
                    scope_type="hunt",
                    scope_id="H.1",
                    lane="stream_full",
                ):
                    result = asyncio.run(ApiAgentRunner(
                        adapter,
                        persist_runtime_files=False,
                    ).run(
                        self.request(),
                        workdir=root,
                        output_dir=root / "analysis" / ".api-runtime",
                    ))
                payload = json.loads(debug_path.read_text(encoding="utf-8"))
                text = json.dumps(payload)

                self.assertEqual(result.status, "succeeded")
                self.assertEqual(payload["configuration"]["provider"], provider)
                self.assertEqual(payload["configuration"]["model"], "gpt-5.6-sol")
                self.assertEqual(
                    payload["configuration"]["field_sources"]["model"],
                    "codex:/safe/config.toml",
                )
                self.assertEqual(
                    payload["configuration"]["base_url"],
                    "https://resource.openai.azure.com/openai/v1/",
                )
                self.assertTrue(
                    payload["requests"][0]["request_options"][
                        "max_output_tokens_sent"
                    ]
                )
                self.assertEqual(
                    payload["requests"][0]["request_options"][
                        "max_output_tokens_requested"
                    ],
                    64000,
                )
                self.assertEqual(adapter.last_request.max_output_tokens, 64000)
                self.assertEqual(
                    payload["provider_attempts"][0][
                        "max_output_tokens_requested"
                    ],
                    64000,
                )
                self.assertTrue(
                    payload["provider_attempts"][0]["max_output_tokens_sent"]
                )
                self.assertGreaterEqual(
                    payload["provider_attempts"][0]["local_output_tokens"], 1
                )
                self.assertNotIn("RAW-EVIDENCE", text)
                self.assertNotIn("SECRET", text)
                self.assertFalse(payload["prompts_persisted"])
                self.assertFalse(payload["model_output_persisted"])

    def test_invalid_request_records_safe_400_diagnostics(self):
        failure = AgentProviderException(
            AgentError(
                classification="invalid_request",
                message="azure_openai invalid_request (HTTP 400)",
                provider_status=400,
                request_id="req-400",
                provider_error_code="invalid_parameter",
                provider_error_param="max_output_tokens",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debug_path = root / "analysis" / "validation-debug.json"
            with DebugSession(
                debug_path,
                scope_type="host",
                scope_id="C.1",
                lane="execution",
            ):
                result = asyncio.run(ApiAgentRunner(
                    FakeAdapter(self.configuration(), failure),
                    retry_policy=RetryPolicy(max_retries=0),
                    persist_runtime_files=False,
                ).run(
                    self.request(),
                    workdir=root,
                    output_dir=root / "analysis" / ".api-runtime",
                ))
            payload = json.loads(debug_path.read_text(encoding="utf-8"))
            attempt = payload["provider_attempts"][0]

        self.assertEqual(result.provider_status, 400)
        self.assertEqual(attempt["provider_status"], 400)
        self.assertEqual(attempt["error_classification"], "invalid_request")
        self.assertEqual(attempt["provider_error_code"], "invalid_parameter")
        self.assertEqual(attempt["provider_error_param"], "max_output_tokens")
        self.assertEqual(attempt["provider_request_id"], "req-400")

    def test_output_limit_failure_records_safe_terminal_telemetry(self):
        failure = AgentProviderException(
            AgentError(
                classification="output_limit_reached",
                message="openai output limit reached",
                request_id="req-limit",
                usage=AgentUsage(10, 64_000, 64_010, 2),
                finish_reason="max_output_tokens",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debug_path = root / "analysis" / "validation-debug.json"
            with DebugSession(
                debug_path,
                scope_type="hunt",
                scope_id="H.1",
                lane="execution",
            ):
                result = asyncio.run(
                    ApiAgentRunner(
                        FakeAdapter(self.configuration("openai"), failure),
                        retry_policy=RetryPolicy(max_retries=3),
                        persist_runtime_files=False,
                    ).run(
                        self.request(),
                        workdir=root,
                        output_dir=root / "analysis" / ".api-runtime",
                    )
                )
            payload = json.loads(debug_path.read_text(encoding="utf-8"))
            attempt = payload["provider_attempts"][0]

        self.assertEqual(result.attempt_count, 1)
        self.assertEqual(attempt["error_classification"], "output_limit_reached")
        self.assertEqual(attempt["finish_reason"], "max_output_tokens")
        self.assertEqual(attempt["usage"]["output_tokens"], 64_000)
        self.assertEqual(attempt["max_output_tokens_requested"], 64_000)
        self.assertTrue(attempt["max_output_tokens_sent"])

    def test_debug_context_propagates_into_bounded_worker_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debug_path = root / "analysis" / "validation-debug.json"
            adapter = FakeAdapter(
                self.configuration("openai"),
                ProviderResponse("accepted", "req-pool"),
            )
            runner = ApiAgentRunner(adapter, persist_runtime_files=False)
            requests = [
                AgentRequest(
                    task_id="pool-task",
                    prompt="evidence",
                    output_name="pool.txt",
                    metadata={"stage": "chunk-analysis"},
                )
            ]
            with DebugSession(
                debug_path,
                scope_type="hunt",
                scope_id="H.1",
                lane="specialized_stack",
            ):
                results = asyncio.run(run_item_pool(
                    requests,
                    max_concurrency=2,
                    execute=lambda task: runner.run(
                        task,
                        workdir=root,
                        output_dir=root / "analysis" / ".api-runtime",
                    ),
                ))
            payload = json.loads(debug_path.read_text(encoding="utf-8"))

        self.assertEqual(results[0][1].status, "succeeded")
        self.assertEqual(payload["summary"]["request_count"], 1)
        self.assertEqual(payload["provider_attempts"][0]["stage"], "chunk-analysis")


if __name__ == "__main__":
    unittest.main()
