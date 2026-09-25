"""Application bootstrap for provider-neutral analyst runners."""

from __future__ import annotations

from dataclasses import asdict, replace
from typing import Any

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.providers import adapter_for
from vraptor.agent.runtime import (
    AgentRuntimeLimits,
    ApiAgentRunner,
    RetryPolicy,
    TimeoutPolicy,
    validate_spec,
)


def create_agent_runner(
    execution: ResolvedAgentExecution,
    *,
    limits: AgentRuntimeLimits | None = None,
    persist_runtime_files: bool = True,
    client: Any = None,
) -> ApiAgentRunner:
    """Construct a runner from the operation's already-resolved execution."""

    validate_spec(execution)
    from vraptor.analyze.limits import AnalysisLimits, resolve_analysis_limits

    policy = (
        AnalysisLimits(**asdict(limits))
        if limits is not None
        else resolve_analysis_limits({}, execution=execution)
    )
    bounded = policy.for_execution(execution).runtime_limits()
    if limits is not None:
        bounded = replace(
            bounded,
            model_context_tokens=min(
                limits.model_context_tokens, bounded.model_context_tokens
            ),
        )
    limits = bounded
    read_seconds = min(
        float(execution.route.read_timeout_seconds), float(execution.timeout_seconds)
    )
    timeout_policy = TimeoutPolicy(
        connect_seconds=min(10.0, float(execution.timeout_seconds)),
        read_seconds=read_seconds,
        total_seconds=float(execution.timeout_seconds),
        idle_stream_seconds=read_seconds,
    )
    adapter = adapter_for(
        execution,
        timeout_policy=timeout_policy,
        client=client,
    )
    return ApiAgentRunner(
        adapter,
        limits=limits,
        retry_policy=RetryPolicy(max_retries=execution.max_retries),
        timeout_policy=timeout_policy,
        persist_runtime_files=persist_runtime_files,
    )
