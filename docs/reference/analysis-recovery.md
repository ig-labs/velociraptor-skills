# Analysis correction and recovery

Analysis correction is distinct from provider/transport retry. A provider call
must succeed before an output-validation defect can trigger correction. Failed
authentication, cancellation, deterministic token-limit failures and exhausted
transport retries do not receive another call from the correction loop.

The shared analyst TOML supports:

```toml
[analysis_defaults]
validation_correction_attempts = 2
synthesis_correction_attempts = 2
```

Each value counts **extra attempts**, so the defaults permit three total attempts
per chunk or synthesis stage. The range is 0–5; zero disables correction. Non-empty
`AI_SKILLS_ANALYST_AGENT_VALIDATION_CORRECTION_ATTEMPTS` and
`AI_SKILLS_ANALYST_AGENT_SYNTHESIS_CORRECTION_ATTEMPTS` override TOML values.
`vraptor ai config` reports effective values and provenance. Corrections remain
inside the existing scheduler and model token/deadline guards. Provider retries
continue to use `AI_SKILLS_ANALYST_AGENT_MAX_RETRIES` separately.

## Resume failed host analysis

```bash
vraptor analyze --id IR1234 --client C.1234abcd \
  --request-id REQUEST_ID --question 'Was malicious execution observed?' \
  --retry-failed
```

Use the original question, analysis settings, time bounds and case connection.
The exact request is required; the option cannot be combined with reset, force,
preparation or report-only rebuilding. It never recollects evidence.

Accepted artifacts are reused after source and report-hash verification. Failed
artifacts reacquire their existing flow rows once; accepted chunks are restored
from reference-only decisions, revalidated and hydrated against those rows. Only
failed chunks and their dependent synthesis are sent to the model. Source,
question, configuration or prompt changes invalidate reuse. A failed final host
review reuses accepted artifact candidates. Legacy runs without these chunk
checkpoints must review the failed artifact again.

`--reset-artifact` and `--reset-analysis` still explicitly discard accepted work.
Ordinary reruns keep terminal failed artifacts held; use `--retry-failed` to
resume them. Final synthesis can also be resumed by rerunning the saved request.

## Troubleshooting and retention

Every host analysis writes `analysis/analysis-diagnostics.json` under its request.
It records stage/task identity, attempts, provider category, elapsed time,
affected chunk row ranges, structured validator defects, allowed references and
response hashes. Up to 200 task records are retained, prioritizing failures, with
an explicit omitted count. The normal result and report include failed stages,
the diagnostic path and a shell-quoted resume command. Model output, provider
bodies, credentials and source values are excluded. `--debug` adds the existing
provider diagnostics; `--debug-chunk-prompts` explicitly retains evidence-bearing
prompts/responses.

`artifact-recovery/*.json` retains one current generation of accepted compact
chunk decisions per artifact, with hashes and no copied row fields. Request
checkpoints retain accepted artifact candidates, plans, report hashes and final
dispositions, permitting recovery after switching requests. Current host state
and `analysis-host.md` remain atomically replaced derived views. Request switching
or schema mismatch no longer creates `previous-analysis/state-*` snapshots.
Existing historical snapshots and standalone `run_analyst_agent --replace`
bundles are unaffected. Finder `.DS_Store` metadata is ignored by tree validation.

Artifact reports distinguish review completion over exposed rows from collection
completion. Final review checks the evidence-to-claim link, tactics, confidence
and benign explanations, and cannot promote confidence beyond supporting input
candidates. Deterministic checks enforce references and confidence bounds;
semantic accuracy still requires model qualification. Exact normalized duplicate
limitations are removed, while the final reviewer is instructed to consolidate
equivalent prose without losing distinct coverage gaps.

## Offline validation

```bash
.venv/bin/python -m pytest -q tests/test_analysis_recovery.py tests/test_host_final_review.py tests/test_agent_analysis_defaults.py tests/core/test_core_collection_analysis_integration.py tests/core/test_core_host_analysis_state.py
```

Synthetic tests cover correction budgets, terminal failures, failed-chunk reuse,
source/configuration invalidation, corruption, request switching, retained
diagnostics, confidence validation, coverage labels and atomic state publication.
