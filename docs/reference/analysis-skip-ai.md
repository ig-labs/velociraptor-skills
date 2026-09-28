# Prepare analysis without AI

Add `--skip-ai` to `dfir hunt analyze` or
`dfir collect analyze` (including host-analysis workflows).
The switch bypasses AI credentials, model calls and semantic consolidation.
Readiness, source selection, collection reuse and source validation still apply.
It does not prevent an otherwise authorized collection or configured missing-client
retry; use exact existing requests and hunts when collection reuse is required.

| Workflow | Output with `--skip-ai` |
| --- | --- |
| Autoruns hunt (`--profile autoruns`) | Complete native VQL aggregation, count cutoff (default 20), then GoldenDB filtering; `analysis/autoruns_review.csv`, header-only `analysis/autoruns_potential_golden.csv`, canonical hunt state and root `analysis-hunt.md` marked AI-skipped. |
| Generic live hunt (stream) | Projected, time-filtered evidence is streamed through token chunk planning. Counts, source aliases and policy provenance are written to `analysis/analysis-preparation.json`; raw evidence stays transient. DetectRaptor EVTX retains detection partitioning and `--detection-regex` selection. |
| Specialized live hunt (stack) | Existing deterministic reduction, stack outputs and bounded review items; no AI classification or finding consolidation. Uses curated stacks or the existing bounded fallback; AI field selection is disabled. Existing saved findings can remain in cumulative reports. |
| Host / collection | Existing collection resolution and deterministic evidence preparation, followed by request-local `analysis/analysis-plan.json`. No AI checkpoint or cumulative AI report is advanced. The older `--plan-only` remains available for this same preparation path. |
| Snapshot / `hunt analyze-saved` | These workflows already perform deterministic preparation without model execution. `--skip-ai` is accepted for command consistency. Existing explicit snapshot/export persistence settings still apply. |

Results carry `ai_review_status: skipped` and `review_complete: false`.
Preparation is not a clean finding or completed AI review, even when zero rows
remain. Run the command without `--skip-ai` to perform normal AI review.
For host preparation, add `--debug-chunk-prompts [N]` to explicitly retain
up to N rendered prompts without making model calls (one when N is omitted).
The [prompt export contract](chunk-prompt-debug.md) describes the evidence-bearing
files and limitations; hunt preparation may render no standard prompts.
Generic streaming preparation does not advance the reviewed cursor or replace
an existing AI checkpoint. Its summary is published only after stream exhaustion;
a failed scan leaves the previous summary intact.

`--skip-ai` cannot be combined with live hunt `--update`, host
`--reset-artifact` / `--reset-analysis`, or `--rebuild-host-summary`. Those options
operate on existing review state. Preparation covers the current selected scope.

```bash
./dfir hunt analyze --id IR1234 --hunt-id H.EXAMPLE \
  --artifact IG.Windows.Sysinternals.Autoruns --profile autoruns --skip-ai

./dfir collect analyze --id IR1234 --client-id C.EXAMPLE \
  --request-id REQUEST_ID --question "Review persistence" --skip-ai
```

Autoruns CSV columns, in order:
`Category,ImagePath,LaunchString,Signer,TotalRows,ExampleHosts`.
`ExampleHosts` remains a JSON array capped at 10 hosts per identity.
Groups above `--stack-max-total-rows` are excluded before GoldenDB matching and
are absent from this CSV. Their row/group counts remain in state and reports as
GoldenDB not evaluated. Use `--stack-max-total-rows 0 --skip-ai` to export all
GoldenDB residual groups without AI. Exactly 20 remains eligible by default;
21 is excluded. If no groups remain, the residual CSV contains only its header.
The complete-stream and source-fingerprint checks run before publication.
Skipping AI does not reuse classifications; the latest Autoruns state records preparation only.

## Runtime VQL ownership

Production Autoruns loads
[`regex-review-dedup-first.vql`](../../src/vraptor/resources/autoruns/regex-review-dedup-first.vql)
from the installed package on each invocation. `autoruns_dedup_ai.template()`
reads the file; `autoruns_regex_review.build_query()` validates the pinned template,
inserts the source query and normalization expressions, substitutes rule and
host/count limits, and binds compressed GoldenDB rule data. Normalization VQL is
assembled by `autoruns.py`; native deduplication and regex matching are defined
in the VQL file and executed by Velociraptor. Python validates and publishes the
returned stacks. Development files under `vql/autoruns_test/` are not the
production entry point.

## Validation

Run the focused no-AI contract tests from the repository root:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q \
  tests/test_analysis_skip_ai.py tests/test_autoruns_workflow.py \
  tests/test_autoruns_dedup_ai.py
```
