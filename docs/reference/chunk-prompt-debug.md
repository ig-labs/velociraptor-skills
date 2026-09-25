# Inspect chunk prompts and AI responses

Use `--debug-chunk-prompts [N]` to explicitly export the first N standard
artifact/chunk prompts rendered by one command, together with their returned AI
responses when model execution runs. Omitting the option exports
nothing; the flag alone saves at most one prompt. N must be a positive integer.
The limit is shared across artifacts and hunts selected by that command. Under
concurrency, selection follows render order, not artifact or source-row order.

This option is separate from `--debug`, which remains value-free provider and
validation diagnostics. Prompt exports contain the exact question, instructions,
output grammar and projected evidence in the analysis prompt. Treat them as
case evidence. Responses are saved exactly as returned by the analyst runner,
before any validation or normalization, including malformed responses. Provider
credentials, configuration files, conversation history, raw HTTP payloads and
provider-specific system messages are not added to the dump.

```bash
# Inspect one prompt from an existing flow without making model calls.
vraptor analyze --id IR1234 --case-root ~/cases --server-profile lab \
  --client C.EXAMPLE --flow F.EXAMPLE --skip-ai --debug-chunk-prompts

# Save up to five prompt/response pairs during normal existing-flow analysis.
vraptor analyze --id IR1234 --case-root ~/cases --server-profile lab \
  --client C.EXAMPLE --flow F.EXAMPLE --debug-chunk-prompts 5

# Standard streaming hunt analysis uses the same per-command limit.
vraptor analyze --id IR1234 --server-profile lab --hunt H.EXAMPLE \
  --debug-chunk-prompts 3
```

The flag is also available on `collect analyze` and `hunt analyze`. It does not
change their collection or review authorization: use `analyze --flow` when only
existing evidence should be used.

## Files and provenance

Outputs are retained under:

```text
<case-root>/<id>/debug/chunk-prompts/<UTC timestamp>-<unique suffix>/
  chunk-001.prompt.txt
  chunk-001.attempt-001.response.txt
  chunk-001.attempt-002.prompt.txt       # only when a correction retry runs
  chunk-001.attempt-002.response.txt     # only when that retry returns text
  chunk-001.attempt-003.response.txt     # second correction, if needed (default ceiling)
  manifest.json
```

Prompt and response files preserve exact UTF-8 text without truncation or added newlines.
Files are mode `0600`; newly created debug directories are mode `0700`.
Runs never overwrite earlier exports. The manifest records the requested limit,
saved count, artifact, request and chunk identity, row count, first/last source
references, applicable source aliases, byte counts and SHA-256 hashes. Schema 2
also records each attempt's prompt/response paths and hashes, runner status and
validation status (`accepted`, `rejected` or `not_run`). An empty successful
response has a zero-byte file; a failed call with no returned text has no
response file and a null response byte count. This is
an explicit `interoperability_export` under the persistence policy, stored
outside the ordinary analysis/checkpoint tree. Remove unneeded debug runs
explicitly; there is no automatic cross-run retention or rotation.

The command reports saved prompt/response counts and the directory on stderr, including when no
prompts were rendered. JSON output additionally includes `debug_chunk_prompts`.
Already saved prompts, responses and their manifest survive ordinary analysis exceptions.
An output filesystem error is reported rather than silently claiming the dump
succeeded.

## Scope and limitations

- Captures standard `reference-line-v3` chunk prompts, including standard
  DetectRaptor chunks, plus returned responses and validation-correction retries
  for those captured chunks. It excludes synthesis, final-review, specialized
  Autoruns and generic stack-review prompts/responses.
- Each selected chunk can retain up to two analysis attempts, without consuming
  another chunk slot. Provider-internal transport retries, token streams and
  raw provider error bodies are not captured; the runner's returned text is.
- Host `--skip-ai` and `--plan-only` explicitly render up to N prepared chunks
  when this flag is supplied. Planning still reads the selected evidence and
  retains its normal shared-budget behavior; this is not a limit on acquisition.
  No response files are created because no model is called.
- Hunt `--skip-ai`, specialized paths and fully reused checkpoints may render
  no standard prompts. They report zero saved; the flag never forces a review,
  bypasses a checkpoint or initiates a model call.
- Offline snapshot analysis rejects this option.
- Capturing a rendered prompt or response does not prove completed evidence
  review. A prompt may be captured before admission fails. Raw AI text remains
  untrusted even when saved; consult validation status and the final analysis.
- Each prompt has the normal chunk bounds. The count limits exported chunks,
  not the total workload. Failed runs can retain fewer than N prompts.

## Validation

```bash
.venv/bin/python -m pytest -q tests/test_chunk_prompt_debug.py \
  tests/test_analysis_skip_ai.py tests/test_collection_analysis_runtime.py \
  tests/test_flow_analysis.py
```

Tests cover exact prompt bytes and hashes, opt-in defaults, positive limits,
concurrent writers, context cleanup, private permissions, source mapping,
repeat-run preservation, model-free host preparation, exact response pairing,
malformed-response retention and correction retries in host and hunt workflows.
