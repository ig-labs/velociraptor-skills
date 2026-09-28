# Detached Evidence Examples

These examples use deliberately detached, sanitized evidence. The original
file remains authoritative.

## SIEM process-event prevalence

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/siem-process-events.jsonl \
  --question "Which process and parent pairs are uncommon across hosts?" \
  --group-by process.executable \
  --group-by process.parent.executable \
  --host-field host.name \
  --user-field user.name \
  --timestamp-field @timestamp \
  --source-system "SIEM" \
  --acquisition-context "Saved process-start query export" \
  --filter-description "event.category=process and event.type=start" \
  --output-json /case/review/process-stack.json
```

## EDR prevalence without a verdict

Stack signer and executable path separately from any alert disposition. A rare
signed updater still requires source-row and surrounding-event review; a common
living-off-the-land binary is not automatically benign.

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/edr-executions.csv \
  --question "Which signer and executable path combinations need review?" \
  --group-by Signer \
  --group-by ExecutablePath \
  --host-field DeviceName \
  --timestamp-field EventTime \
  --source-system "EDR" \
  --acquisition-context "Incident-window execution export" \
  --output-json /case/review/edr-stack.json
```

## Timeline filename prevalence

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/timeline.csv \
  --question "Which normalized paths have low prevalence?" \
  --group-by Path \
  --normalize Path=windows-user-path \
  --timestamp-field Timestamp \
  --source-system "forensic timeline" \
  --acquisition-context "Sanitized bodyfile-derived timeline" \
  --output-json /case/review/timeline-stack.json
```

## Application authentication log

```bash
./.venv/bin/python ./skills/dfir-log-chunker/scripts/chunk_log.py \
  /case/derived/auth-session.log \
  --format text \
  --question "Does this session show password spraying or lateral movement?" \
  --reduction-description "Filtered the application log to one account and a 30-minute window." \
  --source-system "application authentication log" \
  --acquisition-context "Rotated log copy supplied for incident review" \
  --filter-description "account=user-a; incident window only" \
  --max-lines 1500 \
  --overlap-lines 25 \
  --output-dir /case/review/auth-session
```

## Reduced generic JSONL handoff

```bash
./.venv/bin/python ./skills/dfir-log-chunker/scripts/chunk_log.py \
  /case/derived/question-relevant-events.jsonl \
  --question "Which event sequences support or refute the working hypothesis?" \
  --reduction-description "Selected source rows represented by reviewed stack groups." \
  --upstream-manifest /case/review/process-stack.manifest.json \
  --partition-by host.name \
  --source-system "generic DFIR export" \
  --acquisition-context "Question-relevant rows extracted from immutable source" \
  --output-dir /case/review/event-chunks
```

## Splunk or ECS dotted CSV fields

Literal dotted headers resolve before nested traversal.

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/splunk-process.csv \
  --question "Which process names are uncommon across hosts?" \
  --group-by process.name \
  --host-field host.name \
  --timestamp-field @timestamp \
  --source-system "Splunk" \
  --output-json /case/review/splunk-process-stack.json
```

## Nested Elastic JSON response

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/elastic-search.json.gz \
  --json-record-path hits.hits \
  --question "Which executable names are prevalent?" \
  --group-by _source.process.name \
  --host-field _source.host.name \
  --timestamp-field _source.@timestamp \
  --source-system "Elastic" \
  --output-json /case/review/elastic-process-stack.json
```

## Zeek tabular export

```bash
./.venv/bin/python ./skills/dfir-data-stacking/scripts/stack_data.py \
  /case/derived/zeek-dns.tsv \
  --format tsv \
  --question "Which DNS queries have low source-host prevalence?" \
  --group-by query \
  --host-field id.orig_h \
  --timestamp-field ts \
  --timestamp-format lexical \
  --source-system "Zeek" \
  --output-json /case/review/zeek-dns-stack.json
```
