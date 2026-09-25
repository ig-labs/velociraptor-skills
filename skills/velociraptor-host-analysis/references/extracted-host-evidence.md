# Exported Host Evidence

Exported files are durable evidence only. They are not an alternate
host-analysis workflow.

Resume host analysis through the exact saved request:

```bash
dfir collect analyze \
  --id IR1234 \
  --client-id C.1234abcd \
  --request-id REQUEST_ID \
  --question "Was malicious execution observed?"
```

Use explicit export only when immutable evidence or external-tool
interoperability is required. Preserve exported files and their manifest
unchanged. Do not feed exports, manually assembled CSVs, decision files, or
offline packages back into host analysis.
