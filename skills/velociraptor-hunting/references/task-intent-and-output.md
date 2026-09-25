# Hunt Task Intent and Output

Select the task intent before selecting artifacts, targets, or filters.
Apply the shared [finding enrichment workflow](../../../docs/reference/indicator-enrichment-workflow.md) before final publication.

## Incident response and targeted hunt

- Require an explicit lead, indicator, identity, behavior, keyword, or
  hypothesis.
- Keep host, user, artifact, time, and filter scope exact. Do not drift into
  generic environment discovery.
- Return the exact question and seed, hunt/query identifiers, filters, affected
  hosts and users, prevalence, hits and non-hits, target-execution coverage,
  result-review coverage, caveats, and the next bounded validation action.

## Compromise assessment

- Permit environment discovery and prevalence baselining only when the task is
  explicitly declared as `compromise-assessment`.
- State the population and data surfaces assessed. Retain common, normal, rare,
  and anomalous values needed to explain the environment and coverage.
- Treat anomalies as candidate leads. Rarity, administrative capability, or
  remote-management tooling alone is not evidence of compromise.
- Narrow material leads into exact `targeted-hunt` or `host-forensics` work.

## Response depth

- `rapid`: only highest-signal findings, essential context, exact references,
  material coverage gaps, and the immediate next action. Mark incomplete review
  provisional.
- `standard`: prioritized findings, relevant chronology, finding-linked context,
  provenance, coverage, limitations, and bounded next actions.
- `deep`: complete bounded chronology and correlation, alternate explanations,
  finding-linked identity and causal context, confidence, and coverage.

For every material finding, attach the smallest available set of host/client,
username/account/SID, session/logon, process, file/hash/signer, network,
timestamp, and exact evidence-reference context that changes interpretation.
Omit unavailable fields rather than infer them.

Persist task mode and response depth with the hunt group. Later analysis reruns
inherit that policy unless the operator supplies explicit replacement flags.
