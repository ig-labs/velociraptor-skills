# Finding enrichment

For each material finding, make one bounded enrichment decision: complete,
partial, or not_applicable. Prefer the installed VirusTotal, Shodan or Spur skill
for relevant public observables. Use already-authorized source-native queries
for internal identity, process, file, network, prevalence or chronology context.
Do not submit internal identities, private infrastructure, unknown samples or
customer files to public services without explicit authorization.

Return enrichment to the owning host or hunt analysis with exact source
references, query time, limitations and its effect on the finding. Distinguish
reputation and infrastructure attribution from execution or compromise. Failed
or unavailable enrichment remains an explicit limitation. No case database,
lead register or automatic task queue is involved.
