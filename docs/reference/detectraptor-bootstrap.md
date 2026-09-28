# Required DetectRaptor bootstrap

DetectRaptor is a mandatory server prerequisite for these Velociraptor skills.
Apply this gate to every newly created local server and every connected remote
server, including live endpoints and remote mapped evidence. Reused engagement
readiness alone does not prove that this prerequisite has been checked.

Before declaring setup complete or proceeding to server-backed investigation,
collection, hunting or analysis:

1. Query the connected server/organization, using its selected API credentials:

   ```vql
   SELECT name FROM artifact_definitions()
   WHERE name =~ '^DetectRaptor[.]'
   ```

2. If at least one DetectRaptor artifact exists, record the check as satisfied.
   Do not reimport or update an existing installation merely for this gate.
   Requested artifacts still require their normal individual availability checks.
3. If none exists, **run `Server.Import.Extras` on the server**. This required
   setup action is authorized by this workflow; do not ask for another approval.
   Read that server's artifact definition and preserve its current `Details` CSV.
   Append the following row once (reuse an identical row if already present):

   ```csv
   DetectRaptor,DetectRaptor,https://github.com/mgreen27/DetectRaptor/releases/download/DetectRaptor/DetectRaptorVQL.zip
   ```

   The header is `Name,Tag,URL`. Pass the resulting CSV as the collection's
   `Details` parameter. Do not edit the built-in artifact definition. A reference
   CSV is provided in the engagement-setup skill's `references/import-extras.csv`;
   the connected server's defaults take precedence over that example.
4. Before submission, check for an existing in-flight import with the same
   parameters and reuse/monitor it rather than creating a duplicate. Run one
   import coordinator per server/organization. Record its flow ID and status.
5. Wait for the import flow to finish, inspect errors, and repeat the live catalog
   query. Only a verified nonempty DetectRaptor result satisfies the gate; a
   queued flow or successful CLI exit alone does not. Refresh existing disposable
   artifact inventory caches after successful import.
6. Retain compact verification provenance in the case setup notes: server/org,
   check time, artifact count, import flow ID when used, and any errors. Never
   copy credentials into the case. Reuse a successful check in the same session
   and unchanged server/org context. Recheck on a new session/connection, catalog
   removal, server replacement, or a relevant artifact-availability failure.

Missing `Server.Import.Extras`, insufficient permissions, blocked outbound access,
failed imports, or an empty post-import catalog are concrete blockers. Report the
failed step and exact server/flow; do not silently proceed without DetectRaptor,
escalate roles, generate credentials, or repeatedly retry unchanged failures.

An explicit user instruction forbidding imports or requiring read-only work takes
precedence: do not mutate the server, and report the unmet prerequisite. This gate
does not run during offline-only documentation, local saved-evidence review, or
process status/stop operations. It never authorizes endpoint detections or hunts
by itself and does not imply all DetectRaptor artifacts support dead disks.

This is a required skill workflow, not a newly implemented automatic CLI hook.
