# Resource ownership

Skills own their operating instructions and workflow-specific references.
`src/vraptor` owns the runtime; its `resources/` directory owns
packaged VQL, schemas, profiles and preparation helpers. Shared explanatory
contracts live in `docs/reference/`. Repository validators and
standalone utilities live in `utils/`. The shared collection policy lives in
`src/vraptor/resources/collection-groups.json` for both repository
commands and installed packages. Set `VRAPTOR_COLLECTION_POLICY` to an explicit
file when a site needs different collection rules.

`config/sync-manifest.tsv` records the public export allowlist. Run
`./utils/validate-public-export.py` after changes. Historical export mapping
metadata may retain old source names without requiring the old package.
