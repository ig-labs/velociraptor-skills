PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS autoruns_known_good (
    hash_key TEXT NOT NULL CHECK(length(hash_key) = 40),
    image_path TEXT NOT NULL,
    launch_string TEXT NOT NULL,
    signer TEXT NOT NULL,
    description TEXT NOT NULL,
    modified_time TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    PRIMARY KEY (hash_key)
);

-- One btree stores the compact rules and their paired-pattern key.
-- Both patterns match complete V4-normalized fields, case-insensitively.
CREATE TABLE IF NOT EXISTS autoruns_regex_rules (
    image_path_regex TEXT NOT NULL CHECK(length(image_path_regex) > 0),
    launch_string_regex TEXT NOT NULL CHECK(length(launch_string_regex) > 0),
    -- Reference only: never used in matching or the rule identity.
    signer_regex TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    modified_time TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    PRIMARY KEY (image_path_regex, launch_string_regex)
) WITHOUT ROWID;
