# Windows Artifact Analysis

Source PDF: `IR-Guidebook-Final.pdf`

Purpose: preserve the investigation nuance from the Microsoft Incident
Response artifact guide in a repo-native format that future agents can read
quickly during analysis.

## Contents

- Core principle and artifact strength
- AmCache
- Browser artifacts
- Link files and Jump Lists
- Prefetch
- ShellBags
- Shimcache / AppCompatCache
- SRUM
- User Access Logging
- UserAssist
- Repo application and finding language
- Coverage notes

How to use this note in this repo:

- Read this before making strong claims from execution-adjacent artifacts.
- Treat the sections below as interpretation guardrails, not collection logic.
- When multiple artifacts disagree, favor the artifact with the strongest
  semantics for the exact question being answered.
- Keep the caveats in the investigation wiki and Spreadsheet of Doom whenever
  an artifact is central to a finding.

## Core Principle

Not all Windows forensic artifacts answer the same question.

- Some artifacts are best treated as **evidence of existence** or **presence**.
- Some are **execution-adjacent context**.
- Some can provide stronger **evidence of execution**, but only with
  important limitations.

Do not collapse these into one bucket.

## Artifact Strength Model

Use this rough model when writing findings:

- Stronger execution evidence:
  - Prefetch
  - SRUM, with timeframe caveats
  - UserAssist, but only with the correct Windows 10+ interpretation
  - EVTX script block/process creation evidence when present
- Execution-adjacent or supporting context:
  - BAM
  - Timeline / ActivitiesCache
  - AppCompatPCA
  - Link files / Jump Lists
  - Browser artifacts
- Presence / existence oriented:
  - AmCache
  - Shimcache on Windows 10+
  - ShellBags for folder knowledge and traversal, not file execution

## AmCache

What it is:

- A Windows Registry-backed artifact that stores information about installed
  applications, executed or present programs, drivers, PnP devices, and more.
- On-disk location is typically `%SYSTEMROOT%\\appcompat\\Programs\\Amcache.hve`.

What it is good for:

- Showing that a file existed or previously existed at a path.
- Recovering a SHA1 value for a file path.
- Pivoting on application metadata and Registry key last write times.
- Distinguishing between associated package entries and standalone entries.

What it is **not** good for:

- Proving execution by itself.

Key caveats:

- Treat AmCache as **evidence of presence/existence**, not proof of execution.
- The SHA1 is not always the hash of the full file.
- For files larger than 30 MB, AmCache hashes only the first 31,457,280 bytes.
- Product names and versions come from file metadata and can be manipulated.

Repo mapping:

- `Windows.Detection.Amcache`
- `Windows.Registry.Hunter` categories may also surface related context

How to write it up:

- Prefer wording like "the file was present in AmCache at path X" rather than
  "the file executed because it appears in AmCache."

## Browser Artifacts

What they are good for:

- Profiling user behavior, browsing history, downloads, cache, sessions, and
  local-file access via browsers.
- Understanding where browser artifacts live and which stores hold history for
  Edge/Chrome versus Firefox.

Typical locations:

- Edge: `%LocalAppData%\\Microsoft\\Edge\\UserData\\[Default|ProfileX]\\*`
- Chrome: `%LocalAppData%\\Google\\Chrome\\User Data\\Default\\*`
- Firefox: `%AppData%\\Mozilla\\Firefox\\Profiles\\xxxxxxxx.default-release\\*`
- Firefox cache: `%LocalAppData%\\Mozilla\\Firefox\\Profiles\\xxxxxxxx.default-release\\cache2\\*`

Key caveats:

- Local files viewed in a browser can appear in history.
- `WebCacheV01.dat` may also show local file access such as `file:///C:/...`.
- Chromium history is typically in a `History` SQLite DB, while Firefox uses
  `places.sqlite`.
- Chromium cache content may preserve copies of downloaded files.
- Never rely on a single browser parsing tool for critical findings.
- Make sure the parsing tool is compatible with the browser version.
- Validate important browser findings with multiple tools when possible.

How to use in investigations:

- Good for staging, phishing, download origin, and user intent questions.
- Also useful for showing local review of PDFs, SVGs, archives, and other
  downloaded content.

## Link Files and Jump Lists

What they are good for:

- Showing that files existed and were interacted with.
- Recovering target path, size, file attributes, volume info, system name, and
  timestamps tied to the target.
- Understanding which files a given application touched.
- Understanding taskbar/application recency context through Jump Lists.

Typical locations:

- Link files: `%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent`
- Jump Lists:
  - `%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations`
  - `%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations`

Key caveats:

- Do not ignore them just because they are "shortcuts."
- A same-name file created in a different location can update an existing link.
- If multiple files of the same name exist, Link file creation time can reflect
  the first instance of that name rather than the later one.
- Link file creation time can indicate the first time the target file was
  created in that relationship context, while modification time can indicate
  the last time the target was opened.
- Jump Lists are application-oriented collections of link metadata, not simple
  execution counters.
- `AutomaticDestinations` and `CustomDestinations` serve different purposes,
  and `AutomaticDestinations` are stored in CDF format.

How to use in investigations:

- Good for deleted-file reconstruction and user interaction context.
- Useful when proving a user knew about or opened a document or payload.

## Prefetch

What it is good for:

- One of the stronger Windows execution artifacts when it exists.
- Deriving first execution and last execution windows.
- Recovering files and directories the executable interacted with.
- Recovering up to the most recent eight execution timestamps on Windows 8+.

Typical location:

- `%SYSTEMROOT%\\Prefetch`

Key caveats:

- Prefetch is enabled by default on desktop Windows, but not normally on
  Windows Server.
- The `.pf` filename hash is derived from executable path and in some cases
  command-line context.
- Creation and modification times reflect the prefetching process with an
  approximate 0-10 second delta.
- Windows 8+ retains up to 1,024 Prefetch files using FIFO rotation.
- Missing Prefetch on server hosts is not unusual.

Repo mapping:

- `Windows.Forensics.Prefetch`

How to write it up:

- Treat Prefetch as strong execution support where present.
- On server images, avoid overclaiming from absence.

## ShellBags

What they are good for:

- Showing folder knowledge, directory traversal, archive browsing, and
  interactive user activity.
- Recovering first/last interaction context for folders and some archive types.
- Showing Windows Explorer interaction with archive content that is treated as
  folder-like by the shell.

What they are **not** good for:

- Proving file execution.

Key caveats:

- ShellBags track folders, not ordinary files.
- Archive formats such as `.zip`, `.rar`, `.tar`, and `.tar.gz` can still
  appear because Explorer treats them like folders.
- They reflect Windows Explorer GUI activity, not PowerShell/cmd/Bash usage.
- Deleted folder entries can persist.
- Some folder property changes can create entries even without browsing.
- `Desktop.ini` also stores some folder presentation data, but it is not the
  same artifact and should not be confused with ShellBags.

How to use in investigations:

- Good for staging, collection, and user awareness questions.
- Especially useful for archive handling and removable-media or UNC traversal.
- The existence of ShellBags can also support the inference that an interactive
  user session occurred during the relevant time window.

## Shimcache / AppCompatCache

What it is good for:

- Showing that a file existed or was seen in a location.
- Finding nearby items of interest through cache ordering.
- Historical rename/move inference in some cases.
- On older Windows versions, potentially carrying stronger execution semantics
  than it does on Windows 10+.

What it is **not** good for:

- On Windows 10 and later, proving execution by itself.

Key caveats:

- The timestamp is the file modification time, not execution time.
- On Windows 10+, treat Shimcache/AppCompatCache as **presence/existence**
  evidence.
- On Windows 7/8/8.1, older execution-style interpretations may still appear
  in tooling or documentation, so make sure the OS version is explicit.
- Data is written to disk on reboot or shutdown.
- If you need pre-reboot state, memory extraction may be required.
- Renamed or moved files may be re-shimmed.
- Explorer visibility can influence what gets shimmed.
- Context matters: neighboring cache positions can reveal related files.

Repo mapping:

- `Windows.Registry.Hunter` program execution exports
- Older separate AppCompatCache-style workflows if reintroduced later

How to write it up:

- Prefer "present in AppCompatCache/Shimcache" or
  "execution-compatible context" unless you have a stronger corroborating
  artifact.

## SRUM

What it is good for:

- High-value execution-adjacent and usage context on Windows 8+ and Server
  2019+.
- Tying application usage to user SIDs.
- Showing general timeframe, resource usage, and some network activity.
- Showing network names, byte transfer counts, and some foreground/background
  resource usage patterns.

Typical location:

- `%SYSTEMROOT%\\System32\\sru\\SRUDB.dat`

What it is **not** good for:

- Precise execution timestamp reconstruction.

Key caveats:

- Timestamps should not be read as exact execution times.
- Network usage fields on Windows Server are not populated like desktop hosts.
- It is often overlooked despite being one of the stronger supporting artifacts.
- Some SRUM details overlap with what Task Manager's App History exposes, but
  the underlying database contains far more than the GUI view.

Repo mapping:

- `Windows.Forensics.SRUM`
- This repo exports the four SRUM scopes separately:
  - `Execution Stats`
  - `Application Resource Usage`
  - `Network Connections`
  - `Network Usage`

How to write it up:

- Use SRUM to define a timeframe or usage pattern.
- Do not reduce SRUM to "the exact moment program X executed."

## User Access Logging (UAL)

What it is good for:

- Windows Server access profiling.
- Lateral movement analysis from clients into server roles.
- Identifying first and last access by user/source/role combinations.
- Understanding role-based access patterns over multi-year server history.

Typical location:

- `%SYSTEMROOT%\\System32\\LogFiles\\SUM`
- Common databases include `SystemIdentity.mdb`, `Current.mdb`, and one or
  more GUID-named annual `.mdb` files.

Key caveats:

- Server-only artifact on Windows Server 2012+.
- The recorded IP is the source of activity, not the destination.
- UAL rotates annual GUID-named databases and keeps archival history for prior
  years before overwrite.
- `InsertDate` is first access for the year for a user/source/role tuple, and
  `LastAccess` is the last access for that same tuple.
- The role context matters; "File Server" often implies SMB but not always.

How to use in investigations:

- Good for server-side access profiling and cross-host movement context.

## UserAssist

What it is good for:

- GUI-based program execution context tied to a specific user.
- Focus time can support real execution on Windows 10+.
- Distinguishing executable-file execution from shortcut-file execution through
  UserAssist GUID families.

What it is **not** good for:

- Counting exact executions from Run Count on Windows 10+.
- Treating Last Executed time as definitive execution proof on its own.

Key caveats:

- Metadata is stored in `NTUSER.dat` and is ROT-13 encoded.
- Common GUID families include `CEBFF5CD` for executable-file execution and
  `F4E57C4B` for shortcut-file execution on Windows 7+.
- On Windows 10+, **Focus Time** matters more than Run Count.
- Right-clicking an app and choosing "Open file location" can increment
  Run Count and update Last Executed without actual execution.
- Some execution paths do not create UserAssist records.
- Certain session clues exist, such as paired `Snipping Tool.lnk` and
  `Paint.lnk` patterns with the same timestamp for a user; treat those as
  contextual hints, not universal rules.

Repo mapping:

- `Windows.Registry.Hunter` curated `UserAssist` execution exports

How to write it up:

- For Windows 10+, prefer wording like
  "UserAssist supports GUI-based execution because Focus Time is greater than
  zero" instead of relying on Run Count alone.

## How To Apply This In This Repo

When reviewing the current repo's common artifacts:

- `Windows.Detection.Amcache`
  - Use for presence, metadata, and SHA1 pivots.
  - Do not claim execution from it alone.
- `Windows.Forensics.Bam`
  - Use as recent execution context where present.
  - Expect sparse results on some dead-disk or server images.
- `Windows.Forensics.Timeline`
  - Use as activity context, not a sole execution verdict.
- `Windows.Forensics.SRUM`
  - Use for usage/timeframe/network context.
  - Keep the timestamp caveat explicit.
- `Windows.System.AppCompatPCA`
  - Use as launch-supporting evidence, not universal execution coverage.
- `Windows.Forensics.Prefetch`
  - Use as stronger execution evidence when it exists.
  - Expect it to be absent on many server systems.
- `Windows.Registry.Hunter`
  - Separate the exports by category and apply the right caveat to each
    sub-artifact rather than treating the whole result set uniformly.
  - In particular:
    - `Program Execution` rows can include UserAssist, AppCompatCache, BAM,
      and RADAR, each with different strength.
    - `Services`, `Persistence`, `System Info`, and `User Activity` are
      interpretation domains, not one signal type.

## Recommended Writing Style For Findings

Use explicit wording:

- Good:
  - "AmCache shows the file was present at path X."
  - "Prefetch supports execution of binary Y."
  - "UserAssist Focus Time supports GUI-based execution by user Z."
  - "SRUM places application usage in timeframe T but does not provide a
    precise execution timestamp."
  - "AppCompatCache places the binary on disk and may support execution context
    when corroborated."

- Avoid:
  - "AmCache proves execution."
  - "SRUM shows the exact execution time."
  - "UserAssist Run Count proves the binary ran N times."
  - "AppCompatCache proves execution on Windows 10+."

## Coverage Notes

The source PDF covers:

- AmCache
- Browser forensics
- Link files and Jump Lists
- Prefetch
- ShellBags
- Shimcache
- SRUM
- UAL
- UserAssist

The PDF does not replace artifact documentation or real-case context. Use it
to improve interpretation quality, not to skip corroboration.
