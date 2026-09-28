from __future__ import annotations

import argparse

import pytest

from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles


def test_unbounded_scope_is_stable_and_ignores_profile_support() -> None:
    scope = analysis_time_scope.TimeScope.from_values()
    resolved = analysis_time_scope.resolve_for_profile("Artifact", {}, scope)
    assert scope.canonical() == {"mode": "all"}
    assert resolved.predicate() == ""
    assert resolved.canonical() == {"mode": "all"}


def test_scope_canonicalizes_timezone_and_uses_open_interval() -> None:
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T10:00:00+10:00",
        before="2026-08-02T00:00:00Z",
        roles=["mtime", "btime", "mtime"],
    )
    assert scope.after == "2026-08-01T00:00:00Z"
    assert scope.before == "2026-08-02T00:00:00Z"
    assert scope.requested_roles == ("mtime", "btime")


def test_mft_defaults_resolve_to_mtime_or_btime() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z",
        before="2026-08-02T00:00:00Z",
    )
    profile = artifact_profiles.resolve_profile("Windows.NTFS.MFT", profiles)
    resolved = analysis_time_scope.resolve_for_profile(
        "Windows.NTFS.MFT", profile, scope
    )
    assert resolved.roles == ("mtime", "btime")
    predicate = resolved.predicate()
    assert "LastModified0x10" in predicate
    assert "Created0x10" in predicate
    assert " OR " in predicate
    assert "timestamp(epoch=" not in predicate
    assert " > AnalysisTimeAfter" in predicate
    assert " < " in predicate


def test_bounded_unsupported_profile_falls_back_to_unfiltered() -> None:
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    resolved = analysis_time_scope.resolve_for_profile("No.Time", {}, scope)
    assert resolved.scope.canonical() == {"mode": "all"}
    assert resolved.predicate() == ""
    assert resolved.includes({"Anything": "outside-requested-window"})


def test_eventlogs_name_defaults_to_event_time_without_a_profile() -> None:
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    resolved = analysis_time_scope.resolve_for_profile(
        "Custom.Windows.EventLogs.NewArtifact",
        None,
        scope,
    )
    assert resolved.roles == ("event",)
    assert resolved.expressions == {"event": ("EventTime",)}
    assert resolved.predicate() == "((EventTime > AnalysisTimeAfter))"


def test_explicit_eventlogs_mapping_overrides_name_fallback() -> None:
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    profile = {
        "review": {
            "time_filter": {
                "default_roles": ["record"],
                "roles": {
                    "record": {
                        "semantics": "explicit record time",
                        "expressions": ["Timestamp"],
                    }
                },
            }
        }
    }
    resolved = analysis_time_scope.resolve_for_profile(
        "Custom.Windows.EventLogs.Override",
        profile,
        scope,
    )
    assert resolved.roles == ("record",)
    assert resolved.expressions == {"record": ("Timestamp",)}


def test_explicit_empty_eventlogs_mapping_disables_name_fallback() -> None:
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    resolved = analysis_time_scope.resolve_for_profile(
        "Custom.Windows.EventLogs.NoSafeTimestamp",
        {"review": {"time_filter": {}}},
        scope,
    )
    assert not resolved.scope.bounded
    assert resolved.predicate() == ""

    profiles = artifact_policy.load_artifact_policy().profiles
    parent = analysis_time_scope.resolve_for_profile(
        "Windows.EventLogs.Modifications",
        artifact_profiles.resolve_profile(
            "Windows.EventLogs.Modifications",
            profiles,
        ),
        scope,
    )
    assert not parent.scope.bounded


def test_mixed_artifact_scope_filters_known_fields_and_leaves_unknown_unfiltered() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z",
        roles=["event"],
    )
    resolved = analysis_time_scope.resolve_all(
        ["DetectRaptor.Windows.Detection.Evtx", "IG.Windows.Sysinternals.Autoruns"],
        profiles,
        scope,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    assert resolved["DetectRaptor.Windows.Detection.Evtx"].scope.bounded
    assert not resolved["IG.Windows.Sysinternals.Autoruns"].scope.bounded
    assert resolved["IG.Windows.Sysinternals.Autoruns"].predicate() == ""


def test_naive_timestamp_and_field_without_bounds_are_rejected() -> None:
    with pytest.raises(analysis_time_scope.TimeScopeError, match="timezone"):
        analysis_time_scope.TimeScope.from_values(after="2026-08-01T00:00:00")
    with pytest.raises(analysis_time_scope.TimeScopeError, match="requires"):
        analysis_time_scope.TimeScope.from_values(roles=["event"])


def test_cli_arguments_parse_repeatable_fields() -> None:
    parser = argparse.ArgumentParser()
    analysis_time_scope.add_arguments(parser)
    args = parser.parse_args(
        [
            "--time-after",
            "2026-08-01T00:00:00Z",
            "--time-field",
            "mtime",
            "--time-field",
            "btime",
        ]
    )
    scope = analysis_time_scope.from_args(args)
    assert scope.requested_roles == ("mtime", "btime")


def test_local_filter_matches_open_or_semantics() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z",
        before="2026-08-02T00:00:00Z",
    )
    resolved = analysis_time_scope.resolve_for_profile(
        "Windows.NTFS.MFT",
        artifact_profiles.resolve_profile("Windows.NTFS.MFT", profiles),
        scope,
    )
    assert not resolved.includes(
        {
            "LastModified0x10": "2026-07-01T00:00:00Z",
            "Created0x10": "2026-08-01T00:00:00Z",
        }
    )
    assert resolved.includes(
        {
            "LastModified0x10": "2026-07-01T00:00:00Z",
            "Created0x10": "2026-08-01T00:00:00.000001Z",
        }
    )
    assert not resolved.includes(
        {
            "LastModified0x10": "2026-08-02T00:00:00Z",
            "Created0x10": "2026-07-01T00:00:00Z",
        }
    )


@pytest.mark.parametrize(
    ("artifact", "roles", "expressions"),
    [
        ("Windows.Detection.PublicIP", ("event",), ("EventTime",)),
        ("Windows.EventLogs.RDPAuth", ("event",), ("EventTime",)),
        ("IG.Windows.EventLogs.LateralMovement.RDP", ("event",), ("EventTime",)),
        (
            "IG.Windows.EventLogs.LateralMovement.Kerberos",
            ("event",),
            ("EventTime",),
        ),
        (
            "IG.Windows.EventLogs.LateralMovement.LogonEvents",
            ("event",),
            ("EventTime",),
        ),
        ("IG.Windows.EventLogs.LateralMovement.NTLM", ("event",), ("EventTime",)),
        ("Windows.EventLogs.PowershellModule", ("event",), ("EventTime",)),
        (
            "Windows.EventLogs.PowershellScriptblock",
            ("event",),
            ("EventTime",),
        ),
        (
            "IG.Windows.EventLogs.PowershellScriptblock",
            ("event",),
            ("EventTime",),
        ),
        ("IG.Windows.EventLogs.ServiceCreations", ("event",), ("EventTime",)),
        ("IG.Windows.Applications.RAT.AnyDesk", ("log",), ("Timestamp",)),
        ("Windows.Applications.AnyDesk", ("log",), ("Timestamp",)),
        (
            "Windows.Applications.TeamViewer.Incoming",
            ("session",),
            ("StartTime", "EndTime"),
        ),
        ("DetectRaptor.Windows.Detection.Evtx", ("event",), ("EventTime",)),
        (
            "DetectRaptor.Windows.Detection.Webhistory",
            ("visit", "download"),
            (
                "ArtifactData.Visit_Date",
                "ArtifactData.Last_Visit_Date",
                "ArtifactData.Download_Date",
            ),
        ),
        (
            "DetectRaptor.Windows.Detection.ZoneIdentifier",
            ("mtime", "btime"),
            ("HostTimestampsSI.Mtime", "HostTimestampsSI.Btime"),
        ),
        (
            "DetectRaptor.Windows.Detection.MFT",
            ("mtime", "btime"),
            (
                "SITimestamps.LastModified0x10",
                "FNTimestamps.LastModified0x30",
                "SITimestamps.Created0x10",
                "FNTimestamps.Created0x30",
            ),
        ),
        (
            "Windows.NTFS.MFT",
            ("mtime", "btime"),
            ("LastModified0x10", "Created0x10"),
        ),
        (
            "Windows.EventLogs.Modifications/Channels",
            ("mtime",),
            ("Mtime",),
        ),
        ("Windows.EventLogs.Cleared", ("event",), ("EventTime",)),
        (
            "Windows.EventLogs.Modifications/Providers",
            ("mtime",),
            ("Mtime",),
        ),
        ("Windows.EventLogs.ScheduledTasks", ("event",), ("EventTime",)),
        ("IG.Windows.EventLogs.Ntdsutil", ("event",), ("EventTime",)),
        (
            "IG.Windows.Master.ApplicationExecution/ShimCache",
            ("mtime",),
            ("ModificationTime",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/Amcache",
            ("record",),
            ("Timestamp",),
        ),
        (
            "DetectRaptor.Windows.Detection.Bootloaders",
            ("mtime", "btime"),
            ("Mtime", "Btime"),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/Windows10Timeline",
            ("execution",),
            ("LastModifiedTime",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/Prefetch",
            ("execution",),
            ("event_time",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/CommandExecutedRunDialog",
            ("mtime",),
            ("event_time",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/UserAssist",
            ("execution",),
            ("LastExecution",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/ProgramCompatibilityAssistant",
            ("event",),
            ("EventTime",),
        ),
        (
            "IG.Windows.Master.ApplicationExecution/RecentApps",
            ("execution",),
            ("LastExecution",),
        ),
    ],
)
def test_verified_artifact_roles_resolve_exact_fields(
    artifact: str,
    roles: tuple[str, ...],
    expressions: tuple[str, ...],
) -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    resolved = analysis_time_scope.resolve_for_profile(
        artifact,
        artifact_profiles.resolve_profile(artifact, profiles),
        scope,
    )
    assert resolved.roles == roles
    assert tuple(
        expression
        for role in resolved.roles
        for expression in resolved.expressions[role]
    ) == expressions


def test_source_profile_resolution_prefers_exact_then_parent() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    exact = artifact_profiles.resolve_profile(
        "IG.Windows.Master.ApplicationExecution/Prefetch", profiles
    )
    key, inherited, resolution = artifact_profiles.resolve_profile_match(
        "IG.Windows.Master.ApplicationExecution/UnknownSource", profiles
    )
    assert exact is not None
    assert exact["review"]["time_filter"]["default_roles"] == ["execution"]
    assert key == "IG.Windows.Master.ApplicationExecution"
    assert inherited is not None
    assert resolution == "parent"
    assert inherited["time_bound_support"] == "no"


def test_time_filter_provenance_reports_partial_mixed_coverage() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    artifacts = [
        "Windows.EventLogs.RDPAuth",
        "IG.Windows.Registry.HiddenTasks",
    ]
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    resolved = analysis_time_scope.resolve_all(
        artifacts,
        profiles,
        scope,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    record = analysis_time_scope.provenance(
        artifacts,
        profiles,
        scope,
        resolved,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    assert record["coverage"] == "partial"
    assert record["filtered_artifacts"] == ["Windows.EventLogs.RDPAuth"]
    assert record["unfiltered_artifacts"] == ["IG.Windows.Registry.HiddenTasks"]
    assert record["unsupported_artifacts"] == ["IG.Windows.Registry.HiddenTasks"]
    assert record["resolved_artifacts"]["Windows.EventLogs.RDPAuth"][
        "expressions"
    ] == {"event": ["EventTime"]}


def test_collection_bounds_and_analysis_time_support_are_distinct() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    scope = analysis_time_scope.TimeScope.from_values(
        after="2026-08-01T00:00:00Z"
    )
    artifacts = [
        "DetectRaptor.Windows.Detection.Webhistory",
        "IG.Windows.EventLogs.Splashtop",
    ]
    resolved = analysis_time_scope.resolve_all(
        artifacts,
        profiles,
        scope,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    record = analysis_time_scope.provenance(
        artifacts,
        profiles,
        scope,
        resolved,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    assert resolved["DetectRaptor.Windows.Detection.Webhistory"].scope.bounded
    assert not resolved["IG.Windows.EventLogs.Splashtop"].scope.bounded
    assert record["collection_time_bound_support"] == {
        "DetectRaptor.Windows.Detection.Webhistory": "no",
        "IG.Windows.EventLogs.Splashtop": "yes",
    }


def test_unbounded_provenance_marks_no_artifact_unsupported() -> None:
    profiles = artifact_policy.load_artifact_policy().profiles
    artifacts = ["Windows.EventLogs.RDPAuth", "IG.Windows.Registry.HiddenTasks"]
    scope = analysis_time_scope.TimeScope.from_values()
    record = analysis_time_scope.provenance(
        artifacts,
        profiles,
        scope,
        {},
        profile_resolver=artifact_profiles.resolve_profile,
    )
    assert record["coverage"] == "not_requested"
    assert record["filtered_artifacts"] == []
    assert record["unfiltered_artifacts"] == sorted(artifacts)
    assert record["unsupported_artifacts"] == []
