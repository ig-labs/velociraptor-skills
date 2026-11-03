from vraptor.analyze import identity as run_identity


def test_run_identity_is_stable_across_parameter_order():
    first = run_identity.build_run_identity(
        source_mode="velociraptor-collection",
        target={"client_id": "C.1234"},
        specs=[
            {
                "artifact": "Artifact.Test",
                "env": {"Beta": "2", "Alpha": "1"},
                "timeout_seconds": 600,
            }
        ],
    )
    second = run_identity.build_run_identity(
        source_mode="velociraptor-collection",
        target={"client_id": "C.1234"},
        specs=[
            {
                "artifact": "Artifact.Test",
                "env": {"Alpha": "1", "Beta": "2"},
                "timeout_seconds": 600,
            }
        ],
    )

    assert first == second


def test_run_identity_rejects_extra_artifacts_and_changed_scope():
    expected = run_identity.build_run_identity(
        source_mode="velociraptor-hunt",
        target={"server_target_os": "windows", "include_labels": []},
        specs=[{"artifact": "Artifact.Test", "env": {}}],
    )
    extra_artifact = run_identity.build_run_identity(
        source_mode="velociraptor-hunt",
        target={"server_target_os": "windows", "include_labels": []},
        specs=[
            {"artifact": "Artifact.Other", "env": {}},
            {"artifact": "Artifact.Test", "env": {}},
        ],
    )
    changed_scope = run_identity.build_run_identity(
        source_mode="velociraptor-hunt",
        target={"server_target_os": "linux", "include_labels": []},
        specs=[{"artifact": "Artifact.Test", "env": {}}],
    )

    assert run_identity.identity_mismatches(
        expected["identity"],
        extra_artifact["identity"],
    )
    assert run_identity.identity_mismatches(
        expected["identity"],
        changed_scope["identity"],
    )


def test_execution_state_classification_and_ranking():
    finished = run_identity.classify_state(
        "FINISHED",
        terminal_success_states={"FINISHED"},
        in_flight_states={"RUNNING"},
    )
    running = run_identity.classify_state(
        "RUNNING",
        terminal_success_states={"FINISHED"},
        in_flight_states={"RUNNING"},
    )
    failed = run_identity.classify_state(
        "ERROR",
        terminal_success_states={"FINISHED"},
        in_flight_states={"RUNNING"},
    )

    assert finished == run_identity.TERMINAL_SUCCESS
    assert running == run_identity.IN_FLIGHT
    assert failed == run_identity.FAILED_OR_CANCELLED
    assert run_identity.classification_rank(finished) > run_identity.classification_rank(running)
    assert run_identity.classification_rank(running) > run_identity.classification_rank(failed)
    assert run_identity.reuse_allowed(finished)
    assert run_identity.reuse_allowed(running)
    assert not run_identity.reuse_allowed(failed)
