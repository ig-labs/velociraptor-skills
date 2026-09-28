"""Operator output must not conflate acquired evidence with reviewed analysis."""
import shlex
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from vraptor.analyze import checkpoints, command, runtime, summary
from vraptor.collect import requests as collection


@pytest.mark.parametrize(('status', 'review', 'expected'), [
    ('complete', {}, 'completion unverified'),
    ('complete', {'status': 'failed'}, 'blocked: final review failed'),
    ('complete', {'status': 'complete'}, 'final review complete'),
    ('complete_with_failures', {'status': 'complete'}, 'coverage limitations remain'),
    ('failed', {}, 'blocked: analysis failed'),
    ('planned', {}, 'AI analysis not run'),
    ('running', {}, 'final review pending'),
])
def test_collection_completion_does_not_imply_review(status, review, expected):
    rendered = summary.render_chat_summary(
        {'final_review': review}, status=status, flow_metadata=[], collection_complete=True,
    )
    assert '- Collection: complete' in rendered
    assert expected in rendered


def test_reused_flow_dates_survive_checkpoint_without_affecting_source_identity(tmp_path):
    created = datetime(2026, 8, 11, tzinfo=timezone.utc)
    flow = {'artifact': 'Artifact.Test', 'flow_id': 'F.1', 'flow_state': 'FINISHED',
            'created': str(int(created.timestamp() * 1_000_000)),
            'last_active': '2026-08-11T00:05:00Z', 'reuse_decision': 'reused_exact_flow',
            'is_finished': True, 'total_rows': 1}
    state = checkpoints.new_state(hostname='host01', client_id='C.1', request_id='R.1', analysis_identity='analysis')
    payload = {'artifact_flows': [flow], 'all_artifacts_expected_complete': True}
    checkpoints.reconcile(state, payload=payload, analysis_identity='analysis')
    artifact_report = tmp_path / 'artifact.md'
    artifact_report.write_text('Synthetic accepted report')
    checkpoints.mark_artifact_complete(state, 'Artifact.Test', status='complete',
                                      result={'status': 'complete'}, plan_summary={}, report_file=artifact_report)
    checkpoint = checkpoints.write_request_checkpoint(tmp_path / 'checkpoint.json', state=state,
                  question='Review execution', host_result={'final_review': {'status': 'complete'}}, status='complete')
    rendered = summary.render_chat_summary(checkpoint['result'], status='complete',
                    flow_metadata=checkpoint['artifact_summaries'], analysis_completed_at='2026-09-20T01:00:00Z')
    assert '2026-08-11T00:00:00Z' in rendered
    assert '2026-08-11T00:05:00Z' in rendered
    assert 'Analysis completed: `2026-09-20T01:00:00Z`' in rendered
    assert 'reused_exact_flow' in rendered
    assert 'not the event period' in rendered
    assert 'does not refresh reused evidence' in rendered
    # A later reuse decision is display metadata, not a reason to discard accepted analysis.
    before = checkpoints.artifact_source_fingerprint(flow, analysis_identity='analysis')
    assert checkpoints.artifact_source_fingerprint({**flow, 'reuse_decision': 'follow_saved_exact_flow'}, analysis_identity='analysis') == before


def test_missing_or_naive_dates_are_not_inferred_from_analysis_time():
    rendered = '\n'.join(summary.render_flow_freshness([{'flow_id': 'F.1', 'created': '2026-08-11T00:00:00'}]))
    assert '| F.1 | unknown | unknown | unknown |' in rendered
    assert '2026-08-11' not in rendered
    assert 'unavailable' in '\n'.join(summary.render_flow_freshness([]))


def test_final_review_failure_exposes_resume_without_detailed_diagnostics():
    rendered = summary.render_chat_summary({
        'final_review': {'status': 'failed'}, 'status': 'complete_with_failures',
        'troubleshooting': {'resume_command': 'vraptor analyze --request-id R.1'},
    })
    assert 'vraptor analyze --request-id R.1' in rendered
    assert 'active runner or monitor' in rendered
    assert 'provisional' in rendered


def test_success_does_not_offer_unnecessary_retry():
    assert summary.render_resume({'status': 'complete', 'final_review': {'status': 'complete'},
                                  'troubleshooting': {'resume_command': 'unused'}}) == []


def test_poll_timeout_has_parseable_exact_resume_without_new_collection_selectors(monkeypatch, tmp_path):
    monkeypatch.setattr(collection, 'CASE_ROOT', tmp_path / 'case root')
    args = command.build_parser().parse_args([
        '--id', 'IR1', '--client-id', 'C.1', '--collection-type', 'execution',
        '--question', 'Check "odd" files; do not expand scope', '--server-profile', 'lab',
        '--response-depth', 'deep', '--time-after', '2026-08-01T00:00:00Z',
    ])
    payload = {'request_id': 'R.1', 'client_id': 'C.1', 'all_artifacts_expected_complete': False}
    monkeypatch.setattr(command, 'start_collection', lambda *a, **kw: ('host01', payload, 'reused_existing_flows', None))
    monkeypatch.setattr(collection, 'poll_collection', lambda *a, **kw: {**payload, 'poll_timed_out': True})
    with pytest.raises(RuntimeError) as error:
        command.resolve_collection(Mock(), args, policy=Mock())
    message = str(error.value)
    assert 'analysis is incomplete' in message
    assert 'active runner or monitor' in message
    argv = shlex.split(message.split('\n', 1)[1])
    assert argv[:3] == ['vraptor', 'collect', 'analyze']
    resumed = command.build_parser().parse_args(argv[3:])
    assert resumed.request_id == 'R.1'
    assert resumed.client_id == 'C.1'
    assert resumed.question == args.question
    assert resumed.server_profile == 'lab'
    assert resumed.case_root == str(tmp_path / 'case root')
    assert resumed.time_after == args.time_after
    assert not command._target_arguments_present(resumed)
    assert not resumed.force_run
    assert not resumed.retry_failed


def test_blocked_running_report_keeps_actionable_continuation():
    rendered = runtime.render_running_host_report(plan={}, question='Review execution', progress={
        'status': 'failed', 'resume_command': 'vraptor collect analyze --request-id R.1',
    })
    assert 'final review is not complete' in rendered
    assert 'vraptor collect analyze --request-id R.1' in rendered


def test_existing_only_recovery_keeps_existing_only_route(monkeypatch, tmp_path):
    monkeypatch.setattr(collection, 'CASE_ROOT', tmp_path)
    args = command.build_parser().parse_args(['--id', 'IR1', '--client-id', 'C.1', '--query-timeout-seconds', '90'])
    args.existing_only = True
    argv = shlex.split(command.resume_analysis_command(args, {'client_id': 'C.1', 'request_id': 'R.1'}, retry_failed=True))
    assert argv[:2] == ['vraptor', 'analyze']
    assert '--retry-failed' in argv
    assert argv[argv.index('--query-timeout-seconds') + 1] == '90'
    assert not command._target_arguments_present(command.build_parser().parse_args(argv[2:]))
