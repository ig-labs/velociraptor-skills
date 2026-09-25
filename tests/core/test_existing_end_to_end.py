"""Real parser/readiness/state/reduction exercised with a recording transport."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from vraptor import cli
from vraptor.analyze import command as collection_analysis_cli
from vraptor.collect import requests as collection
from vraptor import readiness_state as engagement_state
import test_core_engagement_context as readiness_fixture


class RecordingApi:
    calls = []

    def __init__(self, api_config, org_id='root', **kwargs):
        self.api_config = api_config
        self.org_id = org_id

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def query(self, text, env=None, **kwargs):
        self.calls.append(('query', text, env))
        assert 'FROM clients()' in text
        return [{'client_id': 'C.1', 'Hostname': 'host01', 'LastSeen': '1'}]

    def query_file(self, name, env=None, **kwargs):
        self.calls.append(('query_file', name, env))
        assert name in {'get_flow.vql', 'list_flows.vql', 'flow_result_rows.vql'}
        if name == 'flow_result_rows.vql':
            return []
        return [{'session_id': 'F.1', 'state': 'FINISHED', 'total_collected_rows': 0,
                 'RequestedArtifacts': ['Windows.Forensics.Prefetch'], 'artifacts_with_results': [],
                 'Created': '1', 'LastActive': '2'}]


def test_new_flow_then_saved_request_reuses_existing_case(tmp_path, capsys, monkeypatch):
    root = tmp_path / 'cases'
    root.mkdir()
    api = readiness_fixture.EngagementContextTest().publish_ready(root, engagement_id='IR1', server_profile='lab', source='explicit')
    readiness = root / 'IR1/engagement.json'
    before = readiness.read_bytes()
    RecordingApi.calls = []
    monkeypatch.setattr(collection, 'CASE_ROOT', root)
    common = ['--id', 'IR1', '--case-root', str(root), '--api-client', str(api), '--client', 'C.1', '--skip-ai', '--no-progress', '--json']
    with patch.object(collection_analysis_cli, 'VeloApiClient', RecordingApi):
        assert cli.main(['analyze', '--flow', 'F.1', *common]) == 2
        output = json.loads(capsys.readouterr().out)
        assert output['review_complete'] is False
        assert output['status'] == 'planned'
        request = output['request_id']
        plan = Path(output['analysis_plan_file'])
        assert plan.is_relative_to(root / 'IR1/systems/host01/collection/requests' / request)
        assert cli.main(['analyze', '--request-id', request, *common]) == 2
        resumed = json.loads(capsys.readouterr().out)
        assert resumed['request_id'] == request
    assert readiness.read_bytes() == before
    assert not list(root.rglob('workspace.json'))
    assert not list(root.rglob('vraptor'))
    assert (root / 'IR1/logs/velociraptor-progress.log').is_file()
    assert RecordingApi.calls
