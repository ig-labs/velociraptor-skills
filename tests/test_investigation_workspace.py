import json
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from unittest.mock import patch

import pytest
from vraptor import cli, workspace


@pytest.fixture
def offline_config(tmp_path, monkeypatch):
    from vraptor.agent import config, manage
    from vraptor.paths import load_repo_env

    monkeypatch.setattr(workspace, 'repository_root', lambda: tmp_path)
    monkeypatch.setattr('vraptor.resources.repository_root', lambda: tmp_path)
    monkeypatch.setattr(manage, 'resolve_agent_execution', partial(config.resolve_agent_execution, repo_root=tmp_path))
    monkeypatch.setattr(manage, 'version', lambda _: '1.0.0')
    home = tmp_path / 'home'
    home.mkdir()
    load_repo_env.cache_clear()
    with (
        patch.dict(os.environ, {'HOME': str(home)}, clear=True),
        patch('vraptor.agent.manage.model_metadata', side_effect=AssertionError('network metadata called')),
        patch('vraptor.agent.factory.create_agent_runner', side_effect=AssertionError('inference called')),
    ):
        yield tmp_path
    load_repo_env.cache_clear()


def test_init_is_standalone_and_preserves_existing_work(tmp_path):
    first = workspace.initialize('ir1234', tmp_path)
    folder = tmp_path / 'ir1234'
    assert first['status'] == 'initialized'
    assert first['readiness_checked'] is False
    assert {p.name for p in folder.iterdir()} == {'AGENTS.md'}
    (folder / 'AGENTS.md').write_text('Operator guidance\n')
    report = folder / 'hunts/H.123/analysis-hunt.md'
    report.parent.mkdir(parents=True)
    report.write_text('Retained findings\n')
    evidence = folder / 'evidence.bin'
    evidence.write_bytes(b'original')
    again = workspace.initialize('ir1234', tmp_path)
    assert again['status'] == 'reused'
    assert again['existing_outputs'] == ['hunts/H.123/analysis-hunt.md']
    assert not again['guidance_created']
    assert (folder / 'AGENTS.md').read_text() == 'Operator guidance\n'
    assert evidence.read_bytes() == b'original'
    assert report.read_text() == 'Retained findings\n'


@pytest.mark.parametrize('identity', ['../escape', '.', '..', 'bad/name', 'bad\nname', 'bad`id'])
def test_invalid_ids_do_not_create_folders(tmp_path, identity):
    with pytest.raises(ValueError):
        workspace.initialize(identity, tmp_path)
    assert not list(tmp_path.iterdir())


def test_conflicting_readiness_is_rejected_without_changes(tmp_path):
    folder = tmp_path / 'ir1234'
    folder.mkdir()
    state = folder / 'engagement.json'
    state.write_text(json.dumps({'engagement_id': 'ir-other'}))
    before = state.read_bytes()
    with pytest.raises(ValueError, match='different investigation'):
        workspace.initialize('ir1234', tmp_path)
    assert state.read_bytes() == before
    assert not (folder / 'AGENTS.md').exists()


def test_explicit_folder_rejects_identity_and_parent_conflicts(tmp_path):
    with pytest.raises(ValueError):
        workspace.initialize('ir1234', tmp_path, str(tmp_path / 'different'))
    with pytest.raises(SystemExit):
        workspace.main(['--id', 'ir1234', '--case-root', str(tmp_path), '--investigation-dir', str(tmp_path / 'other/ir1234')])


def test_parallel_projects_and_repeat_initialization(tmp_path):
    ids = ['ir-one', 'ir-two', 'ir-one', 'ir-two']
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda identity: workspace.initialize(identity, tmp_path), ids))
    assert {p.name for p in tmp_path.iterdir()} == {'ir-one', 'ir-two'}
    for result, identity in zip(results, ids):
        assert result['investigation_dir'] == str(tmp_path / identity)
    assert sum(r['guidance_created'] for r in results) == 2


def test_discovery_is_bounded_and_excludes_external_symlinks(tmp_path):
    folder = tmp_path / 'ir1234'
    for i in range(501):
        p = folder / f'hunts/H.{i}/analysis-hunt.md'
        p.parent.mkdir(parents=True)
        p.write_text('report')
    outside = tmp_path / 'external-report.md'
    outside.write_text('external')
    (folder / 'engagement.json').symlink_to(outside)
    # A malformed readiness file is rejected before any guidance is created.
    with pytest.raises(ValueError):
        workspace.initialize('ir1234', tmp_path)
    (folder / 'engagement.json').unlink()
    result = workspace.initialize('ir1234', tmp_path)
    assert len(result['existing_outputs']) == 500
    assert result['outputs_truncated']


def test_init_does_not_invoke_readiness_or_read_global_project(tmp_path, capsys, monkeypatch, offline_config):
    monkeypatch.setenv('CASE_INVESTIGATION_DIR', str(tmp_path / 'wrong'))
    with patch('vraptor.readiness.main', side_effect=AssertionError('network readiness invoked')):
        assert cli.main(['setup', 'init', '--id', 'ir1234', '--case-root', str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['investigation_dir'] == str(tmp_path / 'ir1234')
    assert not (tmp_path / 'wrong').exists()


@pytest.mark.parametrize('process_override', [False, True])
def test_startup_checks_environment_precedence_and_profile_without_secrets(offline_config, monkeypatch, process_override):
    root = offline_config
    shared = root / 'home/.codex/.env'
    shared.parent.mkdir()
    shared.write_text('AI_SKILLS_ANALYST_AGENT_MODEL=shared-model\nTEST_KEY=shared-secret\n')
    config = root / 'agents.toml'
    config.write_text('''schema_version = 2
[selection]
default_profile = "review"
[connections.test]
provider = "openai"
api_key_env = "TEST_KEY"
[profiles.review]
connection = "test"
model = "profile-model"
''')
    (root / '.env').write_text(
        f'AI_SKILLS_ANALYST_AGENT_CONFIG_FILE={config}\n'
        'AI_SKILLS_ANALYST_AGENT_MODEL=repository-model\nTEST_KEY=repository-secret\n'
    )
    if process_override:
        monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_MODEL', 'process-model')
    report = workspace.configuration_checks()
    assert report['status'] == 'ready'
    assert [item['status'] for item in report['dotenv']] == ['loaded', 'loaded']
    analyst = report['analyst_agent']
    effective = analyst['configuration']['execution']['effective']
    assert effective['model'] == ('process-model' if process_override else 'repository-model')
    assert effective['execution_profile'] == 'review'
    assert effective['config_file'] == str(config)
    assert analyst['configuration']['credentials'][0]['present']
    assert analyst['authentication'] == 'not_checked'
    assert analyst['inference'] == 'not_tested'
    assert 'shared-secret' not in json.dumps(report)
    assert 'repository-secret' not in json.dumps(report)


@pytest.mark.parametrize('problem', ['credential', 'invalid_config', 'unreadable_dotenv', 'disabled', 'dependency'])
def test_configuration_problems_do_not_block_folder_creation(offline_config, monkeypatch, capsys, problem):
    from vraptor.agent import manage

    root = offline_config
    monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE', 'application')
    monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_TRANSPORT', 'api')
    if problem != 'credential':
        monkeypatch.setenv('OPENAI_API_KEY', 'never-print-this')
    if problem == 'invalid_config':
        config = root / 'broken.toml'
        config.write_text('invalid secret = "never-print-this')
        monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_CONFIG_FILE', str(config))
    elif problem == 'unreadable_dotenv':
        (root / '.env').write_bytes(b'\xff')
    elif problem == 'disabled':
        monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_ENABLED', 'false')
    elif problem == 'dependency':
        def missing_dependency(_):
            raise manage.PackageNotFoundError('openai')
        monkeypatch.setattr(manage, 'version', missing_dependency)
    args = ['setup', 'init', '--id', 'project-a', '--case-root', str(root / 'investigations')]
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'initialized'
    assert result['configuration_checks']['status'] == 'needs_attention'
    assert result['configuration_checks']['analyst_agent']['issues']
    assert 'never-print-this' not in json.dumps(result)
    folder = root / 'investigations/project-a'
    assert {path.name for path in folder.iterdir()} == {'AGENTS.md'}
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'reused'


def test_missing_dotenv_is_optional_with_complete_process_configuration(offline_config, monkeypatch):
    monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE', 'application')
    monkeypatch.setenv('AI_SKILLS_ANALYST_AGENT_TRANSPORT', 'api')
    monkeypatch.setenv('OPENAI_API_KEY', 'never-print-this')
    report = workspace.configuration_checks()
    assert report['status'] == 'ready'
    assert [item['status'] for item in report['dotenv']] == ['missing', 'missing']


@pytest.mark.parametrize('problem', ['malformed', 'missing_env'])
def test_invalid_operational_settings_reported_after_folder_creation(offline_config, capsys, problem):
    root = offline_config
    settings_file = root / 'operational.toml'
    settings_file.write_text(
        'unexpected secret = "never-print-this'
        if problem == 'malformed' else
        'schema_version = 1\n[credentials]\nenv_file="missing.env"\n'
    )
    result = cli.main(['setup', 'init', '--id', 'ir1234', '--settings-file', str(settings_file)])
    assert result == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report['investigation_dir'] == str(root / 'home/cases/ir1234')
    assert report['configuration_checks']['settings']['status'] == 'needs_configuration'
    assert report['configuration_checks']['analyst_agent']['issues']
    assert 'never-print-this' not in output
    assert (root / 'home/cases/ir1234/AGENTS.md').is_file()
