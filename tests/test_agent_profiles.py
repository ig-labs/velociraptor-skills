from unittest.mock import patch

import pytest
from vraptor.agent import profiles


def test_analysis_profiles_keep_intent_and_depth():
    config = profiles.load_agent_profile_config()
    assert tuple(config.profiles) == profiles.PROFILE_NAMES
    assert tuple(config.response_depths) == profiles.RESPONSE_DEPTH_NAMES
    assert config.profiles['host_forensics'].default_depth == 'deep'
    assert 'UTC timeline' in config.profiles['host_forensics'].output_contract
    assert 'prevalence' in config.profiles['compromise_assessment'].output_contract
    assert not hasattr(config, 'runtime')


@pytest.mark.parametrize('value,expected', [('incident-response','incident_response'), ('ad-hoc-hunt','targeted_hunt'), ('host-forensics','host_forensics')])
def test_profile_aliases(value, expected):
    assert profiles.normalize_profile_name(value) == expected


def test_invalid_default_depth_fails(tmp_path):
    config = tmp_path / 'profiles.toml'
    config.write_text(profiles.PROFILES_PATH.read_text().replace('default_depth = "deep"', 'default_depth = "missing"'))
    profiles.load_agent_profile_config.cache_clear()
    try:
        with patch.object(profiles, 'PROFILES_PATH', config), pytest.raises(ValueError, match='Unknown response depth'):
            profiles.load_agent_profile_config()
    finally:
        profiles.load_agent_profile_config.cache_clear()
