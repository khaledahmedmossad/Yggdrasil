import pytest
from delegationflow.core.config import load_settings
from delegationflow.core.exceptions import ConfigurationError


def test_settings_from_overrides():
    settings = load_settings(None, {
        "server": "dc.inlanefreight.local",
        "base_dn": "DC=example,DC=local",
        "username": "EXAMPLE\\\\analyst",
    })
    assert settings.port == 389
    assert settings.server == "dc.inlanefreight.local"


def test_rejects_password_in_yaml(tmp_path):
    config = tmp_path / "bad.yaml"
    config.write_text("server: dc\\nbase_dn: DC=x\\nusername: x\\npassword: secret\\n")
    with pytest.raises(ConfigurationError):
        load_settings(str(config), {})
