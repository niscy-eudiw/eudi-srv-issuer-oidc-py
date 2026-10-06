"""Builds the authorization server from config.json with throw-away keys."""

import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BACKEND_API_KEY = "k" * 40


def _test_config(tmp_path):
    with open(os.path.join(ROOT, "config.json")) as f:
        config = json.load(f)
    config = copy.deepcopy(config)
    config["logging"] = {"version": 1, "disable_existing_loggers": False, "root": {"level": "WARNING"}}
    server_info = config["op"]["server_info"]
    # Generated per test run; nothing is written into the repository.
    server_info["keys"].update(
        {
            "private_path": str(tmp_path / "jwks.json"),
            "public_path": str(tmp_path / "public_jwks.json"),
            "read_only": False,
        }
    )
    server_info["cookie_handler"]["kwargs"]["keys"]["private_path"] = str(tmp_path / "cookie_jwks.json")
    token_args = server_info["token_handler_args"]
    token_args.pop("jwks_file", None)
    token_args["jwks_def"] = {
        "private_path": str(tmp_path / "token_jwks.json"),
        "key_defs": [
            {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
            {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
        ],
        "read_only": False,
    }
    config["backend_api_key"] = BACKEND_API_KEY
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return str(path)


@pytest.fixture
def app(tmp_path):
    from idpyoidc.configure import Configuration, create_from_config_file
    from idpyoidc.server.configure import OPConfiguration

    import application
    from application import oidc_provider_init_app

    application.request_manager.__init__(default_expiry_minutes=1450)
    config = create_from_config_file(
        Configuration,
        entity_conf=[{"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}],
        filename=_test_config(tmp_path),
        base_path=ROOT,
    )
    app = oidc_provider_init_app(config.op, "oidc_op")
    app.config["TESTING"] = True
    app.authorization_redirect_url = "https://backend.test/auth_choice"
    app.backend_api_key = getattr(config, "backend_api_key", None)
    return app


@pytest.fixture
def client(app):
    return app.test_client()
