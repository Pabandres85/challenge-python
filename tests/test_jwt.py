import os
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_PUB_PATH  = os.path.join(_root, "app", "keys", "public_key.pem")
_PRIV_PATH = os.path.join(_root, "app", "keys", "private_key.pem")


@pytest.fixture(scope="module")
def public_key():
    with open(_PUB_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


@pytest.fixture(scope="module")
def module_private_key():
    with open(_PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ---------------------------------------------------------------------------
# Firma y verificación RS256
# ---------------------------------------------------------------------------

def test_valid_jwt_accepted(module_private_key, public_key):
    token = jwt.encode({"user": "bob", "role": "cloudsec"}, module_private_key, algorithm="RS256")
    payload = jwt.decode(token, public_key, algorithms=["RS256"])
    assert payload["user"] == "bob"
    assert payload["role"] == "cloudsec"


def test_invalid_signature_rejected(module_private_key, public_key):
    token = jwt.encode({"user": "bob", "role": "cloudsec"}, module_private_key, algorithm="RS256")
    parts = token.split(".")
    bad_token = parts[0] + "." + parts[1] + ".invalidsignature"
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(bad_token, public_key, algorithms=["RS256"])


def test_wrong_algorithm_rejected(public_key):
    hs_token = jwt.encode({"user": "bob", "role": "cloudsec"}, "secret", algorithm="HS256")
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(hs_token, public_key, algorithms=["RS256"])


def test_expired_token_rejected(module_private_key, public_key):
    import time
    token = jwt.encode(
        {"user": "bob", "role": "cloudsec", "exp": int(time.time()) - 10},
        module_private_key,
        algorithm="RS256",
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])


# ---------------------------------------------------------------------------
# Claims faltantes — probados vía endpoint /admin/flag
# ---------------------------------------------------------------------------

def test_missing_role_claim_returns_403(client, private_key, mock_db):
    token = jwt.encode({"user": "bob"}, private_key, algorithm="RS256")
    resp = client.get("/admin/flag", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_missing_user_claim_returns_403(client, private_key, mock_db):
    token = jwt.encode({"role": "cloudsec"}, private_key, algorithm="RS256")
    resp = client.get("/admin/flag", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403