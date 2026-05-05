import json
import os

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------

def test_status_endpoint(client):
    resp = client.get("/status")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /users
# ---------------------------------------------------------------------------

def test_users_endpoint(client, mock_db):
    resp = client.get("/users")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "users" in data
    assert set(data["users"]) == {"alice", "bob", "admin"}


# ---------------------------------------------------------------------------
# GET /admin/flag
# ---------------------------------------------------------------------------

def test_flag_without_token(client):
    resp = client.get("/admin/flag")
    assert resp.status_code == 403


def test_flag_with_invalid_token(client):
    resp = client.get("/admin/flag", headers={"Authorization": "Bearer notavalidtoken"})
    assert resp.status_code == 403


def test_flag_with_valid_token(client, valid_token, mock_db):
    resp = client.get("/admin/flag", headers={"Authorization": f"Bearer {valid_token}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "flag" in data
    assert "FLAG{" in data["flag"]


def test_flag_wrong_role_returns_403(client, private_key, mock_db):
    import jwt
    token = jwt.encode({"user": "alice", "role": "user"}, private_key, algorithm="RS256")
    resp = client.get("/admin/flag", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /resources/ingest — validación de input
# ---------------------------------------------------------------------------

def test_ingest_empty_body(client):
    resp = client.post("/resources/ingest", data="", content_type="application/json")
    assert resp.status_code == 400


def test_ingest_invalid_json(client):
    resp = client.post("/resources/ingest", data="not-json", content_type="application/json")
    assert resp.status_code == 400


def test_ingest_missing_resource_id(client, mock_db):
    payload = [{"type": "VM", "instance_type": "t2.micro"}]
    resp = client.post("/resources/ingest", json=payload)
    assert resp.status_code == 400


def test_ingest_missing_type(client, mock_db):
    payload = [{"resource_id": "vm-001", "instance_type": "t2.micro"}]
    resp = client.post("/resources/ingest", json=payload)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /resources/ingest — payload válido
# ---------------------------------------------------------------------------

def test_ingest_valid_payload_single_object(client, mock_db):
    with open(os.path.join(_root, "data", "current.json")) as f:
        current = json.load(f)
    # Enviar como objeto único
    resp = client.post("/resources/ingest", json=current[0])
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["processed"] == 1
    assert "drifts_detected" in data
    assert isinstance(data["drifts"], list)


def test_ingest_valid_payload_array(client, mock_db):
    with open(os.path.join(_root, "data", "current.json")) as f:
        current = json.load(f)
    resp = client.post("/resources/ingest", json=current)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["processed"] == 2
    assert data["drifts_detected"] == 4
    assert len(data["drifts"]) == 4


def test_ingest_detects_correct_severities(client, mock_db):
    with open(os.path.join(_root, "data", "current.json")) as f:
        current = json.load(f)
    resp = client.post("/resources/ingest", json=current)
    data = resp.get_json()
    severities = {d["severity"] for d in data["drifts"]}
    assert "Critical" in severities
    assert "High" in severities
    assert "Medium" in severities
    assert "Low" in severities


def test_ingest_no_drift_when_current_equals_baseline(client, mock_db):
    with open(os.path.join(_root, "data", "baseline.json")) as f:
        baseline = json.load(f)
    # Ingestar el baseline como current → sin drifts
    resp = client.post("/resources/ingest", json=baseline)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["drifts_detected"] == 0


# ---------------------------------------------------------------------------
# GET /drifts/summary
# ---------------------------------------------------------------------------

def test_drifts_summary_structure(client, mock_db):
    resp = client.get("/drifts/summary")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "by_type" in data
    assert "by_severity" in data
    assert "total" in data
    assert isinstance(data["total"], int)


def test_drifts_summary_values(client, mock_db):
    resp = client.get("/drifts/summary")
    data = resp.get_json()
    assert data["by_type"] == {"VM": 3, "LoadBalancer": 1}
    assert data["by_severity"] == {"Critical": 1, "High": 1, "Medium": 1, "Low": 1}
    assert data["total"] == 4