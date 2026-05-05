from drift_detector import detect_drifts, compare_resources


def _vm(resource_id="vm-001", instance_type="t2.micro", tags=None, rules=None):
    return {
        "resource_id": resource_id,
        "type": "VM",
        "instance_type": instance_type,
        "tags": tags or {},
        "security_groups": [{"group_id": "sg-001", "rules": rules or []}],
    }


def _lb(resource_id="lb-001", listeners=None, tags=None):
    return {
        "resource_id": resource_id,
        "type": "LoadBalancer",
        "listeners": listeners or [],
        "tags": tags or {},
    }


# ---------------------------------------------------------------------------
# Regla 1 — Instance type mismatch
# ---------------------------------------------------------------------------

def test_detect_instance_type_drift():
    baseline = _vm(instance_type="t2.micro")
    current  = _vm(instance_type="t2.large")
    drifts = detect_drifts(baseline, current)
    assert len(drifts) == 1
    assert drifts[0]["severity"] == "High"
    assert "t2.micro" in drifts[0]["description"]
    assert "t2.large" in drifts[0]["description"]


def test_no_drift_same_instance_type():
    resource = _vm(instance_type="t2.micro")
    assert detect_drifts(resource, resource) == []


# ---------------------------------------------------------------------------
# Regla 2 — Security group rule deviation
# ---------------------------------------------------------------------------

def test_detect_security_group_added_rule():
    rule_http = {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}
    rule_ssh  = {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"}
    baseline = _vm(rules=[rule_http])
    current  = _vm(rules=[rule_http, rule_ssh])
    drifts = detect_drifts(baseline, current)
    added = [d for d in drifts if "Security rule added" in d["description"]]
    assert len(added) == 1
    assert added[0]["severity"] == "Critical"
    assert "22" in added[0]["description"]


def test_detect_security_group_removed_rule():
    rule_http = {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}
    rule_ssh  = {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"}
    baseline = _vm(rules=[rule_http, rule_ssh])
    current  = _vm(rules=[rule_http])
    drifts = detect_drifts(baseline, current)
    removed = [d for d in drifts if "Security rule removed" in d["description"]]
    assert len(removed) == 1
    assert removed[0]["severity"] == "High"


# ---------------------------------------------------------------------------
# Regla 3 — Missing or incorrect tags
# ---------------------------------------------------------------------------

def test_detect_missing_tag():
    baseline = _vm(tags={"owner": "team-a", "environment": "production"})
    current  = _vm(tags={"environment": "production"})
    drifts = detect_drifts(baseline, current)
    missing = [d for d in drifts if "missing" in d["description"]]
    assert len(missing) == 1
    assert missing[0]["severity"] == "Medium"
    assert "owner" in missing[0]["description"]


def test_detect_changed_tag():
    baseline = _vm(tags={"environment": "production"})
    current  = _vm(tags={"environment": "staging"})
    drifts = detect_drifts(baseline, current)
    changed = [d for d in drifts if "changed" in d["description"]]
    assert len(changed) == 1
    assert changed[0]["severity"] == "Medium"
    assert "production" in changed[0]["description"]
    assert "staging" in changed[0]["description"]


# ---------------------------------------------------------------------------
# Regla 4 — Listener changes (LoadBalancer)
# ---------------------------------------------------------------------------

def test_detect_listener_added():
    baseline = _lb(listeners=[{"protocol": "HTTP",  "port": 80}])
    current  = _lb(listeners=[{"protocol": "HTTP",  "port": 80},
                               {"protocol": "HTTPS", "port": 443}])
    drifts = detect_drifts(baseline, current)
    added = [d for d in drifts if "Listener added" in d["description"]]
    assert len(added) == 1
    assert added[0]["severity"] == "Low"
    assert "HTTPS" in added[0]["description"]


def test_detect_listener_removed():
    baseline = _lb(listeners=[{"protocol": "HTTP",  "port": 80},
                               {"protocol": "HTTPS", "port": 443}])
    current  = _lb(listeners=[{"protocol": "HTTP", "port": 80}])
    drifts = detect_drifts(baseline, current)
    removed = [d for d in drifts if "Listener removed" in d["description"]]
    assert len(removed) == 1
    assert removed[0]["severity"] == "High"


# ---------------------------------------------------------------------------
# Sin drift cuando baseline == current
# ---------------------------------------------------------------------------

def test_no_drift_when_equal():
    resource = _vm(
        instance_type="t2.micro",
        tags={"environment": "production"},
        rules=[{"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}],
    )
    assert detect_drifts(resource, resource) == []


# ---------------------------------------------------------------------------
# compare_resources — recursos nuevos y faltantes
# ---------------------------------------------------------------------------

def test_compare_resources_new_resource():
    baselines = [_vm("vm-001")]
    currents  = [_vm("vm-001"), _vm("vm-002")]
    drifts = compare_resources(baselines, currents)
    new = [d for d in drifts if "New resource" in d["description"]]
    assert len(new) == 1
    assert new[0]["resource_id"] == "vm-002"
    assert new[0]["severity"] == "Medium"


def test_compare_resources_missing_resource():
    baselines = [_vm("vm-001"), _vm("vm-002")]
    currents  = [_vm("vm-001")]
    drifts = compare_resources(baselines, currents)
    missing = [d for d in drifts if "missing from current" in d["description"]]
    assert len(missing) == 1
    assert missing[0]["resource_id"] == "vm-002"
    assert missing[0]["severity"] == "High"


def test_compare_resources_sample_data():
    """Verifica los 4 drifts esperados contra los datos de ejemplo del challenge."""
    import json, os
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root, "data", "baseline.json")) as f:
        baseline = json.load(f)
    with open(os.path.join(root, "data", "current.json")) as f:
        current = json.load(f)

    drifts = compare_resources(baseline, current)
    assert len(drifts) == 4

    severities = {d["severity"] for d in drifts}
    assert "Critical" in severities
    assert "High" in severities
    assert "Medium" in severities
    assert "Low" in severities