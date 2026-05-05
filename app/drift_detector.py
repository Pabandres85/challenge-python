def detect_drifts(baseline: dict, current: dict) -> list[dict]:
    """
    Compara dos recursos y retorna lista de drifts detectados.
    Cada drift: {resource_id, type, description, severity}
    """
    drifts = []
    resource_id = current.get("resource_id", baseline.get("resource_id"))
    resource_type = current.get("type", baseline.get("type"))

    # Regla 1: Instance type mismatch (solo VM)
    if resource_type == "VM":
        baseline_itype = baseline.get("instance_type")
        current_itype = current.get("instance_type")
        if baseline_itype and current_itype and baseline_itype != current_itype:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Instance type changed from {baseline_itype} to {current_itype}",
                "severity": "High",
            })

    # Regla 2: Security group rule deviation (solo VM)
    if resource_type == "VM":
        def extract_rules(resource):
            rules = set()
            for sg in resource.get("security_groups", []):
                for rule in sg.get("rules", []):
                    rules.add((rule.get("protocol"), rule.get("port"), rule.get("source")))
            return rules

        baseline_rules = extract_rules(baseline)
        current_rules = extract_rules(current)

        for protocol, port, source in current_rules - baseline_rules:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Security rule added: {protocol}/{port} from {source}",
                "severity": "Critical",
            })
        for protocol, port, source in baseline_rules - current_rules:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Security rule removed: {protocol}/{port} from {source}",
                "severity": "High",
            })

    # Regla 3: Missing or incorrect tags (todos los tipos)
    baseline_tags = baseline.get("tags", {})
    current_tags = current.get("tags", {})
    for key, value in baseline_tags.items():
        if key not in current_tags:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Tag '{key}' missing",
                "severity": "Medium",
            })
        elif current_tags[key] != value:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Tag '{key}' changed from '{value}' to '{current_tags[key]}'",
                "severity": "Medium",
            })

    # Regla 4: Listener changes (solo LoadBalancer)
    if resource_type == "LoadBalancer":
        baseline_listeners = {(l.get("protocol"), l.get("port")) for l in baseline.get("listeners", [])}
        current_listeners = {(l.get("protocol"), l.get("port")) for l in current.get("listeners", [])}

        for protocol, port in current_listeners - baseline_listeners:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Listener added: {protocol}/{port}",
                "severity": "Low",
            })
        for protocol, port in baseline_listeners - current_listeners:
            drifts.append({
                "resource_id": resource_id,
                "type": resource_type,
                "description": f"Listener removed: {protocol}/{port}",
                "severity": "High",
            })

    return drifts


def compare_resources(baselines: list[dict], currents: list[dict]) -> list[dict]:
    """
    Compara listas completas de recursos.
    Llama detect_drifts por cada resource_id presente en ambas.
    Recursos nuevos (en current pero no en baseline) → drift Medium.
    Recursos faltantes (en baseline pero no en current) → drift High.
    """
    all_drifts = []
    baseline_map = {r["resource_id"]: r for r in baselines}
    current_map = {r["resource_id"]: r for r in currents}

    for resource_id, current in current_map.items():
        if resource_id in baseline_map:
            all_drifts.extend(detect_drifts(baseline_map[resource_id], current))
        else:
            all_drifts.append({
                "resource_id": resource_id,
                "type": current.get("type", "Unknown"),
                "description": f"New resource detected: {resource_id}",
                "severity": "Medium",
            })

    for resource_id, baseline in baseline_map.items():
        if resource_id not in current_map:
            all_drifts.append({
                "resource_id": resource_id,
                "type": baseline.get("type", "Unknown"),
                "description": f"Resource missing from current state: {resource_id}",
                "severity": "High",
            })

    return all_drifts