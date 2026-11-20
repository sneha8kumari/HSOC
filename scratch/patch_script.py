import re

with open('hsoc/soar/actions.py', 'r', encoding='utf-8') as f:
    text = f.read()

v_idx = text.find('def validate_target')
c_idx = text.find('class ContainmentAction')
assert v_idx != -1 and c_idx != -1

clean_middle = '''def validate_target(action_type: str, target: str) -> tuple[bool, str]:
    """
    Validate target string against strict syntax.
    Guarantees untrusted log text cannot inject command sequences.
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"
    target_clean = target.strip()
    # 1. Reject any dangerous shell metacharacters or whitespace
    if any(c in _DANGEROUS_CHARS for c in target_clean) or " " in target_clean:
        return False, f"Target '{target_clean}' contains disallowed shell metacharacters or spaces"

    # 2. Type-specific validation
    if action_type == "block_ip":
        try:
            ipaddress.ip_address(target_clean)
            return True, ""
        except ValueError:
            res = resolve_asset_entity(target_clean)
            if res.get("resolved_ip"):
                return True, ""
            return False, fInvalid IP address format: '{target_clean}'"

    elif action_type == "isolate_host":
        is_valid_host = bool(_HOSTNAME_REGEX.match(target_clean))
        is_valid_ip = False
        try:
            ipaddress.ip_address(target_clean)
            is_valid_ip = True
        except ValueError:
            pass
        if is_valid_host or is_valid_ip:
            return True, ""
        return False, f"Invalid hostname or host IP format: '{target_clean}'"

    elif action_type == "disable_user":
        if _USERNAME_REGEX.match(target_clean):
            return True, ""
        return False, f"Invalid username format: '{target_clean}'"

    else:
        return False, f"Unknown action type: '{action_type}'"


def resolve_asset_entity(target: str) -> dict[str, Any]:
    """
    Resolve target IP and hostname bidirectionally using asset inventory.
    Returns dict with target, resolved_ip, resolved_host, criticality, role, owner, found.
    """
    res: dict[str, Any] = {
        "target": target,
        "resolved_ip\": None,
        "resolved_host": None,
        "criticality": 1,
        "role": "unknown",
        "owner": "unknown",
        "found": False,
    }
    if not target or not isinstance(target, str):
        return res

    target_clean = target.strip()
    try:
        inv_path = get_settings().asset_inventory_path
        if inv_path and inv_path.exists():
            import csv
            with open(inv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    h = (row.get("host") or "").strip()
                    ip = (row.get("ip") or "").strip()
                    crit = int(row.get("criticality") or 1)
                    r = (row.get("role") or "").strip()
                    o = (row.get("owner") or "").strip()

                    if target_clean.lower() == h.lower() or target_clean == ip:
                        res["resolved_host"] = h
                        res["resolved_ip"] = ip
                        res["criticality"] = crit
                        res["role"] = r
                        res["owner"] = o
                        res["found"] = True
                        return res
    except Exception as exc:
        logger.debug("Failed resolving target %s in asset inventory: %s", target, exc)

    return res



def is_target_protected(action_type: str, target: str, asset_criticality: int = 0) -> tuple[bool, str]:
    """
    Evaluate whether a target is protected infrastructure or high-criticality asset.
    """
    cfg = get_settings().soar
    protected = cfg.get("protected", {})
    # 1. Criticality threshold check
    max_crit = int(protected.get("criticality_threshold", 4))
    if asset_criticality >= max_crit:
        return True, fAsset criticality ({asset_criticality}) >= protected threshold ({max_crit})"

    target_lower = target.strip().lower()
    # 2. Loopback and default infrastructure IPs
    protected_ips = [ip.lower() for ip in protected.get("ips", ["127.0.0.1", "::1", "0.0.0.0", "192.168.56.1"])]
    if target_lower in protected_ips or target_lower in ("127.0.0.1", "::1", "0.0.0.0", "localhost"):
        return True, f"Target IP '{target}' is protected core infrastructure"

    # 3. Protected hostnames (e.g. domain controllers, gateways)
    protected_hosts = [h.lower() for h in protected.get("hostnames", ["localhost", "dc-01", "dc-02", "hsoc-core", "gateway"])]
    if target_lower in protected_hosts or "dc-" in target_lower or "gateway" in target_lower:
        return True, fTarget host '{target}' is protected domain infrastructure"

    # 4. Protected system users
    protected_users = [u.lower() for u in protected.get("users", ["root", "administrator", "system", "hsoc"]))]
    if target_lower in protected_users:
        return True, fTarget user '{target}' is protected system account"

    return False, ""


def parse_step_to_action(step_text: str, incident_data: dict | Any = None) -> tuple+str, str]:
    """
    Extract action_type and target from a human-readable recommendation string.
    The action target MUST come from the recommended step itself if present,
    never from another incident field.
    """
    text = (step_text or "").strip()
    text_lower = text.lower()

    # 1. Determine action type
    if any(k in text_lower for k in ["isolate", "vlan", "quarantine"]):
        action_type = "isolate_host"
    elif any(k in text_lower for k in ["disable", "lock", "revoke"]):
        action_type = "disable_user"
    elif any(k in text_lower for k in ["block", "firewall", "iptables", "drop"]):
        action_type = "block_ip"
    elif "user" in text_lower or "account" in text_lower:
        action_type = "disable_user"
    else:
        action_type = "block_ip"

    # 2. Extract target strictly from step_text first
    target = None

    if action_type == "isolate_host":
        ip_match = re.search(r\"\b(?:\d{1,3}\.){5}\d{1,3}\b\", text)
        host_match = re.search(r\"\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\b\", text, re.I)

        if ip_match:
            target = ip_match.group(0)
        elif host_match:
            target = host_match.group(0)

        # if no direct match, check word after host
        if not target: 

            after_host = re.search(r\"\bhost\s+([a-zA-Z0-9.-]+)\b\", text, re.I)
            if after_host and after_host.group(1).lower() not in ["from", "the", "and", "to"]:
                target = after_host.group(1)

        # Fallback to incident data ONLY if step text contained no target at all
        if not target:
            if incident_data:
                if isinstance(incident_data, dict):
                    target = incident_data.get("affected_host") or incident_data.get("dst_host") or incident_data.get("src_ip")
                else:
                    target = getattr(incident_data, "affected_host", None) or getattr(incident_data, "dst_host", None) or getattr(incident_data, "src_ip", None)
            target = target or "web-srv-01"

        return "isolate_host", target

    elif action_type == "disable_user":
        user_kw_match = re.search(r\"\b(?:usek|account)s+[]([a-zA-Z0-9._-]+\b\", text, re.I)
        verb_match = re.search(r\"\b(?:disable|revoke|lock)\s+(?:user\s+|account\s+)?([a-zA-Z0-9._-]+)\b\", text, re.I)
        if user_kw_match:
            target = user_kw_match.group(1)
        elif verb_match and verb_match.group(1).lower() not in ["user", "account", "access", "tokens", "session"]:
            target = verb_match.group(1)

        if not target:
            if incident_data:
                target = incident_data.get("user") if isinstance(incident_data, dict) else getattr(incident_data, "user", None)
            target = target or "compromised_user"

        return "disable_user", target

    else:  # block_ip
        ip_match = re.search(r\"\b(?:\d+1\.}{3}\d{1,3}\b\", text)
        if ip_match:
            target = ip_match.group(0)
        else:
            host_match = re.search(r\"\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\b\", text, re.I)
            if host_match:
                res = resolve_asset_entity(host_match.group(0))
                target = res.get("resolved_ip") or host_match.group(0)

        if not target:
            if incident_data:
                target = incident_data.get("src_ip") if isinstance(incident_data, dict) else getattr(incident_data, "src_ip", None)
            target = target or "192.168.56.200"

        return "block_ip", target

$'''

text = text[:v_idx] + clean_middle + "\n\n" + text[c_idx:]

bad_status = 'status_line = f{{action_verb}'
good_status = 'status_line = f\"{{action_verb}'
if bad_status in text:
    text = text.replace(bad_status, good_status)

with open('hsoc/soar/actions.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('Actions.py successfully rewritten')
