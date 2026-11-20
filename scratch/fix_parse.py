with open('hsoc/soar/actions.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix line 153 extra closing parenthesis
text = text.replace(
    'protected_users = [u.lower() for u in protected.get("users", ["root", "administrator", "system", "hsoc"]))]',
    'protected_users = [u.lower() for u in protected.get("users", ["root", "administrator", "system", "hsoc"])]'
)

# Replace parse_step_to_action up to class ContainmentAction cleanly
p_start = text.find('def parse_step_to_action')
c_start = text.find('class ContainmentAction')

new_parse_code = """def parse_step_to_action(step_text: str, incident_data: dict | Any = None) -> tuple[str, str]:
    \"\"\"
    Extract action_type and target from a human-readable recommendation string.
    The action target MUST come from the recommended step itself if present,
    never from another incident field.
    \"\"\"
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
        ip_match = re.search(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", text)
        host_match = re.search(r"\\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\\b", text, re.I)

        if ip_match:
            target = ip_match.group(0)
        elif host_match:
            target = host_match.group(0)

        # If no direct match, check token after host
        if not target:
            after_host = re.search(r"\\bhost\\s+([a-zA-Z0-9.-]+)\\b", text, re.I)
            if after_host and after_host.group(1).lower() not in ["from", "the", "and", "to", "subnets"]:
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
        user_kw_match = re.search(r"\\b(?:user|account)\\s+([a-zA-Z0-9._-]+)\\b", text, re.I)
        verb_match = re.search(r"\\b(?:disable|revoke|lock)\\s+(?:user\\s+|account\\s+)?([a-zA-Z0-9._-]+)\\b", text, re.I)
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
        ip_match = re.search(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", text)
        if ip_match:
            target = ip_match.group(0)
        else:
            host_match = re.search(r"\\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\\b", text, re.I)
            if host_match:
                res = resolve_asset_entity(host_match.group(0))
                target = res.get("resolved_ip") or host_match.group(0)

        if not target:
            if incident_data:
                target = incident_data.get("src_ip") if isinstance(incident_data, dict) else getattr(incident_data, "src_ip", None)
            target = target or "192.168.56.200"

        return "block_ip", target
"""

text = text[:p_start] + new_parse_code + "\n\n\n" + text[c_start:]

with open('hsoc/soar/actions.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('Successfully cleaned up parse_step_to_action')
