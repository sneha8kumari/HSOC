with open('hsoc/soar/actions.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = """    # 1. Determine action type
    if any(k in text_lower for k in ["isolate", "vlan", "quarantine"]):
        action_type = "isolate_host"
    elif any(k in text_lower for k in ["disable", "lock", "revoke"]):
        action_type = "disable_user"
    elif any(k in text_lower for k in ["block", "firewall", "iptables", "drop"]):
        action_type = "block_ip"
    elif "user" in text_lower or "account" in text_lower:
        action_type = "disable_user"
    else:
        action_type = "block_ip" """

replacement = """    # 1. Determine action type (note: check 'block' before 'lock' to avoid matching 'b-lock')
    if any(k in text_lower for k in ["block", "firewall", "iptables", "drop"]):
        action_type = "block_ip"
    elif any(k in text_lower for k in ["isolate", "vlan", "quarantine"]):
        action_type = "isolate_host"
    elif any(k in text_lower for k in ["disable", "revoke", "user", "account"]) or bool(re.search(r"\\block\\b", text_lower)):
        action_type = "disable_user"
    else:
        action_type = "block_ip" """

if target.strip() in text:
    text = text.replace(target.strip(), replacement.strip(), 1)
    with open('hsoc/soar/actions.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Fixed block vs lock check')
else:
    print('Target not found')
