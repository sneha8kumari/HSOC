with open('hsoc/soar/actions.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('fInvalid ', 'f"Invalid ')
text = text.replace('fRUnknown ', 'f"Unknown ')
text = text.replace('fAsset ', 'f"Asset ')
text = text.replace('fTarget ', 'f"Target ')
text = text.replace('f{action_verb}', 'f"{action_verb}')
text = text.replace('"isable_user"', '"disable_user"')
text = text.replace('tuple+str, str]:', 'tuple[str, str]:')

with open('hsoc/soar/actions.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('Done replace')
