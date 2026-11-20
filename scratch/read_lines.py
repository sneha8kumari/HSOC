with open('hsoc/soar/actions.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i in range(205, min(250, len(lines))):
    print(f'{i+1}: {lines[i]}', end='')
