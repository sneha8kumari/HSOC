with open('hsoc/config.py', 'r', encoding='utf-8') as f:
    c = f.read()

target = '''    @property
    def soar(self) -> dict[str, Any]:
        " \\SOAR automated response settings.\\\
 return self._data.get(\soar\, {})'''

addition = '''

 @property
 def assets(self) -> dict[str, Any]:
 \\\Asset inventory and default criticality settings.\\\
 return self._data.get(\assets\, {})'''

if target in c and 'def assets' not in c:
 c = c.replace(target, target + addition, 1)
 with open('hsoc/config.py', 'w', encoding='utf-8') as f:
 f.write(c)
 print('SUCCESS')
else:
 print('ALREADY OR NOT FOUND')
