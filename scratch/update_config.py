with open('hsoc/config.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = '''    @property
    def soar(self) -> dict[str, Any]:
        " \\SOAR automated response settings.\\\
 return self._data.get(\soar\, {})'''

replacement = ''' @property
 def soar(self) -> dict[str, Any]:
 \\\SOAR automated response settings.\\\
 return self._data.get(\soar\, {})

 @property
 def assets(self) -> dict[str, Any]:
 \\\Asset inventory and default criticality settings.\\\
 return self._data.get(\assets\, {})'''

if target in content:
 with open('hsoc/config.py', 'w', encoding='utf-8') as f:
 f.write(content.replace(target, replacement, 1))
 print('Updated hsoc/config.py successfully')
else:
 print('Target not found')
