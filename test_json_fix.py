import sys
sys.path.append("c:\\deploy\\strix\\ctf-engine")
from tools import parse_tool_call

text1 = '''
<tool>write_file</tool>
<args>{"path": "docker-compose.yml", "content": "version: '3'\\nservices:\\n  app:\\n    build: .\\n    ports:\\n      - \\"3000:3000\\""</args>
'''

text2 = '''
<tool>write_file</tool>
<args>{"path": "docker-compose.yml", "content": "version: '3'\\nservices:\\n  app:\\n    build: .\\n    ports:\\n      - \\"3000:3000\\"
'''

t1, a1 = parse_tool_call(text1)
print(f"Test 1: {t1} -> {a1}")

t2, a2 = parse_tool_call(text2)
print(f"Test 2: {t2} -> {a2}")
