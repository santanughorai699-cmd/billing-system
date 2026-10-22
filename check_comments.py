import re

with open("index.py", "r", encoding="utf-8") as f:
    content = f.read()

lines = content.splitlines()
for idx, line in enumerate(lines, 1):
    stripped = line.strip()
    if stripped.startswith("#"):
        print(f"Line {idx} (full comment): {line}")
    elif "#" in line:
        print(f"Line {idx} (inline comment): {line}")
    elif stripped.startswith('"""') or stripped.startswith("'''"):
        print(f"Line {idx} (docstring): {line}")
