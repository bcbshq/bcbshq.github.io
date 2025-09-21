#!/usr/bin/env python3
"""
Lightweight local validator (placeholder). Install jsonschema and run:
python scripts/validate_local.py data/input/org-a data/schemas/technique-schema.json
"""
import sys, json
from jsonschema import validate, ValidationError
from pathlib import Path
if len(sys.argv) < 3:
    print("Usage: validate_local.py <json-file> <schema-file>")
    sys.exit(2)
jf = Path(sys.argv[1])
sf = Path(sys.argv[2])
data = json.loads(jf.read_text(encoding='utf-8'))
schema = json.loads(sf.read_text(encoding='utf-8'))
try:
    validate(instance=data, schema=schema)
    print("Validation OK")
except ValidationError as e:
    print("Validation FAILED:", e.message)
    sys.exit(1)
