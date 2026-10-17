"""Reviewed contributor tool pins; SDK compatibility lives in compatibility.json."""
import json
from pathlib import Path


def get(*keys):
    if not keys or keys[0] != "tools":
        raise ValueError("Unknown tool pin namespace")
    value = json.loads((Path(__file__).resolve().parents[1] / "tools.json").read_text())
    for key in keys[1:]:
        value = value[key]
    return value
