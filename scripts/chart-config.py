#!/usr/bin/env python3
"""Convert Helm's flat `show chart` metadata to an OCI chart config JSON."""

import json
import re
import sys


FIELD = re.compile(r"^([A-Za-z]+): ([^ ].*)$")


def scalar(value: str) -> str:
    if value.startswith('"'):
        result = json.loads(value)
        if not isinstance(result, str):
            raise ValueError("double-quoted chart scalar is not a string")
        return result
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ValueError("unterminated single-quoted chart scalar")
        inner = value[1:-1]
        unescaped = inner.replace("''", "")
        if "'" in unescaped:
            raise ValueError("invalid single-quoted chart scalar")
        return inner.replace("''", "'")
    if value.startswith(("[", "{", "|", ">", "!", "&", "*")):
        raise ValueError("chart metadata must contain only flat string scalars")
    return value


def parse(lines: list[str]) -> dict[str, str]:
    config = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        match = FIELD.fullmatch(line)
        if match is None:
            raise ValueError("Chart.yaml holds more than flat scalars; extend this conversion")
        key, raw = match.groups()
        if key in config:
            raise ValueError(f"duplicate chart metadata field: {key}")
        config[key] = scalar(raw)
    return config


if __name__ == "__main__":
    try:
        json.dump(parse(sys.stdin.readlines()), sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
    except (ValueError, json.JSONDecodeError) as error:
        print(f"invalid Helm chart metadata: {error}", file=sys.stderr)
        sys.exit(1)
