#!/usr/bin/env python3
"""Query boards.json from shell scripts and justfile."""

import json
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / "boards.json"


def main():
    boards = json.loads(MANIFEST.read_text())["boards"]
    by_name = {b["name"]: b for b in boards}
    args = sys.argv[1:]

    if not args or args[0] == "list":
        print(" ".join(b["name"] for b in boards))
        return

    if args[0] == "get" and len(args) == 3:
        name, field = args[1], args[2]
        if name not in by_name or field not in by_name[name]:
            sys.exit(f"unknown board/field: {name} {field}")
        print(by_name[name][field])
        return

    sys.exit("usage: boards.py [list | get <board> <field>]")


if __name__ == "__main__":
    main()
