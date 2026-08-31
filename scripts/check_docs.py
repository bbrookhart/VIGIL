#!/usr/bin/env python3
"""Fail when a local Markdown link points at a missing repository path."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#", "data:")


def main() -> int:
    failures: list[str] = []
    for document in sorted([ROOT / "README.md", *ROOT.glob("docs/**/*.md")]):
        text = document.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), 1):
            for raw_target in LINK.findall(line):
                target = raw_target.strip().split()[0].strip("<>")
                target = target.split("#", 1)[0]
                if not target or target.startswith(SKIP_PREFIXES):
                    continue
                resolved = (document.parent / target).resolve()
                if not resolved.is_relative_to(ROOT) or not resolved.exists():
                    failures.append(
                        f"{document.relative_to(ROOT)}:{line_number}: missing {raw_target}"
                    )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("verified local Markdown link targets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
