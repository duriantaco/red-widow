from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from red_widow.fixtures import FAULTY_FIXTURES, build_faulty_vsix


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an intentionally faulty Red Widow VSIX fixture.")
    parser.add_argument(
        "output",
        nargs="?",
        default="/private/tmp/red-widow-faulty.vsix",
        help="output VSIX path",
    )
    parser.add_argument(
        "--fixture",
        choices=sorted(FAULTY_FIXTURES),
        default="kitchen-sink",
        help="fixture variant to build",
    )
    args = parser.parse_args()

    output = build_faulty_vsix(Path(args.output), args.fixture)
    sys.stdout.write(f"{output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
