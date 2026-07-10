"""
CLI entry for sentinel.

Thin wrapper so you can also run via the installed entry point or
`python -m projects.sentinel.cli.main`.

All the real logic + new Wireshark-style --filter support lives in
../sentinel.py (argparse is handled there).
"""

import sys
from ..sentinel import main as _sentinel_main


def main():
    _sentinel_main(sys.argv[1:])


if __name__ == "__main__":
    main()
