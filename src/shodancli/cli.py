from __future__ import annotations

import argparse

from shodancli import __version__
from shodancli.commands.explore import run as run_explore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shodancli",
        description="Extensible command-line client for working with the Shodan API.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    explore_parser = subparsers.add_parser(
        "explore",
        help="Discover exposed systems in IPv4 addresses and ranges.",
        description="Discover exposed systems in IPv4 addresses and ranges using the Shodan API.",
    )
    explore_parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        help="Path to a file containing one target per line. Can be passed multiple times.",
    )
    explore_parser.add_argument(
        "-r",
        "--ranges",
        action="append",
        default=[],
        help="Inline comma-separated or space-separated IPs or ranges. Can be passed multiple times.",
    )
    explore_parser.add_argument(
        "--api-key",
        default=None,
        help="Shodan API key. Defaults to SHODAN_API_KEY environment variable.",
    )
    explore_parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="HTTP timeout in seconds for Shodan requests. Default: 20.",
    )
    explore_parser.set_defaults(func=run_explore)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    return int(args.func(args))
