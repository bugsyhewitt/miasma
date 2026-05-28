"""miasma command-line interface.

Two-phase flow: recon a single host with nmap, then run the requested
verification plugins against the fingerprinted target and emit JSON findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from miasma import __version__
from miasma.recon import recon
from miasma.runner import available_plugins, run_plugins


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miasma",
        description=(
            "Lightweight, plugin-driven verifier of high-confidence "
            "vulnerabilities. Fingerprints a host with nmap, then runs benign "
            "verification probes for the CVEs you care about."
        ),
    )
    parser.add_argument(
        "--target",
        required=False,
        help="Host to scan and probe (IP or hostname), e.g. 127.0.0.1",
    )
    parser.add_argument(
        "--plugins",
        default="",
        help=(
            "Comma-separated plugin names to run (file stems under "
            "miasma/plugins). Empty runs none. Use --list-plugins to see them."
        ),
    )
    parser.add_argument(
        "--port-range",
        default="1-1000",
        help="nmap port spec for the recon phase (default: 1-1000).",
    )
    parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        metavar="PATH",
        help=(
            "Write the JSON report to this file instead of stdout, enabling "
            "piping into downstream tooling. Use '-' for stdout (the default)."
        ),
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List available plugins and exit.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"miasma {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_plugins:
        for name in available_plugins():
            print(name)
        return 0

    if not args.target:
        parser.error("--target is required (unless using --list-plugins)")

    target = recon(args.target, args.port_range)
    plugin_names = [p.strip() for p in args.plugins.split(",") if p.strip()]
    findings = run_plugins(target, plugin_names)

    report = {
        "target": target.host,
        "port_range": args.port_range,
        "open_ports": target.open_ports(),
        "plugins": plugin_names,
        "findings": [f.to_dict() for f in findings],
    }

    if args.format == "json":
        text = json.dumps(report, indent=2) + "\n"
        if args.output_file in (None, "-"):
            sys.stdout.write(text)
        else:
            with open(args.output_file, "w", encoding="utf-8") as fh:
                fh.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
