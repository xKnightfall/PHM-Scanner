"""PHM command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phm import __version__
from phm.core.autodetect import plan_analysis
from phm.core.models import Category
from phm.core.orchestrator import InvestigationOrchestrator
from phm.core.registry import registry
from phm.core.reporting import REPORTERS, render_report, write_report
from phm.core.storage import InvestigationStore
from phm.crypto_engine import SmartCryptoEngine


ETHICS_NOTICE = (
    "Use PHM only on data, systems, identities, and organizations you are authorized to investigate. "
    "Respect privacy laws, terms of service, and scope restrictions."
)

BANNER = r"""
██████╗ ██╗  ██╗███╗   ███╗
██╔══██╗██║  ██║████╗ ████║
██████╔╝███████║██╔████╔██║
██╔═══╝ ██╔══██║██║╚██╔╝██║
██║     ██║  ██║██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝

Projekt Hail Mary
Version {version}
""".strip()


def render_banner() -> str:
    return BANNER.format(version=__version__)


def _read_input_or_file(value: str) -> str:
    path = Path(value)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return value


def _category_from_name(name: str) -> Category:
    aliases = {
        "org": Category.ORGANIZATION,
        "organization": Category.ORGANIZATION,
        "personal": Category.PERSONAL,
        "identity": Category.IDENTITY,
        "technical": Category.TECHNICAL,
        "dns": Category.DNS,
        "network": Category.NETWORK,
        "web": Category.WEB,
        "file": Category.FILE,
        "binary": Category.BINARY,
        "image": Category.IMAGE,
        "document": Category.DOCUMENT,
        "archive": Category.ARCHIVE,
        "metadata": Category.METADATA,
        "geo": Category.GEOSPATIAL,
        "geospatial": Category.GEOSPATIAL,
        "media": Category.MEDIA,
        "historical": Category.HISTORICAL,
        "history": Category.HISTORICAL,
        "crypto": Category.CRYPTO,
    }
    try:
        return aliases[name]
    except KeyError as exc:
        raise argparse.ArgumentTypeError(f"Unknown category '{name}'") from exc


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=sorted(REPORTERS), default="terminal", help="report output format")
    parser.add_argument("--output", "-o", help="write rendered report to a file instead of stdout")
    parser.add_argument("--verbose", action="store_true", help="show plugin names and raw evidence details")
    parser.add_argument("--no-banner", action="store_true", help="hide the startup banner for terminal output")
    parser.add_argument("--plugin", action="append", dest="plugins", help="run a specific internal check; may be repeated")
    parser.add_argument("--timeout", type=float, default=8.0, help="network timeout for lookups")
    parser.add_argument("--max-workers", type=int, default=4, help="maximum parallel checks")
    parser.add_argument("--cache", action="store_true", help="cache public lookup results")
    parser.add_argument("--cache-ttl", type=int, default=3600, help="lookup cache TTL in seconds")
    parser.add_argument("--cache-db", default="investigations/source_cache.db", help="SQLite database path for lookup cache")
    parser.add_argument("--save", action="store_true", help="persist the investigation report to SQLite")
    parser.add_argument("--db", default="investigations/phm.db", help="SQLite database path for --save")
    parser.add_argument("--mode", choices=("auto", "osint", "steg", "crypto"), default="auto", help="choose an investigation track; auto follows useful pivots")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phm",
        description="PHM analyzes cybersecurity targets and shows what to investigate next.",
        epilog=ETHICS_NOTICE,
    )
    parser.add_argument("--version", action="version", version=f"Projekt Hail Mary {__version__}")
    parser.add_argument("--banner", action="store_true", help="show the Projekt Hail Mary banner and exit")
    parser.add_argument("--list-plugins", action="store_true", help="list registered checks and exit")

    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="auto-detect the target type and run the right analysis")
    analyze.add_argument("target", help="file, domain, IP, URL, email, username, hash, or encoded text")
    _add_common_options(analyze)

    investigate = subparsers.add_parser("investigate", help="follow useful public clues through bounded passive pivots")
    investigate.add_argument("target", help="starting clue")
    investigate.add_argument("--max-nodes", type=int, default=12, help="maximum unique clues to investigate")
    _add_common_options(investigate)

    for command in ["technical", "personal", "organization", "org", "geospatial", "media", "historical"]:
        sub = subparsers.add_parser(command, help=f"run {command} checks")
        sub.add_argument("target", help="investigation target")
        _add_common_options(sub)

    for command in ["domain", "ip", "dns", "web", "email", "username", "hash", "file", "binary", "image", "document", "archive", "metadata"]:
        sub = subparsers.add_parser(command, help=f"run {command} analysis directly")
        sub.add_argument("target", help=f"{command} target")
        _add_common_options(sub)

    crypto = subparsers.add_parser("crypto", help="run crypto/encoding analysis")
    crypto.add_argument("input", help="ciphertext/encoded string or path to a text file")
    crypto.add_argument("--format", choices=sorted(REPORTERS), default="terminal", help="report output format")
    crypto.add_argument("--output", "-o", help="write rendered report to a file instead of stdout")
    crypto.add_argument("--verbose", action="store_true", help="show plugin names and raw evidence details")
    crypto.add_argument("--no-banner", action="store_true", help="hide the startup banner for terminal output")
    crypto.add_argument("--max-depth", type=int, default=4, help="maximum decoding graph depth")
    crypto.add_argument("--beam-width", type=int, default=8, help="candidate beam width")
    crypto.add_argument("--enable-xor", action="store_true", help="force single-byte XOR attempts even for printable input")
    crypto.add_argument("--disable-rot13", action="store_true", help="disable ambiguous ROT13 branch")
    crypto.add_argument("--show-graph", action="store_true", help="include graph metadata in terminal output via JSON/Markdown output if needed")
    crypto.add_argument("--save", action="store_true", help="persist the crypto report to SQLite")
    crypto.add_argument("--db", default="investigations/phm.db", help="SQLite database path for --save")

    storage = subparsers.add_parser("storage", help="inspect persisted investigations")
    storage.add_argument("action", choices=["list", "show"], help="storage action")
    storage.add_argument("id", nargs="?", type=int, help="investigation id for 'show'")
    storage.add_argument("--db", default="investigations/phm.db", help="SQLite database path")
    storage.add_argument("--limit", type=int, default=20, help="number of rows for 'list'")

    run = subparsers.add_parser("run", help="generic runner: phm run <category> <target>")
    run.add_argument("category", type=_category_from_name, help="category name")
    run.add_argument("target", help="investigation target")
    _add_common_options(run)

    return parser


def _print_plugins() -> None:
    grouped = registry.grouped_names()
    print("Registered PHM plugins:")
    for category, names in grouped.items():
        print(f"  {category}:")
        for name in names:
            print(f"    - {name}")


def _render_or_write(
    report,
    output_format: str,
    output: str | None,
    save: bool = False,
    db_path: str = "investigations/phm.db",
    verbose: bool = False,
    no_banner: bool = False,
) -> int:
    report.metadata.setdefault("display", {})["verbose"] = verbose
    if save:
        investigation_id = InvestigationStore(db_path).save(report)
        report.metadata["storage"] = {"db_path": db_path, "investigation_id": investigation_id}
    rendered = render_report(report, output_format)
    if output:
        write_report(rendered, output)
        print(f"Wrote {output_format} report to {output}")
        if save:
            print(f"Saved investigation #{report.metadata['storage']['investigation_id']} to {db_path}")
    else:
        if output_format == "terminal" and not no_banner:
            print(render_banner())
            print()
        print(rendered)
        if save:
            print(f"\nSaved investigation #{report.metadata['storage']['investigation_id']} to {db_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.banner:
        print(render_banner())
        return 0

    if args.list_plugins:
        _print_plugins()
        return 0

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "storage":
        store = InvestigationStore(args.db)
        if args.action == "list":
            rows = store.list(args.limit)
            if not rows:
                print("No saved investigations.")
                return 0
            for row in rows:
                print(f"#{row['id']} [{row['category']}] {row['target']} findings={row['finding_count']} generated_at={row['generated_at']}")
            return 0
        if args.id is None:
            print("storage show requires an investigation id", file=sys.stderr)
            return 2
        report = store.load(args.id)
        if report is None:
            print(f"No investigation found with id {args.id}", file=sys.stderr)
            return 1
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    if args.command == "investigate":
        from phm.core.investigator import InvestigationRunner
        report = InvestigationRunner(args.max_nodes, args.max_workers).run(args.target, options={"timeout": args.timeout, "cache": args.cache, "cache_ttl": args.cache_ttl, "cache_path": args.cache_db})
        return _render_or_write(report, args.format, args.output, args.save, args.db, args.verbose, args.no_banner)

    if args.command == "analyze":
        plan = plan_analysis(args.target)
        selected_plugins = args.plugins or plan.plugins
        if plan.target_type == "file" and not args.plugins:
            suffix = Path(args.target).suffix.lower()
            if suffix in {".png", ".jpg", ".jpeg", ".gif"}: selected_plugins = ["file_analysis", "image_analysis"]
            elif suffix in {".zip", ".jar"}: selected_plugins = ["file_analysis", "archive_analysis"]
        if plan.use_crypto_engine and not selected_plugins:
            report = SmartCryptoEngine().run(plan.target)
        else:
            orchestrator = InvestigationOrchestrator()
            report = orchestrator.run(
                category=plan.category,
                target_value=plan.target,
                plugin_names=selected_plugins,
                options={"timeout": args.timeout, "cache": args.cache, "cache_ttl": args.cache_ttl, "cache_path": args.cache_db},
                max_workers=args.max_workers,
            )
        report.metadata["analysis_plan"] = {
            "target_type": plan.target_type,
            "category": plan.category.value,
            "plugins": selected_plugins,
            "use_crypto_engine": plan.use_crypto_engine and not selected_plugins,
            "confidence": plan.confidence,
            "reason": plan.reason,
            "notes": plan.notes,
            "alternatives": plan.alternatives,
        }
        return _render_or_write(report, args.format, args.output, args.save, args.db, args.verbose, args.no_banner)

    if args.command == "crypto":
        value = _read_input_or_file(args.input)
        engine = SmartCryptoEngine(max_depth=args.max_depth, beam_width=args.beam_width)
        report = engine.run(
            value,
            options={
                "max_depth": args.max_depth,
                "beam_width": args.beam_width,
                "enable_xor": args.enable_xor,
                "enable_rot13": not args.disable_rot13,
            },
        )
        return _render_or_write(report, args.format, args.output, args.save, args.db, args.verbose, args.no_banner)

    artifact_shortcuts = {
        "domain": (Category.TECHNICAL, None),
        "ip": (Category.TECHNICAL, None),
        "dns": (Category.TECHNICAL, ["dns_lookup"]),
        "web": (Category.TECHNICAL, ["technology_fingerprint"]),
        "email": (Category.PERSONAL, ["email_lookup"]),
        "username": (Category.PERSONAL, ["username_lookup", "github_user_lookup"]),
        "hash": (Category.CRYPTO, ["hash_identifier"]),
        "file": (Category.FILE, ["file_analysis"]),
        "binary": (Category.FILE, ["file_analysis"]),
        "image": (Category.FILE, ["image_analysis"]),
        "document": (Category.FILE, ["file_analysis"]),
        "archive": (Category.FILE, ["archive_analysis"]),
        "metadata": (Category.FILE, ["file_analysis"]),
    }

    if args.command == "run":
        category = args.category
        target = args.target
        shortcut_plugins = None
    elif args.command in artifact_shortcuts:
        category, shortcut_plugins = artifact_shortcuts[args.command]
        target = args.target
    else:
        category = _category_from_name(args.command)
        target = args.target
        shortcut_plugins = None

    if category == Category.CRYPTO and not (args.plugins or shortcut_plugins):
        value = _read_input_or_file(target)
        report = SmartCryptoEngine().run(value)
        return _render_or_write(
            report,
            args.format,
            args.output,
            getattr(args, "save", False),
            getattr(args, "db", "investigations/phm.db"),
            getattr(args, "verbose", False),
            getattr(args, "no_banner", False),
        )

    orchestrator = InvestigationOrchestrator()
    report = orchestrator.run(
        category=category,
        target_value=target,
        plugin_names=args.plugins or shortcut_plugins,
        options={"timeout": args.timeout, "cache": args.cache, "cache_ttl": args.cache_ttl, "cache_path": args.cache_db},
        max_workers=args.max_workers,
    )
    return _render_or_write(report, args.format, args.output, args.save, args.db, args.verbose, args.no_banner)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
