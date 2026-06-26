#!/usr/bin/env python3
"""
main.py
-------
BountyMind — Entry point and workflow orchestrator.

Usage:
  bountymind -d example.com
  bountymind -l targets.txt
  bountymind --bootstrap
  bountymind --help
"""

from __future__ import annotations

import argparse
import datetime
import sys
import uuid
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run directly
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(_PROJECT_ROOT))

from utils.config_manager import ConfigManager
from utils.exceptions import ConfigurationError
from utils.logger import get_logger, setup_logging
from utils.models import ScanSession
from utils.output_helpers import OutputManager, is_valid_domain, load_targets_from_file
from utils.platform_utils import PlatformInfo
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("main")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bountymind",
        description=(
            "BountyMind — modular automated reconnaissance, vulnerability assessment, "
            "WAF detection & evasion framework."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single domain:
    bountymind -d example.com

  Multiple targets from file:
    bountymind -l targets.txt
    bountymind -f targets.txt          (alias for -l)

  Install missing tools after git clone:
    git clone https://github.com/PratyushJoshi/bountymind.git
    cd bountymind && bountymind --bootstrap
    sudo ./install.sh                  (full system install)

  Custom output directory and report format:
    bountymind -d example.com --output-dir /tmp/scan --format markdown,html

  Update all tools and templates then exit:
    bountymind --update-tools --dry-run

  Self-update BountyMind from GitHub, then rerun install.sh if changed:
    bountymind --update
    bountymind --update --dry-run

  Increase concurrency:
    bountymind -d example.com --concurrency 10

  Use a custom config file:
    bountymind -d example.com --config config/custom.yaml

Safety note:
  This framework runs in safe, unauthenticated, non-intrusive mode by default.
  All destructive, brute-force, and exploit-class checks are excluded.
        """,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Single target domain (e.g., example.com)",
    )
    target_group.add_argument(
        "-l", "--list",
        metavar="FILE",
        dest="target_list",
        help="Path to a file containing one target domain per line",
    )
    target_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        dest="target_list",
        help="Alias for -l / --list",
    )

    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=None,
        help="Override output directory (default: from config or 'output/')",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Path to config YAML file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        default=None,
        help="Report format(s): markdown, html, or both as 'markdown,html' (default: from config)",
    )
    parser.add_argument(
        "--concurrency",
        metavar="N",
        type=int,
        default=None,
        help="Override max concurrency (default: from config)",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        default=False,
        help="Install all external tools (pipx, go, SecretFinder venv) then exit unless targets given",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Fetch latest BountyMind code from GitHub and run install.sh if changes were applied",
    )
    parser.add_argument(
        "--update-tools",
        action="store_true",
        default=False,
        help="Check for tool updates and update nuclei templates, then continue with scan",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="With --update-tools/--bootstrap: show what would be installed without running",
    )
    parser.add_argument(
        "--check-env",
        action="store_true",
        default=False,
        help="Verify tool availability (exit 1 if required tools are missing)",
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        default=False,
        help="Skip subdomain discovery phase (use target directly for probing)",
    )
    parser.add_argument(
        "--skip-scanning",
        action="store_true",
        default=False,
        help="Skip nuclei vulnerability scanning phase",
    )
    parser.add_argument(
        "--skip-dirs",
        action="store_true",
        default=False,
        help="Skip directory/file discovery",
    )
    parser.add_argument(
        "--skip-harvest",
        action="store_true",
        default=False,
        help="Skip URL harvesting phase (gau, waybackurls, katana)",
    )
    parser.add_argument(
        "--skip-secrets",
        action="store_true",
        default=False,
        help="Skip JavaScript secret scanning",
    )
    parser.add_argument(
        "--skip-cloud",
        action="store_true",
        default=False,
        help="Skip cloud bucket enumeration",
    )
    parser.add_argument(
        "--skip-screenshots",
        action="store_true",
        default=False,
        help="Skip visual screenshot capture (gowitness)",
    )
    parser.add_argument(
        "--skip-waf",
        action="store_true",
        default=False,
        help="Skip WAF detection and evasion scans",
    )
    parser.add_argument(
        "--auth",
        metavar="TOKEN",
        default=None,
        help="Optional authentication token to attach to the shared target context",
    )
    parser.add_argument(
        "--no-auto-bootstrap",
        action="store_true",
        default=False,
        help="Do not auto-install missing tools on first scan",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed console output (INFO level; default is WARNING only)",
    )

    return parser.parse_args()


def validate_targets(raw_targets: List[str]) -> List[str]:
    """Validate and clean a list of target domains."""
    valid = []
    for t in raw_targets:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        if t.startswith(("http://", "https://")):
            from utils.output_helpers import extract_domains_from_url
            t = extract_domains_from_url(t)
        if is_valid_domain(t):
            valid.append(t.lower())
        else:
            log.warning("Skipping invalid target: %s", t)
    seen: set = set()
    deduped = []
    for t in valid:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def _derive_output_label(targets: List[str]) -> str:
    """
    Build a filesystem-friendly label used to group output by website.

    Single-target scans use the bare domain (e.g. ``output/example.com/``).
    Multi-target list scans are grouped under the first target plus a count
    so concurrent batch runs remain distinguishable.
    """
    if not targets:
        return "scan"
    if len(targets) == 1:
        return targets[0]
    return f"{targets[0]}_plus_{len(targets) - 1}_more"


def print_banner(progress: ProgressManager) -> None:
    try:
        from utils.progress import render_banner
        render_banner()
    except Exception:
        print("\n  BOUNTYMIND — automated recon & bug hunting\n")


def _resolve_config_path(cli_config: str | None) -> Path:
    if cli_config:
        return Path(cli_config)
    default = _PROJECT_ROOT / "config" / "config.yaml"
    if default.exists():
        return default
    example = _PROJECT_ROOT / "config" / "config.example.yaml"
    if example.exists():
        import shutil
        default.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(example, default)
        return default
    return default


def run_scan(args: argparse.Namespace, cfg: ConfigManager, progress: ProgressManager) -> int:
    """Execute the full scan workflow."""
    output_root = Path(args.output_dir) if args.output_dir else cfg.output_dir
    if args.format:
        formats = [f.strip().lower() for f in args.format.split(",")]
        cfg._data.setdefault("general", {})["report_formats"] = formats
    if args.concurrency:
        cfg._data.setdefault("general", {})["max_concurrency"] = args.concurrency

    platform = PlatformInfo()

    # ------------------------------------------------------------------
    # Resolve targets up front so each scan gets its OWN per-website output
    # directory. This keeps simultaneous sessions (e.g. several Kali
    # workspaces/desktops each scanning a different site) fully isolated —
    # no two runs ever write to the same files.
    # ------------------------------------------------------------------
    raw_targets: List[str] = []
    target_file_error: str | None = None
    if args.domain:
        raw_targets = [args.domain]
    elif args.target_list:
        try:
            raw_targets = load_targets_from_file(args.target_list)
        except FileNotFoundError as exc:
            target_file_error = str(exc)

    targets = validate_targets(raw_targets) if raw_targets else []
    has_targets = bool(targets)

    session_id = uuid.uuid4().hex[:12]

    if has_targets:
        # output/<website>/<timestamp>_<session_id>/{raw,parsed,reports,screenshots}
        output = OutputManager(
            output_root, session_id=session_id, label=_derive_output_label(targets)
        )
    else:
        # Maintenance-only invocations (--bootstrap/--update/--check-env) do not
        # need a per-website folder; keep their scratch output out of the way.
        output = OutputManager(output_root / "_maintenance")

    runner = CommandRunner(raw_output_dir=output.raw)

    from modules.updater import ToolUpdater
    updater = ToolUpdater(cfg, runner, progress, platform)

    # Auto-bootstrap missing tools before scan (Linux only)
    if (
        has_targets
        and not args.no_auto_bootstrap
        and platform.is_linux
        and not args.check_env
    ):
        progress.set_phase_status("bootstrap", "running", "checking tools...")
        statuses = updater.check_environment()
        missing = [s for s in statuses if not s.found]
        if missing:
            progress.print_info(
                f"Auto-installing {len(missing)} missing tool(s) — "
                "run `bountymind --bootstrap` or `sudo ./install.sh` for full setup"
            )
            updater.auto_install_missing(dry_run=False)
        progress.set_phase_status("bootstrap", "done")
    elif not has_targets:
        progress.set_phase_status("bootstrap", "skipped")

    if args.update:
        result = updater.self_update(dry_run=args.dry_run)
        if not has_targets:
            return result
        if result != 0:
            return result

    if args.bootstrap:
        updater.bootstrap_all_tools(dry_run=args.dry_run)
        if not has_targets:
            progress.print_success("Bootstrap complete. No targets specified; exiting.")
            return 0

    if args.update_tools:
        updater.update_tools(dry_run=args.dry_run)
        if not has_targets:
            progress.print_success("Update complete. No targets specified; exiting.")
            return 0

    if args.check_env:
        updater.check_environment()
        ok = updater.verify_environment()
        return 0 if ok else 1

    # No valid targets and no management command handled above → usage error.
    if not has_targets:
        if target_file_error:
            progress.print_error(target_file_error)
        elif raw_targets:
            progress.print_error("No valid targets after validation. Check input and try again.")
        else:
            progress.print_error(
                "No target specified. Use -d DOMAIN or -l FILE. See --help for usage."
            )
            progress.print_usage()
        return 1

    progress.print_success(f"Targets validated: {', '.join(targets)}")
    progress.refresh_dashboard()
    log.info("Validated targets: %s", targets)

    session = ScanSession(
        session_id=session_id,
        targets=targets,
        start_time=datetime.datetime.now(datetime.timezone.utc),
    )
    if args.auth:
        session.auth_token = args.auth
    progress.print_info(f"Session ID: {session_id}")
    progress.print_info(f"Output directory: {output.base}")
    log.info("Session ID: %s | Targets: %s | Output: %s", session_id, targets, output.base)

    with progress.session(f"BountyMind — {', '.join(targets)}"):
        # Phase 1 — Discovery
        from modules.discovery import DiscoveryModule
        if not args.skip_discovery:
            progress.set_phase_status("discovery", "running")
            discovery = DiscoveryModule(cfg, output, runner, progress)
            try:
                session.subdomains = discovery.run(targets)
                progress.set_phase_status(
                    "discovery", "done", f"{len(session.subdomains)} subdomains"
                )
            except Exception as exc:
                msg = f"Discovery phase error: {exc}"
                log.error(msg, exc_info=True)
                session.errors.append(msg)
                progress.set_phase_status("discovery", "error", str(exc)[:40])
                progress.print_error(msg)
        else:
            progress.set_phase_status("discovery", "skipped")

        # Phase 1b — Probing
        progress.set_phase_status("probing", "running")
        if args.skip_dirs:
            cfg._data.setdefault("probing", {})["dir_discovery_enabled"] = False
        from modules.probing import ProbingModule
        probing = ProbingModule(cfg, output, runner, progress)
        try:
            session.live_hosts, session.port_services, session.directory_findings = (
                probing.run(targets, session.subdomains)
            )
            progress.set_phase_status(
                "probing", "done",
                f"{len(session.live_hosts)} live, {len(session.port_services)} ports",
            )
        except Exception as exc:
            msg = f"Probing phase error: {exc}"
            log.error(msg, exc_info=True)
            session.errors.append(msg)
            progress.set_phase_status("probing", "error")
            progress.print_error(msg)

        # Phase 1.5 — URL Harvesting
        from modules.harvester import URLHarvester
        harvester: URLHarvester | None = None
        if not args.skip_harvest:
            progress.set_phase_status("harvest", "running")
            harvester = URLHarvester(cfg, output, runner, progress)
            live_urls_for_harvest = [h.url for h in session.live_hosts]
            try:
                session.harvested_urls = harvester.run(targets, live_urls_for_harvest)
                progress.set_phase_status(
                    "harvest", "done", f"{len(session.harvested_urls)} URLs"
                )
            except Exception as exc:
                msg = f"URL harvesting error: {exc}"
                log.error(msg, exc_info=True)
                session.warnings.append(msg)
                progress.set_phase_status("harvest", "error")
        else:
            progress.set_phase_status("harvest", "skipped")

        if not args.skip_discovery and session.subdomains:
            from modules.discovery import DiscoveryModule as _DM
            _disc = _DM(cfg, output, runner, progress)
            try:
                session.subdomains = _disc.run_subzy(session.subdomains)
            except Exception as exc:
                log.warning("subzy takeover check failed: %s", exc)

        # Phase 2 — Vulnerability Scanning
        if not args.skip_scanning:
            progress.set_phase_status("scanning", "running")
            from modules.scanner import ScannerModule
            scanner = ScannerModule(cfg, output, runner, progress)
            live_urls = [h.url for h in session.live_hosts]
            try:
                session.nuclei_findings = scanner.run(live_urls)
                progress.set_phase_status(
                    "scanning", "done", f"{len(session.nuclei_findings)} findings"
                )
            except Exception as exc:
                msg = f"Scanning phase error: {exc}"
                log.error(msg, exc_info=True)
                session.errors.append(msg)
                progress.set_phase_status("scanning", "error")
                progress.print_error(msg)
        else:
            progress.set_phase_status("scanning", "skipped")

        # Phase 2.5 — Extended capabilities
        if not args.skip_secrets:
            progress.set_phase_status("secrets", "running")
            updater.ensure_secretfinder()
            from modules.secret_scanner import JSSecretScanner
            js_urls = harvester.get_js_urls(session.harvested_urls) if harvester else []
            extra_js = [
                h.url for h in session.live_hosts
                if h.url and h.url.lower().endswith(".js")
            ]
            all_js = list(set(js_urls + extra_js))
            if all_js:
                secret_scanner = JSSecretScanner(cfg, output, runner, progress)
                try:
                    session.secret_findings = secret_scanner.run(all_js)
                    progress.set_phase_status(
                        "secrets", "done", f"{len(session.secret_findings)} secrets"
                    )
                except Exception as exc:
                    session.warnings.append(f"Secret scanning error: {exc}")
                    progress.set_phase_status("secrets", "error")
            else:
                progress.set_phase_status("secrets", "done", "no JS files")
        else:
            progress.set_phase_status("secrets", "skipped")

        if not args.skip_cloud:
            progress.set_phase_status("cloud", "running")
            from modules.advanced_scanners import CloudBucketScanner
            cloud = CloudBucketScanner(log, runner)
            try:
                cloud.scan_buckets(session)
                progress.set_phase_status(
                    "cloud", "done", f"{len(session.cloud_buckets)} buckets"
                )
            except Exception as exc:
                session.warnings.append(f"Cloud bucket scan error: {exc}")
                progress.set_phase_status("cloud", "error")
        else:
            progress.set_phase_status("cloud", "skipped")

        if not args.skip_screenshots:
            progress.set_phase_status("screenshots", "running")
            from modules.screenshots import ScreenshotModule
            screenshotter = ScreenshotModule(cfg, output, runner, progress)
            try:
                session.live_hosts = screenshotter.run(session.live_hosts)
                captured = sum(1 for h in session.live_hosts if h.screenshot_path)
                progress.set_phase_status("screenshots", "done", f"{captured} captured")
            except Exception as exc:
                session.warnings.append(f"Screenshot error: {exc}")
                progress.set_phase_status("screenshots", "error")
        else:
            progress.set_phase_status("screenshots", "skipped")

        # Phase 2.6 — WAF Detection & Evasion
        if not args.skip_waf:
            progress.set_phase_status("waf", "running")
            from modules.waf_evasion import WAFEvasion
            waf = WAFEvasion(cfg, output, runner, progress)
            try:
                waf.run(session, targets)
                progress.set_phase_status(
                    "waf", "done",
                    f"{len(session.waf_detections)} WAFs, "
                    f"{len(session.evasion_findings)} evasion findings",
                )
            except Exception as exc:
                msg = f"WAF evasion error: {exc}"
                log.error(msg, exc_info=True)
                session.warnings.append(msg)
                progress.set_phase_status("waf", "error")
                progress.print_error(msg)
        else:
            progress.set_phase_status("waf", "skipped")

        # Phase 2.7 — Deep Detection Scans
        from modules.advanced_scanners import (
            Bypass403Scanner,
            AdvancedNucleiScans,
            CachePoisoningTester,
            CORSScanner,
            CSRFTester,
            DASTFuzzingScanner,
            GraphQLFinder,
            HiddenParamScanner,
            IDORScanner,
            InfoDisclosure,
            MassAssignmentScanner,
            JWTScanner,
            OAuthTester,
            PathTraversalScanner,
            PrototypePollutionScanner,
            RaceConditionTester,
            SensitiveDirectoryScanner,
            SchemaFuzzer,
            SSTIScanner,
            SQLiScanner,
            SmugglerScanner,
            WebSocketTester,
            XSSScanner,
        )

        progress.set_phase_status("deep-scans", "running")

        def _safe_scan(label: str, fn) -> None:
            """Run one detection module in isolation.

            A failure in any single scanner must never abort the rest — every
            tool gets its chance so no bug is left unturned.
            """
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - isolate per-scanner failures
                msg = f"{label} error: {exc}"
                log.error(msg, exc_info=True)
                session.warnings.append(msg)
                progress.print_warning(msg)

        advanced_nuclei = AdvancedNucleiScans(log, runner)
        deep_scans = [
            # Surface/context gathering first (other scanners depend on results)
            ("InfoDisclosure", lambda: InfoDisclosure(log, runner).scan(session)),
            ("SensitiveDirectories", lambda: SensitiveDirectoryScanner(log, runner).scan(session)),
            ("GraphQLFinder", lambda: GraphQLFinder(log, runner).find_graphql(session)),
            # Injection / high-bounty active testing
            ("DASTFuzzing", lambda: DASTFuzzingScanner(log, runner, cfg.dast_max_urls).scan(session)
                if cfg.dast_enabled else None),
            ("SQLi", lambda: SQLiScanner(log, runner).scan(session)),
            ("XSS", lambda: XSSScanner(log, runner).scan(session)),
            ("SSTI", lambda: SSTIScanner(log, runner).scan(session)),
            ("OpenRedirect", lambda: advanced_nuclei.scan_open_redirects(session)),
            ("SSRF", lambda: advanced_nuclei.scan_ssrf(session)),
            ("CORS", lambda: CORSScanner(log, runner).scan_cors(session)),
            ("PathTraversal", lambda: PathTraversalScanner(log, runner).scan(session)),
            ("IDOR", lambda: IDORScanner(log, runner).scan(session)),
            ("JWT", lambda: JWTScanner(log, runner).scan(session)),
            ("RaceCondition", lambda: RaceConditionTester(log, runner).scan(session)),
            ("CSRF", lambda: CSRFTester(log, runner).scan(session)),
            ("WebSocket", lambda: WebSocketTester(log, runner).scan(session)),
            ("OAuth", lambda: OAuthTester(log, runner).scan(session)),
            ("CachePoisoning", lambda: CachePoisoningTester(log, runner).scan(session)),
            # High-bounty specialty scanners
            ("Smuggling", lambda: SmugglerScanner(log, runner).scan(session)),
            ("PrototypePollution", lambda: PrototypePollutionScanner(log, runner, harvester).scan(session)),
            ("Bypass403", lambda: Bypass403Scanner(log, runner).scan(session)),
            ("HiddenParams", lambda: HiddenParamScanner(log, runner).scan(session)),
            ("SchemaFuzzing", lambda: SchemaFuzzer(log, runner).scan(session)),
            ("MassAssignment", lambda: MassAssignmentScanner(log, runner).scan(session)),
        ]
        for label, fn in deep_scans:
            progress.set_phase_status("deep-scans", "running", label)
            _safe_scan(label, fn)
        progress.set_phase_status("deep-scans", "done")

        # Phase 3 — Reporting
        progress.set_phase_status("reporting", "running")
        from modules.reporter import ReportGenerator
        reporter = ReportGenerator(cfg, output, progress)
        try:
            report_paths = reporter.run(session)
            for path in report_paths:
                progress.print_success(f"Report: {path}")
            progress.set_phase_status("reporting", "done", f"{len(report_paths)} report(s)")
        except Exception as exc:
            msg = f"Report generation error: {exc}"
            log.error(msg, exc_info=True)
            session.errors.append(msg)
            progress.set_phase_status("reporting", "error")
            progress.print_error(msg)
            return 1

    # Final summary
    duration = session.duration
    progress.print_summary_table(
        rows=[
            ["Targets",          str(len(targets))],
            ["Subdomains",       str(len(session.subdomains))],
            ["Live Hosts",       str(len(session.live_hosts))],
            ["Open Ports",       str(len(session.port_services))],
            ["Dir Findings",     str(len(session.directory_findings))],
            ["Nuclei Findings",  str(len(session.nuclei_findings))],
            ["WAF Endpoints",    str(len(session.waf_detections))],
            ["Evasion Findings", str(len(session.evasion_findings))],
            ["Harvested URLs",   str(len(session.harvested_urls))],
            ["JS Secrets",       str(len(session.secret_findings))],
            ["Cloud Buckets",    str(len(session.cloud_buckets))],
            ["Screenshots",      str(sum(1 for h in session.live_hosts if h.screenshot_path))],
            ["Manual Flags",     str(len(session.manual_flags))],
            ["Errors",           str(len(session.errors))],
            ["Duration",         str(duration).split(".")[0] if duration else "N/A"],
        ],
        headers=["Metric", "Count"],
        title="Scan Summary",
    )
    progress.print_success(f"All artifacts saved under: {output.base}")

    log.info(
        "Scan complete | session=%s | duration=%s | findings=%d | errors=%d",
        session_id,
        str(duration).split(".")[0] if duration else "N/A",
        len(session.nuclei_findings),
        len(session.errors),
    )

    return 1 if session.errors else 0


def main() -> int:
    args = parse_arguments()

    config_path = _resolve_config_path(args.config)
    try:
        cfg = ConfigManager(str(config_path))
    except ConfigurationError as exc:
        print(f"\n[ERROR] {exc}\n", file=sys.stderr)
        return 1

    console_level = "INFO" if args.verbose else "WARNING"
    setup_logging(
        log_file=str(cfg.log_file),
        log_level=cfg.log_level,
        console_level=console_level,
    )

    progress = ProgressManager()
    print_banner(progress)
    progress.print_usage()

    log.info("BountyMind starting — session init")
    platform = PlatformInfo()
    progress.print_info(f"Platform: {platform.distro_name} {platform.distro_version}")

    return run_scan(args, cfg, progress)


def cli() -> None:
    """Console entry point for setuptools."""
    sys.exit(main())


if __name__ == "__main__":
    cli()
