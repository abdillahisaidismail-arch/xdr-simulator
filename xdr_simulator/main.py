"""
XDR Simulator — Main Entry Point
=================================
Full pipeline execution:
1. Generate 10,000+ events/day (Syslog, Filebeat, JSON)
2. Parse and normalize all events
3. Run multi-source correlation
4. Execute automated detection (3 incident types)
5. Generate PCI-DSS compliance report
6. Display dashboard
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .generators import EventOrchestrator
from .parsers import EventParser
from .correlation import CorrelationEngine
from .detection import DetectionEngine
from .compliance import PCIDSSCompliance
from .dashboard import DashboardReporter
from .utils.logger import get_logger


def _write_progress(output_dir: str, phase: int, data: dict) -> None:
    """Écrit l'état courant du pipeline pour le HUD en temps réel."""
    progress = {
        "phase": phase,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    path = Path(output_dir) / "progress.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(progress, f, indent=2)


def run_simulation(
    events_per_day: int = 12000,
    attack_probability: float = 0.12,
    output_dir: str = "data",
    log_dir: str = "logs",
    verbose: bool = True,
) -> dict:
    """
    Run the full XDR simulation pipeline.

    Args:
        events_per_day: Number of events to generate per day.
        attack_probability: Probability of attack events (0.0-1.0).
        output_dir: Directory for output files.
        log_dir: Directory for log files.
        verbose: Print detailed output.

    Returns:
        Dictionary with simulation results and metrics.
    """
    start_time = time.time()
    logger = get_logger(log_dir)

    logger.log_audit("SIMULATION_START", {
        "events_per_day": events_per_day,
        "attack_probability": attack_probability,
    })

    print("\n" + "=" * 70)
    print("  XDR SIMULATOR — Banque Centrale de Djibouti")
    print("  Extended Detection & Response — SI Bancaire PCI-DSS")
    print("=" * 70 + "\n")

    # ---------------------------------------------------------------
    # Phase 1: Event Generation
    # ---------------------------------------------------------------
    print("[1/6] Generating events...")
    orchestrator = EventOrchestrator(events_per_day, attack_probability)
    raw_events = orchestrator.generate_day(inject_attack_scenario=True)
    gen_time = time.time() - start_time
    print(f"      ✓ Generated {len(raw_events):,} events in {gen_time:.2f}s")
    print(f"        Sources: Syslog + Filebeat + JSON API")

    _write_progress(output_dir, 1, {
        "total_events": len(raw_events),
        "gen_time": round(gen_time, 2),
        "status": "generating",
    })

    # ---------------------------------------------------------------
    # Phase 2: Parsing & Normalization
    # ---------------------------------------------------------------
    print("\n[2/6] Parsing and normalizing events...")
    parser = EventParser()
    t = time.time()
    normalized_events = parser.parse_batch(raw_events)
    parse_time = time.time() - t
    stats = parser.get_stats()
    print(f"      ✓ Parsed {stats['parsed_count']:,} events in {parse_time:.2f}s")
    print(f"        Success rate: {stats['success_rate']}")

    _write_progress(output_dir, 2, {
        "total_events": len(raw_events),
        "parsed_events": stats["parsed_count"],
        "parse_rate": stats["success_rate"],
        "status": "parsing",
    })

    # ---------------------------------------------------------------
    # Phase 3: Multi-Source Correlation
    # ---------------------------------------------------------------
    print("\n[3/6] Running multi-source correlation...")
    correlation_engine = CorrelationEngine()
    t = time.time()
    correlation_engine.ingest(normalized_events)
    correlations = correlation_engine.correlate()
    corr_time = time.time() - t
    corr_stats = correlation_engine.get_stats()
    print(f"      ✓ Found {len(correlations)} correlation matches in {corr_time:.2f}s")

    multi_source = sum(1 for c in correlations if c.get("multi_source"))
    print(f"        Multi-source correlations: {multi_source}")

    _write_progress(output_dir, 3, {
        "total_events": len(raw_events),
        "parsed_events": stats["parsed_count"],
        "correlations": len(correlations),
        "multi_source": multi_source,
        "status": "correlating",
    })

    # ---------------------------------------------------------------
    # Phase 4: Automated Detection
    # ---------------------------------------------------------------
    print("\n[4/6] Running automated detection...")
    detection_engine = DetectionEngine()
    t = time.time()
    incidents = detection_engine.detect(normalized_events, correlations)
    detect_time = time.time() - t
    det_stats = detection_engine.get_stats()
    print(f"      ✓ Detected {len(incidents)} incidents in {detect_time:.2f}s")

    for inc in incidents:
        severity_icon = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
        }.get(inc.severity.value, "⚪")
        print(
            f"        {severity_icon} [{inc.severity.value.upper()}] "
            f"{inc.incident_type.value} — {inc.source_ip}"
        )

    # _write_progress HORS de la boucle for
    _write_progress(output_dir, 4, {
        "total_events": len(raw_events),
        "parsed_events": stats["parsed_count"],
        "correlations": len(correlations),
        "incidents": len(incidents),
        "severity_distribution": det_stats.get("by_severity", {}),
        "incident_list": [
            {
                "incident_type": inc.incident_type.value,
                "severity": inc.severity.value,
                "source_ip": inc.source_ip,
                "mitre_technique": inc.mitre_technique,
                "description": inc.description[:100],
            }
            for inc in incidents
        ],
        "status": "detecting",
    })

    # ---------------------------------------------------------------
    # Phase 5: PCI-DSS Compliance
    # ---------------------------------------------------------------
    print("\n[5/6] Generating PCI-DSS compliance report...")
    compliance = PCIDSSCompliance(output_dir)
    t = time.time()
    compliance_report = compliance.generate_compliance_report(
        normalized_events, incidents, correlations
    )
    audit_path = compliance.generate_audit_trail(normalized_events)
    comp_time = time.time() - t
    print(f"      ✓ Compliance report generated in {comp_time:.2f}s")
    print(f"        Audit trail: {audit_path}")

    for incident in incidents:
        ir = compliance.generate_incident_report(incident)
        ir_path = Path(output_dir) / f"IR-{incident.incident_id[:8]}.json"
        with open(ir_path, "w", encoding="utf-8") as f:
            json.dump(ir, f, indent=2, ensure_ascii=False)

    # _write_progress HORS du with open
    _write_progress(output_dir, 5, {
        "total_events": len(raw_events),
        "parsed_events": stats["parsed_count"],
        "correlations": len(correlations),
        "incidents": len(incidents),
        "incident_list": [
            {
                "incident_type": inc.incident_type.value,
                "severity": inc.severity.value,
                "source_ip": inc.source_ip,
                "mitre_technique": inc.mitre_technique,
                "description": inc.description[:100],
            }
            for inc in incidents
        ],
        "severity_distribution": det_stats.get("by_severity", {}),
        "status": "reporting",
    })

    # ---------------------------------------------------------------
    # Phase 6: Dashboard & Reporting
    # ---------------------------------------------------------------
    print("\n[6/6] Generating dashboard...")
    reporter = DashboardReporter(output_dir)
    report_path = reporter.save_json_report(
        normalized_events, incidents, correlations
    )

    if verbose:
        reporter.print_dashboard(
            normalized_events, incidents, correlations,
            stats, corr_stats, det_stats,
        )

    total_time = time.time() - start_time

    results = {
        "total_events": len(raw_events),
        "parsed_events": stats["parsed_count"],
        "correlations": len(correlations),
        "incidents": len(incidents),
        "incident_types": [inc.incident_type.value for inc in incidents],
        "severity_distribution": det_stats.get("by_severity", {}),
        "execution_time_seconds": total_time,
        "report_path": report_path,
        "compliance_report_id": compliance_report["report_id"],
    }

    logger.log_audit("SIMULATION_COMPLETE", results)

    print(f"\n{'=' * 70}")
    print(f"  Simulation complete in {total_time:.2f}s")
    print(f"  Events: {len(raw_events):,} | Incidents: {len(incidents)} | Reports: {output_dir}/")
    print(f"{'=' * 70}\n")

    return results


def main():
    """CLI entry point."""
    arg_parser = argparse.ArgumentParser(
        description="XDR Simulator — Banque Centrale de Djibouti",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m xdr_simulator                          # Default: 12,000 events/day
  python -m xdr_simulator --events 20000           # 20,000 events/day
  python -m xdr_simulator --attack-prob 0.25       # Higher attack rate
  python -m xdr_simulator --output reports/        # Custom output directory
  python -m xdr_simulator --quiet                  # No dashboard display
        """,
    )

    arg_parser.add_argument("--events", "-e", type=int, default=12000,
        help="Number of events to generate per day (default: 12000)")
    arg_parser.add_argument("--attack-prob", "-a", type=float, default=0.12,
        help="Attack event probability 0.0-1.0 (default: 0.12)")
    arg_parser.add_argument("--output", "-o", type=str, default="data",
        help="Output directory for reports (default: data/)")
    arg_parser.add_argument("--log-dir", type=str, default="logs",
        help="Log directory (default: logs/)")
    arg_parser.add_argument("--quiet", "-q", action="store_true",
        help="Suppress dashboard output")

    args = arg_parser.parse_args()

    if args.events <= 0:
        arg_parser.error("--events must be a positive integer (got %d)" % args.events)
    if not 0.0 <= args.attack_prob <= 1.0:
        arg_parser.error(
            "--attack-prob must be between 0.0 and 1.0 (got %s)" % args.attack_prob
        )

    try:
        results = run_simulation(
            events_per_day=args.events,
            attack_probability=args.attack_prob,
            output_dir=args.output,
            log_dir=args.log_dir,
            verbose=not args.quiet,
        )
    except PermissionError as exc:
        print(f"\n[ERROR] Permission denied while writing outputs: {exc}", file=sys.stderr)
        print("        Try a different --output / --log-dir or fix folder permissions.", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[ABORT] Simulation interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        print(f"\n[ERROR] Simulation failed: {exc}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0 if results["incidents"] >= 0 else 1)


if __name__ == "__main__":
    main()
