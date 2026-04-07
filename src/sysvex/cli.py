import argparse
from sysvex.engine.loader import load_modules
from sysvex.engine.runner import run_modules
from sysvex.reporting.console import print_report
from sysvex.reporting.json_report import export_json
from sysvex.reporting.file_reports import export_csv, export_html
from sysvex.utils.platform import get_platform_config
from sysvex.utils.filters import filter_findings

DEFAULT_MODULES = ["filesystem", "network", "processes"]

def main():
    parser = argparse.ArgumentParser(description="Sysvex Security Auditor")
    parser.add_argument("--modules", help="Comma-separated modules")
    parser.add_argument("--output", help="Output file path (auto-generates with timestamp if not specified)")
    parser.add_argument("--format", choices=["json", "csv", "html", "console"], 
                       default="console", help="Output format (default: console)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")

    parser.add_argument("--exclude-paths", help="Comma-separated glob patterns to exclude (e.g., '*.log,node_modules')")
    parser.add_argument("--max-depth", type=int, help="Maximum directory depth to scan (e.g., 5)")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                       help="Minimum severity level to report (filters out lower severities)")
    parser.add_argument("--timeout", type=int, default=60,
                       help="Timeout per module in seconds (default: 60)")

    args = parser.parse_args()

    # Load platform config once and cache
    platform_config = get_platform_config()

    module_names = (
        args.modules.split(",") if args.modules else DEFAULT_MODULES
    )

    # Build context with filtering options
    context = {
        'platform_config': platform_config,
        'exclude_paths': args.exclude_paths.split(",") if args.exclude_paths else set(),
        'max_depth': args.max_depth,
        'timeout': args.timeout,
    }

    modules = load_modules(module_names)
    findings = run_modules(modules, context, timeout=args.timeout)

    # Filter by minimum severity if specified
    if args.min_severity:
        findings = filter_findings(findings, min_severity=args.min_severity)

    # Handle output
    if args.format == "console":
        print_report(findings)
    elif args.format == "json":
        output_path = export_json(findings, args.output)
        if not args.quiet:
            print(f"JSON report saved to: {output_path}")
            print(f"Total findings: {len(findings)}")
    elif args.format == "csv":
        output_path = export_csv(findings, args.output)
        if not args.quiet:
            print(f"CSV report saved to: {output_path}")
            print(f"Total findings: {len(findings)}")
    elif args.format == "html":
        output_path = export_html(findings, args.output)
        if not args.quiet:
            print(f"HTML report saved to: {output_path}")
            print(f"Total findings: {len(findings)}")

if __name__ == "__main__":
    main()