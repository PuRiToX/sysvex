import argparse
from sysvex.engine.loader import load_modules
from sysvex.engine.runner import run_modules
from sysvex.reporting.console import print_report
from sysvex.reporting.json_report import export_json
from sysvex.reporting.file_reports import export_csv, export_html

DEFAULT_MODULES = ["filesystem", "network", "processes"]

def main():
    parser = argparse.ArgumentParser(description="Sysvex Security Auditor")
    parser.add_argument("--modules", help="Comma-separated modules")
    parser.add_argument("--output", help="Output file path (auto-generates with timestamp if not specified)")
    parser.add_argument("--format", choices=["json", "csv", "html", "console"], 
                       default="console", help="Output format (default: console)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")

    args = parser.parse_args()

    module_names = (
        args.modules.split(",") if args.modules else DEFAULT_MODULES
    )

    modules = load_modules(module_names)
    findings = run_modules(modules)

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