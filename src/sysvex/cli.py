import argparse
from sysvex.engine.loader import load_modules
from sysvex.engine.runner import run_modules
from sysvex.reporting.console import print_report

DEFAULT_MODULES = ["filesystem", "network", "processes"]

def main():
    parser = argparse.ArgumentParser(description="Sysvex Security Auditor")
    parser.add_argument("--modules", help="Comma-separated modules")

    args = parser.parse_args()

    module_names = (
        args.modules.split(",") if args.modules else DEFAULT_MODULES
    )

    modules = load_modules(module_names)
    findings = run_modules(modules)

    print_report(findings)