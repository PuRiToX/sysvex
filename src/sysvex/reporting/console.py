def print_report(findings):
    if not findings:
        print("No issues found.")
        return

    for f in findings:
        print(f"[{f.severity}] {f.title}")
        print(f"  -> {f.description}")
        if f.evidence:
            print(f"  Evidence: {f.evidence}")
        print()