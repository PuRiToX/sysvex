def run_modules(modules):
    findings = []

    for module in modules:
        try:
            results = module.run()
            findings.extend(results)
        except Exception as e:
            print(f"[ERROR] Module {module.name} failed: {e}")

    return findings