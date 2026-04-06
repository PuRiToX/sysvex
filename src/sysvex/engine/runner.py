def run_modules(modules, context=None):
    findings = []

    for module in modules:
        try:
            results = module.run(context)
            findings.extend(results)
        except (NotImplementedError, AttributeError, ValueError, RuntimeError) as e:
            print(f"[ERROR] Module {module.name} failed: {e}")

    return findings