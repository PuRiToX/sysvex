import concurrent.futures


def run_modules(modules, context=None, timeout=60):
    """
    Run all modules with optional timeout.

    Args:
        modules: List of module instances to run
        context: Optional context dict with filtering options
        timeout: Maximum seconds per module (default: 60)

    Returns:
        List of all findings from all modules
    """
    findings = []

    for module in modules:
        try:
            # Use ThreadPoolExecutor to enforce timeout per module
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(module.run, context)
                try:
                    results = future.result(timeout=timeout)
                    if results:
                        findings.extend(results)
                except concurrent.futures.TimeoutError:
                    print(f"[TIMEOUT] Module {module.name} exceeded {timeout}s timeout, skipping")
                except (NotImplementedError, AttributeError, ValueError, RuntimeError) as e:
                    print(f"[ERROR] Module {module.name} failed: {e}")
        except Exception as e:
            print(f"[ERROR] Failed to execute module {module.name}: {e}")

    return findings