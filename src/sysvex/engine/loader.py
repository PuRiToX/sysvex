import importlib

def load_modules(module_names):
    modules = []

    for name in module_names:
        module = importlib.import_module(f"sysvex.modules.{name}")
        modules.append(module.Module())

    return modules
