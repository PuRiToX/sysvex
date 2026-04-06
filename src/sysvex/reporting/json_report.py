import json

def export_json(findings, path="report.json"):
    with open(path, "w") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)