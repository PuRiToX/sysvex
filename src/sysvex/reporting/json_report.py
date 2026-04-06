import json

def export_json(findings, path="report.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)
