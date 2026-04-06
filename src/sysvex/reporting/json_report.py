import json
import os
from datetime import datetime
from sysvex.utils.platform import ensure_reports_dir

def export_json(findings, path="report.json"):
    """Export findings to JSON file with timestamp"""
    # Use default reports directory if path is not provided or is just filename
    if not path or not os.path.dirname(path):
        reports_dir = ensure_reports_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = path if path and path != "report.json" else f"sysvex_report_{timestamp}.json"
        path = os.path.join(reports_dir, filename)
    
    # Create report data with metadata
    report_data = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "severity_breakdown": _get_severity_breakdown(findings)
        },
        "findings": [f.to_dict() for f in findings]
    }
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    
    return path

def _get_severity_breakdown(findings):
    """Count findings by severity"""
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = finding.severity
        if severity in breakdown:
            breakdown[severity] += 1
    return breakdown
