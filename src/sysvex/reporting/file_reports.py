import os
from datetime import datetime
from sysvex.utils.platform import ensure_reports_dir

def export_csv(findings, path="report.csv"):
    """Export findings to CSV file with timestamp"""
    import csv
    
    # Use default reports directory if path is not provided or is just filename
    if not path or not os.path.dirname(path):
        reports_dir = ensure_reports_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = path if path and path != "report.csv" else f"sysvex_report_{timestamp}.csv"
        path = os.path.join(reports_dir, filename)
    
    # CSV headers
    headers = ['ID', 'Title', 'Severity', 'Description', 'Evidence', 'Recommendation', 'Source Module']
    
    with open(path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for finding in findings:
            writer.writerow([
                finding.id,
                finding.title,
                finding.severity,
                finding.description,
                finding.evidence or '',
                finding.recommendation or '',
                finding.source_module or ''
            ])
    
    return path

def export_html(findings, path="report.html"):
    """Export findings to HTML report with timestamp"""
    # Use default reports directory if path is not provided or is just filename
    if not path or not os.path.dirname(path):
        reports_dir = ensure_reports_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = path if path and path != "report.html" else f"sysvex_report_{timestamp}.html"
        path = os.path.join(reports_dir, filename)
    
    # Generate HTML content
    html_content = _generate_html_report(findings)
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return path

def _generate_html_report(findings):
    """Generate HTML content for findings report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Severity colors
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14', 
        'MEDIUM': '#ffc107',
        'LOW': '#28a745'
    }
    
    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Sysvex Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .severity-box {{ padding: 10px; border-radius: 5px; color: white; text-align: center; min-width: 100px; }}
        .finding {{ border: 1px solid #ddd; margin-bottom: 10px; padding: 15px; border-radius: 5px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .severity-badge {{ padding: 5px 10px; border-radius: 3px; color: white; font-size: 12px; }}
        .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; margin: 10px 0; }}
        .recommendation {{ background: #e7f3ff; padding: 10px; border-radius: 3px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Sysvex Security Report</h1>
        <p>Generated: {timestamp}</p>
        <p>Total Findings: {len(findings)}</p>
    </div>
    
    <div class="summary">
"""
    
    # Add severity summary
    for severity, color in severity_colors.items():
        count = severity_counts.get(severity, 0)
        html += f'<div class="severity-box" style="background: {color};">{severity}<br><strong>{count}</strong></div>'
    
    html += """
    </div>
    
    <h2>Findings Details</h2>
"""
    
    # Add findings
    for finding in findings:
        color = severity_colors.get(finding.severity, '#6c757d')
        html += f"""
    <div class="finding">
        <div class="finding-header">
            <h3>{finding.title}</h3>
            <span class="severity-badge" style="background: {color};">{finding.severity}</span>
        </div>
        <p><strong>ID:</strong> {finding.id}</p>
        <p><strong>Module:</strong> {finding.source_module}</p>
        <p><strong>Description:</strong> {finding.description}</p>
"""
        
        if finding.evidence:
            html += f'<div class="evidence"><strong>Evidence:</strong> {finding.evidence}</div>'
        
        if finding.recommendation:
            html += f'<div class="recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>'
        
        html += '</div>'
    
    html += """
</body>
</html>
"""
    
    return html
