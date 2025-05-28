import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib import colors
import textwrap
import re

with open("app/static/recommendations_gitleaks.json", "r") as f:
    RECOMMENDATIONS_GITLEAKS = json.load(f)

with open("app/static/recommendations_semgrep.json", "r") as f:
    RECOMMENDATIONS_SEMGREP = json.load(f)
# Register custom fonts
try:
    # Register Cairo font
    pdfmetrics.registerFont(TTFont('Cairo', '/usr/share/fonts/ttf-cairo/Cairo-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('Cairo-Bold', '/usr/share/fonts/ttf-cairo/Cairo-Bold.ttf'))
    
    # Register Open Sans font
    pdfmetrics.registerFont(TTFont('OpenSans', '/usr/share/fonts/TTF/OpenSans-Light.ttf'))
    pdfmetrics.registerFont(TTFont('OpenSans-Regular', '/usr/share/fonts/TTF/OpenSans-Regular.ttf'))
    
    CUSTOM_FONTS_AVAILABLE = True
except:
    print("Warning: Custom fonts not found. Falling back to default fonts.")
    CUSTOM_FONTS_AVAILABLE = False

# Define Plutonium theme colors
PLUTONIUM_COLORS = {
    'background': HexColor('#272b34'),
    'text': HexColor('#ffffff'),
    'heading': HexColor('#99cc33'),
    'risk_3': HexColor('#ff3333'),  # High risk
    'risk_2': HexColor('#ff9933'),  # Medium risk
    'risk_1': HexColor('#ffcb33'),  # Low risk
    'risk_0': HexColor('#5C77F5'),  # Info
}

# OWASP Top 10 2021 mapping
OWASP_MAP = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

def create_styles():
    """Create Plutonium-like styles for the PDF"""
    # Define base font settings based on availability
    heading_font = 'Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold'
    body_font = 'OpenSans' if CUSTOM_FONTS_AVAILABLE else 'Helvetica'
    
    return {
        'heading1': ParagraphStyle(
            'Heading1',
            fontSize=24,
            fontName=heading_font,
            textColor=PLUTONIUM_COLORS['heading'],
            spaceAfter=30,
            spaceBefore=30,
        ),
        'heading2': ParagraphStyle(
            'Heading2',
            fontSize=18,
            fontName=heading_font,
            textColor=PLUTONIUM_COLORS['heading'],
            spaceAfter=20,
            spaceBefore=20,
        ),
        'normal': ParagraphStyle(
            'Normal',
            fontSize=12,
            fontName=body_font,
            textColor=PLUTONIUM_COLORS['text'],
            spaceAfter=12,
            leading=16,  # Increased line spacing
        ),
        'datetime': ParagraphStyle(
            'DateTime',
            fontSize=10,
            fontName=body_font,
            textColor=PLUTONIUM_COLORS['text'],
            spaceAfter=30,
        ),
        'issue_high': ParagraphStyle(
            'IssueHigh',
            fontSize=12,
            fontName=heading_font,
            textColor=PLUTONIUM_COLORS['risk_3'],
            spaceAfter=12,
            leading=16,  # Increased line spacing
        ),
        'issue_medium': ParagraphStyle(
            'IssueMedium',
            fontSize=12,
            fontName=heading_font,
            textColor=PLUTONIUM_COLORS['risk_2'],
            spaceAfter=12,
            leading=16,  # Increased line spacing
        ),
        'issue_low': ParagraphStyle(
            'IssueLow',
            fontSize=12,
            fontName=heading_font,
            textColor=PLUTONIUM_COLORS['risk_1'],
            spaceAfter=12,
            leading=16,  # Increased line spacing
        ),
    }

def get_risk_style(severity, styles):
    """Get appropriate style based on risk level"""
    if severity.lower() in ['high', 'critical']:
        return styles['issue_high']
    elif severity.lower() == 'medium':
        return styles['issue_medium']
    else:
        return styles['issue_low']

def read_json_safely(json_file: str) -> dict:
    """
    Reads a JSON file safely, handling encoding issues.
    """
    try:
        with open(json_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
            if not content:
                raise ValueError(f"Error: JSON file {json_file} is empty.")
            return json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Error parsing JSON file {json_file}: {e}")
    except Exception as e:
        raise ValueError(f"Error reading JSON file {json_file}: {e}")

def create_severity_pie_chart(severity_counts):
    """Create a pie chart showing distribution of severities"""
    drawing = Drawing(400, 200)
    
    # Create Pie
    pie = Pie()
    pie.x = 150
    pie.y = 0
    pie.width = 150
    pie.height = 150
    
    # Data and colors setup
    pie.data = [count for count in severity_counts.values()]
    
    # Remove labels from pie itself
    pie.labels = None
    pie.slices.strokeWidth = 0
    pie.slices.strokeColor = None

    # Colors for each severity
    colors_map = {
        'High': PLUTONIUM_COLORS['risk_3'],
        'Medium': PLUTONIUM_COLORS['risk_2'],
        'Low': PLUTONIUM_COLORS['risk_1'],
        'Info': PLUTONIUM_COLORS['risk_0'],
    }
    
    # Apply colors to slices
    for i, (severity, _) in enumerate(severity_counts.items()):
        pie.slices[i].fillColor = colors_map.get(severity, colors.white)
    
    drawing.add(pie)
    
    # Add custom colored labels
    y_position = 140
    x_position = 320
    for severity, count in severity_counts.items():
        if count > 0:  # Only show labels for non-zero values
            color = colors_map.get(severity, colors.white)
            # Add colored rectangle as bullet point
            drawing.add(Rect(x_position - 15, y_position - 8, 10, 10,
                           fillColor=color,
                           strokeColor=None))
            # Add text
            drawing.add(String(x_position, y_position,
                             f'{severity} ({count})',
                             fontName='Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold',
                             fontSize=10,
                             fillColor=color))
            y_position -= 20
    
    return drawing

def create_summary_table(severity_counts):
    """Create a summary table of severity counts"""
    data = [['Risk Level', 'Number of Alerts']]
    for severity, count in severity_counts.items():
        data.append([severity, str(count)])
    
    # Increased column widths for a wider table
    table = Table(data, colWidths=[250, 250])
    
    # Define colors for each severity level
    severity_colors = {
        'High': PLUTONIUM_COLORS['risk_3'],
        'Medium': PLUTONIUM_COLORS['risk_2'],
        'Low': PLUTONIUM_COLORS['risk_1'],
        'Info': PLUTONIUM_COLORS['risk_0'],
    }
    
    # Define alternating background colors for the second column
    alt_colors = [
        HexColor('#252932'),
        HexColor('#1e2329')
    ]
    
    style = TableStyle([
        # Header styling - using Cairo Bold, 1em (12pt)
        ('BACKGROUND', (0, 0), (-1, 0), PLUTONIUM_COLORS['heading']),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),  # 1em = 12pt
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        
        # Default row styling for numbers column - using Open Sans Light
        ('BACKGROUND', (0, 1), (-1, -1), PLUTONIUM_COLORS['background']),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
        ('FONTSIZE', (0, 1), (-1, -1), 12),  # 1em = 12pt
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        
        # Specific styling for numbers column
        ('FONTNAME', (1, 1), (1, -1), 'OpenSans' if CUSTOM_FONTS_AVAILABLE else 'Helvetica'),
    ])
    
    # Add specific colors for severity rows (first column) and alternating backgrounds (second column)
    for i, (severity, _) in enumerate(severity_counts.items(), start=1):
        if severity in severity_colors:
            # Color for severity column
            style.add('BACKGROUND', (0, i), (0, i), severity_colors[severity])
            # Alternating dark backgrounds for number column
            style.add('BACKGROUND', (1, i), (1, i), alt_colors[i % 2])
            # White text for both columns
            style.add('TEXTCOLOR', (0, i), (-1, i), colors.white)
            # Cairo Bold for severity names
            style.add('FONTNAME', (0, i), (0, i), 'Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold')
    
    table.setStyle(style)
    return table

def estimate_gitleaks_severity(secret):
    """
    Estimate the severity of a gitleaks finding based on entropy and rule ID.
    """
    entropy = secret.get("Entropy", 0)
    rule_id = secret.get("RuleID", "").lower()

    # First determine base severity from rule type
    if "private" in rule_id or "token" in rule_id or "secret" in rule_id or "jwt" in rule_id:
        severity = "High"
    elif "key" in rule_id or "password" in rule_id:
        severity = "Medium"
    else:
        severity = "Low"

    # Only upgrade severity based on entropy, never downgrade
    if entropy and isinstance(entropy, (float, int)):
        if entropy > 4.5 and severity != "High":
            severity = "High"
        elif entropy > 3.5 and severity == "Low":
            severity = "Medium"

    print(f"[DEBUG] Gitleaks finding - Rule: {rule_id}, Entropy: {entropy}, Severity: {severity}")
    return severity

def format_description(description: str) -> str:
    """
    Format the description text by:
    1. Converting markdown-style newlines to actual newlines
    2. Converting sections into properly formatted paragraphs
    3. Properly formatting bullet points and markdown links
    """
    if not description:
        return "N/A"

    # Replace \n with actual newlines and clean up the text
    description = description.replace('\\n', '\n').strip()
    
    # Split into sections
    sections = description.split('##')
    formatted_sections = []
    
    for section in sections:
        if not section.strip():
            continue
            
        # Process each section
        section = section.strip()
        if section.lower().startswith('description'):
            # Remove the "Description" header and just keep the content
            content = section[len('description'):].strip()
            formatted_sections.append(content)
        elif section.lower().startswith('remediations'):
            # Format Remediations section
            content = section[len('remediations'):].strip()
            formatted_sections.append(f"<b>Remediations:</b>\n{content}")
        elif section.lower().startswith('resources'):
            # Format Resources/References section
            content = section[len('resources'):].strip()
            formatted_sections.append(f"<b>References:</b>\n{content}")
        elif section.lower().startswith('references'):
            # Format Resources/References section
            content = section[len('references'):].strip()
            formatted_sections.append(f"<b>References:</b>\n{content}")
        else:
            # For any other sections, keep them as is
            formatted_sections.append(section.strip())

    # Join sections with double newlines
    description = '\n\n'.join(formatted_sections)

    # Convert bullet points to proper bullet format
    lines = []
    for line in description.split('\n'):
        line = line.strip()
        if line.startswith('- '):
            # Convert markdown bullet to bullet point with proper indentation
            lines.append('• ' + line[2:].strip())
        elif line.startswith('* '):
            # Handle alternate bullet point style
            lines.append('• ' + line[2:].strip())
        else:
            lines.append(line)

    # Join lines with proper spacing
    description = '\n'.join(lines)

    # Convert markdown links to ReportLab links
    description = re.sub(r'\[(.*?)\]\((.*?)\)', r'<link href="\2">\1</link>', description)
    
    # Convert markdown bold to ReportLab bold
    parts = description.split('**')
    formatted_parts = []
    for i, part in enumerate(parts):
        if i % 2 == 1:  # This is the text between ** markers
            formatted_parts.append(f'<b>{part}</b>')
        else:
            formatted_parts.append(part)
    description = ''.join(formatted_parts)

    # Clean up any multiple newlines while preserving intentional line breaks
    while '\n\n\n' in description:
        description = description.replace('\n\n\n', '\n\n')

    return description.strip()

def format_owasp_references(owasp_list):
    """Format OWASP references with links"""
    if not owasp_list:
        return "N/A"
    
    formatted_refs = []
    for ref in owasp_list:
        # Extract the ID (e.g., "A07:2021" from "A07:2021 - Something")
        ref_id = ref.split(" - ")[0] if " - " in ref else ref
        if ref_id in OWASP_MAP:
            # Create a clickable link with the full reference text
            formatted_refs.append(f'<link href="{OWASP_MAP[ref_id]}">{ref}</link>')
        else:
            formatted_refs.append(ref)
    
    return ", ".join(formatted_refs)

def format_cwe_references(cwe_list):
    """Format CWE references with links to MITRE"""
    if not cwe_list:
        return "N/A"
    
    formatted_refs = []
    for cwe in cwe_list:
        # Handle full CWE description format (e.g., "CWE-798: Use of Hard-coded Credentials")
        if ':' in cwe:
            cwe_id, description = cwe.split(':', 1)
        else:
            cwe_id, description = cwe, ''
        
        # Extract just the number
        cwe_num = cwe_id.replace("CWE-", "") if cwe_id.startswith("CWE-") else cwe_id
        
        if cwe_num.isdigit():
            # Create a clickable link with the full original text
            url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            full_text = cwe if ':' in cwe else f"CWE-{cwe_num}"
            formatted_refs.append(f'<link href="{url}">{full_text}</link>')
        else:
            formatted_refs.append(cwe)
    
    return ", ".join(formatted_refs)

def create_tool_pie_chart(severity_counts, tool_name):
    """Create a pie chart showing distribution of severities for a specific tool"""
    drawing = Drawing(300, 200)  # Smaller size for tool-specific charts
    
    # Create Pie
    pie = Pie()
    pie.x = 100  # Adjusted position
    pie.y = 0
    pie.width = 120  # Smaller size
    pie.height = 120  # Smaller size
    
    # Data and colors setup
    pie.data = [count for count in severity_counts.values()]
    
    # Remove labels from pie itself
    pie.labels = None
    pie.slices.strokeWidth = 0
    pie.slices.strokeColor = None

    # Colors for each severity
    colors_map = {
        'High': PLUTONIUM_COLORS['risk_3'],
        'Medium': PLUTONIUM_COLORS['risk_2'],
        'Low': PLUTONIUM_COLORS['risk_1'],
        'Info': PLUTONIUM_COLORS['risk_0'],
    }
    
    # Apply colors to slices
    for i, (severity, _) in enumerate(severity_counts.items()):
        pie.slices[i].fillColor = colors_map.get(severity, colors.white)
    
    drawing.add(pie)
    
    # Add title
    drawing.add(String(10, 180,
                      f"{tool_name} Findings Distribution",
                      fontName='Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold',
                      fontSize=12,
                      fillColor=PLUTONIUM_COLORS['heading']))
    
    # Add custom colored labels
    y_position = 140
    x_position = 240  # Adjusted position
    for severity, count in severity_counts.items():
        if count > 0:  # Only show labels for non-zero values
            color = colors_map.get(severity, colors.white)
            # Add colored rectangle as bullet point
            drawing.add(Rect(x_position - 15, y_position - 8, 10, 10,
                           fillColor=color,
                           strokeColor=None))
            # Add text
            drawing.add(String(x_position, y_position,
                             f'{severity} ({count})',
                             fontName='Cairo-Bold' if CUSTOM_FONTS_AVAILABLE else 'Helvetica-Bold',
                             fontSize=8,  # Smaller font
                             fillColor=color))
            y_position -= 20
    
    return drawing

def convert_json_to_pdf(json_files: dict, scan_id: str, source_info: str) -> str:
    """
    Generates a single PDF report for multiple scan types with Plutonium-like styling.
    """
    # Add separate sets for counting and details
    counting_seen_locations = set()
    details_seen_locations = set()

    def is_duplicate(path, line, seen_set):
        # Use full path instead of just filename
        full_path = str(path).strip()
        key = f"{full_path}|{line}"
        if key in seen_set:
            return True
        seen_set.add(key)
        return False

    try:
        pdf_filename = f"security_scan_report_{scan_id}.pdf"
        pdf_output_path = os.path.join("reports", pdf_filename)

        # Create the document with custom styling
        doc = SimpleDocTemplate(
            pdf_output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=48,
            bottomMargin=24,
            title=f"Security Scan Report - {source_info}",
            author="RepoScan Security Scanner",
            subject="Application Security Assessment Report",
            keywords=["security", "scan", "SAST", "vulnerabilities", "code analysis"],
            creator="RepoScan Security Scanner v1.0",
        )

        styles = create_styles()
        story = []

        # Add title and datetime
        story.append(Paragraph(f"Security Scan Report", styles['heading1']))
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S")
        story.append(Paragraph(f"Generated on {current_time}", styles['datetime']))
        story.append(Paragraph(f"Source: {source_info}", styles['normal']))
        story.append(Spacer(1, 14))  # Reduced spacing

        # Initialize severity counters for overall and per-tool statistics
        severity_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        tool_severity_counts = {
            'gitleaks': {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'semgrep': {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'bearer': {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        }

        # First pass: count severities
        for report_type, json_file in json_files.items():
            print(f"[DEBUG] Processing {report_type} report from {json_file}")
            try:
                data = read_json_safely(json_file)
                print(f"[DEBUG] {report_type} data type: {type(data)}")
                
                if report_type == "bearer":
                    print(f"[DEBUG] Bearer data keys: {list(data.keys()) if isinstance(data, dict) else 'No keys (not a dict)'}")
                    if isinstance(data, dict):
                        for severity in ['critical', 'high', 'medium', 'low', 'info']:
                            findings = data.get(severity, [])
                            print(f"[DEBUG] Bearer {severity} findings: {len(findings)}")
                            for finding in findings:
                                file = finding.get('filename', 'N/A')
                                line = finding.get('line_number', 0)
                                if not is_duplicate(file, line, counting_seen_locations):  # Use counting set
                                    if severity in ['critical', 'high']:
                                        severity_counts['High'] += 1
                                        tool_severity_counts['bearer']['High'] += 1
                                    elif severity == 'medium':
                                        severity_counts['Medium'] += 1
                                        tool_severity_counts['bearer']['Medium'] += 1
                                    elif severity == 'low':
                                        severity_counts['Low'] += 1
                                        tool_severity_counts['bearer']['Low'] += 1
                                    else:
                                        severity_counts['Info'] += 1
                                        tool_severity_counts['bearer']['Info'] += 1

                elif report_type == "semgrep":
                    results = data.get('results', [])
                    print(f"[DEBUG] Semgrep results count: {len(results)}")
                    for result in results:
                        file = result.get('path', 'N/A')
                        line = result.get('start', {}).get('line', 0)
                        if not is_duplicate(file, line, counting_seen_locations):  # Use counting set
                            severity = result.get('extra', {}).get('metadata', {}).get('impact', 'medium')
                            if severity.lower() in ['high', 'critical']:    
                                severity_counts['High'] += 1
                                tool_severity_counts['semgrep']['High'] += 1
                            elif severity.lower() == 'medium':
                                severity_counts['Medium'] += 1
                                tool_severity_counts['semgrep']['Medium'] += 1
                            else:
                                severity_counts['Low'] += 1
                                tool_severity_counts['semgrep']['Low'] += 1

                elif report_type == "gitleaks":
                    findings = data if isinstance(data, list) else []
                    print(f"[DEBUG] Gitleaks findings count: {len(findings)}")
                    high_count = 0
                    medium_count = 0
                    low_count = 0
                    for finding in findings:
                        file = finding.get('File', 'N/A')
                        line = finding.get('StartLine', 0)
                        if not is_duplicate(file, line, counting_seen_locations):  # Use counting set
                            severity = estimate_gitleaks_severity(finding)
                            if severity == "High":
                                high_count += 1
                            elif severity == "Medium":
                                medium_count += 1
                            else:
                                low_count += 1
                            severity_counts[severity] += 1
                            tool_severity_counts['gitleaks'][severity] += 1
                    print(f"[DEBUG] Gitleaks severity breakdown - High: {high_count}, Medium: {medium_count}, Low: {low_count}")

            except Exception as e:
                print(f"[ERROR] Failed to process {report_type} report: {str(e)}")
                continue

        print(f"[DEBUG] Final severity counts: {severity_counts}")

        # Add Summary section with charts
        story.append(Paragraph("Summary", styles['heading2']))

        # Add overall pie chart
        if sum(severity_counts.values()) > 0:  # Only add chart if there are findings
            story.append(create_severity_pie_chart(severity_counts))
            story.append(Spacer(1, 20))

        # Add summary table
        story.append(create_summary_table(severity_counts))
        story.append(Spacer(1, 30))

        # Second pass: add detailed findings
        # Note: We don't need to clear seen_locations anymore since we're using a separate set
        
        tool_order = ['gitleaks', 'semgrep', 'bearer']
        for report_type in tool_order:
            if report_type not in json_files:
                continue

            json_file = json_files[report_type]
            print(f"[DEBUG] Processing details for {report_type}")
            data = read_json_safely(json_file)
            
            # Add tool heading
            story.append(Paragraph(f"{report_type.capitalize()} Scan Results", styles['heading2']))
            
            # Add tool-specific pie chart if there are findings
            tool_counts = tool_severity_counts[report_type]
            if sum(tool_counts.values()) > 0:
                story.append(create_tool_pie_chart(tool_counts, report_type.capitalize()))
                story.append(Spacer(1, 20))

            if report_type == "gitleaks" and isinstance(data, list):
                print(f"[DEBUG] Processing {len(data)} gitleaks findings")
                if not data:  # No findings
                    story.append(Paragraph("No secrets or sensitive information found", styles['normal']))
                    story.append(Spacer(1, 20))
                    continue

                for idx, leak in enumerate(data, 1):
                    file = leak.get('File', 'N/A')
                    line = leak.get('StartLine', 0)
                    if is_duplicate(file, line, details_seen_locations):
                        continue

                    severity = estimate_gitleaks_severity(leak)
                    story.append(Paragraph(
                        f"<b>Issue #{idx}: {leak.get('Description', 'Detected Secret')}</b>",
                        get_risk_style(severity.lower(), styles)
                    ))

                    rule_id = leak.get('RuleID', 'N/A')  # получаем RuleID
                    recommendation_gitleaks = RECOMMENDATIONS_GITLEAKS.get(rule_id, "No specific recommendation available.")

                    details = [
                        f"<b>File:</b> {file}",
                        f"<b>Line:</b> {line}",
                        f"<b>Severity:</b> {severity}",
                        f"<b>Secret:</b> {leak.get('Match', 'N/A')}",
                        f"<b>Commit:</b> {leak.get('Commit', 'N/A')}",
                        f"<b>Author:</b> {leak.get('Author', 'N/A')}",
                        f"<b>Message:</b> {leak.get('Message', 'N/A')}",
                        f"<b>Date:</b> {leak.get('Date', 'N/A')}",
                        f"<b>Context:</b> {rule_id}"
                    ]
                    story.append(Paragraph("<br/>".join(details), styles['normal']))
                    story.append(Paragraph(f"<b>Recommendation:</b> {recommendation_gitleaks}", styles['normal']))
                    story.append(Spacer(1, 15))

            elif report_type == "semgrep" and isinstance(data, dict):
                results = data.get('results', [])
                print(f"[DEBUG] Processing {len(results)} semgrep findings")
                if not results:  # No findings
                    story.append(Paragraph("No code quality or security issues found", styles['normal']))
                    story.append(Spacer(1, 20))
                    continue

                semgrep_counter = 1
                for result in results:
                    file = result.get('path', 'N/A')
                    line = result.get('start', {}).get('line', 0)
                    if is_duplicate(file, line, details_seen_locations):
                        continue

                    # Escape HTML-like content in the message
                    message = escape_html(result.get('extra', {}).get('message', 'N/A'))
                    severity = result.get('extra', {}).get('metadata', {}).get('impact', 'medium')
                    recommendation = RECOMMENDATIONS_SEMGREP.get(message, None)  # Get recommendation if message matches a key

                    # Create the issue title, adding recommendation if available
                    issue_title = f"<b>Issue #{semgrep_counter}: {message}"
                    if recommendation:
                        issue_title += f". {recommendation}"
                    issue_title += "</b>"

                    story.append(Paragraph(issue_title, get_risk_style(severity, styles)))

                    # Escape HTML in all detail fields
                    details = [
                        f"<b>File:</b> {file}",
                        f"<b>Line:</b> {line}",
                        f"<b>Impact:</b> {severity}",
                        f"<b>OWASP:</b> {format_owasp_references(result.get('extra', {}).get('metadata', {}).get('owasp', []))}",
                        f"<b>CWE:</b> {format_cwe_references(result.get('extra', {}).get('metadata', {}).get('cwe', []))}"
                    ]
                    story.append(Paragraph("<br/>".join(details), styles['normal']))
                    story.append(Spacer(1, 20))
                    semgrep_counter += 1

            elif report_type == "bearer" and isinstance(data, dict):
                issue_counter = 1
                print(f"[DEBUG] Processing bearer findings with keys: {list(data.keys())}")
                has_findings = False
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    findings = data.get(severity, [])
                    if findings:
                        has_findings = True
                        break

                if not has_findings:  # No findings
                    story.append(Paragraph("No security vulnerabilities or policy violations found", styles['normal']))
                    story.append(Spacer(1, 20))
                    continue

                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    findings = data.get(severity, [])
                    print(f"[DEBUG] Processing {len(findings)} bearer {severity} findings")
                    for issue in findings:
                        file = issue.get('filename', 'N/A')
                        line = issue.get('line_number', 0)
                        if is_duplicate(file, line, details_seen_locations):
                            continue

                        title = issue.get('title', 'N/A')
                        story.append(Paragraph(
                            f"<b>Issue #{issue_counter}: {title}</b>",
                            get_risk_style(severity, styles)
                        ))

                        # Basic details without description
                        basic_details = [
                            f"<b>Severity:</b> {severity.capitalize()}",
                            f"<b>File:</b> {file}",
                            f"<b>Line:</b> {line}",
                            f"<b>Category:</b> {issue.get('id', 'N/A')}",
                            f"<b>Context:</b> {issue.get('detailed_context', 'N/A')}",
                            f"<b>Code extract:</b> {format_code_extract(issue.get('code_extract', 'N/A'))}"
                        ]
                        story.append(Paragraph("<br/>".join(basic_details), styles['normal']))
                        story.append(Spacer(1, 10))

                        # Format and add description separately
                        desc = format_description(issue.get('description', 'N/A'))
                        desc_parts = desc.split('\n')
                        for part in desc_parts:
                            if part.strip():  # Only add non-empty lines
                                story.append(Paragraph(part, styles['normal']))
                        
                        # Add CWE IDs at the end
                        story.append(Spacer(1, 10))
                        story.append(Paragraph(
                            f"<b>CWE IDs:</b> {', '.join(issue.get('cwe_ids', []))}",
                            styles['normal']
                        ))
                        
                        story.append(Spacer(1, 20))
                        issue_counter += 1

        # Build the PDF with dark background
        def dark_background(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(PLUTONIUM_COLORS['background'])
            canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=True)
            canvas.restoreState()
        
        doc.build(story, onFirstPage=dark_background, onLaterPages=dark_background)
        
        return pdf_output_path

    except Exception as e:
        print(f"[ERROR] PDF generation failed: {str(e)}")
        raise Exception(f"Error generating PDF: {e}")

def escape_html(text):
    """Escape HTML special characters in text."""
    if not isinstance(text, str):
        text = str(text)
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))

def format_code_extract(code):
    """Format code extract to be PDF-safe by escaping HTML and handling special characters."""
    if not code or code == 'N/A':
        return 'N/A'
    
    # First escape any HTML tags and special characters
    code = escape_html(code)
    
    # Replace PHP tags with a more readable format
    code = code.replace('&lt;?php', '<?php')
    code = code.replace('?&gt;', '?>')
    
    return code
