import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os


def convert_json_to_pdf(json_file: str, report_type: str) -> str:
    try:
        with open(json_file, "r") as f:
            data = json.load(f)

        pdf_output_path = json_file.replace(".json", ".pdf")
        pdf_output_path = os.path.join("reports", os.path.basename(pdf_output_path))

        c = canvas.Canvas(pdf_output_path, pagesize=letter)
        width, height = letter

        c.setFont("Helvetica-Bold", 16)
        if report_type == "gitleaks":
            c.drawString(100, height - 40, "Gitleaks Scan Report")
        elif report_type == "semgrep":
            c.drawString(100, height - 40, "Semgrep Scan Report")

        c.setFont("Helvetica", 12)
        c.drawString(100, height - 60, f"Generated from: {json_file}")

        if report_type == "gitleaks":
            c.drawString(100, height - 80, "Detected Secrets:")
            y_position = height - 100

            if not data:
                c.drawString(100, y_position, "No secrets found.")
                c.save()
                return pdf_output_path

            for leak in data:
                file_path = leak.get("File", "N/A")
                line = leak.get("StartLine", "N/A")
                commit = leak.get("Commit", "N/A")
                description = leak.get("Description", "N/A")
                rule_id = leak.get("RuleID", "N/A")

                c.setFont("Helvetica", 10)
                c.drawString(100, y_position, f"File: {file_path}")
                c.drawString(100, y_position - 15, f"Line: {line}")
                c.drawString(100, y_position - 30, f"Commit: {commit}")
                c.drawString(100, y_position - 45, f"Description: {description}")
                c.drawString(100, y_position - 60, f"Rule ID: {rule_id}")
                y_position -= 80

                if y_position < 40:
                    c.showPage()
                    y_position = height - 40

        elif report_type == "semgrep":
            c.drawString(100, height - 80, "Detected Issues:")
            y_position = height - 100

            if not data.get("results"):
                c.drawString(100, y_position, "No issues found.")
                c.save()
                return pdf_output_path

            for result in data.get("results", []):
                file_path = result.get("path", "N/A")
                line = result.get("start", {}).get("line", "N/A")
                description = result.get("extra", {}).get("message", "N/A")

                c.setFont("Helvetica", 10)
                c.drawString(100, y_position, f"File: {file_path}")
                c.drawString(100, y_position - 15, f"Line: {line}")
                c.drawString(100, y_position - 30, f"Description: {description}")
                y_position -= 60

                if y_position < 40:
                    c.showPage()
                    y_position = height - 40

        c.save()
        return pdf_output_path

    except Exception as e:
        raise Exception(f"Error generating PDF: {e}")