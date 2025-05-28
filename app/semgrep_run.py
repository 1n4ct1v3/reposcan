import subprocess
from pathlib import Path
import json

def run_semgrep(repo_path: Path) -> str:
    try:
        command = [
            "semgrep", "--config", "auto", "--json",
            "--exclude", "gitleaks-report.json",
            "--output", str(repo_path / "semgrep-report.json"),
            str(repo_path)
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Error running Semgrep: {result.stderr}")

        return str(repo_path / "semgrep-report.json")

    except Exception as e:
        raise Exception(f"Error running Semgrep: {e}")

def process_semgrep_report(report_path: str) -> str:
    try:
        with open(report_path, "r") as f:
            data = json.load(f)

        if not data.get("results"):
            return None

        return report_path

    except Exception as e:
        raise Exception(f"Error processing Semgrep report: {e}")