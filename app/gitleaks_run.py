import shutil
import subprocess
from git import Repo
from pathlib import Path

def clone_repo(repo_url: str, destination: Path) -> Path:
    try:
        if destination.exists():
            shutil.rmtree(destination)
        Repo.clone_from(repo_url, destination)
        return destination
    except Exception as e:
        raise Exception(f"Error cloning repository: {e}")

def run_gitleaks(repo_path: Path) -> str:
    try:
        command = [
            "gitleaks", "detect", "--source", str(repo_path),
            "--report-path", str(repo_path / "gitleaks-report.json"),
            "--report-format", "json"
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode not in [0, 1]:
            raise Exception(f"Error running gitleaks: {result.stderr}")
        return str(repo_path / "gitleaks-report.json")

    except Exception as e:
        raise Exception(f"Error running gitleaks: {e}")

def run_gitleaks_on_extracted(extract_path: Path) -> str:
    return run_gitleaks(extract_path)

def process_repository(repo_url: str = None, *, destination: Path, from_zip: bool = False) -> str:
    if not from_zip:
        if not repo_url:
            raise Exception("Repository URL is required when not processing a zip file.")
        clone_repo(repo_url, destination)
    return run_gitleaks(destination)