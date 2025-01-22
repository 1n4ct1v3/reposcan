import os
import subprocess
import shutil
from git import Repo
from pathlib import Path

REPO_DIR = Path("app") / "repositories"

def clone_repo(repo_url: str, repo_name: str):
    try:
        repo_path = REPO_DIR / repo_name
        if repo_path.exists():
            shutil.rmtree(repo_path)
        Repo.clone_from(repo_url, repo_path)
        return repo_path
    except Exception as e:
        raise Exception(f"Error cloning repository: {e}")

def run_gitleaks(repo_path: Path) -> str:
    try:
        command = ["gitleaks", "detect", "--source", str(repo_path),
                   "--report-path", str(repo_path / "gitleaks-report.json"),
                   "--report-format", "json"]

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode not in [0, 1]:
            raise Exception(f"Error running gitleaks: {result.stderr}")
        return str(repo_path / "gitleaks-report.json")

    except Exception as e:
        raise Exception(f"Error running gitleaks: {e}")

def run_gitleaks_on_extracted(extract_path: Path) -> str:
    return run_gitleaks(extract_path)

def process_repository(repo_url: str):
    repo_name = repo_url.strip().split("/")[-1]
    repo_path = clone_repo(repo_url, repo_name)
    return run_gitleaks(repo_path)
