import subprocess
import os
import shutil
from app.pdf_convert import convert_json_to_pdf


def run_bearer(target_directory: str, scan_id: str) -> str:
    temp_moved_files = []
    try:
        target_directory = str(target_directory)
        temp_dir = os.path.join(target_directory, "temp_reports")
        os.makedirs(temp_dir, exist_ok=True)

        # Move unwanted JSON files to temporary folder
        for filename in ["gitleaks-report.json", "semgrep-report.json"]:
            src = os.path.join(target_directory, filename)
            if os.path.exists(src):
                dst = os.path.join(temp_dir, filename)
                shutil.move(src, dst)
                temp_moved_files.append((src, dst))

        output_json = f"reports/bearer_{scan_id}.json"
        os.makedirs("reports", exist_ok=True)

        skip_path_arg = "temp_reports"

        command = [
            "bearer", "scan", target_directory,
            "--scanner=secrets,sast",
            "--report", "security",
            "--output", output_json,
            "--format", "json",
            "--exit-code=0",
            "--skip-path", skip_path_arg
        ]

        print(f"[+] Running command: {' '.join(command)}")
        subprocess.run(command, check=True)

        if not os.path.exists(output_json):
            raise FileNotFoundError(f"JSON report not found: {output_json}")

        if os.path.getsize(output_json) == 0:
            raise ValueError(f"JSON report is empty: {output_json}")

        return output_json

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Bearer scan failed:\n{e}")
    except Exception as e:
        raise RuntimeError(f"Error during Bearer scan:\n{e}")
    finally:
        # Move JSON files back to their original location
        for original_path, temp_path in temp_moved_files:
            if os.path.exists(temp_path):
                shutil.move(temp_path, original_path)
        
        # Clean up the temporary directory if it exists and is empty
        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)


if __name__ == "__main__":
    target_directory = "path_to_your_project"  # replace with your path
    scan_id = "example_scan"

    try:
        json_report = run_bearer(target_directory, scan_id)
        print(f"[✓] Final report generated at: {json_report}")
    except Exception as e:
        print(e)
