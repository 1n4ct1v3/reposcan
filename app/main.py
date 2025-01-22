from fastapi import FastAPI, Form, Request, HTTPException, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from app.gitleaks_run import process_repository, run_gitleaks_on_extracted
from app.semgrep_run import run_semgrep
from app.pdf_convert import convert_json_to_pdf
import os
import shutil
import zipfile
from pathlib import Path

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

REPORT_DIR = os.path.join("reports")
REPO_DIR = Path("app") / "repositories"

os.makedirs(REPORT_DIR, exist_ok=True)


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})


@app.post("/scan")
async def scan(request: Request, repo_url: str = Form(None), uploaded_file: UploadFile = File(None)):
    gitleaks_report = None
    semgrep_report = None

    try:
        if repo_url:
            print(f"Cloning repository {repo_url}...")
            gitleaks_report = process_repository(repo_url)
            print(f"Gitleaks report generated: {gitleaks_report}")

            print(f"Running Semgrep on repository {repo_url}...")
            semgrep_report = run_semgrep(Path("app") / "repositories" / repo_url.strip().split("/")[-1])
            print(f"Semgrep report generated: {semgrep_report}")

        elif uploaded_file:
            if not uploaded_file.filename.endswith('.zip'):
                raise HTTPException(status_code=400, detail="Only .zip files are allowed.")

            extract_path = REPO_DIR / uploaded_file.filename.replace('.zip', '')
            zip_file_path = REPO_DIR / uploaded_file.filename

            with open(zip_file_path, "wb") as f:
                shutil.copyfileobj(uploaded_file.file, f)

            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(REPO_DIR)

            extracted_dirs = list(REPO_DIR.iterdir())
            if len(extracted_dirs) == 1 and extracted_dirs[0].is_dir():
                nested_dir = extracted_dirs[0]
                nested_contents = list(nested_dir.iterdir())

                for item in nested_contents:
                    shutil.move(str(item), str(REPO_DIR))

                shutil.rmtree(nested_dir)

            os.remove(zip_file_path)

            print(f"Running gitleaks on extracted contents of {uploaded_file.filename}...")
            gitleaks_report = run_gitleaks_on_extracted(extract_path)
            print(f"Gitleaks report generated: {gitleaks_report}")

            print(f"Running Semgrep on extracted contents of {uploaded_file.filename}...")
            semgrep_report = run_semgrep(extract_path)
            print(f"Semgrep report generated: {semgrep_report}")

        else:
            raise HTTPException(status_code=400,
                                detail="No input provided. Please provide a repository URL or upload a file.")

        if gitleaks_report:
            gitleaks_pdf = convert_json_to_pdf(gitleaks_report, report_type="gitleaks")
            print(f"Gitleaks PDF file generated: {gitleaks_pdf}")
            gitleaks_download_link = f"/reports/{os.path.basename(gitleaks_pdf)}"
        else:
            gitleaks_download_link = None

        if semgrep_report:
            semgrep_pdf = convert_json_to_pdf(semgrep_report, report_type="semgrep")
            print(f"Semgrep PDF file generated: {semgrep_pdf}")
            semgrep_download_link = f"/reports/{os.path.basename(semgrep_pdf)}"
        else:
            semgrep_download_link = None

        return templates.TemplateResponse("results.html", {
            "request": request,
            "success": True,
            "gitleaks_download_link": gitleaks_download_link,
            "semgrep_download_link": semgrep_download_link
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return templates.TemplateResponse("results.html", {
            "request": request,
            "success": False,
            "error_message": str(e)
        })


@app.get("/reports/{file_name}")
async def get_report(file_name: str):
    file_path = os.path.join(REPORT_DIR, file_name)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/pdf", filename=file_name)
    else:
        raise HTTPException(status_code=404, detail="File not found")