import os
from dotenv import load_dotenv
load_dotenv()

# Get admin credentials from environment variables with defaults
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

import shutil
import zipfile
import uuid
from pathlib import Path
import threading
import time
from datetime import datetime, timedelta
import re
import ipaddress
from urllib.parse import urlparse, unquote, urlunparse
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Request, HTTPException, UploadFile, File, Depends, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import jwt

from app.gitleaks_run import process_repository
from app.semgrep_run import run_semgrep
from app.bearer_run import run_bearer
from app.pdf_convert import convert_json_to_pdf
from app.zap_run import start_scan, start_scan_background
from app.database import get_db, Scan, init_db, SQLALCHEMY_DATABASE_URL, User
from app.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    create_initial_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.scan_manager import scan_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    db = next(get_db())
    try:
        # Check if admin user exists before creating
        admin_exists = db.query(User).filter(User.username == ADMIN_USERNAME).first()
        if not admin_exists:
            create_initial_user(
                db,
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                password=ADMIN_PASSWORD
            )
            print("Admin user created successfully")
    except Exception as e:
        print(f"Note: {e}")
    finally:
        db.close()
    yield
    # Shutdown
    pass

app = FastAPI(lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
templates = Jinja2Templates(directory="app/templates")

REPORT_DIR = os.path.join("reports")
REPO_DIR = Path("app") / "repositories"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(REPO_DIR, exist_ok=True)

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/token")
async def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    print(f"Login attempt for user: {username}")
    user = authenticate_user(db, username, password)
    if not user:
        print(f"Authentication failed for user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    print(f"Authentication successful for user: {username}")
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    response = JSONResponse({"access_token": access_token, "token_type": "bearer"})
    print(f"Setting access_token cookie: {access_token[:10]}...")
    response.set_cookie(
        key="access_token",
        value=access_token,  # Don't include Bearer prefix in cookie
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    return response

@app.get("/")
async def dashboard(request: Request, current_user_or_redirect = Depends(get_current_user)):
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user_or_redirect
    })

@app.get("/sast")
async def sast(request: Request, current_user_or_redirect = Depends(get_current_user)):
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect
    return templates.TemplateResponse("sast.html", {
        "request": request,
        "user": current_user_or_redirect
    })

@app.get("/dast")
async def dast(request: Request, current_user_or_redirect = Depends(get_current_user)):
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect
    return templates.TemplateResponse("dast.html", {
        "request": request,
        "user": current_user_or_redirect
    })

def run_sast_scan_background(scan_id: str, repo_url: str = None, uploaded_file_path: str = None):
    try:
        scan_dir = REPO_DIR / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        # Get source info from scan manager instead of constructing it here
        source_info = scan_manager.get_status(scan_id).source_info
        json_reports = {}

        # Run Gitleaks
        try:
            scan_manager.update_status(scan_id, status="running", scan_progress=0)
            if repo_url:
                gitleaks_report = process_repository(repo_url, destination=scan_dir)
            else:
                gitleaks_report = process_repository(None, destination=scan_dir, from_zip=True)
            json_reports["gitleaks"] = gitleaks_report
            scan_manager.update_status(scan_id, scan_progress=25)
        except Exception as e:
            print(f"Gitleaks scan failed: {e}")
            scan_manager.update_status(scan_id, error=f"Gitleaks scan failed: {str(e)}")

        # Run Semgrep
        try:
            scan_manager.update_status(scan_id, scan_progress=25)
            semgrep_report = run_semgrep(scan_dir)
            json_reports["semgrep"] = semgrep_report
            scan_manager.update_status(scan_id, scan_progress=50)
        except Exception as e:
            print(f"Semgrep scan failed: {e}")
            scan_manager.update_status(scan_id, error=f"Semgrep scan failed: {str(e)}")

        # Run Bearer
        try:
            scan_manager.update_status(scan_id, scan_progress=50)
            bearer_report = run_bearer(scan_dir, scan_id)
            json_reports["bearer"] = bearer_report
            scan_manager.update_status(scan_id, scan_progress=75)
        except Exception as e:
            print(f"Bearer scan failed: {e}")
            scan_manager.update_status(scan_id, error=f"Bearer scan failed: {str(e)}")

        # Generate combined report
        try:
            if json_reports:
                combined_pdf = convert_json_to_pdf(json_reports, scan_id=scan_id, source_info=source_info)
                scan_manager.update_status(
                    scan_id,
                    status="completed",
                    scan_progress=100,
                    report_path=combined_pdf
                )
            else:
                raise Exception("No scan reports generated")
        except Exception as e:
            print(f"Report generation failed: {e}")
            scan_manager.update_status(
                scan_id,
                status="failed",
                error=f"Report generation failed: {str(e)}"
            )

    except Exception as e:
        scan_manager.update_status(scan_id, status="failed", error=str(e))
    finally:
        # Cleanup
        if uploaded_file_path and os.path.exists(uploaded_file_path):
            try:
                if os.path.isdir(uploaded_file_path):
                    shutil.rmtree(uploaded_file_path)
                else:
                    os.remove(uploaded_file_path)
            except Exception as e:
                print(f"Error during cleanup: {e}")

@app.post("/scan")
async def scan(request: Request, repo_url: str = Form(None), uploaded_file: UploadFile = File(None), current_user_or_redirect = Depends(get_current_user)):
    # Handle authentication redirect
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect

    try:
        if not repo_url and not uploaded_file:
            return templates.TemplateResponse("sast.html", {
                "request": request,
                "error_message": "No input provided. Please provide a repository URL or upload a file.",
                "user": current_user_or_redirect
            })

        # Validate repository URL if provided
        if repo_url:
            if not repo_url.startswith(('http://', 'https://')):
                return templates.TemplateResponse("sast.html", {
                    "request": request,
                    "error_message": "Invalid repository URL format. URL must start with http:// or https://",
                    "user": current_user_or_redirect
                })
            
            # Check if it's a valid GitHub/GitLab URL
            if not any(domain in repo_url.lower() for domain in ['github.com', 'gitlab.com']):
                return templates.TemplateResponse("sast.html", {
                    "request": request,
                    "error_message": "Please provide a valid GitHub or GitLab repository URL",
                    "user": current_user_or_redirect
                })

        # Create a new scan entry with source_info
        source_info = repo_url if repo_url else uploaded_file.filename if uploaded_file else "Unknown Source"
        scan_id = scan_manager.create_scan(
            target_url=None,  # Don't set target for SAST scans
            scan_type="SAST",
            source_info=source_info
        )

        # Handle file upload if provided
        uploaded_file_path = None
        if uploaded_file:
            if not uploaded_file.filename.endswith('.zip'):
                return templates.TemplateResponse("sast.html", {
                    "request": request,
                    "error_message": "Only .zip files are allowed.",
                    "user": current_user_or_redirect
                })
            
            scan_dir = REPO_DIR / scan_id
            scan_dir.mkdir(parents=True, exist_ok=True)
            uploaded_file_path = str(scan_dir / uploaded_file.filename)
            
            # First save the zip file
            with open(uploaded_file_path, "wb") as f:
                shutil.copyfileobj(uploaded_file.file, f)
            
            # Then extract it
            try:
                with zipfile.ZipFile(uploaded_file_path, 'r') as zip_ref:
                    zip_ref.extractall(str(scan_dir))
                # Remove the zip file after extraction
                os.remove(uploaded_file_path)
                uploaded_file_path = str(scan_dir)
            except zipfile.BadZipFile:
                return templates.TemplateResponse("sast.html", {
                    "request": request,
                    "error_message": "Invalid zip file provided.",
                    "user": current_user_or_redirect
                })

        # Start background scan
        threading.Thread(
            target=run_sast_scan_background,
            args=(scan_id, repo_url, uploaded_file_path),
            daemon=True
        ).start()

        # Check if it's an AJAX request
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JSONResponse({"status": "success", "redirect": "/"})
            
        # Redirect to dashboard
        return RedirectResponse(url="/", status_code=303)

    except Exception as e:
        error_message = str(e)
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JSONResponse({"status": "error", "message": error_message})
            
        return templates.TemplateResponse("sast.html", {
            "request": request,
            "error_message": error_message,
            "user": current_user_or_redirect
        })

def is_localhost_url(url: str) -> bool:
    """Check if URL points to localhost or internal IP ranges."""
    try:
        # Parse and decode the URL
        parsed = urlparse(unquote(url))
        hostname = parsed.hostname
        
        if not hostname:
            return True
            
        # Check for common localhost hostnames
        localhost_names = {
            'localhost', 'localtest.me', '127.0.0.1', '127.1', '127.0.1',
            '0', '0.0.0.0', '::1', '[::1]', '[::]', '0000::1', '[0000::1]',
            'local', 'localdomain', 'ip6-localhost', 'ip6-loopback'
        }
        
        if hostname.lower() in localhost_names:
            return True
            
        # Check for localhost in subdomains
        if any(part in hostname.lower() for part in ['localhost', 'local', 'internal']):
            return True
            
        # Check for IP addresses
        try:
            # Handle IPv4
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                ip = ipaddress.ip_address(hostname)
                return (
                    ip.is_private or  # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    ip.is_loopback or  # 127.0.0.0/8
                    ip.is_link_local or  # 169.254.0.0/16
                    ip.is_reserved or  # Various reserved ranges
                    str(ip) == '0.0.0.0'
                )
            
            # Handle IPv6
            if ':' in hostname:
                ip = ipaddress.ip_address(hostname.strip('[]'))
                return (
                    ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved
                )
                
            # Check for decimal/octal/hex IP representations
            if re.match(r'^\d+$', hostname):
                try:
                    decimal = int(hostname)
                    if 0 <= decimal <= 4294967295:  # Max IPv4 value
                        return True
                except ValueError:
                    pass
                    
            # Check for mixed format IPs
            if re.match(r'^0x[0-9a-f]+$', hostname, re.I):
                return True
                
            # Check for special DNS patterns
            if any(pattern in hostname.lower() for pattern in [
                '.nip.io', '.xip.io', '.localtest.me', '.localhost',
                '.internal', '.local', '.home', '.lan', '.corp', '.localdomain'
            ]):
                return True
                
        except ValueError:
            # If IP parsing fails, check for other bypass patterns
            pass
            
        # Check for encoded characters
        decoded = unquote(hostname)
        if decoded != hostname:
            return is_localhost_url(decoded)
            
        return False
        
    except Exception:
        # If any parsing fails, assume it's a localhost attempt
        return True

def sanitize_url(url: str) -> str:
    """Sanitize URL to prevent XSS and other injection attacks."""
    try:
        # Parse the URL
        parsed = urlparse(url)
        
        # Remove any HTML tags or script content from the URL
        sanitized_path = re.sub(r'<[^>]*>', '', parsed.path)
        sanitized_query = re.sub(r'<[^>]*>', '', parsed.query)
        sanitized_fragment = re.sub(r'<[^>]*>', '', parsed.fragment)
        
        # Remove any JavaScript protocol handlers
        sanitized_scheme = parsed.scheme.lower()
        if sanitized_scheme not in ['http', 'https']:
            sanitized_scheme = 'https'
            
        # Reconstruct the URL with sanitized components
        sanitized_url = urlunparse((
            sanitized_scheme,
            parsed.netloc,
            sanitized_path,
            parsed.params,
            sanitized_query,
            sanitized_fragment
        ))
        
        # Additional XSS prevention - encode special characters
        sanitized_url = sanitized_url.replace('<', '%3C').replace('>', '%3E')
        sanitized_url = sanitized_url.replace('"', '%22').replace("'", '%27')
        sanitized_url = sanitized_url.replace('(', '%28').replace(')', '%29')
        
        return sanitized_url
    except Exception:
        raise ValueError("Invalid URL format")

@app.post("/dast_scan")
async def dast_scan(request: Request, target_url: str = Form(...), current_user_or_redirect = Depends(get_current_user)):
    # Handle authentication redirect
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect

    try:
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": "Invalid URL format. URL must start with http:// or https://",
                "user": current_user_or_redirect
            })
            
        # Sanitize the URL to prevent XSS
        try:
            sanitized_url = sanitize_url(target_url)
        except ValueError as e:
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": str(e),
                "user": current_user_or_redirect
            })
            
        # Check for localhost/internal IP attempts
        if is_localhost_url(sanitized_url):
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": "Not allowed",
                "user": current_user_or_redirect
            })
            
        # Check if URL is a raw content or API endpoint
        if any(pattern in sanitized_url.lower() for pattern in ['github.com', 'raw.githubusercontent.com', '/api/', '/endpoint', '/v1/', '/v2/']):
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": "Invalid target URL. Please provide a web application URL, not an API endpoint or raw content URL.",
                "user": current_user_or_redirect
            })

        # Check if URL is the application's own domain or IP
        parsed_url = urlparse(sanitized_url)
        request_host = request.headers.get('host', '').split(':')[0]  # Remove port if present
        app_ip = "34.88.103.171"  # Current application IP

        # Check domain match
        if parsed_url.netloc.lower() == request_host.lower():
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": "Scanning the application's own domain is not allowed for security reasons.",
                "user": current_user_or_redirect
            })

        # Check IP match
        if parsed_url.netloc.split(':')[0] == app_ip:
            return templates.TemplateResponse("dast.html", {
                "request": request,
                "error_message": "Scanning the application's IP address is not allowed for security reasons.",
                "user": current_user_or_redirect
            })

        # First create the scan in our system
        scan_id = scan_manager.create_scan(
            target_url=sanitized_url,
            scan_type="DAST",
            source_info=sanitized_url
        )
        # Then start the actual ZAP scan
        threading.Thread(
            target=start_scan_background,
            args=(scan_id, sanitized_url),
            daemon=True
        ).start()
        
        # Check if it's an AJAX request
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JSONResponse({"status": "success", "redirect": "/"})
            
        # Redirect to dashboard
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        error_message = str(e)
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JSONResponse({"status": "error", "message": error_message})
            
        return templates.TemplateResponse("dast.html", {
            "request": request,
            "error_message": error_message,
            "user": current_user_or_redirect
        })

@app.get("/active_scans")
async def get_active_scans():
    active_scans = []
    for scan_id, scan in scan_manager.scans.items():
        if scan.status != "completed" or (datetime.now() - scan.end_time).total_seconds() < 5:
            scan_info = {
                "id": scan.id,
                "target_url": scan.target_url,
                "status": scan.status,
                "scan_type": scan.scan_type,
                "spider_progress": scan.spider_progress if scan.scan_type == "DAST" else None,
                "scan_progress": scan.scan_progress,
                "error": scan.error,
                "source_info": scan.source_info,
                "repo_url": scan.source_info if scan.scan_type == "SAST" else None
            }
            active_scans.append(scan_info)
    return active_scans

@app.get("/recent_reports")
async def get_recent_reports():
    reports = []
    for scan_id, scan in scan_manager.scans.items():
        if scan.status == "completed" and scan.report_path:
            report_info = {
                "id": scan.id,
                "target_url": scan.target_url if scan.scan_type == "DAST" else None,
                "source_info": scan.source_info,
                "scan_type": scan.scan_type,
                "completion_time": scan.end_time.isoformat() if scan.end_time else None,
                "report_url": f"/reports/{os.path.basename(scan.report_path)}"
            }
            reports.append(report_info)
    # Sort by completion time, most recent first
    reports.sort(key=lambda x: x["completion_time"] or "", reverse=True)
    return reports[:10]  # Return only the 10 most recent reports

@app.get("/profile")
async def profile(request: Request, current_user_or_redirect = Depends(get_current_user)):
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": current_user_or_redirect
    })

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        # Check if username or email already exists
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Create new user
        create_initial_user(db, username, email, password)
        
        return JSONResponse({
            "status": "success",
            "message": "Registration successful. Please login."
        })
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# Update cleanup task to respect user ownership
def cleanup_task():
    while True:
        time.sleep(3600)
        db = next(get_db())
        now = datetime.utcnow()
        threshold = now - timedelta(hours=24)  # Keep data for 24 hours

        try:
            # Clean up old scans
            old_scans = db.query(Scan).filter(Scan.end_time < threshold).all()
            for scan in old_scans:
                if scan.report_path and os.path.exists(scan.report_path):
                    try:
                        os.remove(scan.report_path)
                    except Exception as e:
                        print(f"Error deleting report file {scan.report_path}: {e}")
                db.delete(scan)
            
            db.commit()
        except Exception as e:
            print(f"Error in cleanup task: {e}")
            db.rollback()
        finally:
            db.close()

threading.Thread(target=cleanup_task, daemon=True).start()