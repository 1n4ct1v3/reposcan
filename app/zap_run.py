import time
import requests
import threading
import os
from datetime import datetime
from app.scan_manager import scan_manager
import json
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ZAP configuration
ZAP_API = "http://localhost:8080"
ZAP_API_KEY = os.getenv('ZAP_API_KEY')

def start_scan_background(scan_id: str, target_url: str):
    """Runs the ZAP scan in the background and updates scan status"""
    try:
        # Initialize scan status
        scan_manager.update_status(scan_id, status="running", spider_progress=0, scan_progress=0)

        # 1️⃣ Start Spider Scan
        spider_url = f"{ZAP_API}/JSON/spider/action/scan/?apikey={ZAP_API_KEY}&url={target_url}"
        response = requests.get(spider_url, timeout=30)  # Increased timeout
        response_json = response.json()
        
        if 'error' in response_json:
            scan_manager.update_status(scan_id, status="failed", error=f"Spider error: {response_json['error']}")
            return
            
        spider_id = response_json.get("scan")

        if not spider_id:
            scan_manager.update_status(scan_id, status="failed", error="Spider scan failed to start - no scan ID returned")
            return

        # 2️⃣ Wait for Spider to Complete
        spider_complete = False
        retry_count = 0
        max_retries = 60  # Increased max retries for spider
        while not spider_complete and retry_count < max_retries:
            try:
                status_response = requests.get(
                    f"{ZAP_API}/JSON/spider/view/status/?apikey={ZAP_API_KEY}&scanId={spider_id}",
                    timeout=30
                ).json()
                
                if 'error' in status_response:
                    retry_count += 1
                    time.sleep(5)
                    continue
                    
                progress = int(status_response.get("status", "0"))
                scan_manager.update_status(scan_id, spider_progress=progress)
                
                if progress == 100:
                    spider_complete = True
                else:
                    time.sleep(5)
                    
            except Exception as e:
                retry_count += 1
                time.sleep(5)
                continue

        if not spider_complete:
            scan_manager.update_status(scan_id, status="failed", error="Spider scan timed out or failed to complete")
            return

        # 3️⃣ Start Active Scan
        scan_url = f"{ZAP_API}/JSON/ascan/action/scan/?apikey={ZAP_API_KEY}&url={target_url}"
        response = requests.get(scan_url, timeout=30)
        response_json = response.json()
        
        if 'error' in response_json:
            scan_manager.update_status(scan_id, status="failed", error=f"Active scan error: {response_json['error']}")
            return
            
        scan_id_zap = response_json.get("scan")

        if not scan_id_zap:
            scan_manager.update_status(scan_id, status="failed", error="Active scan failed to start - no scan ID returned")
            return

        # 4️⃣ Wait for Active Scan to Complete
        scan_complete = False
        retry_count = 0
        max_retries = 600  # Increased significantly for active scan (50 minutes max)
        last_progress = -1
        stall_count = 0
        
        while not scan_complete and retry_count < max_retries:
            try:
                status_response = requests.get(
                    f"{ZAP_API}/JSON/ascan/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id_zap}",
                    timeout=30
                ).json()
                
                if 'error' in status_response:
                    retry_count += 1
                    time.sleep(5)
                    continue
                    
                progress = int(status_response.get("status", "0"))
                scan_manager.update_status(scan_id, scan_progress=progress)
                
                # Check if progress is stalled
                if progress == last_progress:
                    stall_count += 1
                else:
                    stall_count = 0
                    last_progress = progress
                
                # If progress is stalled for too long (5 minutes), check if scan is actually complete
                if stall_count >= 60:
                    try:
                        # Check if the scan is actually finished using the scan status endpoint
                        scan_status = requests.get(
                            f"{ZAP_API}/JSON/ascan/view/scanProgress/?apikey={ZAP_API_KEY}&scanId={scan_id_zap}",
                            timeout=30
                        ).json()
                        
                        if scan_status.get("status") == "100":
                            scan_complete = True
                            break
                    except Exception:
                        pass
                
                if progress == 100:
                    scan_complete = True
                else:
                    time.sleep(5)
                    retry_count += 1
                    
            except Exception as e:
                retry_count += 1
                time.sleep(5)
                continue

        if not scan_complete and retry_count >= max_retries:
            scan_manager.update_status(scan_id, status="failed", error="Active scan timed out or failed to complete")
            return

        # 5️⃣ Generate HTML Report
        try:
            report_url = f"{ZAP_API}/JSON/reports/action/generate/"
            absolute_report_dir = os.path.abspath("reports")

            report_params = {
                "apikey": ZAP_API_KEY,
                "title": f"Security Scan Report - {target_url}",
                "template": "modern",
                "theme": "plutonium",
                "description": f"DAST scan results for {target_url}",
                "sites": target_url,
                "reportFileName": f"zap_report_{scan_id}.html",
                "reportDir": absolute_report_dir,
                "contexts": "",
                "sections": "",
                "includedConfidences": "",
                "includedRisks": "",
                "reportFileNamePattern": "",
                "display": ""
            }

            generate_response = requests.get(report_url, params=report_params, timeout=60)  # Increased timeout for report generation
            
            if generate_response.status_code == 200:
                try:
                    response_data = generate_response.json()
                    zap_report_path = response_data.get("generate")
                    
                    if zap_report_path:
                        with open(zap_report_path, 'r') as f:
                            report_content = f.read()
                        
                        report_path = os.path.join(absolute_report_dir, f"zap_report_{scan_id}.html")
                        with open(report_path, "w") as f:
                            f.write(report_content)
                    else:
                        raise Exception("No report path in response")
                    
                except Exception as e:
                    print(f"Error processing modern report: {e}")
                    # Fallback to traditional report
                    report_url = f"{ZAP_API}/OTHER/core/other/htmlreport/?apikey={ZAP_API_KEY}"
                    report = requests.get(report_url, timeout=60)
                    
                    report_path = os.path.join(absolute_report_dir, f"zap_report_{scan_id}.html")
                    with open(report_path, "wb") as f:
                        f.write(report.content)
            else:
                # Fallback to traditional report if modern template fails
                print(f"Modern template failed: {generate_response.text}")
                report_url = f"{ZAP_API}/OTHER/core/other/htmlreport/?apikey={ZAP_API_KEY}"
                report = requests.get(report_url, timeout=60)
                
                report_path = os.path.join(absolute_report_dir, f"zap_report_{scan_id}.html")
                with open(report_path, "wb") as f:
                    f.write(report.content)

            scan_manager.update_status(scan_id, status="completed", scan_progress=100)
            scan_manager.update_status(scan_id, report_path=report_path)

        except Exception as e:
            scan_manager.update_status(scan_id, status="failed", error=f"Report generation failed: {str(e)}")
            return

    except requests.exceptions.ConnectionError:
        scan_manager.update_status(scan_id, status="failed", error="ZAP is not running or unreachable")
    except requests.exceptions.Timeout:
        scan_manager.update_status(scan_id, status="failed", error="Request to ZAP timed out")
    except Exception as e:
        scan_manager.update_status(scan_id, status="failed", error=str(e))

def start_scan(target_url: str) -> str:
    """Starts a new ZAP scan in the background and returns the scan ID"""
    scan_id = scan_manager.create_scan(
        target_url=target_url,
        scan_type="DAST",
        source_info=target_url
    )
    threading.Thread(target=start_scan_background, args=(scan_id, target_url), daemon=True).start()
    return scan_id
