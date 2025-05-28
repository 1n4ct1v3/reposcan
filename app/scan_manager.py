from typing import Dict, Optional
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ScanStatus:
    id: str
    target_url: str
    status: str  # 'running', 'completed', 'failed'
    scan_type: str  # 'DAST' or 'SAST'
    spider_progress: int = 0
    scan_progress: int = 0
    error: Optional[str] = None
    report_path: Optional[str] = None
    start_time: datetime = None
    end_time: datetime = None
    source_info: Optional[str] = None  # For SAST: repo URL or filename

class ScanManager:
    def __init__(self):
        self.scans: Dict[str, ScanStatus] = {}
        self._lock = threading.Lock()

    def create_scan(self, target_url: str, scan_type: str = "DAST", source_info: str = None) -> str:
        scan_id = str(uuid.uuid4())
        with self._lock:
            self.scans[scan_id] = ScanStatus(
                id=scan_id,
                target_url=target_url,
                status="running",
                scan_type=scan_type,
                start_time=datetime.now(),
                source_info=source_info or target_url  # Use target_url as source_info for DAST scans
            )
        return scan_id

    def update_status(self, scan_id: str, **kwargs):
        with self._lock:
            if scan_id in self.scans:
                scan = self.scans[scan_id]
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                    else:
                        print(f"Warning: Attempting to set unknown attribute {key} on ScanStatus")
                
                if kwargs.get('status') in ['completed', 'failed']:
                    scan.end_time = datetime.now()
                    # If scan failed, schedule its removal after 5 seconds
                    if kwargs.get('status') == 'failed':
                        threading.Timer(5.0, self.remove_scan, args=[scan_id]).start()

    def get_status(self, scan_id: str) -> Optional[ScanStatus]:
        with self._lock:
            return self.scans.get(scan_id)

    def get_active_scans(self, scan_type: Optional[str] = None) -> Dict[str, ScanStatus]:
        with self._lock:
            if scan_type:
                return {
                    scan_id: scan for scan_id, scan in self.scans.items()
                    if scan.status == "running" and scan.scan_type == scan_type
                }
            return {
                scan_id: scan for scan_id, scan in self.scans.items()
                if scan.status == "running"
            }

    def cleanup_old_scans(self, hours: int = 24):
        """Remove scans older than specified hours"""
        current_time = datetime.now()
        with self._lock:
            for scan_id in list(self.scans.keys()):
                scan = self.scans[scan_id]
                if scan.end_time and (current_time - scan.end_time).total_seconds() > hours * 3600:
                    del self.scans[scan_id]

    def remove_scan(self, scan_id: str):
        """Remove a specific scan from the manager"""
        with self._lock:
            if scan_id in self.scans:
                del self.scans[scan_id]

# Global scan manager instance
scan_manager = ScanManager()

# Start cleanup thread
def cleanup_old_scans():
    while True:
        time.sleep(3600)  # Run every hour
        scan_manager.cleanup_old_scans()

threading.Thread(target=cleanup_old_scans, daemon=True).start()