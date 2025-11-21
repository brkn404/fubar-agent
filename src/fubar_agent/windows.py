"""
Windows-specific Agent Implementation
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, Any

from .base import BaseAgent

logger = logging.getLogger(__name__)


class WindowsAgent(BaseAgent):
    """Windows-specific agent implementation"""
    
    async def get_capabilities(self) -> Dict[str, bool]:
        """Get Windows-specific capabilities"""
        capabilities = await super().get_capabilities()
        
        # Windows-specific capabilities
        capabilities.update({
            "vss": self._check_vss(),
            "eventlog": self._check_eventlog(),
            "yara": self._check_yara(),
        })
        
        return capabilities
    
    def _check_vss(self) -> bool:
        """Check if Volume Shadow Copy Service is available"""
        try:
            import subprocess
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                shell=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_eventlog(self) -> bool:
        """Check if Windows Event Log is available"""
        try:
            import win32evtlog
            return True
        except ImportError:
            return False
    
    def _check_yara(self) -> bool:
        """Check if YARA is installed"""
        try:
            import subprocess
            result = subprocess.run(
                ["where", "yara"],
                capture_output=True,
                text=True,
                shell=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _execute_scan_job(self, job: Dict[str, Any]):
        """Execute scan job on Windows"""
        from uuid import UUID
        job_id = UUID(job["job_id"])
        
        try:
            path = job.get("metadata", {}).get("path")
            if not path:
                raise ValueError("No path specified for scan job")
            
            await self.report_job_status(job_id, "running", 10, 100, "Initializing scan...")
            
            # Discover files
            await self.report_job_status(job_id, "running", 20, 100, "Discovering files...")
            files = await self._discover_files_recursive(path)
            
            total_files = len(files)
            await self.report_job_status(job_id, "running", 50, 100, f"Found {total_files} files, scanning...")
            
            # Scan files and calculate total size
            scanned = 0
            total_size = 0
            for file_path in files:
                try:
                    file_stat = Path(file_path).stat()
                    total_size += file_stat.st_size
                except (OSError, FileNotFoundError):
                    pass  # File may have been deleted
                
                await self._scan_file(file_path, job)
                scanned += 1
                
                if scanned % 100 == 0:
                    progress = 50 + int((scanned / total_files) * 50)
                    await self.report_job_status(
                        job_id, "running", progress, 100,
                        f"Scanned {scanned}/{total_files} files"
                    )
            
            # Report completion with metadata
            await self.report_job_status(
                job_id, "completed", 100, 100, "Scan complete",
                metadata={
                    "files_scanned": total_files,
                    "files_processed": scanned,
                    "total_files": total_files,
                    "scanned_files": scanned,
                    "total_size": total_size,
                }
            )
        
        except Exception as e:
            logger.error(f"Scan job failed: {e}")
            raise
    
    async def _discover_files_recursive(self, path: str):
        """Recursively discover files"""
        files = []
        path_obj = Path(path)
        
        if path_obj.is_file():
            return [str(path_obj)]
        
        for file_path in path_obj.rglob("*"):
            if file_path.is_file():
                files.append(str(file_path))
        
        return files
    
    async def _scan_file(self, file_path: str, job: Dict[str, Any]):
        """Scan a single file"""
        # Basic file scanning
        # In production, would integrate with Sentinel scanner
        pass
    
    async def _create_platform_snapshot(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Create snapshot locally on Windows"""
        from uuid import UUID, uuid4
        from datetime import datetime
        
        source = job.get("metadata", {}).get("source")
        if not source:
            raise ValueError("No source specified for backup job")
        
        tags = job.get("metadata", {}).get("tags", [])
        format_type = job.get("metadata", {}).get("format", "hardlink")
        
        # Generate snapshot ID
        snapshot_id = f"snap-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}"
        
        # Create snapshot destination
        snapshot_dir = Path("C:\\Temp\\unified-backups") / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        # Use robocopy for backup on Windows
        cmd = [
            "robocopy",
            source,
            str(snapshot_dir),
            "/E",  # Copy subdirectories
            "/R:3",  # Retry 3 times
            "/W:1",  # Wait 1 second between retries
            "/NP",  # No progress (for automation)
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            shell=True
        )
        
        await process.wait()
        
        # robocopy returns 0-7 for success, 8+ for errors
        if process.returncode >= 8:
            raise RuntimeError(f"robocopy failed with code {process.returncode}")
        
        # Calculate size and file count
        file_count = 0
        total_size = 0
        for f in snapshot_dir.rglob('*'):
            if f.is_file():
                try:
                    total_size += f.stat().st_size
                    file_count += 1
                except (OSError, FileNotFoundError):
                    pass  # File may have been deleted
        
        return {
            "snapshot_id": snapshot_id,
            "source_path": source,
            "snapshot_path": str(snapshot_dir),
            "format": format_type,
            "tags": tags,
            "size": total_size,
            "metadata": {
                "platform": "windows",
                "created_by": "windows-agent",
                "total_files": file_count,
                "file_count": file_count,
            },
            "auto_scan": job.get("metadata", {}).get("auto_scan", False),
        }
    
    async def _execute_restore_job(self, job: Dict[str, Any]):
        """Execute restore job on Windows - downloads chunks and reassembles files"""
        # Use same implementation as Linux agent
        from .linux import LinuxAgent
        linux_agent = LinuxAgent.__new__(LinuxAgent)
        linux_agent.session = self.session
        linux_agent.server_url = self.server_url
        linux_agent.report_job_status = self.report_job_status
        await linux_agent._execute_restore_job(job)

