"""
macOS-specific Agent Implementation
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, Any

from .base import BaseAgent

logger = logging.getLogger(__name__)


class MacOSAgent(BaseAgent):
    """macOS-specific agent implementation"""
    
    async def get_capabilities(self) -> Dict[str, bool]:
        """Get macOS-specific capabilities"""
        capabilities = await super().get_capabilities()
        
        # macOS-specific capabilities
        capabilities.update({
            "spotlight": self._check_spotlight(),
            "timemachine": self._check_timemachine(),
            "yara": self._check_yara(),
        })
        
        return capabilities
    
    def _check_spotlight(self) -> bool:
        """Check if Spotlight is available"""
        try:
            import subprocess
            result = subprocess.run(
                ["mdutil", "-s", "/"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_timemachine(self) -> bool:
        """Check if Time Machine is configured"""
        try:
            import subprocess
            result = subprocess.run(
                ["tmutil", "listbackups"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_yara(self) -> bool:
        """Check if YARA is installed"""
        try:
            import subprocess
            result = subprocess.run(
                ["which", "yara"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _execute_scan_job(self, job: Dict[str, Any]):
        """Execute scan job on macOS"""
        from uuid import UUID
        job_id = UUID(job["job_id"])
        
        try:
            # Get job config
            path = job.get("metadata", {}).get("path")
            if not path:
                raise ValueError("No path specified for scan job")
            
            # Report progress
            await self.report_job_status(job_id, "running", 10, 100, "Initializing scan...")
            
            # Use Spotlight for fast file discovery on macOS
            if self._check_spotlight():
                await self.report_job_status(job_id, "running", 20, 100, "Using Spotlight for file discovery...")
                files = await self._discover_files_spotlight(path)
            else:
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
    
    async def _discover_files_spotlight(self, path: str):
        """Discover files using Spotlight (macOS)"""
        import subprocess
        
        # Use mdfind for fast file discovery
        cmd = ["mdfind", "-onlyin", path, "kMDItemContentType != 'public.folder'"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        
        # Fallback to recursive
        return await self._discover_files_recursive(path)
    
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
        """Create snapshot locally on macOS"""
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
        snapshot_dir = Path("/tmp/unified-backups") / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        # Use rsync for backup (hardlink format)
        import subprocess
        
        # Find previous snapshot for hardlinking
        parent_dir = snapshot_dir.parent
        previous_snapshot = None
        if parent_dir.exists():
            existing_snapshots = sorted(
                [d for d in parent_dir.iterdir() if d.is_dir() and d != snapshot_dir],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            if existing_snapshots:
                previous_snapshot = existing_snapshots[0]
        
        # Build rsync command
        cmd = ["rsync", "-a", "--delete", "--no-group", "--no-owner", "--partial"]
        
        if previous_snapshot:
            cmd.extend(["--link-dest", str(previous_snapshot)])
        
        # Add source and destination
        source_path = Path(source)
        if source_path.is_file():
            cmd.append(str(source_path))
        else:
            cmd.append(f"{source_path}/")
        
        cmd.append(str(snapshot_dir))
        
        # Execute rsync
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await process.wait()
        
        if process.returncode != 0:
            raise RuntimeError(f"rsync failed with code {process.returncode}")
        
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
                "platform": "darwin",
                "created_by": "macos-agent",
                "previous_snapshot": str(previous_snapshot) if previous_snapshot else None,
                "total_files": file_count,
                "file_count": file_count,
            },
            "auto_scan": job.get("metadata", {}).get("auto_scan", False),
        }
    
    async def _execute_restore_job(self, job: Dict[str, Any]):
        """Execute restore job on macOS - downloads chunks and reassembles files"""
        # Use same implementation as Linux agent
        from .linux import LinuxAgent
        linux_agent = LinuxAgent.__new__(LinuxAgent)
        linux_agent.session = self.session
        linux_agent.server_url = self.server_url
        linux_agent.report_job_status = self.report_job_status
        await linux_agent._execute_restore_job(job)

