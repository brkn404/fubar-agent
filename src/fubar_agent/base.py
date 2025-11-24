"""
Base Agent Class

Foundation for platform-specific agents.
"""

import asyncio
import logging
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID

import aiohttp

from .platform_detection import detect_platform, PlatformInfo

logger = logging.getLogger(__name__)


class BaseAgent:
    """
    Base agent class for connecting to central server.
    
    Platform-specific agents should inherit from this class.
    """
    
    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        registration_token: Optional[str] = None,
        agent_id: Optional[str] = None,
        poll_interval: int = 5,
        heartbeat_interval: int = 30,
        max_concurrent_jobs: int = 2,
        # Streaming configuration
        max_concurrent_streams: int = 3,
        max_connections: int = 10,
        max_concurrent_chunks: int = 5,  # Max concurrent chunks per file
        bandwidth_limit: Optional[int] = None,  # Bytes per second
        chunk_size: int = 1024 * 1024,  # 1MB chunks
    ):
        """
        Initialize agent.
        
        Args:
            server_url: Central server URL
            api_key: API key for authentication
            agent_id: Existing agent ID (if reconnecting)
            poll_interval: Seconds between job polls
            heartbeat_interval: Seconds between heartbeats
            max_concurrent_jobs: Maximum concurrent jobs
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.registration_token = registration_token
        self.agent_id = agent_id
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.max_concurrent_jobs = max_concurrent_jobs
        
        # Streaming configuration
        self.max_concurrent_streams = max_concurrent_streams
        self.max_connections = max_connections
        self.max_concurrent_chunks = max_concurrent_chunks
        self.bandwidth_limit = bandwidth_limit
        self.chunk_size = chunk_size
        
        # Auto-tune bandwidth if enabled
        self.auto_tune_bandwidth = os.getenv("AUTO_TUNE_BANDWIDTH", "false").lower() == "true"
        self.target_utilization = float(os.getenv("TARGET_NETWORK_UTILIZATION", "0.80"))
        
        # Platform info
        self.platform_info = detect_platform()
        
        # State
        self.registered = False
        self.running = False
        self.active_jobs: Dict[UUID, asyncio.Task] = {}
        self.host_id: Optional[str] = None  # Linked host ID if registered with token
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # WebSocket connection
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        
        # Streaming
        self.stream_uploader: Optional[Any] = None
    
    async def start(self):
        """Start the agent"""
        if self.running:
            logger.warning("Agent already running")
            return
        
        self.running = True
        
        # Create HTTP session with connection pool limits
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        # Configure connection pool
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=self.max_concurrent_streams,
        )
        
        timeout = aiohttp.ClientTimeout(total=300)  # 5 minute timeout for large uploads
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=timeout,
        )
        
        # Auto-tune bandwidth if enabled
        if self.auto_tune_bandwidth and self.bandwidth_limit is None:
            try:
                from .bandwidth import auto_configure_bandwidth
                logger.info("Auto-tuning bandwidth settings...")
                optimal_settings = await auto_configure_bandwidth(
                    self.server_url,
                    session=self.session,
                    target_utilization=self.target_utilization,
                )
                # Override with optimal settings
                self.max_concurrent_streams = optimal_settings["max_concurrent_streams"]
                self.max_connections = optimal_settings["max_connections"]
                self.bandwidth_limit = optimal_settings["bandwidth_limit"]
                self.chunk_size = optimal_settings["chunk_size"]
                logger.info(f"Auto-tuned to {self.target_utilization*100:.0f}% network utilization")
            except Exception as e:
                logger.warning(f"Auto-tuning failed, using defaults: {e}")
        
        # Initialize stream uploader
        from .streaming import StreamUploader, StreamConfig
        
        stream_config = StreamConfig(
            chunk_size=self.chunk_size,
            max_concurrent_streams=self.max_concurrent_streams,
            max_connections=self.max_connections,
            max_concurrent_chunks=self.max_concurrent_chunks,
            bandwidth_limit=self.bandwidth_limit,
        )
        
        self.stream_uploader = StreamUploader(
            server_url=self.server_url,
            session=self.session,
            config=stream_config,
        )
        
        # Register with server
        await self.register()
        
        # Check for updates immediately on startup
        await self._check_for_updates()
        
        # Start background tasks
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._job_poll_loop())
        asyncio.create_task(self._websocket_loop())
        
        logger.info(f"Agent started: {self.agent_id}")
    
    async def stop(self):
        """Stop the agent"""
        self.running = False
        
        # Cancel active jobs
        for task in self.active_jobs.values():
            task.cancel()
        
        # Close WebSocket
        if self.ws:
            await self.ws.close()
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        logger.info("Agent stopped")
    
    async def register(self) -> bool:
        """Register agent with server"""
        try:
            capabilities = await self.get_capabilities()
            resources = await self.get_resources()
            
            payload = {
                "hostname": self.platform_info.hostname,
                "platform": self.platform_info.platform,
                "version": "0.1.0",
                "capabilities": capabilities,
                "resources": resources,
            }
            
            if self.agent_id:
                payload["agent_id"] = self.agent_id
            
            if self.registration_token:
                payload["registration_token"] = self.registration_token
            
            # Get host_id if available
            if hasattr(self, 'host_id') and self.host_id:
                payload["host_id"] = self.host_id
            
            async with self.session.post(
                f"{self.server_url}/api/v1/agents/register",
                json=payload
            ) as resp:
                if resp.status in (200, 201):  # Accept both 200 OK and 201 Created
                    data = await resp.json()
                    self.agent_id = data.get("agent_id")
                    self.host_id = data.get("host_id")  # Store host_id if linked
                    self.registered = True
                    logger.info(f"Agent registered: {self.agent_id}, host_id: {self.host_id}")
                    
                    # Save agent_id to config file if config_path is available
                    if hasattr(self, 'config_path') and self.config_path:
                        try:
                            import yaml
                            from pathlib import Path
                            config_path = Path(self.config_path)
                            if config_path.exists():
                                with config_path.open("r") as f:
                                    config = yaml.safe_load(f) or {}
                                if "agent" not in config:
                                    config["agent"] = {}
                                config["agent"]["agent_id"] = self.agent_id
                                if self.host_id:
                                    config["agent"]["host_id"] = self.host_id
                                with config_path.open("w") as f:
                                    yaml.dump(config, f)
                                logger.debug(f"Saved agent_id to config: {self.agent_id}")
                        except Exception as e:
                            logger.warning(f"Failed to save agent_id to config: {e}")
                    
                    return True
                else:
                    error_text = await resp.text()
                    logger.error(f"Registration failed: {resp.status} - {error_text}")
                    return False
        
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    async def get_capabilities(self) -> Dict[str, bool]:
        """Get agent capabilities"""
        return {
            "scan": True,
            "backup": True,
            "restore": True,
            "yara": False,  # Platform-specific
            "virustotal": False,  # Requires API key
        }
    
    async def get_resources(self) -> Dict[str, Any]:
        """Get available resources"""
        import psutil
        
        return {
            "cpu_cores": psutil.cpu_count(),
            "memory_gb": psutil.virtual_memory().total // (1024**3),
            "disk_space_gb": psutil.disk_usage('/').free // (1024**3),
        }
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats and check for updates"""
        import time
        update_check_interval = 300  # Check for updates every 5 minutes
        last_update_check = 0
        
        while self.running:
            try:
                await self.send_heartbeat()
                
                # Periodically check for code updates
                current_time = time.time()
                if current_time - last_update_check > update_check_interval:
                    await self._check_for_updates()
                    last_update_check = current_time
                
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def _check_for_updates(self):
        """Check if agent code needs to be updated"""
        if not self.registered or not self.agent_id:
            logger.debug("Skipping update check: agent not registered")
            return
        
        # Prevent update loops - if we just updated, skip this check
        if hasattr(self, '_just_updated') and self._just_updated:
            logger.debug("Skipping update check: just updated, waiting for restart")
            return
        
        try:
            # Get current version using the same method as _get_agent_version()
            current_version = self._get_agent_version()
            
            if current_version == "unknown":
                logger.debug("Could not determine current version, skipping auto-update check")
                logger.info("Note: Auto-update requires git repository. Use 'unified-agent sync' to manually update.")
                return
            
            logger.info(f"Checking for updates (current version: {current_version})...")
            
            # Check server for updates
            async with self.session.get(
                f"{self.server_url}/api/v1/agents/sync/check",
                params={"agent_id": self.agent_id, "current_version": current_version}
            ) as resp:
                if resp.status == 200:
                    update_info = await resp.json()
                    if update_info.get("update_needed"):
                        latest_version = update_info.get("latest_version")
                        logger.info(f"Agent update available: {latest_version} (current: {current_version})")
                        logger.info("Auto-downloading update...")
                        
                        # Auto-download and apply update
                        try:
                            await self._auto_update_agent(latest_version, current_version)
                            # Mark that we just updated to prevent loops
                            self._just_updated = True
                        except Exception as e:
                            logger.error(f"Auto-update failed: {e}")
                            logger.info("You can manually update by running: unified-agent sync")
                    else:
                        logger.info(f"Agent is up to date (version: {current_version})")
                else:
                    logger.warning(f"Update check failed: HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"Update check failed: {e}")
    
    async def _auto_update_agent(self, latest_version: str, current_version: str):
        """Automatically download and apply agent code update"""
        import tempfile
        import zipfile
        import shutil
        from pathlib import Path
        
        logger.info(f"Downloading agent code version {latest_version}...")
        
        # Download code
        async with self.session.get(
            f"{self.server_url}/api/v1/agents/sync/download",
            params={"agent_id": self.agent_id}
        ) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Failed to download code: {resp.status}")
            
            # Get version from headers
            server_version = resp.headers.get("X-Agent-Version", latest_version)
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_file:
                zip_path = Path(tmp_file.name)
                async for chunk in resp.content.iter_chunked(8192):
                    tmp_file.write(chunk)
            
            logger.info(f"Downloaded version {server_version}, extracting...")
            
            # Extract to agent directory
            agent_path = Path(__file__).parent
            backup_path = agent_path.parent / f"agent_backup_{current_version}"
            
            # Backup current code
            if agent_path.exists():
                if backup_path.exists():
                    shutil.rmtree(backup_path)
                shutil.copytree(agent_path, backup_path)
                logger.info(f"Backed up current code to {backup_path}")
            
            # Extract new code
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                zipf.extractall(agent_path.parent)
            
            # Clean up
            zip_path.unlink()
            
            logger.info(f"✅ Agent code updated successfully! New version: {server_version}")
            logger.info(f"Backup saved to: {backup_path}")
            logger.warning("⚠️  Agent code has been updated. Please restart the agent to use the new code.")
            
            # Report version update to server
            try:
                async with self.session.post(
                    f"{self.server_url}/api/v1/agents/{self.agent_id}/heartbeat",
                    json={
                        "status": "online",
                        "active_jobs": len(self.active_jobs),
                        "version": server_version,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                ) as resp:
                    if resp.status == 200:
                        logger.info("✅ Version reported to server")
                    else:
                        logger.warning(f"⚠️  Failed to report version to server: {resp.status}")
            except Exception as e:
                logger.warning(f"⚠️  Failed to report version to server: {e}")
    
    async def send_heartbeat(self):
        """Send heartbeat to server"""
        if not self.registered or not self.session:
            return
        
        # Get current agent code version
        agent_version = self._get_agent_version()
        
        # Don't retry heartbeats - if it fails, just log and continue
        try:
            payload = {
                "status": "online",
                "active_jobs": len(self.active_jobs),
                "timestamp": datetime.utcnow().isoformat(),
                "version": agent_version,  # Include version in heartbeat
            }
            
            async with self.session.post(
                f"{self.server_url}/api/v1/agents/{self.agent_id}/heartbeat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Heartbeat failed: {resp.status}")
        except Exception as e:
            logger.warning(f"Heartbeat error (non-critical): {e}")
    
    def _get_agent_version(self) -> str:
        """Get current agent code version (git commit hash)"""
        try:
            import subprocess
            from pathlib import Path
            # Use git to find the repo root (more reliable than walking directories)
            current_path = Path(__file__).resolve()
            # Try to find git repo root using git command
            try:
                repo_path = subprocess.check_output(
                    ["git", "rev-parse", "--show-toplevel"],
                    cwd=current_path.parent,
                    stderr=subprocess.DEVNULL
                ).decode().strip()
                repo_path = Path(repo_path)
                
                if repo_path.exists() and (repo_path / ".git").exists():
                    commit = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()[:8]
                    return commit
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback: try walking up directories
                repo_path = current_path.parent.parent.parent.parent.parent
                if not (repo_path / ".git").exists():
                    repo_path = repo_path.parent
                if (repo_path / ".git").exists():
                    commit = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()[:8]
                    return commit
        except Exception as e:
            logger.debug(f"Could not get git version: {e}")
        # Fallback to package version
        try:
            from .version import __version__
            return __version__
        except ImportError:
            return "unknown"
    
    async def _job_poll_loop(self):
        """Poll for new jobs"""
        while self.running:
            try:
                if len(self.active_jobs) < self.max_concurrent_jobs:
                    job = await self.poll_job()
                    if job:
                        await self.execute_job(job)
                
                await asyncio.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Job poll error: {e}")
                await asyncio.sleep(self.poll_interval)
    
    async def poll_job(self) -> Optional[Dict[str, Any]]:
        """Poll server for new job"""
        if not self.registered or not self.session:
            return None
        
        # Don't retry polling - if it fails, return None and try again next cycle
        try:
            async with self.session.get(
                f"{self.server_url}/api/v1/agents/{self.agent_id}/jobs/poll",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("job")
                elif resp.status == 204:
                    # No jobs available
                    return None
                else:
                    logger.warning(f"Poll failed: {resp.status}")
                    return None
        except Exception as e:
            logger.warning(f"Poll error (will retry next cycle): {e}")
            return None
    
    async def _websocket_loop(self):
        """Maintain WebSocket connection"""
        while self.running:
            try:
                if not self.registered:
                    await asyncio.sleep(5)
                    continue
                
                ws_url = f"{self.server_url.replace('http', 'ws')}/ws/agents/{self.agent_id}"
                
                async with self.session.ws_connect(ws_url) as ws:
                    self.ws = ws
                    logger.info("WebSocket connected")
                    
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            await self._handle_websocket_message(msg.json())
                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            logger.error(f"WebSocket error: {ws.exception()}")
                            break
                
                self.ws = None
                logger.warning("WebSocket disconnected, reconnecting...")
                await asyncio.sleep(5)
            
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                await asyncio.sleep(5)
    
    async def _handle_websocket_message(self, message: Dict[str, Any]):
        """Handle WebSocket message"""
        msg_type = message.get("type")
        
        if msg_type == "job_assigned":
            job = message.get("job")
            if job and len(self.active_jobs) < self.max_concurrent_jobs:
                await self.execute_job(job)
        
        elif msg_type == "job_cancelled":
            job_id = UUID(message.get("job_id"))
            if job_id in self.active_jobs:
                self.active_jobs[job_id].cancel()
                del self.active_jobs[job_id]
        
        elif msg_type == "ping":
            if self.ws:
                await self.ws.send_json({"type": "pong"})
        
        elif msg_type == "update_requested":
            # Server requested agent to update
            logger.info("Server requested agent update")
            # Agent will check for updates on next heartbeat
            # Could also trigger immediate update here if needed
    
    async def execute_job(self, job: Dict[str, Any]):
        """Execute a job"""
        job_id = UUID(job["job_id"])
        job_type = job["job_type"]
        
        # Check if job is already active
        if job_id in self.active_jobs:
            task = self.active_jobs[job_id]
            # Check if task is done or cancelled
            if task.done():
                # Task is done - remove it and start fresh
                logger.info(f"Job {job_id} task completed, removing and restarting")
                try:
                    task.result()  # Consume any exception
                except Exception:
                    pass  # Ignore exceptions from old task
                del self.active_jobs[job_id]
            else:
                # Task is still running - this can happen if job was paused and resumed
                # Cancel the old task and start fresh to ensure we're in sync with server state
                logger.info(f"Job {job_id} already active - cancelling old task and restarting")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass  # Expected when cancelling
                except Exception as e:
                    logger.warning(f"Error cancelling old task: {e}")
                del self.active_jobs[job_id]
        
        # Create execution task
        task = asyncio.create_task(self._run_job(job))
        self.active_jobs[job_id] = task
    
    async def _run_job(self, job: Dict[str, Any]):
        """Run job execution"""
        job_id = UUID(job["job_id"])
        job_type = job["job_type"]
        
        # Set up agent log handler to mirror logs to server
        agent_log_handler = None
        try:
            agent_log_handler = self._setup_agent_log_handler(job_id)
        except Exception as e:
            logger.debug(f"Could not set up agent log handler: {e}")
        
        try:
            logger.info(f"Starting job {job_id}: {job_type}")
            
            # Check for cancellation before starting
            if asyncio.current_task().cancelled():
                logger.info(f"Job {job_id} was cancelled before starting")
                return
            
            # Report job started (or resumed)
            await self.report_job_status(job_id, "running", 0, 100, "Starting...")
            
            # Execute based on type
            if job_type == "scan":
                await self._execute_scan_job(job)
            elif job_type == "backup":
                await self._execute_backup_job(job)
            elif job_type == "scan_backup" or job_type == "scan-backup":
                await self._execute_scan_backup_job(job)
            elif job_type == "restore":
                await self._execute_restore_job(job)
            else:
                raise ValueError(f"Unknown job type: {job_type}")
            
            # Check for cancellation before reporting completion
            if asyncio.current_task().cancelled():
                logger.info(f"Job {job_id} was cancelled before completion")
                return
            
            # Report completion
            await self.report_job_status(job_id, "completed", 100, 100, "Completed")
            logger.info(f"Job {job_id} completed")
            
            # Stream log files to server after job completion
            await self._stream_job_logs(job_id)
        
        except asyncio.CancelledError:
            logger.info(f"Job {job_id} was cancelled")
            # Report cancellation to server
            try:
                await self.report_job_status(job_id, "cancelled", 0, 100, "Job was cancelled")
            except Exception:
                pass  # Ignore errors when reporting cancellation
            raise
        except Exception as e:
            import traceback
            error_msg = str(e)
            error_trace = traceback.format_exc()
            logger.error(f"Job {job_id} failed: {error_msg}")
            logger.error(f"Traceback: {error_trace}")
            # Report failure with detailed error
            await self.report_job_status(
                job_id, "failed", 0, 100, error_msg,
                metadata={"error": error_msg, "error_trace": error_trace}
            )
        
        finally:
            # Remove agent log handler
            if agent_log_handler:
                try:
                    self._remove_agent_log_handler(agent_log_handler)
                except Exception:
                    pass
            
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
    
    async def _execute_scan_job(self, job: Dict[str, Any]):
        """Execute scan job (platform-specific)"""
        raise NotImplementedError("Platform-specific implementation required")
    
    async def _execute_backup_job(self, job: Dict[str, Any]):
        """
        Execute backup job with hybrid snapshot approach.
        
        Default behavior (snapshot-first mode):
        1. Create snapshot locally in persistent location (with hardlinks for incremental)
        2. Stream snapshot to server
        3. Keep snapshot locally for point-in-time recovery
        
        Alternative modes:
        - Direct streaming: Set stream_directly=true to bypass snapshot
        - Delete after streaming: Set keep_snapshot_local=false to save space
        """
        from uuid import UUID
        job_id = UUID(job["job_id"])
        
        try:
            await self.report_job_status(job_id, "running", 10, 100, "Initializing backup...")
            
            # Check backup mode: snapshot-first (default) or direct streaming
            job_metadata = job.get("metadata", {})
            create_snapshot = job_metadata.get("create_snapshot", True)  # Default to True - create snapshot first
            stream_to_server = job_metadata.get("stream_to_server", True)  # Default to True for backups
            keep_snapshot_local = job_metadata.get("keep_snapshot_local", True)  # Default to True - keep for recovery
            
            # Direct streaming mode (no snapshot) - for very large datasets or when snapshot not needed
            stream_directly = job_metadata.get("stream_directly", False)  # Default to False - use snapshots
            
            # Auto-enable direct streaming for large files (>1GB) to avoid local disk space issues
            if not stream_directly and stream_to_server:
                source_path_str = job.get("source") or job_metadata.get("source") or job_metadata.get("path")
                if source_path_str:
                    try:
                        from pathlib import Path
                        import os
                        # Normalize path for Windows (convert forward slashes to backslashes)
                        normalized_source = os.path.normpath(source_path_str) if os.name == 'nt' else source_path_str
                        source_path = Path(normalized_source).resolve()
                        if not source_path.exists():
                            # Try original path as fallback
                            source_path = Path(source_path_str).resolve()
                        if source_path.exists():
                            if source_path.is_file():
                                file_size = source_path.stat().st_size
                                # Auto-use direct streaming for files > 1GB
                                if file_size > 1024 * 1024 * 1024:  # 1GB
                                    logger.info(f"Large file detected ({file_size / (1024**3):.2f} GB), using direct streaming mode (skipping local snapshot)")
                                    stream_directly = True
                                    create_snapshot = False
                                    # Update metadata to reflect this
                                    job_metadata["stream_directly"] = True
                                    job_metadata["create_snapshot"] = False
                            elif source_path.is_dir():
                                # For directories, check if any single file is large
                                large_file_found = False
                                try:
                                    for f in source_path.rglob('*'):
                                        if f.is_file():
                                            try:
                                                if f.stat().st_size > 1024 * 1024 * 1024:  # 1GB
                                                    large_file_found = True
                                                    logger.info(f"Large file found in directory ({f.stat().st_size / (1024**3):.2f} GB), using direct streaming mode")
                                                    break
                                            except (OSError, FileNotFoundError):
                                                continue
                                except Exception:
                                    pass
                                
                                if large_file_found:
                                    stream_directly = True
                                    create_snapshot = False
                                    job_metadata["stream_directly"] = True
                                    job_metadata["create_snapshot"] = False
                    except Exception as e:
                        logger.debug(f"Could not check source size for auto-streaming: {e}")
            
            logger.info(f"Backup mode: stream_directly={stream_directly}, create_snapshot={create_snapshot}, stream_to_server={stream_to_server}")
            
            if stream_directly and stream_to_server and self.stream_uploader:
                # Stream directly from source to server (no local snapshot)
                await self.report_job_status(job_id, "running", 20, 100, "Streaming directly to server...")
                backup_stats = await self._stream_backup_directly(job, job_id)
                
                # Create a virtual snapshot info for registration
                from datetime import datetime
                from uuid import uuid4
                snapshot_id = f"snap-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}"
                
                snapshot_info = {
                    "snapshot_id": snapshot_id,
                    "source_path": job.get("source") or job_metadata.get("source", ""),
                    "snapshot_path": "",  # No local path - streamed directly
                    "format": "stream",
                    "size": backup_stats.get("total_size", 0),
                    "metadata": {
                        "streamed_directly": True,
                        "type": "backup",
                        "agent_id": self.agent_id,
                    }
                }
                
                await self.report_job_status(job_id, "running", 90, 100, "Registering backup with server...")
                # Register snapshot with server
                await self._register_remote_snapshot(snapshot_info, job_id)
                
                # Report completion with metadata
                await self.report_job_status(
                    job_id, "completed", 100, 100, "Backup complete",
                    metadata={
                        "total_files": backup_stats.get("total_files", 0),
                        "backed_up_files": backup_stats.get("backed_up_files", 0),
                        "total_size": backup_stats.get("total_size", 0),
                        "backup_size": backup_stats.get("total_size", 0),
                        "format": "stream",
                        "streamed_directly": True,
                    }
                )
            elif create_snapshot:
                # Snapshot-first mode (default): Create snapshot, then stream to server
                # This enables incremental backups with hardlinks and point-in-time recovery
                await self.report_job_status(job_id, "running", 20, 100, "Creating snapshot (with hardlinks for incremental)...")
                try:
                    snapshot_info = await self._create_local_snapshot(job)
                    logger.info(f"Snapshot created: {snapshot_info.get('snapshot_id')} at {snapshot_info.get('snapshot_path')}")
                except Exception as snapshot_error:
                    error_msg = str(snapshot_error)
                    # If it's a discovery import error and discovery wasn't requested, make it non-fatal
                    if "discovery" in error_msg.lower() and "No module named" in error_msg:
                        if not job.get("metadata", {}).get("discover_applications", False):
                            logger.warning(f"Discovery import error occurred but discovery wasn't requested: {error_msg}")
                            logger.warning("This is likely a Python path issue. Continuing without discovery...")
                            # Try to create snapshot without discovery
                            try:
                                # Temporarily disable discovery
                                job_metadata = job.get("metadata", {})
                                job_metadata["discover_applications"] = False
                                snapshot_info = await self._create_local_snapshot(job)
                                logger.info(f"Snapshot created (without discovery): {snapshot_info.get('snapshot_id')} at {snapshot_info.get('snapshot_path')}")
                            except Exception as retry_error:
                                logger.error(f"Failed to create snapshot even without discovery: {retry_error}", exc_info=True)
                                raise
                        else:
                            logger.error(f"Failed to create snapshot: {snapshot_error}", exc_info=True)
                            raise
                    else:
                        logger.error(f"Failed to create snapshot: {snapshot_error}", exc_info=True)
                        raise
                
                # Validate snapshot_info has required fields
                if not snapshot_info.get("snapshot_id") or not snapshot_info.get("snapshot_path"):
                    error_msg = f"Snapshot creation returned invalid info: {snapshot_info}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                # Update snapshot metadata to enable streaming
                if stream_to_server:
                    snapshot_metadata = snapshot_info.get("metadata", {})
                    snapshot_metadata["stream_to_server"] = True
                    snapshot_metadata["type"] = "backup"
                    snapshot_info["metadata"] = snapshot_metadata
                
                await self.report_job_status(job_id, "running", 50, 100, "Registering snapshot with server...")
                try:
                    await self._register_remote_snapshot(snapshot_info, job_id)
                    logger.info(f"Snapshot registered: {snapshot_info.get('snapshot_id')}")
                except Exception as register_error:
                    logger.error(f"Failed to register snapshot: {register_error}", exc_info=True)
                    # Continue anyway - snapshot is created locally
                
                # Stream snapshot data to server if enabled
                streaming_succeeded = False
                snapshot_path_str = snapshot_info.get("snapshot_path", "")
                snapshot_id_str = snapshot_info.get("snapshot_id", "")
                
                if stream_to_server and self.stream_uploader:
                    if snapshot_path_str and snapshot_id_str:
                        await self.report_job_status(job_id, "running", 70, 100, "Streaming snapshot to server...")
                        try:
                            await self._stream_snapshot_data(snapshot_path_str, snapshot_id_str, job_id)
                            streaming_succeeded = True
                            logger.info(f"Successfully streamed snapshot {snapshot_id_str} to server")
                        except Exception as stream_error:
                            logger.error(f"Failed to stream snapshot to server: {stream_error}", exc_info=True)
                            streaming_succeeded = False
                    else:
                        logger.warning(f"Cannot stream: snapshot_path={snapshot_path_str}, snapshot_id={snapshot_id_str}")
                elif stream_to_server and not self.stream_uploader:
                    logger.warning("stream_to_server is True but stream_uploader is not initialized")
                
                # Optionally delete snapshot after streaming (if not keeping locally)
                if streaming_succeeded and not keep_snapshot_local:
                    await self.report_job_status(job_id, "running", 95, 100, "Cleaning up local snapshot...")
                    try:
                        snapshot_path_obj = Path(snapshot_path_str)
                        if snapshot_path_obj.exists():
                            import shutil
                            shutil.rmtree(snapshot_path_obj)
                            logger.info(f"Deleted local snapshot after streaming: {snapshot_path_str}")
                    except Exception as e:
                        logger.warning(f"Failed to delete local snapshot: {e}")
                
                # Calculate file count from snapshot
                snapshot_path = Path(snapshot_path_str)
                file_count = 0
                total_size = snapshot_info.get("size", 0)
                if snapshot_path.exists():
                    file_count = sum(1 for _ in snapshot_path.rglob('*') if _.is_file())
                    # Recalculate size if not already set
                    if total_size == 0:
                        total_size = sum(f.stat().st_size for f in snapshot_path.rglob('*') if f.is_file())
                
                # Report completion with metadata
                # Debug: Log what we're about to send
                logger.info(f"Reporting backup completion for job {job_id}")
                logger.info(f"  snapshot_id_str: {snapshot_id_str}")
                logger.info(f"  snapshot_path_str: {snapshot_path_str}")
                logger.info(f"  stream_to_server: {stream_to_server}")
                logger.info(f"  streaming_succeeded: {streaming_succeeded}")
                logger.info(f"  snapshot_info keys: {list(snapshot_info.keys())}")
                logger.info(f"  snapshot_info.get('snapshot_id'): {snapshot_info.get('snapshot_id')}")
                logger.info(f"  snapshot_info.get('snapshot_path'): {snapshot_info.get('snapshot_path')}")
                
                completion_metadata = {
                    "total_files": file_count,
                    "backed_up_files": file_count,
                    "total_size": total_size,
                    "backup_size": total_size,
                    "format": snapshot_info.get("format", "hardlink"),
                    "snapshot_id": snapshot_id_str if snapshot_id_str else snapshot_info.get("snapshot_id", ""),
                    "snapshot_path": str(snapshot_path) if snapshot_path.exists() else (snapshot_path_str if snapshot_path_str else snapshot_info.get("snapshot_path", "")),
                    "source_path": snapshot_info.get("source_path"),
                    "kept_local": keep_snapshot_local,
                    "stream_to_server": stream_to_server,
                    "streamed_to_server": streaming_succeeded,
                }
                
                logger.info(f"  Completion metadata snapshot_id: {completion_metadata.get('snapshot_id')}")
                logger.info(f"  Completion metadata stream_to_server: {completion_metadata.get('stream_to_server')}")
                
                await self.report_job_status(
                    job_id, "completed", 100, 100, "Backup complete",
                    metadata=completion_metadata
                )
            else:
                # No snapshot, no streaming - just register metadata (not recommended)
                logger.warning("Backup job with no snapshot and no streaming - only metadata will be registered")
                await self.report_job_status(job_id, "completed", 100, 100, "Backup metadata registered (no data backed up)")
            
        except Exception as e:
            import traceback
            error_msg = str(e)
            error_trace = traceback.format_exc()
            logger.error(f"Backup job failed: {error_msg}")
            logger.error(f"Traceback: {error_trace}")
            # If error is about discovery module and discovery wasn't requested, log additional context
            if "discovery" in error_msg.lower() and not job.get("metadata", {}).get("discover_applications", False):
                logger.warning("Discovery error occurred even though discovery was not requested - this may indicate a Python path issue")
            
            # Report failure with detailed error message
            # Make sure error is in both message and metadata
            try:
                await self.report_job_status(
                    job_id, "failed", 0, 100, f"Backup failed: {error_msg}",
                    metadata={
                        "error": error_msg,
                        "error_trace": error_trace,
                        "source": job.get("source") or job.get("metadata", {}).get("source", "unknown")
                    }
                )
            except Exception as report_error:
                logger.error(f"Failed to report job failure: {report_error}")
            
            raise
    
    async def _create_local_snapshot(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Create snapshot locally with application discovery and freeze/thaw"""
        # Discover applications if requested (default: False to avoid import issues)
        # Skip discovery entirely if not explicitly requested to avoid any import errors
        applications = []
        discover_apps = job.get("metadata", {}).get("discover_applications", False)
        
        logger.debug(f"_create_local_snapshot: discover_applications={discover_apps}")
        
        if discover_apps:
            logger.debug("Discovery requested, attempting to discover applications...")
            try:
                applications = await self._discover_applications()
                logger.debug(f"Discovery completed, found {len(applications)} applications")
            except Exception as e:
                logger.warning(f"Application discovery failed, continuing without it: {e}")
                import traceback
                logger.debug(f"Discovery error traceback: {traceback.format_exc()}")
                applications = []
        else:
            logger.debug("Discovery not requested, skipping application discovery")
        
        # Determine if freeze is needed (only if we have applications)
        requires_freeze = bool(applications) and any(app.requires_freeze for app in applications)
        
        # Pre-snapshot: Freeze applications if needed
        frozen_apps = []
        if requires_freeze:
            try:
                frozen_apps = await self._freeze_applications(applications)
            except Exception as e:
                logger.warning(f"Application freeze failed, continuing without freeze: {e}")
                frozen_apps = []
        
        try:
            # Create snapshot (platform-specific)
            snapshot_info = await self._create_platform_snapshot(job)
            
            # Add application metadata (only if we have applications)
            if applications:
                snapshot_info["metadata"]["applications"] = [
                    {
                        "type": app.application_type.value,
                        "subtype": app.application_subtype,
                        "name": app.name,
                        "version": app.version,
                        "paths": app.paths,
                    }
                    for app in applications
                ]
            if frozen_apps:
                snapshot_info["metadata"]["frozen_applications"] = [
                    app.name for app in frozen_apps
                ]
            
            return snapshot_info
        
        finally:
            # Post-snapshot: Thaw applications
            if frozen_apps:
                try:
                    await self._thaw_applications(frozen_apps)
                except Exception as e:
                    logger.warning(f"Application thaw failed: {e}")
    
    async def _discover_applications(self):
        """Discover applications on the system."""
        # Check if discovery directory exists AND all required files exist before trying to import
        import os
        # Use __file__ to get the actual location of base.py, then find discovery relative to it
        base_file = Path(__file__).resolve()
        discovery_path = base_file.parent / "discovery"
        required_files = ["__init__.py", "base.py", "databases.py", "vms.py", "filesystems.py"]
        
        # Check if directory exists
        if not discovery_path.exists() or not discovery_path.is_dir():
            logger.debug(f"Discovery module directory not found at {discovery_path}, skipping application discovery")
            return []
        
        # Check if all required files exist
        missing_files = [f for f in required_files if not (discovery_path / f).exists()]
        if missing_files:
            logger.debug(f"Discovery module incomplete (missing: {missing_files}), skipping application discovery")
            return []
        
        logger.debug(f"Discovery module found at {discovery_path}, attempting import...")
        
        # Try multiple import paths with comprehensive error handling
        # IMPORTANT: Wrap ALL import attempts in try/except to prevent any import errors from propagating
        discover_databases = None
        discover_vms = None
        discover_filesystems = None
        
        # Try relative import first
        try:
            from .discovery import discover_databases, discover_vms, discover_filesystems
            logger.debug("Discovery module imported successfully via relative import")
        except (ImportError, ModuleNotFoundError, AttributeError) as e:
            logger.debug(f"Relative import failed: {e}, trying absolute import")
            try:
                # Try absolute import
                from .discovery import discover_databases, discover_vms, discover_filesystems
                logger.debug("Discovery module imported successfully via absolute import")
            except (ImportError, ModuleNotFoundError, AttributeError) as e2:
                # Fallback if discovery module not available
                logger.warning(f"Discovery module not available (relative: {e}, absolute: {e2}), skipping application discovery")
                return []
            except Exception as e2:
                # Catch any other errors during absolute import
                logger.warning(f"Discovery module absolute import error: {e2}, skipping application discovery")
                return []
        except Exception as e:
            # Catch any other import-related errors (including syntax errors, etc.)
            logger.warning(f"Discovery module import error: {e}, skipping application discovery")
            import traceback
            logger.debug(f"Import traceback: {traceback.format_exc()}")
            return []
        
        # Verify imports succeeded
        if discover_databases is None and discover_vms is None and discover_filesystems is None:
            logger.warning("Discovery module imports returned None, skipping application discovery")
            return []
        
        applications = []
        
        if discover_databases:
            try:
                # Discover databases
                db_result = await discover_databases()
                applications.extend(db_result.applications)
            except Exception as e:
                logger.warning(f"Database discovery failed: {e}")
        
        if discover_vms:
            try:
                # Discover VMs
                vm_result = await discover_vms()
                applications.extend(vm_result.applications)
            except Exception as e:
                logger.warning(f"VM discovery failed: {e}")
        
        if discover_filesystems:
            try:
                # Discover filesystems (optional, for metadata)
                fs_result = await discover_filesystems()
                # Don't add filesystems as applications, but include in metadata
            except Exception as e:
                logger.warning(f"Filesystem discovery failed: {e}")
        
        return applications
    
    async def _freeze_applications(self, applications):
        """Freeze applications that require it."""
        frozen = []
        
        for app in applications:
            if app.requires_freeze:
                try:
                    if app.application_subtype == "oracle":
                        await self._freeze_oracle(app)
                    elif app.application_subtype in ["cache", "iris"]:
                        await self._freeze_cache_iris(app)
                    # HANA doesn't need freeze, uses different mechanism
                    
                    frozen.append(app)
                    logger.info(f"Frozen application: {app.name} ({app.application_subtype})")
                except Exception as e:
                    logger.error(f"Failed to freeze {app.name}: {e}")
        
        return frozen
    
    async def _thaw_applications(self, applications):
        """Thaw applications."""
        for app in applications:
            try:
                if app.application_subtype == "oracle":
                    await self._thaw_oracle(app)
                elif app.application_subtype in ["cache", "iris"]:
                    await self._thaw_cache_iris(app)
                
                logger.info(f"Thawed application: {app.name} ({app.application_subtype})")
            except Exception as e:
                logger.error(f"Failed to thaw {app.name}: {e}")
    
    async def _freeze_oracle(self, app):
        """Freeze Oracle database (RMAN freeze)."""
        # Would integrate with Oracle RMAN
        # For now, placeholder
        logger.info(f"Freezing Oracle: {app.name}")
        # In production: Execute RMAN freeze commands
    
    async def _thaw_oracle(self, app):
        """Thaw Oracle database."""
        logger.info(f"Thawing Oracle: {app.name}")
        # In production: Execute RMAN thaw commands
    
    async def _freeze_cache_iris(self, app):
        """Freeze Cache/Iris instance (based on legacy code)."""
        import subprocess
        import os
        
        inst_name = app.name
        
        # Based on legacy ecxcache/backup.py freeze pattern
        # Use csession/irissession to freeze
        cmd = f"csession {inst_name} -U%SYS" if app.application_subtype == "cache" else f"iris session {inst_name} -U%SYS"
        
        # Freeze command (simplified - would use actual Cache/Iris freeze API)
        freeze_cmd = f'##Class(Backup.General).ExternalFreeze("", "backup", 1, 0, 0, 1, 0, "", "", 300)'
        
        logger.info(f"Freezing {app.application_subtype} instance: {inst_name}")
        # In production: Execute actual freeze command
    
    async def _thaw_cache_iris(self, app):
        """Thaw Cache/Iris instance."""
        inst_name = app.name
        
        # Thaw command
        thaw_cmd = f'##Class(Backup.General).ExternalThaw()'
        
        logger.info(f"Thawing {app.application_subtype} instance: {inst_name}")
        # In production: Execute actual thaw command
    
    async def _create_platform_snapshot(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Create snapshot (platform-specific implementation)"""
        raise NotImplementedError("Platform-specific implementation required")
    
    async def _register_remote_snapshot(self, snapshot_info: Dict[str, Any], job_id: UUID):
        """Register snapshot with central server, optionally streaming snapshot data"""
        if not self.session or not self.agent_id:
            return
        
        try:
            snapshot_path = snapshot_info.get("snapshot_path")
            stream_snapshot = snapshot_info.get("metadata", {}).get("stream_to_server", False)
            
            # Register snapshot metadata
            # Include job_id in metadata so we can link back to the job
            snapshot_metadata = snapshot_info.get("metadata", {})
            snapshot_metadata["job_id"] = str(job_id)
            
            payload = {
                "agent_id": self.agent_id,
                "snapshot_id": snapshot_info.get("snapshot_id"),
                "host_id": self.host_id or snapshot_info.get("host_id"),
                "source_path": snapshot_info.get("source_path"),
                "snapshot_path": snapshot_path,
                "format": snapshot_info.get("format", "hardlink"),
                "tags": snapshot_info.get("tags", []),
                "metadata": snapshot_metadata,
                "size": snapshot_info.get("size", 0),
                "auto_scan": snapshot_info.get("auto_scan", False),
                "streamed": stream_snapshot,
            }
            
            async with self.session.post(
                f"{self.server_url}/api/v1/remote-snapshots/register",
                json=payload
            ) as resp:
                if resp.status == 201:
                    result = await resp.json()
                    logger.info(f"Remote snapshot registered: {result.get('remote_snapshot_id')}")
                    
                    # Stream snapshot data if requested
                    if stream_snapshot and snapshot_path and self.stream_uploader:
                        snapshot_id = snapshot_info.get("snapshot_id")
                        await self._stream_snapshot_data(snapshot_path, snapshot_id, job_id)
                else:
                    logger.warning(f"Failed to register remote snapshot: {resp.status}")
        except Exception as e:
            logger.error(f"Error registering remote snapshot: {e}")
    
    async def _stream_snapshot_data(self, snapshot_path: str, snapshot_id: str, job_id: Optional[UUID] = None):
        """Stream snapshot data to server."""
        if not self.stream_uploader:
            logger.warning("Stream uploader not initialized")
            return
        
        try:
            snapshot_dir = Path(snapshot_path)
            
            # Use provided job_id, or try to get from active jobs
            if not job_id:
                for job in self.active_jobs.values():
                    if hasattr(job, 'job_id'):
                        job_id = job.job_id
                        break
            
            # Prepare metadata for backup streaming
            metadata = {
                "snapshot_id": snapshot_id,
                "type": "backup",
                "agent_id": self.agent_id,
            }
            if job_id:
                metadata["job_id"] = str(job_id)
            
            if snapshot_dir.is_file():
                # Stream single file
                logger.info(f"Streaming snapshot file: {snapshot_path}")
                await self.stream_uploader.upload_file(
                    snapshot_dir,
                    "/api/v1/streaming",
                    metadata=metadata,
                )
            elif snapshot_dir.is_dir():
                # Stream directory (all files)
                logger.info(f"Streaming snapshot directory: {snapshot_path}")
                await self.stream_uploader.upload_directory(
                    snapshot_dir,
                    "/api/v1/streaming",
                    metadata=metadata,
                )
            
            logger.info(f"Snapshot data streamed successfully: {snapshot_id}")
        except Exception as e:
            logger.error(f"Error streaming snapshot data: {e}", exc_info=True)
            raise  # Re-raise to ensure caller knows streaming failed
    
    async def _stream_job_logs(self, job_id: UUID):
        """Stream job log files to server after job completion"""
        if not self.stream_uploader:
            logger.debug("Stream uploader not initialized, skipping log streaming")
            return
        
        try:
            # Find log files for this job
            # Logs are typically in: logs/jobs/{job_id}.log and logs/json/{job_id}.jsonl
            from pathlib import Path
            import os
            
            # Try to find log directory (could be in various locations)
            possible_log_dirs = [
                Path("logs"),
                Path(".") / "logs",
                Path.home() / ".fubar_agent" / "logs",
            ]
            
            log_dir = None
            for possible_dir in possible_log_dirs:
                if possible_dir.exists() and possible_dir.is_dir():
                    log_dir = possible_dir
                    break
            
            if not log_dir:
                logger.debug("Log directory not found, skipping log streaming")
                return
            
            job_id_str = str(job_id)
            log_files = []
            
            # Check for job log file
            job_log_file = log_dir / "jobs" / f"{job_id_str}.log"
            if job_log_file.exists():
                log_files.append(job_log_file)
            
            # Check for JSON log file
            json_log_file = log_dir / "json" / f"{job_id_str}.jsonl"
            if json_log_file.exists():
                log_files.append(json_log_file)
            
            if not log_files:
                logger.debug(f"No log files found for job {job_id_str}")
                return
            
            # Stream each log file to server
            for log_file in log_files:
                try:
                    logger.info(f"Streaming log file to server: {log_file.name}")
                    metadata = {
                        "type": "log",
                        "job_id": job_id_str,
                        "agent_id": self.agent_id,
                        "log_type": "job" if log_file.suffix == ".log" else "json",
                    }
                    
                    await self.stream_uploader.upload_file(
                        log_file,
                        "/api/v1/streaming",
                        metadata=metadata,
                    )
                    logger.debug(f"Log file streamed successfully: {log_file.name}")
                except Exception as e:
                    logger.warning(f"Failed to stream log file {log_file.name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error streaming job logs: {e}")
    
    async def _stream_backup_directly(self, job: Dict[str, Any], job_id: UUID) -> Dict[str, Any]:
        """Stream backup directly from source to server without creating local snapshot"""
        from pathlib import Path
        import os
        
        # Get source path
        source = (
            job.get("source") or 
            job.get("metadata", {}).get("source") or
            job.get("metadata", {}).get("path")
        )
        if not source:
            raise ValueError("No source specified for backup job")
        
        # Normalize path for Windows (convert forward slashes to backslashes)
        # pathlib.Path handles forward slashes on Windows, but we'll normalize explicitly
        if os.name == 'nt':
            # On Windows, normalize forward slashes to backslashes
            normalized_source = os.path.normpath(source)
            # Try normalized path first
            source_path = Path(normalized_source)
            if not source_path.exists():
                # Try original path (pathlib might handle it)
                source_path = Path(source)
            # Resolve only if path exists (resolve() can fail if path doesn't exist)
            if source_path.exists():
                try:
                    source_path = source_path.resolve()
                except (OSError, RuntimeError):
                    # If resolve fails, use the path as-is
                    pass
        else:
            source_path = Path(source)
            # Try to check if path exists, using sudo if needed (Linux only)
            path_exists = False
            try:
                if source_path.exists():
                    path_exists = True
                    try:
                        source_path = source_path.resolve()
                    except (OSError, RuntimeError):
                        pass
            except PermissionError:
                # On Linux, try with sudo if permission denied
                if os.name != 'nt':
                    import subprocess
                    try:
                        result = subprocess.run(
                            ["sudo", "test", "-e", str(source_path)],
                            capture_output=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            path_exists = True
                            # Try to resolve with sudo
                            try:
                                result = subprocess.run(
                                    ["sudo", "readlink", "-f", str(source_path)],
                                    capture_output=True,
                                    text=True,
                                    timeout=5
                                )
                                if result.returncode == 0 and result.stdout.strip():
                                    source_path = Path(result.stdout.strip())
                            except Exception:
                                pass
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        pass
            
            if not path_exists:
                raise ValueError(f"Source path does not exist or is not accessible: {source} (tried: {source_path})")
        
        # Prepare metadata for backup streaming
        metadata = {
            "type": "backup",
            "agent_id": self.agent_id,
            "job_id": str(job_id),
            "source_path": str(source_path),
            "streamed_directly": True,
        }
        
        total_files = 0
        backed_up_files = 0
        total_size = 0
        
        # Check if it's a file or directory (using sudo if needed)
        is_file = False
        is_dir = False
        try:
            is_file = source_path.is_file()
            is_dir = source_path.is_dir()
        except PermissionError:
            # On Linux, try with sudo if permission denied
            if os.name != 'nt':
                import subprocess
                try:
                    result = subprocess.run(
                        ["sudo", "test", "-f", str(source_path)],
                        capture_output=True,
                        timeout=5
                    )
                    is_file = result.returncode == 0
                    if not is_file:
                        result = subprocess.run(
                            ["sudo", "test", "-d", str(source_path)],
                            capture_output=True,
                            timeout=5
                        )
                        is_dir = result.returncode == 0
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    raise PermissionError(f"Cannot determine if path is file or directory: {source_path}")
            else:
                raise
        
        if is_file:
            # Stream single file
            logger.info(f"Streaming file directly to server: {source_path}")
            # Get file size (using sudo if needed)
            try:
                file_size = source_path.stat().st_size
            except PermissionError:
                if os.name != 'nt':
                    import subprocess
                    result = subprocess.run(
                        ["sudo", "stat", "-c", "%s", str(source_path)],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        file_size = int(result.stdout.strip())
                    else:
                        raise PermissionError(f"Cannot access file {source_path}: {result.stderr}")
                else:
                    raise
            
            await self.stream_uploader.upload_file(
                source_path,
                "/api/v1/streaming",
                metadata=metadata,
            )
            total_files = 1
            backed_up_files = 1
            total_size = file_size
        elif is_dir:
            # Stream directory files directly
            logger.info(f"Streaming directory directly to server: {source_path}")
            
            # Discover files (using sudo if needed on Linux)
            files = []
            try:
                for file_path in source_path.rglob('*'):
                    if file_path.is_file():
                        files.append(file_path)
            except PermissionError:
                # On Linux, try with sudo find if permission denied
                if os.name != 'nt':
                    import subprocess
                    try:
                        logger.warning(f"Permission denied accessing {source_path}, using sudo find...")
                        result = subprocess.run(
                            ["sudo", "find", str(source_path), "-type", "f"],
                            capture_output=True,
                            text=True,
                            timeout=300  # 5 minute timeout for large directories
                        )
                        if result.returncode == 0:
                            for line in result.stdout.strip().split('\n'):
                                if line.strip():
                                    files.append(Path(line.strip()))
                        else:
                            raise PermissionError(f"Cannot access directory {source_path}: {result.stderr}")
                    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                        raise PermissionError(f"Cannot access directory {source_path}: {e}")
                else:
                    raise
            
            total_files = len(files)
            await self.report_job_status(
                job_id, "running", 30, 100, 
                f"Found {total_files} files, streaming to server..."
            )
            
            # Stream files with progress tracking
            uploaded = 0
            for file_path in files:
                try:
                    # Get file size (using sudo if needed)
                    try:
                        file_size = file_path.stat().st_size
                    except PermissionError:
                        if os.name != 'nt':
                            import subprocess
                            result = subprocess.run(
                                ["sudo", "stat", "-c", "%s", str(file_path)],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            if result.returncode == 0:
                                file_size = int(result.stdout.strip())
                            else:
                                logger.warning(f"Cannot get size for {file_path}, skipping...")
                                continue
                        else:
                            raise
                    
                    total_size += file_size
                    
                    # Update metadata with relative path
                    file_metadata = metadata.copy()
                    try:
                        file_metadata["relative_path"] = str(file_path.relative_to(source_path))
                    except ValueError:
                        # If paths are on different drives or can't be relativized, use absolute
                        file_metadata["relative_path"] = str(file_path)
                    
                    await self.stream_uploader.upload_file(
                        file_path,
                        "/api/v1/streaming",
                        metadata=file_metadata,
                    )
                    backed_up_files += 1
                    uploaded += 1
                    
                    # Update progress every 10 files or 10%
                    if uploaded % max(10, total_files // 10) == 0:
                        progress = 30 + int((uploaded / total_files) * 60)
                        await self.report_job_status(
                            job_id, "running", progress, 100,
                            f"Streamed {uploaded}/{total_files} files ({total_size / (1024*1024):.1f} MB)..."
                        )
                except Exception as e:
                    logger.warning(f"Failed to stream file {file_path}: {e}")
                    # Continue with other files
                    continue
        
        return {
            "total_files": total_files,
            "backed_up_files": backed_up_files,
            "total_size": total_size,
        }
    
    async def _execute_scan_backup_job(self, job: Dict[str, Any]):
        """Execute combined scan+backup job"""
        from uuid import UUID
        job_id = UUID(job["job_id"])
        job_metadata = job.get("metadata", {})
        
        try:
            await self.report_job_status(job_id, "running", 5, 100, "Starting scan+backup job...")
            
            # Extract scan-backup job configuration
            snapshot_id = job.get("snapshot_id") or job_metadata.get("snapshot_id")
            scan_config = job.get("scan_config") or job_metadata.get("scan_config") or {}
            backup_config = job.get("backup_config") or job_metadata.get("backup_config") or {}
            backup_on_success = job.get("backup_on_success", job_metadata.get("backup_on_success", True))
            backup_on_anomalies = job.get("backup_on_anomalies", job_metadata.get("backup_on_anomalies", False))
            anomaly_threshold = job.get("anomaly_threshold", job_metadata.get("anomaly_threshold", "high"))
            
            # Phase 1: Scan
            await self.report_job_status(job_id, "running", 10, 100, "Phase 1: Running scan...")
            
            # Create scan job from scan-backup job
            scan_job = {
                "job_id": str(job_id),  # Use same job_id for tracking
                "job_type": "scan",
                "snapshot_id": snapshot_id,
                "path": scan_config.get("path"),
                "source_system": scan_config.get("source_system"),
                "analyzers": scan_config.get("analyzers", ["quick"]),
                "enable_yara": scan_config.get("enable_yara", False),
                "enable_heuristic": scan_config.get("enable_heuristic", True),
                "metadata": {
                    **job_metadata,
                    "parent_job_type": "scan_backup",  # Mark as part of combo job
                }
            }
            
            # Execute scan and capture results
            scan_results = {}
            scan_metadata = {}
            scan_succeeded = False
            
            try:
                # Store a reference to capture scan results
                scan_job_id = str(job_id) + "_scan"  # Use sub-job ID for scan
                scan_job["job_id"] = scan_job_id
                
                # Execute scan (this will report status with metadata)
                await self._execute_scan_job(scan_job)
                
                # Get scan results from the last status update
                # The scan job reports results in metadata via report_job_status
                # We need to get the job status to extract metadata
                await self.report_job_status(job_id, "running", 50, 100, "Scan completed, analyzing results...")
                
                # Try to get scan results from job status
                # Note: In a real implementation, we'd query the server for the scan job status
                # For now, we'll assume success if no exception was raised
                scan_succeeded = True
                scan_results = {
                    "status": "completed",
                    "message": "Scan completed successfully"
                }
                # The actual scan metadata (files, detections, etc.) would be in the scan job's final status
                # This would need to be retrieved from the server or stored during scan execution
                
            except Exception as scan_error:
                logger.error(f"Scan phase failed: {scan_error}")
                scan_succeeded = False
                scan_results = {
                    "status": "failed",
                    "error": str(scan_error)
                }
            
            # Check if backup should proceed
            should_backup = False
            backup_reason = ""
            
            if scan_succeeded and backup_on_success:
                should_backup = True
                backup_reason = "Scan succeeded"
                await self.report_job_status(job_id, "running", 60, 100, "Scan succeeded, starting backup...")
            elif backup_on_anomalies:
                # Check if anomalies were found in scan results
                # For now, if backup_on_anomalies is True and scan succeeded, we'll backup
                # In production, would check scan_results for actual anomalies
                if scan_succeeded:
                    should_backup = True
                    backup_reason = "Anomalies detected"
                    await self.report_job_status(job_id, "running", 60, 100, "Anomalies detected, starting backup...")
                else:
                    await self.report_job_status(job_id, "running", 90, 100, "Backup skipped: scan failed...")
            else:
                await self.report_job_status(job_id, "running", 90, 100, "Backup skipped based on configuration...")
            
            # Phase 2: Backup (if conditions met)
            backup_results = {}
            if should_backup:
                # Determine source path for backup
                # If snapshot_id provided, use that path, otherwise use scan path
                source_path = None
                if snapshot_id:
                    # Would need to resolve snapshot path
                    source_path = snapshot_id  # Placeholder
                elif scan_config.get("path"):
                    source_path = scan_config.get("path")
                else:
                    raise ValueError("Cannot determine backup source: need either snapshot_id or path")
                
                # Create backup job from scan-backup job
                backup_job = {
                    "job_id": str(job_id),  # Use same job_id for tracking
                    "job_type": "backup",
                    "source": source_path,
                    "target": backup_config.get("target", "server"),
                    "incremental": backup_config.get("incremental", False),
                    "compression": backup_config.get("compression", "none"),
                    "encryption": backup_config.get("encryption", False),
                    "metadata": {
                        **job_metadata,
                        "parent_job_type": "scan_backup",  # Mark as part of combo job
                        "scan_job_id": str(job_id),  # Link to scan
                        "stream_to_server": True,  # Always stream for combo jobs
                    }
                }
                
                try:
                    await self._execute_backup_job(backup_job)
                    backup_results = {"status": "completed"}
                except Exception as backup_error:
                    logger.error(f"Backup phase failed: {backup_error}")
                    backup_results = {"status": "failed", "error": str(backup_error)}
            
            # Report completion with combined results
            await self.report_job_status(
                job_id, "completed", 100, 100, "Scan+backup job completed",
                metadata={
                    "scan_results": scan_results,
                    "backup_results": backup_results,
                    "scan_succeeded": scan_succeeded,
                    "backup_executed": should_backup,
                    "backup_reason": backup_reason if should_backup else "skipped",
                    "job_type": "scan_backup",
                }
            )
            
        except Exception as e:
            import traceback
            error_msg = str(e)
            error_trace = traceback.format_exc()
            logger.error(f"Scan-backup job failed: {error_msg}")
            logger.error(f"Traceback: {error_trace}")
            
            try:
                await self.report_job_status(
                    job_id, "failed", 0, 100, f"Scan-backup failed: {error_msg}",
                    metadata={"error": error_msg, "error_trace": error_trace}
                )
            except Exception as report_error:
                logger.error(f"Failed to report job failure: {report_error}")
            
            raise
    
    async def _execute_restore_job(self, job: Dict[str, Any]):
        """Execute restore job (platform-specific)"""
        raise NotImplementedError("Platform-specific implementation required")
    
    async def report_job_status(
        self,
        job_id: UUID,
        state: str,
        current: int,
        total: int,
        message: str = None,
        metadata: Dict[str, Any] = None
    ):
        """Report job status to server"""
        if not self.session:
            return
        
        try:
            payload = {
                "state": state,
                "progress": {
                    "current": current,
                    "total": total,
                    "percent": (current / total * 100) if total > 0 else 0.0,
                    "message": message,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            # Add metadata if provided
            if metadata:
                payload["metadata"] = metadata
            
            async with self.session.post(
                f"{self.server_url}/api/v1/agents/{self.agent_id}/jobs/{job_id}/status",
                json=payload
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Status report failed: {resp.status}")
        except Exception as e:
            logger.error(f"Status report error: {e}")
    
    async def send_agent_log(
        self,
        job_id: UUID,
        level: str,
        message: str,
        module: str = None,
        extra: Dict[str, Any] = None
    ):
        """Send log message to server for inclusion in job logs"""
        if not self.session or not self.agent_id:
            return
        
        try:
            payload = {
                "level": level,
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            if module:
                payload["module"] = module
            if extra:
                payload["extra"] = extra
            
            async with self.session.post(
                f"{self.server_url}/api/v1/agents/{self.agent_id}/jobs/{job_id}/logs",
                json=payload
            ) as resp:
                if resp.status != 200:
                    # Don't log errors for log sending to avoid recursion
                    pass
        except Exception as e:
            # Silently fail to avoid log spam
            pass
    
    def _setup_agent_log_handler(self, job_id: UUID):
        """Set up a logging handler that sends important logs to server"""
        import logging
        import asyncio
        from collections import deque
        
        class AgentLogHandler(logging.Handler):
            """Custom handler that sends logs to server"""
            def __init__(self, agent, job_id):
                super().__init__()
                self.agent = agent
                self.job_id = job_id
                # Only send INFO, WARNING, ERROR, CRITICAL (skip DEBUG)
                self.setLevel(logging.INFO)
                # Queue for log messages
                self.log_queue = deque(maxlen=100)  # Limit queue size
                self._processing = False
            
            def emit(self, record):
                """Queue log record to be sent to server"""
                try:
                    # Only send if we have a session and agent_id
                    if not self.agent.session or not self.agent.agent_id:
                        return
                    
                    # Get log level name
                    level = record.levelname
                    
                    # Skip DEBUG logs
                    if level == "DEBUG":
                        return
                    
                    # Format message
                    message = self.format(record)
                    
                    # Get module name
                    module = record.module if hasattr(record, 'module') else record.name
                    
                    # Add to queue
                    self.log_queue.append({
                        "level": level,
                        "message": message,
                        "module": module,
                        "extra": {"lineno": record.lineno, "funcName": record.funcName}
                    })
                    
                    # Try to process queue if not already processing
                    if not self._processing:
                        self._process_queue()
                except Exception:
                    # Silently fail to avoid recursion
                    pass
            
            def _process_queue(self):
                """Process queued log messages"""
                if self._processing or not self.log_queue:
                    return
                
                self._processing = True
                
                # Process all queued messages
                while self.log_queue:
                    log_entry = self.log_queue.popleft()
                    try:
                        # Try to get event loop
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                # Create task to send log
                                asyncio.create_task(
                                    self.agent.send_agent_log(
                                        self.job_id,
                                        log_entry["level"],
                                        log_entry["message"],
                                        module=log_entry["module"],
                                        extra=log_entry["extra"]
                                    )
                                )
                            else:
                                # Run directly if loop not running
                                loop.run_until_complete(
                                    self.agent.send_agent_log(
                                        self.job_id,
                                        log_entry["level"],
                                        log_entry["message"],
                                        module=log_entry["module"],
                                        extra=log_entry["extra"]
                                    )
                                )
                        except RuntimeError:
                            # No event loop, skip
                            pass
                    except Exception:
                        # Silently fail
                        pass
                
                self._processing = False
        
        # Create handler
        handler = AgentLogHandler(self, job_id)
        handler.setFormatter(logging.Formatter('%(message)s'))
        
        # Add to root logger (will capture all agent logs)
        root_logger = logging.getLogger()
        handler.name = f"agent_log_handler_{job_id}"
        root_logger.addHandler(handler)
        
        return handler
    
    def _remove_agent_log_handler(self, handler):
        """Remove agent log handler"""
        import logging
        root_logger = logging.getLogger()
        if handler in root_logger.handlers:
            root_logger.removeHandler(handler)
    
    # ============================================================================
    # Shared Scanning Methods
    # These methods are used by all platform-specific agents to reduce duplication
    # ============================================================================
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value (0-8, where 8 is maximum entropy)
        """
        import math
        
        if len(data) == 0:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _check_magic_numbers(self, file_path: Path, known_magics: Optional[List[bytes]] = None) -> bool:
        """
        Check if file matches known magic numbers.
        
        Args:
            file_path: Path to file to check
            known_magics: List of known magic number prefixes (defaults to common ones)
            
        Returns:
            True if file matches a known magic number, False otherwise
        """
        if known_magics is None:
            known_magics = [
                b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'%PDF',
                b'PK\x03\x04', b'\x7fELF', b'MZ', b'\xca\xfe\xba\xbe',
                b'<?xml', b'<!DOCTYPE', b'{\n', b'#!/'
            ]
        
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16)
                return any(magic.startswith(m) for m in known_magics)
        except Exception:
            return False
    
    def _get_known_extensions(self) -> set:
        """
        Get set of known file extensions.
        
        Returns:
            Set of known file extensions
        """
        return {
            '.txt', '.log', '.json', '.xml', '.csv', '.html', '.css', '.js',
            '.py', '.sh', '.pl', '.rb', '.php', '.java', '.cpp', '.c', '.h',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.db', '.sqlite', '.sql', '.sqlite3',
            '.exe', '.dll', '.so', '.dylib', '.bin'
        }
    
    def _check_unknown_file_type(self, file_path: Path, file_ext: Optional[str]) -> bool:
        """
        Check if file type is unknown (not in known extensions or magic numbers).
        
        Args:
            file_path: Path to file
            file_ext: File extension (or None)
            
        Returns:
            True if file type is unknown, False otherwise
        """
        known_extensions = self._get_known_extensions()
        
        # Check extension
        if file_ext and file_ext in known_extensions:
            return False
        
        # Check magic number
        return not self._check_magic_numbers(file_path)
    
    def _run_format_analyzer(
        self,
        file_path: Path,
        file_ext: str,
        scan_results: Dict[str, Any]
    ) -> Tuple[Optional[bool], List[str], Dict[str, Any]]:
        """
        Run format analyzer on file and update scan results.
        
        Args:
            file_path: Path to file to analyze
            file_ext: File extension
            scan_results: Scan results dictionary to update
            
        Returns:
            Tuple of (structure_valid, structure_errors, format_specific_metrics)
        """
        from .format_analyzers import get_analyzer_for_file
        
        structure_valid = None
        structure_errors = []
        format_specific_metrics = {}
        
        analyzer = get_analyzer_for_file(file_path)
        if analyzer:
            try:
                logger.debug(f"Running format analyzer for {file_path.name} ({file_ext})")
                analysis_result = analyzer.analyze(file_path)
                structure_valid = analysis_result.get('structure_valid')
                structure_errors = analysis_result.get('structure_errors', [])
                format_specific_metrics = analysis_result.get('format_specific_metrics', {})
                
                # Track format analysis stats
                if format_specific_metrics:
                    format_type = file_ext or 'unknown'
                    if format_type not in scan_results.get('format_analysis_stats', {}):
                        scan_results.setdefault('format_analysis_stats', {})[format_type] = {
                            'total': 0,
                            'valid': 0,
                            'invalid': 0
                        }
                    scan_results['format_analysis_stats'][format_type]['total'] += 1
                    if structure_valid:
                        scan_results['format_analysis_stats'][format_type]['valid'] += 1
                    elif structure_valid is False:
                        scan_results['format_analysis_stats'][format_type]['invalid'] += 1
            except Exception as e:
                logger.debug(f"Format analyzer error for {file_path.name}: {e}")
                structure_errors.append(f"Analyzer error: {str(e)}")
        
        return structure_valid, structure_errors, format_specific_metrics
    
    def _get_yara_rules_search_paths(self) -> List[Path]:
        """
        Get platform-specific YARA rules search paths.
        
        Subclasses should override this to provide platform-specific paths.
        
        Returns:
            List of paths to search for YARA rules
        """
        agent_cwd = Path.cwd()
        agent_file_dir = Path(__file__).parent.parent.parent
        
        # Base paths that work on all platforms
        base_paths = [
            # Relative to agent code location
            agent_file_dir / 'rules-master',
            agent_file_dir.parent / 'rules-master',
            # Relative to current working directory
            agent_cwd / 'rules-master',
            agent_cwd.parent / 'rules-master',
            agent_cwd.parent.parent / 'rules-master',
        ]
        
        return base_paths
    
    async def _scan_with_yara(self, file_path: Path, rules_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan file with YARA rules.
        
        This method uses platform-specific YARA rules search paths via _get_yara_rules_search_paths().
        
        Args:
            file_path: Path to file to scan
            rules_dir: Optional explicit rules directory (if None, will search)
            
        Returns:
            List of YARA match dictionaries
        """
        import subprocess
        import asyncio
        
        # Check if yara-python is available (but don't fail if it's not)
        try:
            import yara
            yara_python_available = True
        except ImportError:
            yara_python_available = False
            logger.debug("yara-python not available, will use command-line yara")
        
        # Find YARA rules directory (needed for both yara-python and command-line)
        if not rules_dir:
            # Get platform-specific search paths
            possible_paths = self._get_yara_rules_search_paths()
            
            logger.info(f"🔍 Searching for YARA rules directory in {len(possible_paths)} possible locations...")
            for path in possible_paths:
                if path.exists() and (path / 'malware_index.yar').exists():
                    rules_dir = str(path)
                    logger.info(f"✅ Found YARA rules directory: {rules_dir}")
                    break
                else:
                    logger.debug(f"   Checked: {path} (exists: {path.exists()}, has malware_index.yar: {(path / 'malware_index.yar').exists() if path.exists() else False})")
        
        if not rules_dir:
            logger.warning("⚠️  YARA rules directory not found, skipping YARA scan")
            logger.warning(f"   Searched paths: {[str(p) for p in possible_paths]}")
            logger.warning(f"   Current working directory: {Path.cwd()}")
            logger.warning(f"   Agent file location: {Path(__file__).parent}")
            return []
        
        logger.info(f"✅ Using YARA rules directory: {rules_dir}")
        logger.info(f"   malware_index.yar exists: {(Path(rules_dir) / 'malware_index.yar').exists()}")
        logger.info(f"   packers_index.yar exists: {(Path(rules_dir) / 'packers_index.yar').exists()}")
        logger.info(f"   Using command-line yara (yara-python: {'available' if yara_python_available else 'not available'})")
        
        # Use yara command-line tool for scanning (more reliable than yara-python)
        # Scan with malware rules
        malware_rules = Path(rules_dir) / 'malware_index.yar'
        packer_rules = Path(rules_dir) / 'packers_index.yar'
        
        matches = []
        
        # Log which rules files we're using
        logger.debug(f"YARA scanning {file_path.name} with rules from {rules_dir}")
        logger.debug(f"  malware_index.yar: {malware_rules.exists()}")
        logger.debug(f"  packers_index.yar: {packer_rules.exists()}")
        
        # Scan with malware rules
        if malware_rules.exists():
            try:
                logger.debug(f"Running: yara -s {malware_rules} {file_path}")
                process = await asyncio.create_subprocess_exec(
                    'yara', '-s', str(malware_rules), str(file_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                
                # Log YARA return code and output for debugging
                logger.debug(f"YARA return code: {process.returncode}")
                if stderr:
                    stderr_text = stderr.decode()
                    # Only log stderr if it's not just warnings
                    if 'warning:' not in stderr_text.lower() or len(stderr_text) > 500:
                        logger.debug(f"YARA stderr: {stderr_text[:200]}")
                
                if process.returncode == 0 and stdout:
                    # Parse YARA output
                    output = stdout.decode()
                    logger.debug(f"YARA output for {file_path}: {output[:200] if len(output) > 200 else output}")
                    for line in output.splitlines():
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                rule_name = parts[0]
                                match_info = {
                                    'rule': rule_name,
                                    'tags': [],
                                    'meta': {},
                                    'file': str(file_path)
                                }
                                matches.append(match_info)
                                logger.warning(f"✅ YARA rule matched: {rule_name} on {file_path.name}")
                elif stderr:
                    logger.debug(f"YARA stderr for {file_path}: {stderr.decode()[:200]}")
            except asyncio.TimeoutError:
                logger.debug(f"YARA scan timeout for {file_path}")
            except Exception as e:
                logger.debug(f"YARA scan error: {e}")
        
        # Scan with packer rules
        if packer_rules.exists():
            try:
                process = await asyncio.create_subprocess_exec(
                    'yara', '-s', str(packer_rules), str(file_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                
                if process.returncode == 0 and stdout:
                    for line in stdout.decode().splitlines():
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                rule_name = parts[0]
                                matches.append({
                                    'rule': rule_name,
                                    'tags': ['packer'],
                                    'meta': {},
                                    'file': str(file_path)
                                })
            except Exception:
                pass
        
        return matches

