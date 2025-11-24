"""
Data Streaming Module

Handles streaming data from agent to server with bandwidth and connection control.
"""

import asyncio
import logging
import aiohttp
import aiofiles
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from uuid import UUID

logger = logging.getLogger(__name__)


class StreamConfig:
    """Configuration for data streaming."""
    
    def __init__(
        self,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        max_concurrent_streams: int = 3,  # Max parallel uploads
        max_connections: int = 10,  # Max HTTP connections in pool
        max_concurrent_chunks: int = 5,  # Max concurrent chunks per file
        bandwidth_limit: Optional[int] = None,  # Bytes per second (None = unlimited)
        retry_attempts: int = 3,
        retry_delay: float = 1.0,
    ):
        self.chunk_size = chunk_size
        self.max_concurrent_streams = max_concurrent_streams
        self.max_connections = max_connections
        self.max_concurrent_chunks = max_concurrent_chunks
        self.bandwidth_limit = bandwidth_limit
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay


class StreamUploader:
    """Handles streaming file uploads to server."""
    
    def __init__(
        self,
        server_url: str,
        session: aiohttp.ClientSession,
        config: StreamConfig,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ):
        self.server_url = server_url.rstrip('/')
        self.session = session
        self.config = config
        self.progress_callback = progress_callback
        self.semaphore = asyncio.Semaphore(config.max_concurrent_streams)
        self.upload_tokens = asyncio.Semaphore(config.max_concurrent_streams)
        # Semaphore for concurrent chunk uploads within a file
        self.chunk_semaphore = asyncio.Semaphore(config.max_concurrent_chunks)
        # Track active chunk uploads
        self.active_chunks = 0
        self.active_chunks_lock = asyncio.Lock()
    
    async def upload_file(
        self,
        file_path: Path,
        endpoint: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Upload a file to the server in chunks.
        
        Args:
            file_path: Path to file to upload
            endpoint: API endpoint for upload
            metadata: Additional metadata to include
            
        Returns:
            Upload result from server
        """
        async with self.semaphore:  # Limit concurrent uploads
            return await self._upload_file_internal(file_path, endpoint, metadata)
    
    async def _upload_file_internal(
        self,
        file_path: Path,
        endpoint: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Internal upload implementation with retry logic and concurrent chunk uploads."""
        import hashlib
        import os
        
        # Get file size (using sudo if needed on Linux)
        try:
            file_size = file_path.stat().st_size
            use_sudo = False
        except PermissionError:
            # On Linux, try with sudo if permission denied
            if os.name != 'nt':
                import subprocess
                try:
                    result = subprocess.run(
                        ["sudo", "stat", "-c", "%s", str(file_path)],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        file_size = int(result.stdout.strip())
                        use_sudo = True
                    else:
                        raise PermissionError(f"Cannot access file {file_path}: {result.stderr}")
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    raise PermissionError(f"Cannot access file {file_path}: {e}")
            else:
                raise
        else:
            use_sudo = False
        
        # Initialize hash calculator
        sha256_hash = hashlib.sha256()
        
        # Add hash algorithm to metadata (hash will be calculated during upload)
        if metadata is None:
            metadata = {}
        metadata["hash_algorithm"] = "sha256"
        
        # Capture file attributes if not already in metadata
        if "owner" not in metadata and "permissions" not in metadata:
            try:
                from .file_attributes import capture_file_attributes
                captured_attrs = capture_file_attributes(file_path)
                metadata.update(captured_attrs)
            except Exception as e:
                import logging
                logging.debug(f"Failed to capture file attributes for {file_path}: {e}")
        
        uploaded = 0
        
        for attempt in range(self.config.retry_attempts):
            try:
                # Open file (using sudo if needed)
                if use_sudo:
                    # Use subprocess to read file with sudo
                    import subprocess
                    proc = await asyncio.create_subprocess_exec(
                        "sudo", "cat", str(file_path),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    # Create a file-like object from the subprocess
                    class SubprocessFileReader:
                        def __init__(self, proc, file_size):
                            self.proc = proc
                            self.file_size = file_size
                            self.bytes_read = 0
                        
                        async def read(self, size):
                            if self.bytes_read >= self.file_size:
                                return b''
                            chunk = await self.proc.stdout.read(size)
                            self.bytes_read += len(chunk)
                            return chunk
                        
                        async def __aenter__(self):
                            return self
                        
                        async def __aexit__(self, *args):
                            self.proc.terminate()
                            await self.proc.wait()
                    
                    f = SubprocessFileReader(proc, file_size)
                else:
                    f = aiofiles.open(file_path, 'rb')
                
                async with f:
                    # Create multipart upload
                    upload_id = await self._initiate_upload(endpoint, file_path.name, file_size, metadata)
                    
                    # Use a queue-based producer-consumer pattern to avoid loading all chunks into memory
                    chunk_queue = asyncio.Queue(maxsize=self.config.max_concurrent_chunks * 2)
                    total_chunks = (file_size + self.config.chunk_size - 1) // self.config.chunk_size
                    logger.info(f"Uploading {total_chunks} chunks for {file_path.name} (max {self.config.max_concurrent_chunks} concurrent)")
                    
                    uploaded_bytes = 0
                    completed_chunks = 0
                    read_error = None
                    upload_errors = []
                    
                    async def chunk_reader():
                        """Producer: Read chunks from file and put them in queue."""
                        nonlocal read_error, sha256_hash
                        chunk_number = 0
                        total_read = 0
                        try:
                            while total_read < file_size:
                                chunk = await f.read(self.config.chunk_size)
                                if not chunk:
                                    break
                                
                                # Update hash as we read chunks
                                sha256_hash.update(chunk)
                                
                                is_first = (chunk_number == 0)
                                is_last = (total_read + len(chunk) >= file_size)
                                
                                await chunk_queue.put((chunk_number, chunk, is_first, is_last))
                                total_read += len(chunk)
                                chunk_number += 1
                        except Exception as e:
                            read_error = e
                            logger.error(f"Error reading chunks: {e}")
                        finally:
                            # Signal end of chunks
                            await chunk_queue.put(None)
                    
                    async def upload_chunk_with_tracking(chunk_num: int, chunk_data: bytes, is_first: bool, is_last: bool):
                        """Upload a chunk and track active count."""
                        async with self.chunk_semaphore:
                            # Increment active chunks counter
                            async with self.active_chunks_lock:
                                self.active_chunks += 1
                                active = self.active_chunks
                            
                            try:
                                # Log concurrent chunk count periodically
                                if chunk_num % 10 == 0 or active == self.config.max_concurrent_chunks:
                                    logger.info(f"Uploading chunk {chunk_num}/{total_chunks} ({active} concurrent chunks active)")
                                
                                # Apply bandwidth limiting
                                if self.config.bandwidth_limit:
                                    await self._throttle_bandwidth(len(chunk_data))
                                
                                # Upload chunk
                                await self._upload_chunk(
                                    endpoint,
                                    upload_id,
                                    chunk_num,
                                    chunk_data,
                                    is_first,
                                    is_last,
                                )
                                
                                return len(chunk_data)
                            except Exception as e:
                                logger.error(f"Failed to upload chunk {chunk_num}: {e}")
                                raise
                            finally:
                                # Decrement active chunks counter
                                async with self.active_chunks_lock:
                                    self.active_chunks -= 1
                    
                    async def chunk_uploader():
                        """Consumer: Upload chunks from queue concurrently."""
                        nonlocal uploaded_bytes, completed_chunks
                        upload_tasks = []
                        
                        while True:
                            chunk_item = await chunk_queue.get()
                            if chunk_item is None:
                                # No more chunks
                                break
                            
                            chunk_num, chunk_data, is_first, is_last = chunk_item
                            
                            # Create upload task
                            task = asyncio.create_task(
                                upload_chunk_with_tracking(chunk_num, chunk_data, is_first, is_last)
                            )
                            upload_tasks.append((chunk_num, task))
                            chunk_queue.task_done()
                        
                        # Wait for all upload tasks to complete
                        for chunk_num, task in upload_tasks:
                            try:
                                chunk_size = await task
                                uploaded_bytes += chunk_size
                                completed_chunks += 1
                                
                                # Progress callback
                                if self.progress_callback:
                                    self.progress_callback(uploaded_bytes, file_size)
                                
                                # Log progress every 10% or every 10 chunks
                                if completed_chunks % max(10, total_chunks // 10) == 0:
                                    percent = (uploaded_bytes / file_size) * 100
                                    async with self.active_chunks_lock:
                                        active = self.active_chunks
                                    logger.info(f"Upload progress: {percent:.1f}% ({completed_chunks}/{total_chunks} chunks, {active} concurrent)")
                            except Exception as e:
                                logger.error(f"Chunk {chunk_num} upload failed: {e}")
                                upload_errors.append((chunk_num, e))
                    
                    # Start reader and uploader concurrently
                    reader_task = asyncio.create_task(chunk_reader())
                    uploader_task = asyncio.create_task(chunk_uploader())
                    
                    # Wait for both to complete
                    await asyncio.gather(reader_task, uploader_task)
                    
                    # Check for errors
                    if read_error:
                        raise read_error
                    if upload_errors:
                        raise RuntimeError(f"Failed to upload {len(upload_errors)} chunks: {upload_errors[0][1]}")
                    
                    # Calculate final hash (was computed during chunk reading)
                    original_hash = sha256_hash.hexdigest()
                    logger.info(f"Original file hash (SHA256): {original_hash}")
                    
                    # Finalize upload (include hash for verification)
                    logger.info(f"All chunks uploaded for {file_path.name}, finalizing...")
                    result = await self._finalize_upload(endpoint, upload_id, original_hash=original_hash)
                    return result
                    
            except Exception as e:
                logger.error(f"Upload attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    raise
    
    async def _initiate_upload(
        self,
        endpoint: str,
        filename: str,
        file_size: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Initiate multipart upload on server."""
        # Server expects Form data, not JSON
        form_data = aiohttp.FormData()
        form_data.add_field('filename', filename)
        form_data.add_field('size', str(file_size))
        form_data.add_field('chunk_size', str(self.config.chunk_size))
        if metadata:
            import json as json_lib
            form_data.add_field('metadata', json_lib.dumps(metadata))
        
        async with self.session.post(
            f"{self.server_url}{endpoint}/initiate",
            data=form_data
        ) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Failed to initiate upload: {resp.status}")
            
            data = await resp.json()
            return data["upload_id"]
    
    async def _upload_chunk(
        self,
        endpoint: str,
        upload_id: str,
        chunk_number: int,
        chunk_data: bytes,
        is_first: bool,
        is_last: bool,
    ):
        """Upload a single chunk with retry logic."""
        form_data = aiohttp.FormData()
        form_data.add_field('upload_id', upload_id)
        form_data.add_field('chunk_number', str(chunk_number))
        form_data.add_field('chunk', chunk_data, filename=f'chunk_{chunk_number}')
        form_data.add_field('is_first', 'true' if is_first else 'false')
        form_data.add_field('is_last', 'true' if is_last else 'false')
        
        # Retry chunk upload on failure
        max_retries = 3
        for retry in range(max_retries):
            try:
                async with self.session.post(
                    f"{self.server_url}{endpoint}/chunk",
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=60)  # 60 second timeout per chunk
                ) as resp:
                    if resp.status == 200:
                        return  # Success
                    elif resp.status >= 500:
                        # Server error - retry
                        error_text = await resp.text()
                        logger.warning(f"Chunk {chunk_number} upload failed with {resp.status}: {error_text}, retry {retry + 1}/{max_retries}")
                        if retry < max_retries - 1:
                            await asyncio.sleep(1 * (retry + 1))  # Exponential backoff
                            continue
                        else:
                            raise RuntimeError(f"Failed to upload chunk {chunk_number} after {max_retries} retries: {resp.status} - {error_text}")
                    else:
                        # Client error - don't retry
                        error_text = await resp.text()
                        raise RuntimeError(f"Failed to upload chunk {chunk_number}: {resp.status} - {error_text}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Chunk {chunk_number} upload connection error: {e}, retry {retry + 1}/{max_retries}")
                if retry < max_retries - 1:
                    await asyncio.sleep(1 * (retry + 1))
                    continue
                else:
                    raise RuntimeError(f"Failed to upload chunk {chunk_number} after {max_retries} retries: {e}")
    
    async def _finalize_upload(self, endpoint: str, upload_id: str, original_hash: Optional[str] = None) -> Dict[str, Any]:
        """Finalize upload on server."""
        logger.info(f"Finalizing upload {upload_id}...")
        try:
            finalize_data = {"upload_id": upload_id}
            if original_hash:
                finalize_data["original_hash"] = original_hash
            
            async with self.session.post(
                f"{self.server_url}{endpoint}/finalize",
                json=finalize_data
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.error(f"Failed to finalize upload {upload_id}: {resp.status} - {error_text}")
                    raise RuntimeError(f"Failed to finalize upload: {resp.status} - {error_text}")
                
                result = await resp.json()
                logger.info(f"Upload {upload_id} finalized successfully: {result}")
                return result
        except Exception as e:
            logger.error(f"Exception during finalize for {upload_id}: {e}", exc_info=True)
            raise
    
    async def _throttle_bandwidth(self, bytes_to_send: int):
        """Throttle bandwidth to respect limits."""
        if not self.config.bandwidth_limit:
            return
        
        # Calculate delay needed to respect bandwidth limit
        delay = bytes_to_send / self.config.bandwidth_limit
        await asyncio.sleep(delay)
    
    async def upload_directory(
        self,
        directory_path: Path,
        endpoint: str,
        metadata: Optional[Dict[str, Any]] = None,
        pattern: str = "**/*",
    ) -> Dict[str, Any]:
        """
        Upload all files in a directory.
        
        Args:
            directory_path: Directory to upload
            endpoint: API endpoint
            metadata: Additional metadata
            pattern: Glob pattern for files to include
            
        Returns:
            Upload results
        """
        directory_path = Path(directory_path)
        if not directory_path.exists():
            logger.error(f"Directory does not exist: {directory_path}")
            return {
                "total_files": 0,
                "successful": 0,
                "failed": 0,
                "results": [],
            }
        
        files = list(directory_path.glob(pattern))
        files = [f for f in files if f.is_file()]
        
        if not files:
            logger.warning(f"No files found in directory: {directory_path}")
            return {
                "total_files": 0,
                "successful": 0,
                "failed": 0,
                "results": [],
            }
        
        logger.info(f"Found {len(files)} files to upload from {directory_path}")
        
        # Upload files concurrently (limited by semaphore)
        # Include relative path in metadata for each file to preserve directory structure
        tasks = []
        for file_path in files:
            file_metadata = (metadata or {}).copy()
            # Add relative path to preserve directory structure on server
            relative_path = file_path.relative_to(directory_path)
            file_metadata["relative_path"] = str(relative_path)
            file_metadata["original_filename"] = file_path.name
            
            # Capture file attributes using platform-specific capture
            try:
                from .file_attributes import capture_file_attributes
                captured_attrs = capture_file_attributes(file_path)
                file_metadata.update(captured_attrs)
            except Exception as e:
                import logging
                logging.warning(f"Failed to capture file attributes for {file_path}: {e}")
            
            tasks.append(
                self.upload_file(file_path, endpoint, file_metadata)
            )
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any errors
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to upload file {files[i]}: {result}")
        
        successful = sum(1 for r in results if not isinstance(r, Exception))
        failed = sum(1 for r in results if isinstance(r, Exception))
        
        logger.info(f"Upload complete: {successful} successful, {failed} failed out of {len(files)} files")
        
        return {
            "total_files": len(files),
            "successful": successful,
            "failed": failed,
            "results": results,
        }


class BandwidthMonitor:
    """Monitor and control bandwidth usage."""
    
    def __init__(self, limit: Optional[int] = None):
        self.limit = limit  # Bytes per second
        self.current_usage = 0
        self.window_start = asyncio.get_event_loop().time()
        self.lock = asyncio.Lock()
    
    async def record_usage(self, bytes_transferred: int):
        """Record bandwidth usage."""
        async with self.lock:
            current_time = asyncio.get_event_loop().time()
            
            # Reset window if needed (1 second window)
            if current_time - self.window_start >= 1.0:
                self.current_usage = 0
                self.window_start = current_time
            
            self.current_usage += bytes_transferred
    
    async def get_available_bandwidth(self) -> Optional[int]:
        """Get available bandwidth in current window."""
        if not self.limit:
            return None
        
        async with self.lock:
            return max(0, self.limit - self.current_usage)
    
    async def wait_for_bandwidth(self, bytes_needed: int):
        """Wait until bandwidth is available."""
        if not self.limit:
            return
        
        while True:
            available = await self.get_available_bandwidth()
            if available is None or available >= bytes_needed:
                break
            
            # Wait until next window
            await asyncio.sleep(0.1)

