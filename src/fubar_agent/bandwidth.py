"""
Bandwidth Detection and Auto-Tuning

Automatically detects available bandwidth and calculates optimal settings
for 80% network utilization.
"""

import asyncio
import logging
import aiohttp
import time
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


async def detect_bandwidth(
    server_url: str,
    session: Optional[aiohttp.ClientSession] = None,
    test_duration: float = 5.0,
    test_size: int = 10 * 1024 * 1024,  # 10MB test
) -> Optional[float]:
    """
    Detect available bandwidth by uploading test data to server.
    
    Args:
        server_url: Server URL to test against
        session: Optional HTTP session (creates new if not provided)
        test_duration: How long to run test (seconds)
        test_size: Size of test data to upload (bytes)
        
    Returns:
        Detected bandwidth in bytes per second, or None if detection failed
    """
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    
    try:
        # Create test data
        test_data = b'0' * min(test_size, 1024 * 1024)  # 1MB chunks
        
        # Measure upload speed
        total_bytes = 0
        start_time = time.time()
        end_time = start_time + test_duration
        
        upload_id = None
        try:
            # Initiate test upload
            async with session.post(
                f"{server_url}/api/v1/streaming/initiate",
                data={
                    "filename": "bandwidth_test.bin",
                    "size": test_size,
                    "chunk_size": 1024 * 1024,
                    "metadata": '{"type": "bandwidth_test"}'
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    upload_id = data.get("upload_id")
        
            if upload_id:
                chunk_number = 0
                while time.time() < end_time:
                    # Upload chunk
                    form_data = aiohttp.FormData()
                    form_data.add_field('upload_id', upload_id)
                    form_data.add_field('chunk_number', str(chunk_number))
                    form_data.add_field('chunk', test_data)
                    form_data.add_field('is_first', 'true' if chunk_number == 0 else 'false')
                    form_data.add_field('is_last', 'false')
                    
                    async with session.post(
                        f"{server_url}/api/v1/streaming/chunk",
                        data=form_data
                    ) as resp:
                        if resp.status == 200:
                            total_bytes += len(test_data)
                            chunk_number += 1
                        else:
                            break
        except Exception as e:
            logger.warning(f"Bandwidth detection failed: {e}")
            return None
        finally:
            # Clean up test upload if created
            if upload_id:
                try:
                    await session.post(
                        f"{server_url}/api/v1/streaming/finalize",
                        json={"upload_id": upload_id}
                    )
                except:
                    pass
        
        elapsed = time.time() - start_time
        if elapsed > 0:
            bandwidth = total_bytes / elapsed
            logger.info(f"Detected bandwidth: {bandwidth / (1024*1024):.2f} MB/s")
            return bandwidth
        
        return None
        
    finally:
        if close_session:
            await session.close()


def calculate_optimal_settings(
    bandwidth_bps: float,
    target_utilization: float = 0.80,
    min_streams: int = 1,
    max_streams: int = 10,
) -> Dict[str, Any]:
    """
    Calculate optimal streaming settings for target network utilization.
    
    Args:
        bandwidth_bps: Available bandwidth in bytes per second
        target_utilization: Target utilization (0.0-1.0), default 0.80 (80%)
        min_streams: Minimum concurrent streams
        max_streams: Maximum concurrent streams
        
    Returns:
        Dictionary with optimal settings:
        - bandwidth_limit: Target bandwidth in bytes/second
        - max_concurrent_streams: Optimal number of parallel streams
        - chunk_size: Optimal chunk size in bytes
        - max_connections: HTTP connection pool size
    """
    # Calculate target bandwidth (80% of available)
    target_bandwidth = int(bandwidth_bps * target_utilization)
    
    # Calculate optimal chunk size based on bandwidth
    # Rule of thumb: chunk size should allow ~10 chunks per second per stream
    # This balances overhead vs. granularity
    optimal_chunk_size = max(
        256 * 1024,  # Minimum 256KB
        min(
            10 * 1024 * 1024,  # Maximum 10MB
            int(target_bandwidth / 10)  # ~10 chunks/second
        )
    )
    
    # Calculate optimal number of streams
    # More streams = better utilization, but overhead increases
    # Formula: streams = bandwidth / (chunk_size * chunks_per_second_per_stream)
    # We aim for ~5-10 chunks per second per stream
    chunks_per_second_per_stream = 5
    optimal_streams = max(
        min_streams,
        min(
            max_streams,
            int(target_bandwidth / (optimal_chunk_size * chunks_per_second_per_stream))
        )
    )
    
    # Ensure at least 1 stream
    optimal_streams = max(1, optimal_streams)
    
    # Connection pool should be at least 2x concurrent streams for headroom
    optimal_connections = max(optimal_streams * 2, 10)
    
    return {
        "bandwidth_limit": target_bandwidth,
        "max_concurrent_streams": optimal_streams,
        "chunk_size": optimal_chunk_size,
        "max_connections": optimal_connections,
    }


async def auto_configure_bandwidth(
    server_url: str,
    session: Optional[aiohttp.ClientSession] = None,
    target_utilization: float = 0.80,
    fallback_bandwidth: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Automatically detect bandwidth and calculate optimal settings.
    
    Args:
        server_url: Server URL
        session: Optional HTTP session
        target_utilization: Target network utilization (default 0.80 = 80%)
        fallback_bandwidth: Fallback bandwidth if detection fails (bytes/second)
        
    Returns:
        Dictionary with optimal streaming settings
    """
    logger.info("Detecting available bandwidth...")
    
    # Try to detect bandwidth
    detected_bandwidth = await detect_bandwidth(server_url, session)
    
    if detected_bandwidth is None:
        if fallback_bandwidth:
            logger.info(f"Using fallback bandwidth: {fallback_bandwidth / (1024*1024):.2f} MB/s")
            detected_bandwidth = fallback_bandwidth
        else:
            logger.warning("Bandwidth detection failed, using conservative defaults")
            # Conservative defaults: assume 10Mbps (1.25 MB/s)
            detected_bandwidth = 1.25 * 1024 * 1024
    
    # Calculate optimal settings
    settings = calculate_optimal_settings(detected_bandwidth, target_utilization)
    
    logger.info(f"Optimal settings for {target_utilization*100:.0f}% utilization:")
    logger.info(f"  Bandwidth limit: {settings['bandwidth_limit'] / (1024*1024):.2f} MB/s")
    logger.info(f"  Concurrent streams: {settings['max_concurrent_streams']}")
    logger.info(f"  Chunk size: {settings['chunk_size'] / (1024*1024):.2f} MB")
    logger.info(f"  Max connections: {settings['max_connections']}")
    
    return settings

