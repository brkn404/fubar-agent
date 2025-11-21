"""
Windows-specific Agent Implementation
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

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
            logger.info(f"🔍 Starting scan job {job_id}")
            logger.info(f"   Job data: {list(job.keys())}")
            
            # Path can be in job metadata or in the job itself
            path = job.get("metadata", {}).get("path") or job.get("path")
            if not path:
                raise ValueError("No path specified for scan job")
            
            logger.info(f"   Scanning path: {path}")
            await self.report_job_status(job_id, "running", 10, 100, "Initializing scan...")
            
            # Discover files
            await self.report_job_status(job_id, "running", 20, 100, "Discovering files...")
            logger.info(f"   Discovering files in {path}...")
            files = await self._discover_files_recursive(path)
            
            total_files = len(files)
            logger.info(f"   Found {total_files} files to scan")
            await self.report_job_status(job_id, "running", 50, 100, f"Found {total_files} files, scanning...")
            
            # Initialize scan results before scanning
            if not hasattr(self, '_scan_results'):
                self._scan_results = {
                    'detections': [],
                    'anomalies': [],
                    'suspicious_files': [],
                    'file_types': {},
                    'structure_invalid_files': [],
                    'format_analysis_stats': {}
                }
            
            # Log job configuration for debugging
            logger.info(f"🔍 Scan job configuration: enable_yara={job.get('enable_yara')}, enable_heuristic={job.get('enable_heuristic')}, enable_ai_filter_creator={job.get('enable_ai_filter_creator')}")
            logger.info(f"   Job data keys: {list(job.keys())}")
            logger.info(f"   Path: {path}, Total files: {total_files}")
            
            # Scan files and calculate total size
            scanned = 0
            total_size = 0
            logger.info(f"📁 Starting to scan {total_files} files...")
            for file_path in files:
                try:
                    file_stat = Path(file_path).stat()
                    total_size += file_stat.st_size
                except (OSError, FileNotFoundError):
                    pass  # File may have been deleted
                
                try:
                await self._scan_file(file_path, job)
                except Exception as e:
                    logger.debug(f"Error scanning file {file_path}: {e}")
                scanned += 1
                
                # Log progress every 50 files
                if scanned % 50 == 0:
                    logger.info(f"   Scanned {scanned}/{total_files} files...")
                    progress = 50 + int((scanned / total_files) * 50)
                    await self.report_job_status(
                        job_id, "running", progress, 100,
                        f"Scanned {scanned}/{total_files} files"
                    )
            
            # Report completion with metadata including scan results
            scan_metadata = {
                    "files_scanned": total_files,
                    "files_processed": scanned,
                    "total_files": total_files,
                    "scanned_files": scanned,
                    "total_size": total_size,
                }
            
            # Always include scan results (even if empty)
            if hasattr(self, '_scan_results'):
                scan_metadata.update({
                    "detections": len(self._scan_results.get('detections', [])),
                    "anomalies": len(self._scan_results.get('anomalies', [])),
                    "suspicious_files": len(self._scan_results.get('suspicious_files', [])),
                    "file_types": self._scan_results.get('file_types', {}),
                    "structure_invalid_files_count": len(self._scan_results.get('structure_invalid_files', [])),
                    "format_analysis_stats": self._scan_results.get('format_analysis_stats', {}),
                    "scan_details": {
                        "detections": self._scan_results.get('detections', [])[:50],  # Limit to first 50
                        "anomalies": self._scan_results.get('anomalies', [])[:100],  # Limit to first 100
                        "suspicious_files": self._scan_results.get('suspicious_files', [])[:50],  # Limit to first 50
                        "structure_invalid_files": self._scan_results.get('structure_invalid_files', [])[:20]  # Limit to first 20
                    }
                })
                logger.warning(f"📊 Scan results: {len(self._scan_results.get('detections', []))} detections, {len(self._scan_results.get('anomalies', []))} anomalies, {len(self._scan_results.get('suspicious_files', []))} suspicious files")
                logger.warning(f"   Structure invalid: {len(self._scan_results.get('structure_invalid_files', []))} files")
                logger.warning(f"   File types found: {list(self._scan_results.get('file_types', {}).keys())[:10]}")
                logger.warning(f"   Format analysis stats: {self._scan_results.get('format_analysis_stats', {})}")
                # Clear scan results for next job
                delattr(self, '_scan_results')
            else:
                # If _scan_results doesn't exist, include empty results
                scan_metadata.update({
                    "detections": 0,
                    "anomalies": 0,
                    "suspicious_files": 0,
                    "file_types": {},
                    "scan_details": {
                        "detections": [],
                        "anomalies": [],
                        "suspicious_files": []
                    }
                })
                logger.error("⚠️ _scan_results not found, including empty results - scanning may not have run!")
            
            # Log what we're sending
            logger.warning(f"📤 Sending scan results to server: detections={scan_metadata.get('detections', 0)}, anomalies={scan_metadata.get('anomalies', 0)}, suspicious_files={scan_metadata.get('suspicious_files', 0)}")
            logger.warning(f"   Full metadata keys: {list(scan_metadata.keys())}")
            
            await self.report_job_status(
                job_id, "completed", 100, 100, "Scan complete",
                metadata=scan_metadata
            )
            
            logger.info(f"✅ Scan job {job_id} completed and status reported to server")
        
        except Exception as e:
            import traceback
            logger.error(f"❌ Scan job failed: {e}")
            logger.error(f"   Traceback: {traceback.format_exc()}")
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
        """Scan a single file with heuristic analysis, YARA rules, and AI Filter Creator"""
        from pathlib import Path
        import shutil
        import hashlib
        from datetime import datetime
        
        file = Path(file_path)
        if not file.exists():
            return
        
        # Get job configuration
        enable_heuristic = job.get("enable_heuristic", True)
        enable_yara = job.get("enable_yara", False)
        enable_virustotal = job.get("enable_virustotal", False)
        enable_ai_filter_creator = job.get("enable_ai_filter_creator", False)
        analyzers = job.get("analyzers", [])
        yara_rules_dir = job.get("yara_rules_dir") or job.get("metadata", {}).get("yara_rules_dir")
        
        # Initialize scan results at the start of scanning (before first file)
        # This ensures _scan_results exists even if no files are scanned
        if not hasattr(self, '_scan_results'):
            self._scan_results = {
                'detections': [],
                'anomalies': [],
                'suspicious_files': [],
                'file_types': {},
                'structure_invalid_files': [],
                'format_analysis_stats': {}
            }
        
        try:
            file_stat = file.stat()
            file_size = file_stat.st_size
            file_ext = file.suffix.lower()
            
            # Track file types
            if file_ext:
                self._scan_results['file_types'][file_ext] = self._scan_results['file_types'].get(file_ext, 0) + 1
            else:
                self._scan_results['file_types']['no_extension'] = self._scan_results['file_types'].get('no_extension', 0) + 1
            
            # Heuristic scanning
            if enable_heuristic:
                anomalies = []
                
                # Check suspicious file extensions
                suspicious_extensions = {
                    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.jar',
                    '.ps1', '.sh', '.deb', '.rpm', '.pkg', '.dmg', '.app', '.msi', '.sys',
                    '.drv', '.ocx', '.cpl', '.pif', '.application', '.gadget', '.msp', '.mst'
                }
                
                if file_ext in suspicious_extensions:
                    anomalies.append({
                        'type': 'suspicious_extension',
                        'severity': 'medium',
                        'message': f'File has suspicious extension: {file_ext}',
                        'file': str(file),
                        'extension': file_ext
                    })
                
                # Check for very large files (potential data exfiltration)
                if file_size > 100 * 1024 * 1024:  # > 100MB
                    anomalies.append({
                        'type': 'large_file',
                        'severity': 'low',
                        'message': f'Very large file: {file_size:,} bytes',
                        'file': str(file),
                        'size': file_size
                    })
                
                # Check for hidden files (starting with .)
                if file.name.startswith('.'):
                    anomalies.append({
                        'type': 'hidden_file',
                        'severity': 'low',
                        'message': 'Hidden file detected',
                        'file': str(file)
                    })
                
                # Check file header/magic number for mismatches
                try:
                    with open(file, 'rb') as f:
                        header = f.read(16)
                        
                        # Check for PE (Windows executable) header
                        if header[:2] == b'MZ':
                            if file_ext not in {'.exe', '.dll', '.sys', '.scr', '.drv', '.com'}:
                                anomalies.append({
                                    'type': 'header_mismatch',
                                    'severity': 'high',
                                    'message': 'PE executable header found but file extension does not match',
                                    'file': str(file),
                                    'extension': file_ext,
                                    'header': header[:4].hex()
                                })
                        
                        # Check for script shebangs
                        elif header.startswith(b'#!'):
                            if file_ext not in {'.sh', '.py', '.pl', '.rb', '.php', ''}:
                                anomalies.append({
                                    'type': 'script_file',
                                    'severity': 'low',
                                    'message': 'Script file detected',
                                    'file': str(file),
                                    'extension': file_ext
                                })
                except Exception:
                    pass
                
                # Format-specific structural validation (using shared method)
                structure_valid, structure_errors, format_specific_metrics = self._run_format_analyzer(
                    file, file_ext, self._scan_results
                )
                
                if structure_errors:
                    for error in structure_errors:
                        anomalies.append({
                            'type': 'structure_invalid',
                            'severity': 'high',
                            'message': f'Structure validation error: {error}',
                            'file': str(file),
                            'format': file_ext,
                            'structure_errors': structure_errors
                        })
                        logger.warning(f"🔍 Structure validation failed for {file.name}: {error}")
                
                if structure_valid is False:
                    # Structure is invalid - this is a high-severity issue
                    is_malware_suspicious = True
                    malware_reasons.append(f'Invalid file structure: {", ".join(structure_errors[:2])}')
                    logger.warning(f"🚨 Invalid structure detected for {file.name}")
                    
                    # Track structure-invalid files
                    self._scan_results['structure_invalid_files'].append({
                        'file': str(file),
                        'errors': structure_errors,
                        'metrics': format_specific_metrics
                    })
                
                # YARA scanning (if enabled)
                yara_matches = []
                if enable_yara:
                    if not self._check_yara():
                        logger.warning(f"⚠️  YARA not installed, skipping YARA scan for {file.name}")
                    else:
                        try:
                            # Log YARA scanning at INFO level for visibility
                            logger.info(f"🔍 Scanning {file.name} with YARA...")
                            yara_matches = await self._scan_with_yara(file, yara_rules_dir)
                            if yara_matches:
                                logger.warning(f"🚨 YARA match detected: {file.name}")
                                for match in yara_matches:
                                    logger.warning(f"   Rule: {match.get('rule', 'unknown')}")
                                    logger.warning(f"   Tags: {match.get('tags', [])}")
                            else:
                                # Only log at debug level to avoid spam
                                logger.debug(f"   No YARA matches for {file.name}")
                        except Exception as e:
                            logger.error(f"❌ YARA scan failed for {file.name}: {e}")
                elif enable_yara is False:
                    logger.debug(f"YARA scanning disabled for this job")
                
                # Check for malware indicators (especially in Downloads)
                is_malware_suspicious = False
                malware_reasons = []
                
                # YARA matches are high-confidence malware indicators
                if yara_matches:
                    is_malware_suspicious = True
                    rule_names = [m.get('rule', 'unknown') for m in yara_matches]
                    malware_reasons.append(f'YARA rule match: {", ".join(rule_names[:3])}')  # Limit to first 3
                    logger.debug(f"🔍 YARA match triggered quarantine for: {file}")
                
                # High-risk indicators for Windows
                if file_ext in {'.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.ps1'}:
                    file_str = str(file)
                    # Check for executables in suspicious locations on Windows
                    if '\\Downloads' in file_str or '\\downloads' in file_str.lower() or '/Downloads' in file_str or '/downloads' in file_str.lower():
                        is_malware_suspicious = True
                        malware_reasons.append('Executable in Downloads directory')
                        logger.debug(f"🔍 Executable in Downloads triggered quarantine for: {file}")
                
                # Check for high entropy (potential encryption/packing) - using shared method
                try:
                    with open(file, 'rb') as f:
                        sample = f.read(min(4096, file_size))
                        if len(sample) > 0:
                            entropy = self._calculate_entropy(sample)
                            
                            # High entropy (>7.5) suggests encryption/packing
                            if entropy > 7.5 and file_ext in {'.exe', '.dll', '.bin', '.scr', '.sys'}:
                                is_malware_suspicious = True
                                malware_reasons.append(f'High entropy ({entropy:.2f}) - possible packing/encryption')
                except Exception:
                    pass
                
                # If malware suspicious, download/quarantine it
                if is_malware_suspicious:
                    logger.warning(f"🔍 File flagged as malware suspicious: {file}")
                    logger.warning(f"   Reasons: {', '.join(malware_reasons)}")
                    try:
                        # Try multiple quarantine directory locations (in order of preference) - Windows paths
                        quarantine_dirs = [
                            Path(os.environ.get('TEMP', r'C:\Temp')) / 'fubar_quarantine',  # Windows temp
                            Path(r'C:\Temp') / 'fubar_quarantine',  # C:\Temp fallback
                            Path(os.environ.get('LOCALAPPDATA', r'C:\Users\%USERNAME%\AppData\Local')) / 'fubar_quarantine',  # LocalAppData
                        ]
                        
                        quarantine_dir = None
                        for qdir in quarantine_dirs:
                            try:
                                # Check if directory exists and has space
                                qdir.mkdir(exist_ok=True, parents=True)
                                # Try to create a test file to verify writability and space
                                test_file = qdir / '.space_test'
                                test_file.write_text('test')
                                test_file.unlink()
                                quarantine_dir = qdir
                                logger.info(f"✅ Using quarantine directory: {quarantine_dir}")
                                break
                            except (OSError, IOError) as e:
                                logger.debug(f"Quarantine directory {qdir} not available: {e}")
                                continue
                        
                        if not quarantine_dir:
                            raise OSError("No available quarantine directory with sufficient space")
                        
                        # Generate unique filename with timestamp and hash
                        file_hash = hashlib.sha256()
                        with open(file, 'rb') as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                file_hash.update(chunk)
                        hash_str = file_hash.hexdigest()[:16]
                        
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        safe_name = file.name.replace('/', '_').replace('\\', '_')
                        quarantine_name = f"{timestamp}_{hash_str}_{safe_name}"
                        quarantine_path = quarantine_dir / quarantine_name
                        
                        # Copy to quarantine
                        logger.info(f"📋 Copying {file} to quarantine: {quarantine_path}")
                        shutil.copy2(file, quarantine_path)
                        
                        # Verify the file was actually copied
                        if not quarantine_path.exists():
                            raise OSError(f"Quarantine copy failed: {quarantine_path} does not exist after copy")
                        
                        quarantine_size = quarantine_path.stat().st_size
                        if quarantine_size != file_size:
                            raise OSError(f"Quarantine copy size mismatch: original={file_size}, quarantined={quarantine_size}")
                        
                        logger.info(f"✅ Quarantine copy verified: {quarantine_size} bytes")
                        
                        # Log detection
                        detection = {
                            'type': 'malware_suspicious',
                            'severity': 'high',
                            'message': f'Potential malware detected: {", ".join(malware_reasons)}',
                            'file': str(file),
                            'quarantine_path': str(quarantine_path),
                            'hash': file_hash.hexdigest(),
                            'size': file_size,
                            'reasons': malware_reasons,
                            'yara_matches': yara_matches if yara_matches else None,
                            'structure_valid': structure_valid,
                            'structure_errors': structure_errors if structure_errors else None,
                            'format_specific_metrics': format_specific_metrics if format_specific_metrics else None
                        }
                        
                        # Add YARA-specific logging
                        if yara_matches:
                            logger.warning(f"   YARA Rules Matched: {', '.join([m.get('rule', 'unknown') for m in yara_matches])}")
                        
                        self._scan_results['detections'].append(detection)
                        anomalies.append(detection)
                        
                        logger.warning(f"🚨 Potential malware quarantined: {file} -> {quarantine_path}")
                        logger.warning(f"   Reasons: {', '.join(malware_reasons)}")
                        logger.warning(f"   Hash: {file_hash.hexdigest()}")
                        logger.warning(f"   Quarantine verified: {quarantine_path.exists()} ({quarantine_size} bytes)")
                        
                        # Notify server about quarantine for additional YARA analysis
                        try:
                            await self._notify_server_quarantine(
                                job=job,
                                file_path=str(file),
                                quarantine_path=str(quarantine_path),
                                file_hash=file_hash.hexdigest(),
                                file_size=file_size,
                                detection_reasons=malware_reasons,
                                yara_matches=yara_matches
                            )
                        except Exception as e:
                            logger.debug(f"Failed to notify server about quarantine: {e}")
                        
                    except OSError as e:
                        if "No space left" in str(e) or "errno 28" in str(e).lower() or "not enough space" in str(e).lower():
                            logger.error(f"❌ Failed to quarantine {file.name}: No space left on device")
                            logger.error(f"   Tried directories: {[str(qdir) for qdir in quarantine_dirs]}")
                            # Still record as detection even if quarantine failed
                            detection = {
                                'type': 'malware_suspicious',
                                'severity': 'high',
                                'message': f'Potential malware detected (quarantine failed - no space): {", ".join(malware_reasons)}',
                                'file': str(file),
                                'quarantine_path': None,
                                'quarantine_failed': True,
                                'quarantine_error': str(e),
                                'hash': None,  # Can't calculate hash if we can't read file
                                'size': file_size,
                                'reasons': malware_reasons,
                                'yara_matches': yara_matches if yara_matches else None
                            }
                            self._scan_results['detections'].append(detection)
                            anomalies.append(detection)
                        else:
                            logger.error(f"Failed to quarantine suspicious file {file}: {e}")
                    except Exception as e:
                        logger.error(f"Failed to quarantine suspicious file {file}: {e}")
                
                # AI Filter Creator: Check for unknown file types - using shared method
                if enable_ai_filter_creator:
                    if self._check_unknown_file_type(file, file_ext):
                        logger.info(f"🔍 Unknown file type detected: {file} (extension: {file_ext or 'none'})")
                        logger.info(f"   AI Filter Creator would analyze this file type")
                        # In a full implementation, this would call AI Filter Creator
                        # For now, just log it
                        anomalies.append({
                            'type': 'unknown_file_type',
                            'severity': 'low',
                            'message': f'Unknown file type - AI Filter Creator could analyze',
                            'file': str(file),
                            'extension': file_ext or 'none'
                        })
                
                # Add anomalies to results
                if anomalies:
                    self._scan_results['anomalies'].extend(anomalies)
                    self._scan_results['suspicious_files'].append({
                        'file': str(file),
                        'size': file_size,
                        'anomalies': [a['type'] for a in anomalies],
                        'max_severity': max([a['severity'] for a in anomalies], key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x])
                    })
        
        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {e}")
    
    def _get_yara_rules_search_paths(self) -> List[Path]:
        """Get Windows-specific YARA rules search paths"""
        base_paths = super()._get_yara_rules_search_paths()
        
        # Add Windows-specific paths
        windows_paths = [
            # Windows paths
            Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'fubar-agent' / 'rules-master',
            Path(os.environ.get('LOCALAPPDATA', r'C:\Users\%USERNAME%\AppData\Local')) / 'fubar-agent' / 'rules-master',
            Path(r'C:\fubar-agent\rules-master'),
            Path(r'C:\Program Files\fubar-agent\rules-master'),
        ]
        
        return windows_paths + base_paths
    
    async def _notify_server_quarantine(
        self,
        job: Dict[str, Any],
        file_path: str,
        quarantine_path: str,
        file_hash: str,
        file_size: int,
        detection_reasons: List[str],
        yara_matches: List[Dict[str, Any]]
    ):
        """Notify server about quarantined file for additional YARA analysis"""
        try:
            from datetime import datetime
            
            # Get agent_id from parent class
            agent_id = getattr(self, 'agent_id', None)
            if not agent_id:
                logger.debug("Agent ID not available, skipping server notification")
                return
            
            # Get server URL from parent class
            server_url = getattr(self, 'server_url', None)
            if not server_url:
                logger.debug("Server URL not available, skipping server notification")
                return
            
            # Get session from parent class
            session = getattr(self, 'session', None)
            if not session:
                logger.debug("HTTP session not available, skipping server notification")
                return
            
            job_id = job.get("job_id")
            
            payload = {
                "agent_id": agent_id,
                "job_id": job_id,
                "file_path": file_path,
                "quarantine_path": quarantine_path,
                "file_hash": file_hash,
                "file_size": file_size,
                "detection_reasons": detection_reasons,
                "yara_matches": yara_matches if yara_matches else None,
                "severity": "high",
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            async with session.post(
                f"{server_url}/api/v1/agents/{agent_id}/quarantine",
                json=payload
            ) as resp:
                if resp.status == 200:
                    logger.debug(f"✅ Server notified about quarantine: {file_path}")
                else:
                    logger.debug(f"⚠️  Server quarantine notification returned status {resp.status}")
        except Exception as e:
            logger.debug(f"Failed to notify server about quarantine: {e}")
    
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
        from uuid import UUID
        from pathlib import Path
        import aiofiles
        
        job_id = UUID(job["job_id"])
        
        try:
            snapshot_id = job.get("metadata", {}).get("snapshot_id")
            target = job.get("metadata", {}).get("target")
            file_paths = job.get("metadata", {}).get("file_paths", [])
            
            if not snapshot_id or not target:
                raise ValueError("Missing snapshot_id or target")
            
            await self.report_job_status(job_id, "running", 10, 100, "Initializing restore...")
            
            # Find uploads for this backup
            async with self.session.get(
                f"{self.server_url}/api/v1/catalog/backups/{snapshot_id}/file-structure"
            ) as resp:
                if resp.status != 200:
                    raise ValueError(f"Failed to get backup file structure: {resp.status}")
                backup_structure = await resp.json()
            
            files = backup_structure.get("files", [])
            if not files:
                raise ValueError(f"No files found in backup {snapshot_id}")
            
            # Filter files if specific paths requested
            if file_paths:
                files = [f for f in files if any(f.get("path", "").endswith(fp.replace("/", "\\")) or f.get("path", "").endswith(fp) for fp in file_paths)]
            
            if not files:
                raise ValueError("No files match restore criteria")
            
            await self.report_job_status(job_id, "running", 20, 100, f"Found {len(files)} files to restore")
            
            # Handle Windows path conventions
            target_path = Path(target)
            if target_path.is_file():
                target_dir = target_path.parent
                target_file = target_path.name
            else:
                target_dir = target_path
                target_file = None
            
            # Create target directory if it doesn't exist
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Restore each file
            for i, file_info in enumerate(files):
                upload_id = file_info.get("upload_id")
                filename = file_info.get("filename") or file_info.get("path", "").split("\\")[-1].split("/")[-1]
                
                if not upload_id:
                    logger.warning(f"No upload_id for file {filename}, skipping")
                    continue
                
                progress = 30 + (i * 60 // len(files))
                await self.report_job_status(job_id, "running", progress, 100, f"Restoring {filename}...")
                
                # Try to download finalized file first
                try:
                    async with self.session.get(
                        f"{self.server_url}/api/v1/streaming/restore/{upload_id}/file"
                    ) as resp:
                        if resp.status == 200:
                            # Finalized file exists, download it
                            dest_path = target_dir / (target_file if target_file and i == 0 else filename)
                            async with aiofiles.open(dest_path, "wb") as f:
                                async for chunk in resp.content.iter_chunked(8192):
                                    await f.write(chunk)
                            logger.info(f"Downloaded finalized file: {filename}")
                            
                            # Restore Windows file attributes if available
                            await self._restore_file_attributes(dest_path, file_info)
                            continue
                except Exception as e:
                    logger.debug(f"Finalized file not available, will download chunks: {e}")
                
                # Download chunks and reassemble
                async with self.session.get(
                    f"{self.server_url}/api/v1/streaming/restore/{upload_id}/chunks"
                ) as resp:
                    if resp.status != 200:
                        raise ValueError(f"Failed to get chunks for {upload_id}: {resp.status}")
                    chunks_info = await resp.json()
                
                chunks = chunks_info.get("chunks", [])
                if not chunks:
                    raise ValueError(f"No chunks found for upload {upload_id}")
                
                logger.info(f"Downloading {len(chunks)} chunks for {filename}")
                
                # Download chunks and reassemble
                dest_path = target_dir / (target_file if target_file and i == 0 else filename)
                async with aiofiles.open(dest_path, "wb") as outfile:
                    for chunk_idx, chunk_info in enumerate(chunks):
                        chunk_num = chunk_info["chunk_number"]
                        async with self.session.get(
                            f"{self.server_url}/api/v1/streaming/restore/{upload_id}/chunk/{chunk_num}"
                        ) as chunk_resp:
                            if chunk_resp.status != 200:
                                raise ValueError(f"Failed to download chunk {chunk_num}: {chunk_resp.status}")
                            async for chunk_data in chunk_resp.content.iter_chunked(8192):
                                await outfile.write(chunk_data)
                        
                        chunk_progress = progress + int((chunk_idx + 1) * (60 / len(files)) / len(chunks))
                        await self.report_job_status(job_id, "running", chunk_progress, 100, f"Downloading chunk {chunk_idx + 1}/{len(chunks)} of {filename}")
                
                logger.info(f"Reassembled {filename} from {len(chunks)} chunks")
                
                # Restore Windows file attributes if available
                await self._restore_file_attributes(dest_path, file_info)
            
            await self.report_job_status(job_id, "running", 100, 100, f"Restored {len(files)} files to {target}")
            logger.info(f"Restore completed: {len(files)} files restored to {target}")
        
        except Exception as e:
            logger.error(f"Restore job failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise
    
    async def _restore_file_attributes(self, file_path: Path, file_info: Dict[str, Any]):
        """Restore Windows file attributes (permissions, ACLs, Windows attributes, ADS)"""
        try:
            import os
            import stat
            import subprocess
            import platform
            
            if platform.system() != "Windows":
                return  # Only run on Windows
            
            # Restore permissions if available
            permissions = file_info.get("permissions")
            if permissions:
                try:
                    # Convert octal string to mode
                    if isinstance(permissions, str):
                        mode = int(permissions, 8)
                    else:
                        mode = permissions
                    os.chmod(file_path, mode)
                except Exception as e:
                    logger.debug(f"Failed to restore permissions for {file_path}: {e}")
            
            # Restore Windows file attributes (read-only, hidden, system, etc.)
            windows_attrs = file_info.get("windows_attributes") or file_info.get("attributes")
            if windows_attrs:
                try:
                    import win32api
                    import win32con
                    attrs = 0
                    if windows_attrs.get("readonly"):
                        attrs |= win32con.FILE_ATTRIBUTE_READONLY
                    if windows_attrs.get("hidden"):
                        attrs |= win32con.FILE_ATTRIBUTE_HIDDEN
                    if windows_attrs.get("system"):
                        attrs |= win32con.FILE_ATTRIBUTE_SYSTEM
                    if windows_attrs.get("archive"):
                        attrs |= win32con.FILE_ATTRIBUTE_ARCHIVE
                    if windows_attrs.get("compressed"):
                        attrs |= win32con.FILE_ATTRIBUTE_COMPRESSED
                    if windows_attrs.get("encrypted"):
                        attrs |= win32con.FILE_ATTRIBUTE_ENCRYPTED
                    
                    if attrs:
                        win32api.SetFileAttributes(str(file_path), attrs)
                except ImportError:
                    logger.debug("win32api not available, skipping Windows attributes")
                except Exception as e:
                    logger.debug(f"Failed to restore Windows attributes for {file_path}: {e}")
            
            # Also try to restore from attributes_value if available
            if not windows_attrs and file_info.get("windows_attributes_value") is not None:
                try:
                    import win32api
                    win32api.SetFileAttributes(str(file_path), file_info["windows_attributes_value"])
                except (ImportError, Exception) as e:
                    logger.debug(f"Failed to restore Windows attributes from value for {file_path}: {e}")
            
            # Restore ACLs if available (requires pywin32)
            acl_data = file_info.get("acl") or file_info.get("permissions_acl")
            if acl_data:
                try:
                    import win32security
                    import win32api
                    
                    # Parse ACL data and apply
                    # This is a simplified version - full ACL restoration would be more complex
                    if isinstance(acl_data, str):
                        # If ACL is stored as SDDL string, we can apply it directly
                        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                            acl_data, win32security.SDDL_REVISION_1
                        )
                        win32security.SetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION, sd)
                except ImportError:
                    logger.debug("win32security not available, skipping ACL restoration")
                except Exception as e:
                    logger.debug(f"Failed to restore ACL for {file_path}: {e}")
            
            # Restore Alternate Data Streams (ADS) if available
            ads_data = file_info.get("ads") or file_info.get("alternate_data_streams")
            if ads_data:
                try:
                    # Use PowerShell to restore ADS
                    for stream_name, stream_content in ads_data.items():
                        if isinstance(stream_content, str):
                            stream_content = stream_content.encode('utf-8')
                        
                        # Write ADS using PowerShell
                        ps_cmd = f'''
                        $content = [System.Convert]::FromBase64String('{stream_content.decode("latin-1") if isinstance(stream_content, bytes) else stream_content}')
                        Set-Content -Path "{file_path}:{stream_name}" -Value $content -Encoding Byte
                        '''
                        subprocess.run(
                            ["powershell", "-Command", ps_cmd],
                            check=False,
                            capture_output=True
                        )
                except Exception as e:
                    logger.debug(f"Failed to restore ADS for {file_path}: {e}")
        
        except Exception as e:
            logger.debug(f"Error restoring file attributes for {file_path}: {e}")

