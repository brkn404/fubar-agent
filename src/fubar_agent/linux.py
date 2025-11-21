"""
Linux-specific Agent Implementation
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import BaseAgent
from .format_analyzers import get_analyzer_for_file

logger = logging.getLogger(__name__)


class LinuxAgent(BaseAgent):
    """Linux-specific agent implementation"""
    
    async def get_capabilities(self) -> Dict[str, bool]:
        """Get Linux-specific capabilities"""
        capabilities = await super().get_capabilities()
        
        # Linux-specific capabilities
        capabilities.update({
            "inotify": self._check_inotify(),
            "systemd": self._check_systemd(),
            "lvm": self._check_lvm(),
            "zfs": self._check_zfs(),
            "yara": self._check_yara(),
        })
        
        return capabilities
    
    def _check_inotify(self) -> bool:
        """Check if inotify is available"""
        try:
            import inotify
            return True
        except ImportError:
            return False
    
    def _check_systemd(self) -> bool:
        """Check if systemd is available"""
        try:
            import subprocess
            result = subprocess.run(
                ["systemctl", "--version"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_lvm(self) -> bool:
        """Check if LVM is available"""
        try:
            import subprocess
            result = subprocess.run(
                ["which", "lvcreate"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_zfs(self) -> bool:
        """Check if ZFS is available"""
        try:
            import subprocess
            result = subprocess.run(
                ["which", "zfs"],
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
        """Execute scan job on Linux"""
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
            
            # Use find for fast file discovery on Linux
            await self.report_job_status(job_id, "running", 20, 100, "Discovering files...")
            logger.info(f"   Discovering files in {path}...")
            files = await self._discover_files_find(path)
            
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
    
    async def _discover_files_find(self, path: str):
        """Discover files using find command (Linux)"""
        import subprocess
        
        # Use find for fast file discovery
        cmd = ["find", path, "-type", "f"]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return [line.decode().strip() for line in stdout.splitlines() if line.strip()]
        
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
        """Scan a single file with heuristic analysis, YARA rules, and AI Filter Creator"""
        from pathlib import Path
        import os
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
                
                # Check for executable files on Linux (should not normally have .exe)
                if file_ext == '.exe' and os.name != 'nt':
                    anomalies.append({
                        'type': 'windows_executable_on_linux',
                        'severity': 'high',
                        'message': 'Windows executable (.exe) found on Linux system',
                        'file': str(file),
                        'size': file_size
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
                
                # Check file permissions (world-writable executables)
                try:
                    file_mode = file.stat().st_mode
                    if file_mode & 0o111 and file_mode & 0o002:  # Executable and world-writable
                        anomalies.append({
                            'type': 'insecure_permissions',
                            'severity': 'high',
                            'message': 'World-writable executable file',
                            'file': str(file),
                            'permissions': oct(file_mode)[-3:]
                        })
                except Exception:
                    pass
                
                # Check file header/magic number for mismatches
                try:
                    with open(file, 'rb') as f:
                        header = f.read(16)
                        
                        # Check for PE (Windows executable) header
                        if header[:2] == b'MZ':
                            if file_ext not in {'.exe', '.dll', '.sys', '.scr', '.drv'}:
                                anomalies.append({
                                    'type': 'header_mismatch',
                                    'severity': 'high',
                                    'message': 'PE executable header found but file extension does not match',
                                    'file': str(file),
                                    'extension': file_ext,
                                    'header': header[:4].hex()
                                })
                        
                        # Check for ELF (Linux executable) header
                        elif header[:4] == b'\x7fELF':
                            if file_ext not in {'.so', '.bin', ''}:
                                anomalies.append({
                                    'type': 'header_mismatch',
                                    'severity': 'medium',
                                    'message': 'ELF executable header found',
                                    'file': str(file),
                                    'extension': file_ext
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
                
                # Format-specific structural validation
                structure_valid = None
                structure_errors = []
                format_specific_metrics = {}
                
                analyzer = get_analyzer_for_file(file)
                if analyzer:
                    try:
                        logger.debug(f"Running format analyzer for {file.name} ({file_ext})")
                        analysis_result = analyzer.analyze(file)
                        structure_valid = analysis_result.get('structure_valid')
                        structure_errors = analysis_result.get('structure_errors', [])
                        format_specific_metrics = analysis_result.get('format_specific_metrics', {})
                        
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
                        
                        # Track format analysis stats
                        if format_specific_metrics:
                            format_type = file_ext or 'unknown'
                            if format_type not in self._scan_results['format_analysis_stats']:
                                self._scan_results['format_analysis_stats'][format_type] = {
                                    'total': 0,
                                    'valid': 0,
                                    'invalid': 0
                                }
                            self._scan_results['format_analysis_stats'][format_type]['total'] += 1
                            if structure_valid:
                                self._scan_results['format_analysis_stats'][format_type]['valid'] += 1
                            elif structure_valid is False:
                                self._scan_results['format_analysis_stats'][format_type]['invalid'] += 1
                    except Exception as e:
                        logger.debug(f"Format analyzer error for {file.name}: {e}")
                        structure_errors.append(f"Analyzer error: {str(e)}")
                
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
                
                # High-risk indicators
                if file_ext == '.exe' and os.name != 'nt':
                    is_malware_suspicious = True
                    malware_reasons.append('Windows executable on Linux')
                    logger.debug(f"🔍 Windows exe on Linux triggered quarantine for: {file}")
                
                if file_ext in {'.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.ps1'}:
                    file_str = str(file)
                    if '/Downloads' in file_str or '/downloads' in file_str.lower():
                        is_malware_suspicious = True
                        malware_reasons.append('Executable in Downloads directory')
                        logger.debug(f"🔍 Executable in Downloads triggered quarantine for: {file}")
                
                # Debug: Log if file should be quarantined but isn't
                if file_ext == '.exe' and os.name != 'nt' and not is_malware_suspicious:
                    logger.warning(f"⚠️  Windows exe on Linux NOT quarantined: {file} (is_malware_suspicious={is_malware_suspicious})")
                
                # Check for high entropy (potential encryption/packing)
                try:
                    with open(file, 'rb') as f:
                        sample = f.read(min(4096, file_size))
                        if len(sample) > 0:
                            # Calculate Shannon entropy
                            import math
                            byte_counts = [0] * 256
                            for byte in sample:
                                byte_counts[byte] += 1
                            
                            entropy = 0
                            for count in byte_counts:
                                if count > 0:
                                    p = count / len(sample)
                                    entropy -= p * math.log2(p)
                            
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
                        # Try multiple quarantine directory locations (in order of preference)
                        quarantine_dirs = [
                            Path('/home/kit/fubar_quarantine'),  # User's home directory (more space)
                            Path('/var/tmp/fubar_quarantine'),  # /var/tmp (persists across reboots)
                            Path('/tmp/fubar_quarantine'),      # /tmp (fallback)
                        ]
                        
                        quarantine_dir = None
                        for qdir in quarantine_dirs:
                            try:
                                # Check if directory exists and has space
                                qdir.mkdir(exist_ok=True, mode=0o700)
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
                        if "No space left" in str(e) or "errno 28" in str(e).lower():
                            logger.error(f"❌ Failed to quarantine {file.name}: No space left on device")
                            logger.error(f"   Tried directories: {[str(qdir) for qdir in quarantine_dirs]}")
                            logger.error(f"   Consider: df -h to check disk space, or clean up /tmp")
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
                
                # AI Filter Creator: Check for unknown file types
                if enable_ai_filter_creator:
                    # Detect unknown file types (no recognized extension or magic number)
                    known_extensions = {
                        '.txt', '.log', '.json', '.xml', '.csv', '.html', '.css', '.js',
                        '.py', '.sh', '.pl', '.rb', '.php', '.java', '.cpp', '.c', '.h',
                        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
                        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
                        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
                        '.db', '.sqlite', '.sql', '.sqlite3',
                        '.exe', '.dll', '.so', '.dylib', '.bin'
                    }
                    
                    # Check if file type is unknown
                    is_unknown = False
                    if not file_ext or file_ext not in known_extensions:
                        # Check magic number
                        try:
                            with open(file, 'rb') as f:
                                magic = f.read(16)
                                # Common magic numbers
                                known_magics = [
                                    b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'%PDF',
                                    b'PK\x03\x04', b'\x7fELF', b'MZ', b'\xca\xfe\xba\xbe',
                                    b'<?xml', b'<!DOCTYPE', b'{\n', b'#!/'
                                ]
                                
                                is_known_magic = any(magic.startswith(m) for m in known_magics)
                                if not is_known_magic:
                                    is_unknown = True
                        except Exception:
                            is_unknown = True
                    
                    if is_unknown:
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
    
    async def _scan_with_yara(self, file_path: Path, rules_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
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
            # Try to find rules-master directory
            # Get the agent's working directory to search relative to it
            agent_cwd = Path.cwd()
            agent_file_dir = Path(__file__).parent.parent.parent.parent
            
            possible_paths = [
                # Linux host paths
                Path('/home/kit/fubar/rules-master'),
                Path('/home/kit/fubar-main/rules-master'),
                Path('/home/kit/fubar/unified-pipeline/rules-master'),
                Path('/home/kit/rules-master'),
                # Mac development path
                Path('/Volumes/evo4TB/kit/kit/fubar/rules-master'),
                # Relative to current working directory
                agent_cwd / 'rules-master',
                agent_cwd.parent / 'rules-master',
                agent_cwd.parent.parent / 'rules-master',
                # Relative to agent code location
                agent_file_dir / 'rules-master',
                agent_file_dir.parent / 'rules-master',
                # System-wide
                Path('/') / 'rules-master',
                Path('/usr/local') / 'rules-master',
                Path('/opt') / 'rules-master',
            ]
            
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
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    server_matches = result.get("server_yara_matches", [])
                    if server_matches:
                        logger.warning(
                            f"✅ Server-side YARA matches: "
                            f"{', '.join([m.get('rule', 'unknown') for m in server_matches])}"
                        )
                    logger.debug(f"Server quarantine notification successful: {result}")
                else:
                    logger.debug(f"Server quarantine notification failed: {resp.status}")
        except Exception as e:
            logger.debug(f"Error notifying server about quarantine: {e}")
    
    async def _create_platform_snapshot(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Create snapshot locally on Linux"""
        from uuid import UUID, uuid4
        from datetime import datetime
        
        # Try multiple places for source path
        source = (
            job.get("source") or 
            job.get("metadata", {}).get("source") or
            job.get("metadata", {}).get("path")
        )
        if not source:
            raise ValueError("No source specified for backup job")
        
        # Validate source path exists
        source_path = Path(source)
        if not source_path.exists():
            raise ValueError(f"Source path does not exist: {source}")
        if not source_path.is_dir() and not source_path.is_file():
            raise ValueError(f"Source path is not a file or directory: {source}")
        
        tags = job.get("metadata", {}).get("tags", [])
        format_type = job.get("metadata", {}).get("format", "hardlink")
        
        # Generate snapshot ID
        snapshot_id = f"snap-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}"
        
        # Create snapshot destination
        # Try multiple locations in order of preference
        snapshot_base = None
        for base_path in [
            Path.home() / "unified-backups",  # User's home directory
            Path("/home/kit/unified-backups"),  # Specific location for kit user
            Path("/tmp/unified-backups"),  # Fallback to /tmp
        ]:
            try:
                # Check if we can write to this location
                base_path.mkdir(parents=True, exist_ok=True)
                # Check available space (rough check - try to create a test file)
                test_file = base_path / ".write_test"
                try:
                    test_file.write_text("test")
                    test_file.unlink()
                    snapshot_base = base_path
                    break
                except (OSError, PermissionError):
                    continue
            except (OSError, PermissionError):
                continue
        
        if not snapshot_base:
            # Last resort: use /tmp
            snapshot_base = Path("/tmp/unified-backups")
            snapshot_base.mkdir(parents=True, exist_ok=True)
        
        snapshot_dir = snapshot_base / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        # Use rsync for backup (hardlink format)
        import subprocess
        
        # Check if this is an incremental backup
        is_incremental = job.get("incremental", job.get("metadata", {}).get("incremental", False))
        base_snapshot = job.get("base_snapshot") or job.get("metadata", {}).get("base_snapshot")
        
        # Find previous snapshot for hardlinking (for incremental backups)
        previous_snapshot = None
        if is_incremental:
            if base_snapshot:
                # Use specified base snapshot
                base_path = Path(base_snapshot)
                if base_path.exists() and base_path.is_dir():
                    previous_snapshot = base_path
                    logger.info(f"Using specified base snapshot: {base_snapshot}")
            else:
                # Find most recent snapshot automatically
                parent_dir = snapshot_dir.parent
                if parent_dir.exists():
                    existing_snapshots = sorted(
                        [d for d in parent_dir.iterdir() if d.is_dir() and d != snapshot_dir],
                        key=lambda x: x.stat().st_mtime,
                        reverse=True
                    )
                    if existing_snapshots:
                        previous_snapshot = existing_snapshots[0]
                        logger.info(f"Using most recent snapshot for hardlinks: {previous_snapshot}")
        
        # Build rsync command
        cmd = ["rsync", "-a", "--delete", "--no-group", "--no-owner", "--partial"]
        
        # Exclude common cache and temporary directories to save space
        exclude_patterns = [
            "**/.cache/**",
            "**/cache/**",
            "**/tmp/**",
            "**/.tmp/**",
            "**/node_modules/**",
            "**/.git/**",
            "**/__pycache__/**",
            "**/*.pyc",
            "**/.DS_Store",
        ]
        for pattern in exclude_patterns:
            cmd.extend(["--exclude", pattern])
        
        # Add hardlink support for incremental backups
        if previous_snapshot:
            cmd.extend(["--link-dest", str(previous_snapshot)])
            logger.info(f"Incremental backup: using hardlinks from {previous_snapshot}")
        elif is_incremental:
            logger.warning("Incremental backup requested but no previous snapshot found - performing full backup")
        
        # Add source and destination
        source_path = Path(source)
        if source_path.is_file():
            cmd.append(str(source_path))
        else:
            cmd.append(f"{source_path}/")
        
        cmd.append(str(snapshot_dir))
        
        # Verify source exists and is accessible
        if not source_path.exists():
            raise ValueError(f"Source path does not exist: {source}")
        
        # Check source permissions
        if not os.access(source_path, os.R_OK):
            raise PermissionError(f"Source path is not readable: {source}")
        
        # Verify destination directory exists and is writable
        if not snapshot_dir.parent.exists():
            snapshot_dir.parent.mkdir(parents=True, exist_ok=True)
        
        if not os.access(snapshot_dir.parent, os.W_OK):
            raise PermissionError(f"Destination directory is not writable: {snapshot_dir.parent}")
        
        # Check disk space (rough estimate - need at least file size + 10% overhead)
        if source_path.is_file():
            file_size = source_path.stat().st_size
            import shutil
            free_space = shutil.disk_usage(snapshot_dir.parent).free
            if free_space < file_size * 1.1:
                raise RuntimeError(f"Insufficient disk space: need {file_size * 1.1 / (1024**3):.2f} GB, have {free_space / (1024**3):.2f} GB free")
        
        logger.info(f"Executing rsync: {' '.join(cmd)}")
        
        # Execute rsync
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            stderr_text = stderr.decode('utf-8', errors='ignore') if stderr else "No error output"
            stdout_text = stdout.decode('utf-8', errors='ignore') if stdout else "No output"
            error_msg = f"rsync failed with code {process.returncode}"
            if stderr_text:
                error_msg += f": {stderr_text[:500]}"  # Limit error message length
            if stdout_text and len(stdout_text) < 500:
                error_msg += f" (stdout: {stdout_text})"
            
            # Check for common errors and provide helpful messages
            error_str = error_msg.lower()
            if "no space left on device" in error_str or process.returncode == 11:
                # Check available space
                import shutil
                try:
                    total, used, free = shutil.disk_usage(snapshot_base)
                    free_gb = free / (1024**3)
                    raise RuntimeError(
                        f"Backup failed: No space left on device. "
                        f"Available space: {free_gb:.2f} GB. "
                        f"Snapshot location: {snapshot_base}. "
                        f"Try using a smaller source directory or free up disk space. "
                        f"Original error: {error_msg}"
                    )
                except Exception:
                    raise RuntimeError(
                        f"Backup failed: No space left on device. "
                        f"Snapshot location: {snapshot_base}. "
                        f"Try using a smaller source directory or free up disk space. "
                        f"Original error: {error_msg}"
                    )
            else:
                raise RuntimeError(error_msg)
        
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
                "platform": "linux",
                "created_by": "linux-agent",
                "previous_snapshot": str(previous_snapshot) if previous_snapshot else None,
                "total_files": file_count,
                "file_count": file_count,
            },
            "auto_scan": job.get("metadata", {}).get("auto_scan", False),
        }
    
    async def _execute_restore_job(self, job: Dict[str, Any]):
        """Execute restore job on Linux - downloads chunks and reassembles files"""
        from uuid import UUID
        from pathlib import Path
        import aiohttp
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
                files = [f for f in files if any(f.get("path", "").endswith(fp) for fp in file_paths)]
            
            if not files:
                raise ValueError("No files match restore criteria")
            
            await self.report_job_status(job_id, "running", 20, 100, f"Found {len(files)} files to restore")
            
            target_path = Path(target)
            if target_path.is_file():
                target_dir = target_path.parent
                target_file = target_path.name
            else:
                target_dir = target_path
                target_file = None
            
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Restore each file
            for i, file_info in enumerate(files):
                upload_id = file_info.get("upload_id")
                filename = file_info.get("filename") or file_info.get("path", "").split("/")[-1]
                
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
            
            await self.report_job_status(job_id, "running", 100, 100, f"Restored {len(files)} files to {target}")
            logger.info(f"Restore completed: {len(files)} files restored to {target}")
        
        except Exception as e:
            logger.error(f"Restore job failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise

