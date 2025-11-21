"""
macOS-specific Agent Implementation
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

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
            logger.info(f"🔍 Starting scan job {job_id}")
            logger.info(f"   Job data: {list(job.keys())}")
            
            # Path can be in job metadata or in the job itself
            path = job.get("metadata", {}).get("path") or job.get("path")
            if not path:
                raise ValueError("No path specified for scan job")
            
            logger.info(f"   Scanning path: {path}")
            await self.report_job_status(job_id, "running", 10, 100, "Initializing scan...")
            
            # Use Spotlight for fast file discovery on macOS
            await self.report_job_status(job_id, "running", 20, 100, "Discovering files...")
            logger.info(f"   Discovering files in {path}...")
            if self._check_spotlight():
                files = await self._discover_files_spotlight(path)
            else:
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
                
                # Check for executable files on macOS (should not normally have .exe)
                if file_ext == '.exe' and os.name != 'nt':
                    anomalies.append({
                        'type': 'windows_executable_on_unix',
                        'severity': 'high',
                        'message': 'Windows executable (.exe) found on macOS system',
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
                        
                        # Check for Mach-O (macOS executable) header
                        elif header[:4] in {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'}:
                            if file_ext not in {'.app', '.dylib', '.bundle', '.framework', ''}:
                                anomalies.append({
                                    'type': 'header_mismatch',
                                    'severity': 'medium',
                                    'message': 'Mach-O executable header found',
                                    'file': str(file),
                                    'extension': file_ext
                                })
                        
                        # Check for ELF (Linux executable) header
                        elif header[:4] == b'\x7fELF':
                            if file_ext not in {'.so', '.bin', ''}:
                                anomalies.append({
                                    'type': 'header_mismatch',
                                    'severity': 'medium',
                                    'message': 'ELF executable header found on macOS',
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
                
                # High-risk indicators
                if file_ext == '.exe' and os.name != 'nt':
                    is_malware_suspicious = True
                    malware_reasons.append('Windows executable on macOS')
                    logger.debug(f"🔍 Windows exe on macOS triggered quarantine for: {file}")
                
                if file_ext in {'.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.ps1'}:
                    file_str = str(file)
                    if '/Downloads' in file_str or '/downloads' in file_str.lower():
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
                            if entropy > 7.5 and file_ext in {'.exe', '.dll', '.bin', '.scr', '.sys', '.dmg', '.app'}:
                                is_malware_suspicious = True
                                malware_reasons.append(f'High entropy ({entropy:.2f}) - possible packing/encryption')
                except Exception:
                    pass
                
                # If malware suspicious, download/quarantine it
                if is_malware_suspicious:
                    logger.warning(f"🔍 File flagged as malware suspicious: {file}")
                    logger.warning(f"   Reasons: {', '.join(malware_reasons)}")
                    try:
                        # Try multiple quarantine directory locations (in order of preference) - macOS paths
                        quarantine_dirs = [
                            Path.home() / 'fubar_quarantine',  # User's home directory (more space)
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
        """Get macOS-specific YARA rules search paths"""
        base_paths = super()._get_yara_rules_search_paths()
        
        # Add macOS-specific paths
        macos_paths = [
            # macOS paths
            Path.home() / 'fubar-agent' / 'rules-master',
            Path.home() / 'fubar' / 'rules-master',
            Path('/usr/local/fubar-agent/rules-master'),
            Path('/opt/fubar-agent/rules-master'),
            Path('/Applications/fubar-agent/rules-master'),
            Path('/usr/local/rules-master'),
            Path('/opt/rules-master'),
        ]
        
        return macos_paths + base_paths
    
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

