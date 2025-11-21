"""
Format-Specific Analyzers for File Integrity Checking

Implements structural validation for various file formats as described in scanner.md.
Each analyzer validates the internal structure of files to detect corruption,
encryption, and hidden problems.
"""

import logging
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import struct

logger = logging.getLogger(__name__)


class FormatAnalyzer:
    """Base class for format-specific analyzers"""
    
    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze a file and return structure validation results.
        
        Returns:
            {
                'structure_valid': bool,
                'structure_errors': List[str],
                'format_specific_metrics': Dict[str, Any]
            }
        """
        raise NotImplementedError


class DOCXAnalyzer(FormatAnalyzer):
    """Analyzer for DOCX files (Office Open XML)"""
    
    REQUIRED_ENTRIES = [
        '[Content_Types].xml',
        '_rels/.rels',
        'word/document.xml'
    ]
    
    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """Validate DOCX structure"""
        errors = []
        metrics = {
            'zip_valid': False,
            'required_xml_present': False,
            'xml_parse_errors': 0,
            'zip_entry_count': 0,
            'zip_entry_entropy_stats': {},
            'encrypted_entries': []
        }
        
        try:
            # Check magic number (ZIP header: 50 4B 03 04)
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'PK\x03\x04':
                    errors.append(f"Invalid DOCX magic number: expected ZIP header, got {magic.hex()}")
                    return {
                        'structure_valid': False,
                        'structure_errors': errors,
                        'format_specific_metrics': metrics
                    }
            
            # Open as ZIP
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    metrics['zip_valid'] = True
                    metrics['zip_entry_count'] = len(zip_file.namelist())
                    
                    # Check for required entries
                    missing_entries = []
                    for required in self.REQUIRED_ENTRIES:
                        if required not in zip_file.namelist():
                            missing_entries.append(required)
                    
                    if missing_entries:
                        errors.append(f"Missing required DOCX entries: {', '.join(missing_entries)}")
                        metrics['required_xml_present'] = False
                    else:
                        metrics['required_xml_present'] = True
                    
                    # Validate XML structure
                    xml_errors = 0
                    high_entropy_entries = []
                    
                    for entry_name in zip_file.namelist():
                        if entry_name.endswith('.xml'):
                            try:
                                xml_data = zip_file.read(entry_name)
                                
                                # Try to parse XML
                                try:
                                    ET.fromstring(xml_data)
                                except ET.ParseError as e:
                                    xml_errors += 1
                                    errors.append(f"XML parse error in {entry_name}: {str(e)}")
                                
                                # Check entropy of XML entries (encrypted files have high entropy)
                                if len(xml_data) > 0:
                                    entropy = self._calculate_entropy(xml_data)
                                    if entropy > 7.5:
                                        high_entropy_entries.append({
                                            'entry': entry_name,
                                            'entropy': entropy,
                                            'size': len(xml_data)
                                        })
                                        
                            except Exception as e:
                                xml_errors += 1
                                errors.append(f"Error reading ZIP entry {entry_name}: {str(e)}")
                    
                    metrics['xml_parse_errors'] = xml_errors
                    metrics['encrypted_entries'] = high_entropy_entries
                    
                    # Check for encryption indicators
                    if high_entropy_entries:
                        errors.append(f"High entropy detected in {len(high_entropy_entries)} XML entries (possible encryption)")
                    
            except zipfile.BadZipFile as e:
                errors.append(f"Invalid ZIP structure: {str(e)}")
                metrics['zip_valid'] = False
            except Exception as e:
                errors.append(f"Error analyzing DOCX: {str(e)}")
                metrics['zip_valid'] = False
        
        except Exception as e:
            errors.append(f"Failed to analyze DOCX file: {str(e)}")
        
        structure_valid = len(errors) == 0 and metrics.get('zip_valid', False) and metrics.get('required_xml_present', False)
        
        return {
            'structure_valid': structure_valid,
            'structure_errors': errors,
            'format_specific_metrics': metrics
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
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


class PDFAnalyzer(FormatAnalyzer):
    """Analyzer for PDF files"""
    
    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """Validate PDF structure"""
        errors = []
        metrics = {
            'pdf_version': None,
            'xref_valid': False,
            'trailer_found': False,
            'object_count': 0,
            'xref_table_count': 0,
            'corrupted_objects': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Check PDF header (%PDF-1.x)
                header = f.read(8)
                if not header.startswith(b'%PDF-'):
                    errors.append(f"Invalid PDF header: {header[:20]}")
                    return {
                        'structure_valid': False,
                        'structure_errors': errors,
                        'format_specific_metrics': metrics
                    }
                
                # Extract PDF version
                try:
                    version_str = header[5:8].decode('ascii')
                    metrics['pdf_version'] = version_str
                except:
                    pass
                
                # Read file to find xref and trailer
                f.seek(0)
                content = f.read()
                
                # Look for xref table
                xref_positions = []
                xref_keyword = b'xref'
                pos = 0
                while True:
                    pos = content.find(xref_keyword, pos)
                    if pos == -1:
                        break
                    xref_positions.append(pos)
                    pos += len(xref_keyword)
                
                if xref_positions:
                    metrics['xref_table_count'] = len(xref_positions)
                    metrics['xref_valid'] = True
                else:
                    errors.append("No xref table found")
                
                # Look for trailer
                trailer_keywords = [b'trailer', b'<<', b'/Size']
                trailer_found = False
                for keyword in trailer_keywords:
                    if keyword in content:
                        trailer_found = True
                        break
                
                if trailer_found:
                    metrics['trailer_found'] = True
                else:
                    errors.append("No trailer found")
                
                # Count objects (rough estimate: count "obj" keywords)
                obj_count = content.count(b' obj')
                metrics['object_count'] = obj_count
                
                # Basic sanity checks
                if obj_count == 0:
                    errors.append("No PDF objects found")
                elif obj_count > 100000:
                    errors.append(f"Suspiciously high object count: {obj_count}")
                
                # Check for end-of-file marker
                if not content.rstrip().endswith(b'%%EOF'):
                    errors.append("Missing %%EOF marker")
        
        except Exception as e:
            errors.append(f"Error analyzing PDF: {str(e)}")
        
        structure_valid = (
            len(errors) == 0 and
            metrics.get('xref_valid', False) and
            metrics.get('trailer_found', False) and
            metrics.get('object_count', 0) > 0
        )
        
        return {
            'structure_valid': structure_valid,
            'structure_errors': errors,
            'format_specific_metrics': metrics
        }


class SQLiteAnalyzer(FormatAnalyzer):
    """Analyzer for SQLite database files"""
    
    SQLITE_HEADER = b'SQLite format 3\x00'
    
    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """Validate SQLite structure"""
        errors = []
        metrics = {
            'page_count': 0,
            'page_size': 0,
            'bad_pages': 0,
            'btree_invariants_ok': True,
            'checksum_mismatch_count': 0,
            'file_size_matches': False
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Check SQLite header
                header = f.read(16)
                if not header.startswith(self.SQLITE_HEADER):
                    errors.append(f"Invalid SQLite header: expected 'SQLite format 3\\x00'")
                    return {
                        'structure_valid': False,
                        'structure_errors': errors,
                        'format_specific_metrics': metrics
                    }
                
                # Read page size (bytes 16-17, big-endian)
                f.seek(16)
                page_size_bytes = f.read(2)
                if len(page_size_bytes) == 2:
                    page_size = struct.unpack('>H', page_size_bytes)[0]
                    if page_size == 1:
                        # Page size 1 means 65536 bytes
                        page_size = 65536
                    metrics['page_size'] = page_size
                else:
                    errors.append("Could not read page size")
                    return {
                        'structure_valid': False,
                        'structure_errors': errors,
                        'format_specific_metrics': metrics
                    }
                
                # Get file size
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                
                # Calculate expected page count
                if page_size > 0:
                    expected_pages = file_size // page_size
                    metrics['page_count'] = expected_pages
                    
                    # Check if file size matches page boundaries
                    if file_size % page_size == 0:
                        metrics['file_size_matches'] = True
                    else:
                        errors.append(f"File size ({file_size}) not aligned to page size ({page_size})")
                
                # Sample pages for validation
                bad_pages = 0
                checksum_errors = 0
                
                # Check first few pages
                f.seek(0)
                for page_num in range(min(10, expected_pages)):
                    page_data = f.read(page_size)
                    if len(page_data) < page_size:
                        break
                    
                    # Check page type (first byte)
                    page_type = page_data[0]
                    
                    # Valid page types: 0x0D (leaf table), 0x05 (interior table),
                    # 0x0A (leaf index), 0x02 (interior index), 0x01 (freelist)
                    valid_types = [0x0D, 0x05, 0x0A, 0x02, 0x01, 0x00]
                    if page_type not in valid_types and page_num > 0:  # Page 0 is header
                        bad_pages += 1
                        errors.append(f"Invalid page type {hex(page_type)} on page {page_num}")
                
                metrics['bad_pages'] = bad_pages
                metrics['checksum_mismatch_count'] = checksum_errors
        
        except Exception as e:
            errors.append(f"Error analyzing SQLite: {str(e)}")
        
        structure_valid = (
            len(errors) == 0 and
            metrics.get('page_size', 0) > 0 and
            metrics.get('file_size_matches', False) and
            metrics.get('bad_pages', 1) == 0
        )
        
        return {
            'structure_valid': structure_valid,
            'structure_errors': errors,
            'format_specific_metrics': metrics
        }


class ImageAnalyzer(FormatAnalyzer):
    """Analyzer for image files (JPEG, PNG)"""
    
    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """Validate image structure"""
        errors = []
        metrics = {
            'image_type': None,
            'width': None,
            'height': None,
            'valid_structure': False
        }
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                # JPEG: FF D8 FF
                if header[:3] == b'\xff\xd8\xff':
                    metrics['image_type'] = 'jpeg'
                    # Check for JPEG end marker (FF D9)
                    f.seek(0, 2)  # Seek to end
                    file_size = f.tell()
                    f.seek(max(0, file_size - 2))
                    end_marker = f.read(2)
                    if end_marker == b'\xff\xd9':
                        metrics['valid_structure'] = True
                    else:
                        errors.append("JPEG missing end marker (FF D9)")
                
                # PNG: 89 50 4E 47 0D 0A 1A 0A
                elif header[:8] == b'\x89PNG\r\n\x1a\n':
                    metrics['image_type'] = 'png'
                    # Check for PNG chunks (IHDR, IEND)
                    f.seek(0)
                    content = f.read()
                    
                    if b'IHDR' in content and b'IEND' in content:
                        metrics['valid_structure'] = True
                        
                        # Try to read dimensions from IHDR chunk
                        try:
                            ihdr_pos = content.find(b'IHDR')
                            if ihdr_pos != -1 and ihdr_pos + 8 < len(content):
                                # Width and height are 4 bytes each after 'IHDR'
                                width = struct.unpack('>I', content[ihdr_pos + 4:ihdr_pos + 8])[0]
                                height = struct.unpack('>I', content[ihdr_pos + 8:ihdr_pos + 12])[0]
                                metrics['width'] = width
                                metrics['height'] = height
                        except:
                            pass
                    else:
                        errors.append("PNG missing required chunks (IHDR or IEND)")
                
                else:
                    errors.append(f"Unknown image format: {header[:8].hex()}")
        
        except Exception as e:
            errors.append(f"Error analyzing image: {str(e)}")
        
        structure_valid = len(errors) == 0 and metrics.get('valid_structure', False)
        
        return {
            'structure_valid': structure_valid,
            'structure_errors': errors,
            'format_specific_metrics': metrics
        }


def get_analyzer_for_file(file_path: Path) -> Optional[FormatAnalyzer]:
    """Get appropriate analyzer for a file based on extension and content"""
    ext = file_path.suffix.lower()
    
    # Check magic number first
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(16)
    except:
        return None
    
    # DOCX (ZIP-based Office formats)
    if magic[:4] == b'PK\x03\x04':
        if ext in ['.docx', '.xlsx', '.pptx']:
            return DOCXAnalyzer()
        elif ext == '.docx':
            return DOCXAnalyzer()
    
    # PDF
    if magic[:4] == b'%PDF' or ext == '.pdf':
        return PDFAnalyzer()
    
    # SQLite
    if magic[:16] == SQLiteAnalyzer.SQLITE_HEADER or ext in ['.db', '.sqlite', '.sqlite3']:
        return SQLiteAnalyzer()
    
    # Images
    if magic[:3] == b'\xff\xd8\xff' or ext in ['.jpg', '.jpeg']:
        return ImageAnalyzer()
    if magic[:8] == b'\x89PNG\r\n\x1a\n' or ext == '.png':
        return ImageAnalyzer()
    
    return None

