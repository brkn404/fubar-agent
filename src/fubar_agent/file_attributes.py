"""
File Attribute Capture

Platform-specific file attribute capture and restoration utilities.
"""

import os
import stat
import platform
from pathlib import Path
from typing import Dict, Any, Optional


def capture_file_attributes(file_path: Path) -> Dict[str, Any]:
    """
    Capture all file attributes for the current platform.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing all captured file attributes
    """
    system = platform.system()
    
    if system == "Darwin":
        return capture_macos_attributes(file_path)
    elif system == "Windows":
        return capture_windows_attributes(file_path)
    else:
        # Linux/Unix
        return capture_unix_attributes(file_path)


def capture_unix_attributes(file_path: Path) -> Dict[str, Any]:
    """Capture Unix/Linux file attributes"""
    attrs = {}
    
    try:
        file_stat = file_path.stat()
        
        # Owner and group
        import pwd
        import grp
        
        try:
            owner_info = pwd.getpwuid(file_stat.st_uid)
            attrs["owner"] = owner_info.pw_name
            attrs["owner_uid"] = file_stat.st_uid
        except (KeyError, OSError):
            attrs["owner"] = f"uid:{file_stat.st_uid}"
            attrs["owner_uid"] = file_stat.st_uid
        
        try:
            group_info = grp.getgrgid(file_stat.st_gid)
            attrs["group"] = group_info.gr_name
            attrs["group_gid"] = file_stat.st_gid
        except (KeyError, OSError):
            attrs["group"] = f"gid:{file_stat.st_gid}"
            attrs["group_gid"] = file_stat.st_gid
        
        # Permissions
        mode = file_stat.st_mode
        attrs["permissions"] = oct(mode)[-3:]  # Octal string (e.g., "755")
        attrs["permissions_mode"] = mode  # Integer mode
        
        # Symbolic permissions
        attrs["permissions_symbolic"] = "".join([
            "r" if mode & 0o400 else "-",
            "w" if mode & 0o200 else "-",
            "x" if mode & 0o100 else "-",
            "r" if mode & 0o040 else "-",
            "w" if mode & 0o020 else "-",
            "x" if mode & 0o010 else "-",
            "r" if mode & 0o004 else "-",
            "w" if mode & 0o002 else "-",
            "x" if mode & 0o001 else "-",
        ])
        
        # File type
        if stat.S_ISDIR(mode):
            attrs["file_type"] = "directory"
        elif stat.S_ISREG(mode):
            attrs["file_type"] = "regular"
        elif stat.S_ISLNK(mode):
            attrs["file_type"] = "symlink"
        else:
            attrs["file_type"] = "other"
        
        # Timestamps
        attrs["atime"] = file_stat.st_atime
        attrs["mtime"] = file_stat.st_mtime
        attrs["ctime"] = file_stat.st_ctime
        
    except Exception as e:
        import logging
        logging.debug(f"Failed to capture Unix attributes for {file_path}: {e}")
    
    return attrs


def capture_macos_attributes(file_path: Path) -> Dict[str, Any]:
    """Capture macOS-specific file attributes including xattr"""
    attrs = capture_unix_attributes(file_path)
    
    try:
        # Extended attributes (xattr)
        try:
            import xattr
            xattr_dict = {}
            for attr_name in xattr.listxattr(file_path):
                try:
                    attr_value = xattr.getxattr(file_path, attr_name)
                    # Convert bytes to base64 string for JSON serialization
                    import base64
                    xattr_dict[attr_name] = base64.b64encode(attr_value).decode('utf-8')
                except Exception as e:
                    import logging
                    logging.debug(f"Failed to read xattr {attr_name} for {file_path}: {e}")
            
            if xattr_dict:
                attrs["xattr"] = xattr_dict
                attrs["extended_attributes"] = xattr_dict  # Alias
        except ImportError:
            # xattr module not available
            pass
        except Exception as e:
            import logging
            logging.debug(f"Failed to capture xattr for {file_path}: {e}")
        
        # macOS-specific metadata (Finder info, resource fork, etc.)
        try:
            import subprocess
            # Get Finder info using xattr
            finder_info = None
            try:
                import xattr
                finder_info_attr = xattr.getxattr(file_path, "com.apple.FinderInfo")
                if finder_info_attr:
                    import base64
                    attrs["finder_info"] = base64.b64encode(finder_info_attr).decode('utf-8')
            except (ImportError, OSError, KeyError):
                pass
            
            # Resource fork (if exists)
            resource_fork_path = file_path / "..namedfork" / "rsrc"
            if resource_fork_path.exists():
                attrs["has_resource_fork"] = True
                attrs["resource_fork_size"] = resource_fork_path.stat().st_size
            else:
                attrs["has_resource_fork"] = False
        except Exception as e:
            import logging
            logging.debug(f"Failed to capture macOS metadata for {file_path}: {e}")
        
    except Exception as e:
        import logging
        logging.debug(f"Failed to capture macOS attributes for {file_path}: {e}")
    
    return attrs


def capture_windows_attributes(file_path: Path) -> Dict[str, Any]:
    """Capture Windows-specific file attributes including ACLs and ADS"""
    attrs = {}
    
    try:
        file_stat = file_path.stat()
        
        # Basic permissions (Unix-style for compatibility)
        mode = file_stat.st_mode
        attrs["permissions"] = oct(mode)[-3:]
        attrs["permissions_mode"] = mode
        
        # Timestamps
        attrs["atime"] = file_stat.st_atime
        attrs["mtime"] = file_stat.st_mtime
        attrs["ctime"] = file_stat.st_ctime
        
        # Windows-specific attributes
        try:
            import win32api
            import win32con
            import win32security
            
            # File attributes (read-only, hidden, system, archive, etc.)
            file_attrs = win32api.GetFileAttributes(str(file_path))
            windows_attrs = {}
            
            if file_attrs & win32con.FILE_ATTRIBUTE_READONLY:
                windows_attrs["readonly"] = True
            if file_attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                windows_attrs["hidden"] = True
            if file_attrs & win32con.FILE_ATTRIBUTE_SYSTEM:
                windows_attrs["system"] = True
            if file_attrs & win32con.FILE_ATTRIBUTE_ARCHIVE:
                windows_attrs["archive"] = True
            if file_attrs & win32con.FILE_ATTRIBUTE_COMPRESSED:
                windows_attrs["compressed"] = True
            if file_attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED:
                windows_attrs["encrypted"] = True
            
            attrs["windows_attributes"] = windows_attrs
            attrs["windows_attributes_value"] = file_attrs
            
            # Owner and group (SID-based)
            try:
                sd = win32security.GetFileSecurity(
                    str(file_path),
                    win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION
                )
                
                # Owner
                owner_sid = sd.GetSecurityDescriptorOwner()
                try:
                    owner_name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                    attrs["owner"] = f"{domain}\\{owner_name}" if domain else owner_name
                except Exception:
                    attrs["owner"] = str(owner_sid)
                attrs["owner_sid"] = str(owner_sid)
                
                # Group
                group_sid = sd.GetSecurityDescriptorGroup()
                try:
                    group_name, domain, _ = win32security.LookupAccountSid(None, group_sid)
                    attrs["group"] = f"{domain}\\{group_name}" if domain else group_name
                except Exception:
                    attrs["group"] = str(group_sid)
                attrs["group_sid"] = str(group_sid)
            except Exception as e:
                import logging
                logging.debug(f"Failed to capture owner/group for {file_path}: {e}")
            
            # ACL (Access Control List)
            try:
                sd = win32security.GetFileSecurity(
                    str(file_path),
                    win32security.DACL_SECURITY_INFORMATION
                )
                dacl = sd.GetSecurityDescriptorDacl()
                
                if dacl:
                    # Convert ACL to SDDL string for storage
                    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        sd,
                        win32security.SDDL_REVISION_1,
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    attrs["acl"] = sddl
                    attrs["permissions_acl"] = sddl  # Alias
            except Exception as e:
                import logging
                logging.debug(f"Failed to capture ACL for {file_path}: {e}")
            
        except ImportError:
            # pywin32 not available
            import logging
            logging.debug("pywin32 not available, skipping Windows-specific attributes")
        except Exception as e:
            import logging
            logging.debug(f"Failed to capture Windows attributes for {file_path}: {e}")
        
        # Alternate Data Streams (ADS)
        try:
            import subprocess
            # Use PowerShell to list ADS
            ps_cmd = f'Get-Item "{file_path}" | Get-ItemProperty -Name * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Streams -ErrorAction SilentlyContinue'
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse ADS streams (simplified - full parsing would be more complex)
                ads_streams = {}
                # Note: Full ADS capture would require reading each stream
                # For now, we'll just note that ADS exist
                attrs["has_ads"] = True
                # TODO: Implement full ADS reading if needed
            else:
                attrs["has_ads"] = False
        except Exception as e:
            import logging
            logging.debug(f"Failed to capture ADS for {file_path}: {e}")
            attrs["has_ads"] = False
    
    except Exception as e:
        import logging
        logging.debug(f"Failed to capture Windows attributes for {file_path}: {e}")
    
    return attrs

