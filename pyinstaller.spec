# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for fubar-agent

import os
from pathlib import Path

block_cipher = None

# Get project root
project_root = Path(SPECPATH).parent
src_dir = project_root / "src"
rules_dir = project_root / "rules-master"

a = Analysis(
    [str(src_dir / "fubar_agent" / "cli.py")],
    pathex=[str(src_dir)],
    binaries=[],
    datas=[
        (str(rules_dir), "rules-master"),
    ] if rules_dir.exists() else [],
    hiddenimports=[
        'fubar_agent',
        'fubar_agent.base',
        'fubar_agent.linux',
        'fubar_agent.macos',
        'fubar_agent.windows',
        'fubar_agent.platform',
        'fubar_agent.streaming',
        'fubar_agent.file_attributes',
        'fubar_agent.format_analyzers',
        'fubar_agent.bandwidth',
        'fubar_agent.discovery',
        'fubar_agent.cli',
        'fubar_agent.version',
        'click',
        'aiohttp',
        'yaml',
        'asyncio',
        'aiofiles',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='fubar-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

