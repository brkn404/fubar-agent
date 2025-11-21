from setuptools import setup, find_packages
from pathlib import Path

# Read version from version.py
version_file = Path(__file__).parent / "src" / "fubar_agent" / "version.py"
version = {}
exec(version_file.read_text(), version)
__version__ = version.get("__version__", "0.1.0")

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="fubar-agent",
    version=__version__,
    description="Fubar Unified Pipeline Agent - Standalone agent for backup, restore, and scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Fubar Team",
    url="https://github.com/brkn404/fubar-agent",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "click>=8.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "macos": [
            "xattr>=0.9.0",  # For macOS extended attributes
        ],
        "windows": [
            "pywin32>=300; sys_platform == 'win32'",  # For Windows-specific features
        ],
        "all": [
            "xattr>=0.9.0",
            "pywin32>=300; sys_platform == 'win32'",
        ],
    },
    entry_points={
        "console_scripts": [
            "fubar-agent=fubar_agent.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "fubar_agent": [
            # Include YARA rules if packaged
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
