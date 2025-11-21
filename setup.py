from setuptools import setup, find_packages

setup(
    name="fubar-agent",
    version="0.1.0",
    description="Fubar Unified Pipeline Agent",
    author="Fubar Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "click>=8.0.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "fubar-agent=fubar_agent.cli:main",
        ],
    },
)
