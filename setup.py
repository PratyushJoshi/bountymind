"""
setup.py
--------
Installs the 'bountymind' CLI command system-wide.

After `pip install -e .` (or via install.sh), you can run:
    bountymind -d example.com
    bountymind -l targets.txt
    bountymind --check-env
    bountymind --update-tools
"""

from setuptools import find_packages, setup

setup(
    name="bountymind",
    version="2.0.0",
    description=(
        "BountyMind — Modular automated reconnaissance, vulnerability assessment, "
        "WAF detection & evasion, JS secret mining, and cloud recon framework"
    ),
    long_description=open("README.md", encoding="utf-8").read()
    if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="PratyushJoshi",
    url="https://github.com/PratyushJoshi/bountymind",
    project_urls={
        "Source": "https://github.com/PratyushJoshi/bountymind",
        "Issues": "https://github.com/PratyushJoshi/bountymind/issues",
    },
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests*", "tools*"]),
    install_requires=[
        "PyYAML>=6.0.1",
        "rich>=13.7.1",
        "Markdown>=3.5.2",
        "requests>=2.31.0",
        "typing-extensions>=4.9.0",
    ],
    extras_require={
        "full": [
            # Optional Python-based security tools
            "wafw00f>=2.2.0",
            "arjun>=2.2.1",
            "cloud_enum>=0.5",
        ],
        "dev": [
            "pytest>=7.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        # Primary CLI entrypoint — installed as 'bountymind' command
        "console_scripts": [
            "bountymind=main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
)
