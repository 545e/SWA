#!/usr/bin/env python3
"""
SWA AI — Autonomous Application Security & Penetration Testing Engine
Package configuration and installation setup.
"""

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="swa-ai",
    version="2.1.0",
    author="545e",
    description="Autonomous Multi-Agent Cybersecurity & Penetration Testing Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/545e/SWA",
    packages=find_packages(),
    py_modules=["swa_cli", "run"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn>=0.28.0",
        "httpx>=0.27.0",
        "pydantic>=2.6.0",
        "beautifulsoup4>=4.12.0",
        "websockets>=12.0",
        "jinja2>=3.1.0",
        "dnspython>=2.6.0",
        "cryptography>=42.0.0",
        "tldextract>=5.1.0",
        "pyyaml>=6.0",
        "python-multipart>=0.0.9",
        "setuptools>=69.0.0",
    ],
    entry_points={
        "console_scripts": [
            "swa=swa_cli:main",
            "swa-cli=swa_cli:main",
        ],
    },
    include_package_data=True,
)
