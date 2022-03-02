from setuptools import setup, find_packages

import os
import sys

version_file_path = os.path.join(
	os.path.dirname(os.path.abspath(__file__)),
	"omemo",
	"version.py"
)

version = {}

with open(version_file_path) as fp:
	exec(fp.read(), version)

with open("README.md") as f:
    long_description = f.read()

setup(
    name = "OMEMO",
    version = version["__version__"],
    description = (
        "A Python implementation of the OMEMO Multi-End Message and Object Encryption " +
        "protocol."
    ),
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/Syndace/python-omemo",
    author = "Tim Henkes",
    author_email = "me@syndace.dev",
    license = "MIT",
    packages = find_packages(),
    install_requires = [
        "X3DH>=0.5.9,<0.6",
        "cryptography>=2"
    ],
    python_requires = ">=3.4, <4",
    zip_safe = False,
    classifiers = [
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",

        "License :: OSI Approved :: MIT License",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9"
    ]
)
