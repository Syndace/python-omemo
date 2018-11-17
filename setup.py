from setuptools import setup, find_packages

import os
import sys

version_file_path = os.path.join(
	os.path.dirname(os.path.abspath(__file__)),
	"omemo",
	"version.py"
)

version = {}

try:
	execfile(version_file_path, version)
except:
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
    author_email = "tim@cifg.io",
    license = "GPLv3",
    packages = find_packages(),
    install_requires = [
        "X3DH>=0.5.3,<0.6",
        "cryptography>=2"
    ],
    python_requires = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    zip_safe = False,
    classifiers = [
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7"
    ]
)
