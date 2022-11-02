# pylint: disable=exec-used
import os
from typing import Dict, Union, List

from setuptools import setup, find_packages  # type: ignore[import]

source_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omemo")

version_scope: Dict[str, Dict[str, str]] = {}
with open(os.path.join(source_root, "version.py"), encoding="utf-8") as f:
    exec(f.read(), version_scope)
version = version_scope["__version__"]

project_scope: Dict[str, Dict[str, Union[str, List[str]]]] = {}
with open(os.path.join(source_root, "project.py"), encoding="utf-8") as f:
    exec(f.read(), project_scope)
project = project_scope["project"]

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

classifiers = [
    "Intended Audience :: Developers",

    "License :: OSI Approved :: MIT License",

    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3 :: Only",

    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",

    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy"
]

classifiers.extend(project["categories"])

if version["tag"] == "alpha":
    classifiers.append("Development Status :: 3 - Alpha")

if version["tag"] == "beta":
    classifiers.append("Development Status :: 4 - Beta")

if version["tag"] == "stable":
    classifiers.append("Development Status :: 5 - Production/Stable")

del project["categories"]
del project["year"]

setup(
    version=version["short"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "XEdDSA>=1.0.0,<2",
        "typing-extensions>=4.3.0"
    ],
    python_requires=">=3.7",
    include_package_data=True,
    zip_safe=False,
    classifiers=classifiers,
    **project
)
