from setuptools import setup, find_packages

with open("README.md") as f:
    long_description = f.read()

setup(
    name = "OMEMO",
    version = "0.6.0",
    description = "A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/Syndace/python-omemo",
    author = "Tim Henkes",
    author_email = "tim@cifg.io",
    license = "GPLv3",
    packages = find_packages(),
    install_requires = [
        "X3DH>=0.4.0",
        "DoubleRatchet>=0.3.0",
        "hkdf==0.0.3",
        "pynacl>=1.0.1",
        "cryptography>=1.7.1",
        "protobuf>=2.6.1"
    ],
    python_requires = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    zip_safe = True,
    classifiers = [
        "Development Status :: 3 - Alpha",

        "Intended Audience :: Developers",

        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Operating System :: OS Independent",

        "Programming Language :: Python :: Implementation :: CPython",

        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7"
    ]
)
