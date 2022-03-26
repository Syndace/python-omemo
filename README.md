[![PyPI](https://img.shields.io/pypi/v/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![Build Status](https://travis-ci.org/Syndace/python-omemo.svg?branch=master)](https://travis-ci.org/Syndace/python-omemo)
[![Documentation Status](https://readthedocs.org/projects/python-omemo/badge/?version=latest)](https://python-omemo.readthedocs.io/en/latest/?badge=latest)

# python-omemo #

A Python implementation of the [OMEMO Multi-End Message and Object Encryption protocol](https://xmpp.org/extensions/xep-0384.html).

This library combines [python-x3dh](https://github.com/Syndace/python-x3dh) and [python-doubleratchet](https://github.com/Syndace/python-doubleratchet) with XMPP-specific functionality to offer a complete implementation of [XEP-0384](https://xmpp.org/extensions/xep-0384.html). python-omemo supports different versions of the specification through so-called backends. One backend for OMEMO in the `urn:xmpp:omemo:1` namespace is shipped with python-omemo. A backend for (legacy) OMEMO in the `eu.siacs.conversations.axolotl` namespace is available as a separate package: [python-omemo-backend-legacy](https://github.com/Syndace/python-omemo-backend-legacy). Multiple backends can be loaded and used at the same time, the library manages their coexistence transparently.

## Installation ##

python-omemo depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa) and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install OMEMO`) or manually from source by running `pip install .` (recommended) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of python-omemo) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows for the amd64 architecture. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Testing, Type Checks and Linting ##

python-omemo uses [pytest](https://docs.pytest.org/en/latest/) as its testing framework, [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All tests/checks can be run locally with the following commands:

```sh
$ pip install pytest pytest-asyncio mypy pylint flake8
$ mypy --strict omemo/ setup.py
$ pylint omemo/ setup.py
$ flake8 omemo/ setup.py
$ pytest
```

## Getting Started ##

Refer to the documentation on [readthedocs.io](https://python-omemo.readthedocs.io/en/latest/), or build/view it locally in the `docs/` directory.

The `functionality.md` file contains an overview of supported functionality/use cases, mostly targeted at developers.
