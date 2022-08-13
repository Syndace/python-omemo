[![PyPI](https://img.shields.io/pypi/v/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![Build Status](https://travis-ci.org/Syndace/python-omemo.svg?branch=stable)](https://travis-ci.org/Syndace/python-omemo)
TODO: Add doc badge

# python-omemo #

A Python implementation of the [OMEMO Multi-End Message and Object Encryption protocol](https://xmpp.org/extensions/xep-0384.html).

A complete implementation of [XEP-0384](https://xmpp.org/extensions/xep-0384.html) on protocol-level, i.e. more than just the cryptography. python-omemo supports different versions of the specification through so-called backends. A backend for OMEMO in the `urn:xmpp:omemo:2` namespace (the most recent version of the specification) is available in the [python-twomemo](https://github.com/Syndace/python-twomemo) Python package. A backend for (legacy) OMEMO in the `eu.siacs.conversations.axolotl` namespace is available in the [python-oldmemo](https://github.com/Syndace/python-oldmemo) package. Multiple backends can be loaded and used at the same time, the library manages their coexistence transparently.

## Installation ##

python-omemo depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa)>=2,<3 and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install OMEMO`) or manually from source by running `pip install .` (recommended) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of python-omemo) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows for the amd64 architecture, and potentially for MacOS arm64 too. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Testing, Type Checks and Linting ##

python-omemo uses [pytest](https://docs.pytest.org/en/latest/) as its testing framework, [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All tests/checks can be run locally with the following commands:

```sh
$ pip install --upgrade pytest pytest-asyncio mypy pylint flake8
$ mypy --strict --disable-error-code str-bytes-safe omemo/ setup.py tests/
$ pylint omemo/ setup.py tests/
$ flake8 omemo/ setup.py tests/
$ pytest
```

## Getting Started ##

Refer to the documentation on [readthedocs.io](https://python-omemo.readthedocs.io/en/latest/), or build/view it locally in the `docs/` directory. To build the docs locally, install the requirements listed in `docs/requirements.txt`, e.g. using `pip install -r docs/requirements.txt`, and then run `make html` from within the `docs/` directory. The documentation can then be found in `docs/_build/html/`.

The `functionality.md` file contains an overview of supported functionality/use cases, mostly targeted at developers.
