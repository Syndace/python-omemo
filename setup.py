#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "OMEMO",
    version = "0.2",
    description = "An open python implementation of the OMEMO Multi-End Message and Object Encryption protocol.",
    author = "Tim Henkes",
    url = "https://github.com/Syndace/python-omemo",
    packages = ["omemo", "omemo.signal", "omemo.signal.doubleratchet", "omemo.signal.exceptions", "omemo.signal.wireformat", "omemo.signal.x3dh"],
    requires = ["x3dh", "doubleratchet", "scci"],
    provides = ["omemo"]
)
