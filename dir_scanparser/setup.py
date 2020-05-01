#!/usr/bin/env python

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "scanparser",
    version = "1.0.4",
    author = "Magicannon",
    description = ("Takes scan results and outputs IDS rules"),
    packages = find_packages()
)
