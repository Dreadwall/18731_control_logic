#!/usr/bin/env python

from scanparser.target import Target

class Source:
    def __init__(self, **kwargs):
        self.name = None
        self.scan_engine = None

    def parse(self):
        pass
