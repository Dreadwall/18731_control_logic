#!/usr/bin/env python

from scanparser.sources import Source
from loguru import logger
from scanparser.target import Target

class Plugin(Source):
    def __init__(self, name, inputfile):
        self.name = name
        self.scan_engine = 'test_source'
        self.filename = inputfile

    def parse(self):
        targets = []
        logger.debug(f"Running {self.name} source.")
        filename = self.filename
        with open(filename, "r") as fp:
            for line in fp:
                values = line.split()
                logger.debug(values)
                if len(values) != 3:
                    continue
                target = Target()
                target.set_dst_ip(values[0])
                target.set_dst_port(values[1])
                target.set_cve(values[2])
                targets.append(target)
        logger.debug(f"Source {self.name} generated {len(targets)} targets.")
        return targets
