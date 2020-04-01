#!/usr/bin/env python

import sys
from loguru import logger
import yaml

from scanparser.config import Config

class Parser:
    def __init__(self, configfile):
        self.config = Config(configfile)
        self.load_sources()
        self.load_rulesets()
        self.targets = []

    def load_sources(self):
        self.sources = self.config.load_sources()

    def load_rulesets(self):
        self.rulesets = self.config.load_rulesets()

    def run(self):
        #Run parsers
        for source in self.sources:
            targets = source.parse()
            self.targets += targets

        for ruleset in self.rulesets:
            ruleset.generate(self.targets, 'output.txt')

def main():
    if len(sys.argv) != 2:
        logger.error("Failed to specify a configuration YAML file.")
        sys.exit(-1)
    parser = Parser(sys.argv[1])
    parser.run()

if __name__ == "__main__":
    main()
