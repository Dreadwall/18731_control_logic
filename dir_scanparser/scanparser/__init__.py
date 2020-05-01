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
        logger.debug("Loading source plugins...")
        self.sources = {name: source(**kwargs) 
                        for name, source, kwargs in self.config.load_sources()}

        logger.debug("Completed loading source plugins.")

    def load_rulesets(self):
        logger.debug("Loading ruleset plugins...")
        self.rulesets = {name: ruleset(**kwargs) 
                        for name, ruleset, kwargs in self.config.load_rulesets()}

        logger.debug("Completed loading source plugins.")

    def run(self):
        #Run parsers
        for name in self.sources:
            targets = self.sources[name].parse()
            self.targets += targets

        for name in self.rulesets:
            self.rulesets[name].generate(self.targets)

def main():
    if len(sys.argv) != 2:
        logger.error("Failed to specify a configuration YAML file.")
        sys.exit(-1)
    parser = Parser(sys.argv[1])
    parser.run()

if __name__ == "__main__":
    main()
