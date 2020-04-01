#!/usr/bin/env python

import yaml
import importlib
from loguru import logger

SOURCE = 'scanparser.sources'
RULESET = 'scanparser.rulesets'

class Config:
    def __init__(self, configfile):
        logger.debug("Loading configuration file...")
        with open(configfile, 'r') as fp:
            try:
                self.config = yaml.safe_load(fp.read())
            except yaml.error.YAMLError:
                logger.error("Unable to load configuration file.")

    def load_sources(self):
        logger.debug("Loading source plugins...")
        modules = []
        for source in self.config['sources']:
            try:
                logger.debug(f"Loading module {source['name']}")
                module = importlib.import_module('.'.join([SOURCE, source['name']])).Plugin()
                modules.append(module)
            except ImportError:
                logger.error(f"Failed to load module {source['name']}")
                continue
        return modules

    def load_rulesets(self):
        logger.debug("Loading ruleset plugins...")
        modules = []
        for ruleset in self.config['rulesets']:
            try:
                logger.debug(f"Loading module {ruleset['name']}")
                module = importlib.import_module('.'.join([RULESET, ruleset['name']])).Plugin()
                modules.append(module)
            except ImportError:
                logger.error(f"Failed to load module {ruleset['name']}")
                continue
        return modules
