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
        modules = []
        for source in self.config['sources']:
            kwargs = {}
            #Load kwarg values from configuration settings
            for key, value in source.items():
                if key == 'inputfile':
                    kwargs[key] = self.project_directory() + "/" + value

                else:
                    kwargs[key] = value

            try:
                logger.debug(f"Loading module {source['name']}")
                module = importlib.import_module('.'.join([SOURCE, source['name']]))
                modules.append((source['name'], module.Plugin, kwargs))

            except ImportError:
                logger.error(f"Failed to load module {source['name']}")
                continue

        logger.debug(f"Successfully loaded {len(modules)} sources.")
        return modules

    def load_rulesets(self):
        modules = []
        for ruleset in self.config['rulesets']:
            kwargs = {}
            #Load kwarg values from configuration settings
            for key, value in ruleset.items():
                if key == 'outputfile':
                    kwargs[key] = self.project_directory() + "/" + value

                else:
                    kwargs[key] = value

            try:
                logger.debug(f"Loading module {ruleset['name']}")
                module = importlib.import_module('.'.join([RULESET, ruleset['name']]))
                modules.append((ruleset['name'], module.Plugin, kwargs))

            except ImportError:
                logger.error(f"Failed to load module {ruleset['name']}")
                continue

        logger.debug(f"Successfully loaded {len(modules)} rulesets.")
        return modules

    def project_directory(self):
        return self.config['general']['proj_dir']
