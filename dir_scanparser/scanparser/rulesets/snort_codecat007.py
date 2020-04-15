#!/usr/bin/env python

from scanparser.rulesets import Ruleset
from loguru import logger
import glob

class Plugin(Ruleset):
    def __init__(self, **kwargs):
        self.name = kwargs['name']
        self.outputfile = kwargs['outputfile']
        self.root_dir = kwargs['rootdirectory']
        self.files = []

    def generate(self, targets):
        rules = []
        #Generate list of rule files
        self.files = glob.glob(self.root_dir + '/**/*.rules', recursive=True)

        for target in targets:
            if target.cve is not None:
                logger.debug(f"Processing {target.cve} Snort rule...")
                rule = self.search_snort_rule(target.cve)
                if rule is not None:
                    rules.append(rule)
            else:
                continue

        #write rules into output file
        logger.debug(f"Writing {self.name} output to {self.outputfile}...({len(rules)} rules)")
        self.write_snort_rules(self.outputfile, rules)

    def search_snort_rule(self, cve_id):
        for filename in self.files:
            if filename.endswith(".rules"):
                logger.debug(f"Processing file {filename}.")
                rule = self.get_snort_rule(cve_id, filename)
                if rule is not None:
                    return rule
        return None

    def get_snort_rule(self, cve_id, filename):
        try:
            with open(filename, "r") as fp:
                for line in fp:
                    if (not line.lstrip().startswith('#') and (cve_id in line)):
                        return line
                    else:
                        continue
            return None
        except:
            return None

    def write_snort_rules(self, filename, rules):
        with open(filename, 'w') as fp:
            for rule in rules:
                fp.write(rule)
