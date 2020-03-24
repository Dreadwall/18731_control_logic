#!/usr/bin/env python

from scanparser.rulesets import Ruleset

class Plugin(Ruleset):
    def __init__(self):
        pass

    def generate(self, targets, filename):
        rules = []
        for target in targets:
            try:
                rule = self.create_iptables_rule(target)
            except:
                continue
            rules.append(rule)

        self.write_iptables_rule(filename, rules)

    def create_iptables_rule(self, target):
        rule = 'iptables -t filter -A INPUT'
        if target.src_ip is not None:
            rule += ' -s ' + str(target.src_ip)

        if target.dst_ip is not None:
            rule += ' -d ' + str(target.dst_ip)
            
        if target.proto is not None:
            rule += ' -p ' + str(target.proto)
        
        if target.src_port is not None:
            rule += ' --sport ' + str(target.src_port)
            
        if target.dst_port is not None:
            rule += ' --dport ' + str(target.dst_port)
        
        rule += ' -j DROP'
        return rule

    def write_iptables_rule(self, filename, rules):
        with open(filename, 'w') as fp:
            for rule in rules:
                fp.write(rule)
