#!/usr/bin/env python

import collections
import xmltodict
import json
from loguru import logger
from scanparser.sources import Source
from scanparser.target import Target

class Plugin(Source):
    def __init__(self, name, inputfile):
        self.name = name
        self.scan_engine = 'nmap'
        self.filename = inputfile

    def parse(self):
        targets = []

        logger.debug("Parsing Nmap script-vuln output.")
        with open(self.filename) as fp:
            try:
                scan = xmltodict.parse(fp.read())['nmaprun']
                ipaddr = scan['host']['address']['@addr']
                ports = scan['host']['ports']['port']
                if isinstance(ports, collections.Mapping):
                    portnum = ports['@portid']
                    service = ports['service']['@name']
                    scripts = ports['script']
                    if isinstance(scripts, collections.Mapping):
                        target = self.handle_script(scripts, ipaddr, portnum, service)
                        if target is not None:
                            targets.append(target)
     
                    if type(scripts) == list:
                        for script in scripts:
                            target = self.handle_script(script, ipaddr, portnum, service)
                            if target is not None:
                                targets.append(target)
    
                if type(ports) == list:
                    for port in ports:
                        portnum = port['@portid']
                        service = port['service']['@name']
                        scripts = port['script']
                        if isinstance(scripts, collections.Mapping):
                            target = self.handle_script(scripts, ipaddr, portnum, service)
                            if target is not None:
                                targets.append(target)
        
                        if type(scripts) == list:
                            for script in scripts:
                                target = self.handle_script(script, ipaddr, portnum, service)
                                if target is not None:
                                    targets.append(target)
            except:
                return []

        return targets

    def handle_script(self, script, ipaddr, portnum, service):
        if script['@id'] == 'http-slowloris-check':
            logger.debug(f"Found Slow Loris entry")
            if 'VULNERABLE' in script['@output']:
                cve = script['table']['@key']
                logger.debug(f"Found Slow Loris vuln: {cve}")
                target = Target()
                target.set_dst_ip(ipaddr)
                target.set_dst_port(portnum)
                target.set_proto(service)
                target.set_cve(cve)
                logger.debug(f"Target found | Dst IP: {ipaddr} | Dst port: {portnum} | Protocol: {service}")
                return target
        return None
