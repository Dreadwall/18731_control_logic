#!/usr/bin/env python

import xml.etree.ElementTree as ET
from scanparser.sources import Source
from loguru import logger
from scanparser.target import Target

class Plugin(Source):
    def __init__(self, name, inputfile):
        self.name = name
        self.scan_engine = 'nmap'
        self.filename = inputfile

    def parse(self):
        logger.debug("Parsing Nmap script-vuln output.")
        filename = self.filename
        tree = ET.parse(filename)
        root = tree.getroot()
        hosts = tree.findall('host')

        targets = []

        for host in hosts:
            ipaddr_t = host.find('address')
            try:
                destip = ipaddr_t.get('addr')
            except:
                continue
    
            try:
                ports = host.find('ports').findall('port')
            except:
                continue
    
            #Parse each port
            for port in ports:
                portnum = port.get('portid')
                proto = port.get('protocol')
                service = port.find('service').get('name')
                logger.debug(portnum + '|' + proto + '|' + service)
    
                #Parse results of each script run on port
                scripts = port.findall('script')
                for script in scripts:
                    logger.debug('\t' + script.get('id'))
                    if script.get('id') == 'vulners':
                        if self.handle_vulners(script) != True:
                            target = Target()
                            target.set_dst_ip(destip)
                            target.set_dst_port(portnum)
                            target.set_proto(proto)
                            targets.append(target)
                            logger.debug(f"Target found: \
                                Dst IP: {destip},\t\
                                Dst port: {portnum},\t\
                                Protocol: {proto}")

        return targets

    def handle_vulners(self, script):
        try:
            tables = script.find('table').findall('table')
        except:
            return False
    
        for table in tables:
            elems = table.findall('elem')
            if elems[2].text == 'true':
                return True
