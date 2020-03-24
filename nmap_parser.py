#!/usr/bin/env python

import xml.etree.ElementTree as ET
import sys

IPTABLES_RULE = 'iptables.out'

def write_iptables_rule(rules, filename=IPTABLES_RULE):
    with open(filename, 'w') as fp:
        for rule in rules:
            fp.write(rule)

def create_iptables_rule(table='filter', chain='INPUT', sourceip=None, destip=None, \
    sourceport=None, destport=None, proto=None, action='DROP'):
    rule = 'iptables -t ' + table + ' -A ' + chain
    if sourceip is not None:
        rule += ' -s ' + str(sourceip)
    if destip is not None:
        rule += ' -d ' + str(destip)
    if proto is not None:
        rule += ' -p ' + str(proto)
    if sourceport is not None:
        rule += ' --sport ' + str(sourceport)
    if destport is not None:
        rule += ' --dport ' + str(destport)
    rule += ' -j ' + action
    return rule

def handle_vulners(script):
    try:
        tables = script.find('table').findall('table')
    except:
        return False

    for table in tables:
        elems = table.findall('elem')
        if elems[2].text == 'true':
            return True
            
def main(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    hosts = tree.findall('host')
    rules = []

    #Parse each host
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
            print(portnum + '|' + proto + '|' + service)

            #Parse results of each script run on port
            scripts = port.findall('script')
            for script in scripts:
                print('\t' + script.get('id'))
                if script.get('id') == 'vulners':
                    if handle_vulners(script) == True:
                        rule = create_iptables_rule(\
                            destip=destip,\
                            destport = portnum,\
                            proto=proto\
                        )
                        print(rule)
                        rules += rule

    write_iptables_rule(rules=rules)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('[!] Error: Must provide the name of the file to parse.')
        sys.exit(-1);
    main(sys.argv[1])
