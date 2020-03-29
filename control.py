import schedule
import configparser
import json
import nmap
import math
import time
from signal import signal, SIGINT
from sys import exit
from os import system

CONFIG = configparser.ConfigParser()
CONFIG.read('controller.ini')

OS_DB = {}
SV_DB = {}
IP_DB = {}
# ip->port->data[times tried, curr_speed]
IP_OS_CACHE = {}

########## FINGERPRINT LOADER ##########


with open(CONFIG['DEFAULT']['OSStore']) as json_file:
    try:
        OS_DB = json.load(json_file)
    except ValueError: pass

with open(CONFIG['DEFAULT']['ServiceStore']) as json_file:
    try:
        SV_DB = json.load(json_file)
    except ValueError: pass

with open(CONFIG['DEFAULT']['IPStore']) as json_file:
    try:
        IP_DB = json.load(json_file)
    except ValueError: pass

########## INFO GATHERING ##########


def get_IPs():
    global CONFIG
    ip_addresses = {}
    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ip_addrs"

    os.system("nmap -n -p1-10000 -O " + CONFIG['DEFAULT']['Subnet'] + " -oG - | cut -f1,4 >" + 
        ouput_file)
    ip_lines = open(ouput_file, "r")
    ip_lines = ip_lines.readlines()
    os.remove(ouput_file)
    for line in ip_lines:
        ip_slug = line.split(" ")[1]
        os_slug = line.split("\t")[1]
        ip_addresses[ip_slug] = os_slug
    return ip_addresses

def cache_IPs():
    global IP_CACHE
    IP_CACHE = get_IPs()


def get_port_services():
    port_service = {}

    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ports"
    os.system("nmap -n -p1-10000 -O " + CONFIG['DEFAULT']['Subnet'] + " -oG - | cut -f2 >" + 
    ouput_file)
    port_lines = open(ouput_file, "r")
    port_lines = port_lines.readlines()
    os.remove(ouput_file)
    
    for line in port_lines:
        if("Ports:" in line):
            part = a.split("Ports: ")[1]
            port_infos = b.split(",")
            for port_info in port_infos:
                all_info = port_info.split("/")
                port_service[all_info[0]] = all_info[6]

    return port_service

########## CLASSIFIERS ##########


def get_speed_and_callback():
    data = IP_DB.get(ip, {}).get(port)    

    # Check if machine has previous data
    if(data != NULL):
        # Found previous ip:port
        speed = data['speed']
        if(data['times'] >= 0):
            return (speed + 1, increase_speed_callback)
        else:
            return (speed, normal_speed_callback)

    # Rely on single service fingerprint
    speed = SV_DB.get(service)
    if(speed != NULL):
        # Found service fingerprint
        return (speed, normal_speed_callback)

    # Rely on OS fingerprint
    speed = OS_DB.get(os_print)
    if(speed != NULL):
        # Found OS fingerprint
        return (speed, normal_speed_callback)


########## SCANNER ##########


def smart_scan():
    global IP_CACHE
    
    if(IP_CACHE == {}):
        todo = get_IPs()
    else:
        todo = IP_CACHE

    for ip, os_print in todo.items():
        port_service = get_port_services()
        for port, service in port_service.items():
            speed = get_speed()
            perform_scan(ip, port, speed)


def nmap_scan(ip, port, speed):
    # TODO: Need true/false if nmap successful

    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/output.xml"

    os.system('nmap --vuln -p port -Tspeed ip -oX ' + ouput_file)
    os.system('python nmap_parser.py ' + ouput_file)
    return True

def perform_scan(ip, port, speed, callback):
    successful = nmap_scan(ip, port, speed)

    # Seed data if missing
    if(IP_DB.get(ip, NULL) == NULL):
        IP_DB[ip] = {}
    if(IP_DB[ip].get(port, NULL) == NULL):
        IP_DB[ip][port] = {
            "times": 0,
            "speed": speed
        }

    # Perform metric changes
    callback(ip, port, speed, successful)


########## SPEED CALLBACKS ##########

def increase_speed_callback(ip, port, speed, result):
    global IP_DB
    if(result == True):
        if(data['times'] == CONFIG['Speedup']['Attempts']):
            # We can speed up
            IP_DB[ip][port]['speed'] = min(speed + 1, CONFIG['NMap']['MaxSpeed'])
            IP_DB[ip][port]['times'] = 0
        else:
            IP_DB[ip][port]['times'] = IP_DB[ip][port]['times'] + 1
    else:
        IP_DB[ip][port]['times'] = -1

def normal_speed_callback(ip, port, speed, result):
    global IP_DB
    if(result == False):
        # Scan failed, we need to slow down
        IP_DB[ip][port]['times'] = 0
        IP_DB[ip][port]['speed'] = max(speed - 1, CONFIG['NMap']['MinSpeed'])        



########## SIGNAL HANDLER ##########

def terminate():
    global CONFIG
    global OS_DB
    global SV_DB
    global IP_DB

    with open(CONFIG['DEFAULT']['OSStore'], 'w') as outfile:
        json.dump(OS_DB, outfile)

    with open(CONFIG['DEFAULT']['ServiceStore'], 'w') as outfile:
        json.dump(SV_DB, outfile)

    with open(CONFIG['DEFAULT']['IPStore'], 'w') as outfile:
        json.dump(SV_DB, outfile)

def sig_int_handler(signal_received, frame):
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    terminate()
    exit(0)

########## JOB SCHEDULER ##########

if(CONFIG['Cache']['CacheIP']):
    # Setup Job schedule
    interval = int(math.floor(1.0 /  float(CONFIG['Cache']['CacheFreq'])))
    if(CONFIG['Cache']['CacheUnit'] == 'hour'):
        schedule.every(interval).hour.do(cache_IPs)
    else:
        schedule.every(interval).days.do(cache_IPs)

if(CONFIG['Cache']['CacheUnit'] == 'hour'):
    schedule.every(interval).hour.do(smart_scan)
else:
    schedule.every(interval).days.do(smart_scan)



# setup terminate
signal(SIGINT, sig_int_handler)

while True:
    schedule.run_pending()

    # Sleep until next job
    time.sleep(schedule.idle_seconds())


