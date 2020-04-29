import os
import schedule
import configparser
import json
import math
import time
from signal import signal, SIGINT
from sys import exit
from os import system
from IPy import IP
import http.server
from demand_server import MyHandler 
import _thread
import subprocess
from SystemFingerprint import *

CONFIG = configparser.ConfigParser()
CONFIG.read('controller.ini')

OS_DB = {}
SV_DB = {}
IP_DB = {}
IP_CACHE = {}
# ip->port->data[times tried, curr_speed]

SYSTEM_FINGERPRINTS_DB = []
# Array of SystemFingerprints


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

    os.system("nmap -n -O " + CONFIG['DEFAULT']['Subnet'] + " -oG - | cut -f1,4 >" + 
        ouput_file)
    ip_lines = open(ouput_file, "r")
    ip_lines = ip_lines.readlines()
    os.remove(ouput_file)
    for line in ip_lines:
        if(not "Host:" in line):
            continue
        ip_slug = line.split(" ")[1]
        os_slug = line.split(" ")[2]
        ip_addresses[ip_slug] = os_slug
    return ip_addresses

def cache_IPs():
    global IP_CACHE
    IP_CACHE = get_IPs()


def get_port_services(ip):
    port_service = {}

    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ports"
    os.system("nmap -n -p1-10000 -O " + ip + " -oG - | cut -f2 >" + 
    ouput_file)
    port_lines = open(ouput_file, "r")
    port_lines = port_lines.readlines()
    os.remove(ouput_file)
    
    for line in port_lines:
        if("Ports:" in line):
            print(line)

            part = line.split("Ports: ")[1]
            port_infos = part.split(",")
            for port_info in port_infos:
                all_info = port_info.split("/")
                port_service[all_info[0]] = all_info[6]

    return port_service

########## CLASSIFIERS ##########


def get_speed_and_callback(port, service, ip, os, port_service):
    global IP_DB
    global SYSTEM_FINGERPRINTS_DB
    global SV_DB
    global OS_DB

    data = IP_DB.get(ip, {}).get(port, None)    
    fingerprintID = -1


    # Check if we have a system fingerprint
    sys_fingerprint = gen_fingerprint(port_service, ip, os, -1)
    for i in range(len(SYSTEM_FINGERPRINTS_DB)):
        if sys_fingerprint.equal_in_tolerance(SYSTEM_FINGERPRINTS_DB[i], CONFIG['DEFAULT']['Tolerance']):
            fingerprintID = i
            break

    # Save for later editting
    if(fingerprintID == -1):
        fingerprintID = len(SYSTEM_FINGERPRINTS_DB)
        SYSTEM_FINGERPRINTS_DB.append(sys_fingerprint)


    # Check if machine has previous data
    if(data != None):
        # Found previous ip:port
        speed = data['speed']
        if(data['times'] >= 0):
            return (speed + 1, increase_speed_callback, fingerprintID)
        else:
            return (speed, normal_speed_callback, fingerprintID)

    # Rely on single service fingerprint
    speed = SV_DB.get(service, None)
    if(speed != None):
        # Found service fingerprint
        return (speed, normal_speed_callback, fingerprintID)

    # Rely on OS fingerprint
    speed = OS_DB.get(os, None)
    if(speed != None):
        # Found OS fingerprint
        return (speed, normal_speed_callback, fingerprintID)

    return (CONFIG['NMap']['InitialSpeed'], normal_speed_callback, fingerprintID)


########## SCANNER ##########


def smart_scan():
    global IP_CACHE

    print("running smart scan...")
    
    if(IP_CACHE == {}):
        todo = get_IPs()
    else:
        todo = IP_CACHE

    smart_scan_curried(todo)


def smart_scan_curried(todo):
    for ip, os_print in todo.items():
        port_service = get_port_services(ip)
        for port, service in port_service.items():
            speed, callback, ID = get_speed_and_callback(port, service, ip, os_print, port_service)
            perform_scan(ip, port, speed, callback, ID)


def perform_scan(ip, port, speed, callback, ID):
    print("Performing Scan")

    successful = nmap_scan(ip, port, speed)

    # Seed data if missing
    if(IP_DB.get(ip, None) == None):
        IP_DB[ip] = {}
    if(IP_DB[ip].get(port, None) == None):
        IP_DB[ip][port] = {
            "times": 0,
            "speed": speed
        }

    # Perform metric changes
    callback(ip, port, speed, successful, ID)


def nmap_scan(ip, port, speed):
    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/output.xml"

    output = subprocess.check_output(f"nmap --script vuln -p {port} -T{speed} {ip} -oX {ouput_file}", shell=True)
    output_str = output.decode("utf-8")

    if output_str.find("ERROR"):
        return False

    if output_str.find("closed"):
        return False

    os.system('python nmap_parser.py ' + ouput_file)
    return True


########## SPEED CALLBACKS ##########

def increase_speed_callback(ip, port, speed, result, fingerprintID):
    global IP_DB
    global SYSTEM_FINGERPRINTS_DB

    speed = int(speed)
    min_speed = min(speed, int(CONFIG['NMap']['MaxSpeed']))

    if(result == True):
        if(IP_DB[ip][port]['times'] == CONFIG['Speedup']['Attempts']):
            # We can speed up
            IP_DB[ip][port]['speed'] = min_speed
            IP_DB[ip][port]['times'] = 0
            SYSTEM_FINGERPRINTS_DB[fingerprintID].set_speed(port, min_speed)
        else:
            IP_DB[ip][port]['times'] = IP_DB[ip][port]['times'] + 1
    else:
        IP_DB[ip][port]['times'] = -1
    


def normal_speed_callback(ip, port, speed, result, fingerprintID):
    global IP_DB
    global SYSTEM_FINGERPRINTS_DB

    speed = int(speed)
    max_speed = max(speed - 1, int(CONFIG['NMap']['MinSpeed']))

    if(result == False):
        # Scan failed, we need to slow down
        IP_DB[ip][port]['times'] = 0
        IP_DB[ip][port]['speed'] = max_speed
        SYSTEM_FINGERPRINTS_DB[fingerprintID].set_speed(port, max_speed)
    else:
        SYSTEM_FINGERPRINTS_DB[fingerprintID].set_speed(port, speed) 


########## DEMAND CALLBACK ##########
def on_demand_scan(ip):
    smart_scan_curried([ip])


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
    # interval = int(math.floor(1.0 /  float(CONFIG['Cache']['CacheFreq'])))
    if(CONFIG['Cache']['CacheUnit'] == 'hour'):
        schedule.every(float(CONFIG['Cache']['CacheFreq'])).hours.do(cache_IPs)
    else:
        schedule.every(float(CONFIG['Cache']['CacheFreq'])).days.do(cache_IPs)

if(CONFIG['Scan']['ScanUnit'] == 'hour'):
    schedule.every(float(CONFIG['Scan']['ScanFreq'])).hours.do(smart_scan)
else:
    schedule.every(float(CONFIG['Scan']['ScanFreq'])).days.do(smart_scan)

# setup terminate
signal(SIGINT, sig_int_handler)

PORT_NUMBER = 9090
HOST_NAME = "localhost"

try:
    MyHandler.set_demand_callback(on_demand_scan)
    server_class = http.server.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)

    _thread.start_new_thread( httpd.serve_forever, () )
except Exception as e:
    print(str(e))
    print ("Error: unable to start thread")

smart_scan()
print("Complete")


while True:
    schedule.run_pending()

    # Sleep until next job
    time.sleep(schedule.idle_seconds())



