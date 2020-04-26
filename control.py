import schedule
import configparser
import json
import math
import time
from signal import signal, SIGINT
from sys import exit
from os import system, remove
from IPy import IP
import http.server
from demand_server import MyHandler 
import _thread
from SystemFingerprint import *

CONFIG = configparser.ConfigParser()
CONFIG.read('controller.ini')

OS_DB = {}
SV_DB = {}
IP_DB = {}
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

    system("nmap -n -p22,80 127.0.0.1/32 -A -oG - | grep -v 'Status' | awk '/Host/ {print}' | cut -f1,2,3 > " + 
		ouput_file)
        
    ip_lines = open(ouput_file, "r")
    ip_lines = ip_lines.readlines()
    #remove(ouput_file)
    for line in ip_lines:
        try:
            ip_slug = line.split(" ")[1]
            os_slug = line.split("\t")[2].split(':')[1].strip()
            print(f"OS SLUG OUTPUT: {os_slug}")
            ip_addresses[ip_slug] = os_slug
            OS_DB[ip_slug] = {
                        "OS" : os_slug
                    } 
            with open(CONFIG['DEFAULT']['OSStore'], 'w') as outfile:
                json.dump(OS_DB, outfile)
        except:
            continue
    return ip_addresses

def cache_IPs():
    global IP_CACHE
    IP_CACHE = get_IPs()


def get_port_services():
    port_service = {}

    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ports"
    system("nmap -n -p22,80 -O 127.0.0.1/32  -sV -oG - | grep -v 'Status' | awk '/Host/ {print}' | cut -f2  >" + 
	ouput_file)
    port_lines = open(ouput_file, "r")
    port_lines = port_lines.readlines()
    #remove(ouput_file)
    
    for line in port_lines:
        if("Ports:" in line):
            part = line.split("Ports: ")[1]
            port_infos = part.split(",")
            for port_info in port_infos:
                all_info = port_info.split("/")
                try:
                    port_service[all_info[0]] = all_info[6]
                    SV_DB[part] = {
                        "service" : port_service
                    } 
                    with open(CONFIG['DEFAULT']['ServiceStore'], 'w') as outfile:
                        json.dump(SV_DB, outfile)
                except:
                    continue

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
    sys_fingerprint = SystemFingerprint.gen_fingerprint(port_service, ip, -1, os)
    for i in range(len(SYSTEM_FINGERPRINTS_DB)):
        if sys_fingerprint.equal_in_tolerance(SYSTEM_FINGERPRINTS_DB, CONFIG['DEFAULT']['Tolerance']):
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
        if(IP_DB[ip][port]['times'] >= 0):
            IP_DB[ip][port]['speed'] += 1
            if(IP_DB[ip][port]['speed'] > 5):
                IP_DB[ip][port]['speed'] = 5
            return (speed, increase_speed_callback, fingerprintID)
        else:
            return (speed, normal_speed_callback, fingerprintID)

    # Rely on single service fingerprint
    speed = SV_DB.get('service')
    if(speed != None):
        # Found service fingerprint
        return (speed, normal_speed_callback, fingerprintID)

    # Rely on OS fingerprint
    speed = OS_DB.get('os_print')
    if(speed != None):
        # Found OS fingerprint
        return (speed, normal_speed_callback, fingerprintID)

    return (int(CONFIG['NMap']['InitialSpeed']), normal_speed_callback, fingerprintID)


########## SCANNER ##########


def smart_scan():
    global IP_CACHE
    
    if(IP_CACHE == {}):
        todo = get_IPs()
    else:
        todo = IP_CACHE

    smart_scan_curried(todo)


def smart_scan_curried(todo):
    for ip, os_print in todo.items():
        port_service = get_port_services()
        for port, service in port_service.items():
            speed, callback, ID = get_speed_and_callback(port, service, ip, os_print, port_service)
            perform_scan(ip, port, speed, callback, ID)


def perform_scan(ip, port, speed, callback, ID):
    successful = nmap_scan(ip, port, speed)

    # Seed data if missing
    if(IP_DB.get(ip, None) == None):
        IP_DB[ip] = {}
        print("IP not in database yet")
    if(IP_DB[ip].get(port, None) == None):
        IP_DB[ip][port] = {
            "times": 0,
            "speed": speed
        }
    IP_DB[ip][port]['times'] += 1
    print("Successful scan, times+1")
    print(IP_DB)
    with open(CONFIG['DEFAULT']['IPStore'], 'w') as outfile:
        json.dump(IP_DB, outfile)

    # Perform metric changes
    callback(ip, port, speed, successful, ID)


def nmap_scan(ip, port, speed):
    # TODO: Need true/false if nmap successful

    ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/output.xml"
    
    nmap_command = 'nmap --script vuln -p ' + str(port) + \
		' -T ' + str(speed) + \
		' ' + str(ip) + \
		' -oX ./dir_scanparser/scanparser/scan_results/script_vuln.nmap'
    system(nmap_command)
    system('python3.6 ./dir_scanparser/scanparser/__init__.py ./dir_scanparser/config.yml')
    return True


########## SPEED CALLBACKS ##########

def increase_speed_callback(ip, port, speed, result, fingerprintID):
    global IP_DB
    global SYSTEM_FINGERPRINTS_DB

    if(result == True):
        if(IP_DB[ip][port]['times'] == CONFIG['Speedup']['Attempts']):
            # We can speed up
            IP_DB[ip][port]['speed'] = min(speed, CONFIG['NMap']['MaxSpeed'])
            IP_DB[ip][port]['times'] = 0
            SYSTEM_FINGERPRINTS_DB[fingerprintID].set_speed(port, speed)
        else:
            IP_DB[ip][port]['times'] = IP_DB[ip][port]['times'] + 1
    else:
        IP_DB[ip][port]['times'] = -1
    


def normal_speed_callback(ip, port, speed, result, fingerprintID):
    global IP_DB
    if(result == False):
        # Scan failed, we need to slow down
        IP_DB[ip][port]['times'] = 0
        IP_DB[ip][port]['speed'] = max(speed - 1, CONFIG['NMap']['MinSpeed'])   
        SYSTEM_FINGERPRINTS_DB[fingerprintID].set_speed(port, speed - 1)
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
    interval = int(math.floor(1.0 /  float(CONFIG['Cache']['CacheFreq'])))
    if(CONFIG['Cache']['CacheUnit'] == 'hour'):
        schedule.every(interval).hour.do(cache_IPs)
    else:
        #schedule.every(interval).days.do(cache_IPs)
        schedule.every(1).minutes.do(cache_IPs)

if(CONFIG['Cache']['CacheUnit'] == 'hour'):
    schedule.every(interval).hour.do(smart_scan)
else:
    #schedule.every(interval).days.do(smart_scan)
    schedule.every(1).minutes.do(smart_scan)

# setup terminate
signal(SIGINT, sig_int_handler)

try:
    MyHandler.set_demand_callback(on_demand_scan)
    server_class = http.server.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)

    _thread.start_new_thread( httpd.serve_forever )
except:
    print ("Error: unable to start thread")


while True:
    schedule.run_pending()

    # Sleep until next job
    #time.sleep(schedule.idle_seconds())
    time.sleep(1)


