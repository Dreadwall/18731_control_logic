import schedule
import configparser
import json
import nmap
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

with open(CONFIG['DEFAULT']['OSStore']) as json_file:
    OS_DB = json.load(json_file)

with open(CONFIG['DEFAULT']['ServiceStore']) as json_file:
    SV_DB = json.load(json_file)

with open(CONFIG['DEFAULT']['IPStore']) as json_file:
    IP_DB = json.load(json_file)

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

def get_IPs():
	global CONFIG
	ip_addresses = {}
	ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ip_addrs"

	os.system("nmap -n -p1-10000 -O 10.0.0.0/24 -oG - | cut -f1,4 >" + 
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


def nmap_scan(ip, port, speed):
	# TODO: Need logic for scanning, parsing, etc
	os.system('nmap --vuln -p port -Tspeed ip -oX output.xml')
    os.system('python nmap_parser.py output.xml')

	return True

def perform_scan(ip, port, speed, speedup_attempt=False):
	successful = nmap_scan(ip, port, speed)

	# Seed data if missing
	if(IP_DB.get(ip, NULL) == NULL):
		IP_DB[ip] = {}
	if(IP_DB[ip].get(port, NULL) == NULL):
		IP_DB[ip][port] = {
			'times' = 0
			'speed' = speed
		}

	# Perform metric changes
	if(not successful && speedup_attempt):
		IP_DB[ip][port]['times'] = -1
	elif(not successful && not speedup_attempt):
		IP_DB[ip][port]['times'] = 0
		IP_DB[ip][port]['speed'] = speed - 1
	elif(successful && speedup_attempt):
		IP_DB[ip][port]['times'] = IP_DB[ip][port]['times'] + 1


def smart_scan():
	global IP_CACHE
	global IP_DB
	global SV_DB
	global OS_DB
 
	if(IP_CACHE == {}):
		todo = get_IPs()
	else:
		todo = IP_CACHE

	for ip, os_print in todo.items():
		port_service = {}

		ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ports"
		os.system("nmap -n -p1-10000 -O 10.0.0.0/24 -oG - | cut -f2 >" + 
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

		for port, service in port_service.items():
			if((data = IP_DB.get(ip, {}).get(port)) != NULL):
				# Found previous ip:port
				speed = data['speed']
				if(data['times'] == CONFIG['Speedup']['Attempts']):
					IP_DB[ip][port]['speed'] = speed + 1
					perform_scan(ip, port, speed + 1)
				elif(data['times'] >= 0):
					perform_scan(ip, port, speed + 1, True)
				else
					perform_scan(ip, port, speed)

				perform_scan(ip, port, speed)
			elif((speed = SV_DB.get(service)) != NULL):
				# Found service fingerprint
				perform_scan(ip, port, speed)
			elif((speed = OS_DB.get(os_print)) != NULL):
				# Found OS fingerprint
				perform_scan(ip, port, speed)
			else:
				# use default CONFIG['DEFAULT']['InitialNmapLevel']
				perform_scan(ip, port, CONFIG['DEFAULT']['InitialNmapLevel'])


def sig_int_handler(signal_received, frame):
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    terminate()
    exit(0)

if(CONFIG['Cache']['CacheIP']):
	# Setup Job schedule
	interval = int(floor(1.0 /  float(CONFIG['Cache']['CacheFreq'])))
	if(CONFIG['Cache']['CacheUnit'] == 'hour'):
		schedule.every(interval).hour.do(cache_IPs)
	else:
		schedule.every(interval).day.do(cache_IPs)

if(CONFIG['Cache']['CacheUnit'] == 'hour'):
	schedule.every(interval).hour.do(smart_scan)
else:
	schedule.every(interval).day.do(smart_scan)

# setup terminate
signal(SIGINT, sig_int_handler)

while True:
	schedule.run_pending()

	# Sleep until next job
	time.sleep(schedule.idle_seconds())


