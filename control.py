import schedule
import configparser
import json
import nmap
from signal import signal, SIGINT
from sys import exit

CONFIG = configparser.ConfigParser()
CONFIG.read('controller.ini')

OS_DB = {}
SV_DB = {}
IP_DB = {}
IP_CACHE = []


# TODO fix up IP_CACHE, needs to be map of IP:OS



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
	ouput_file = CONFIG['DEFAULT']['OutputDir'] + "/ip_addrs"

	os.system("nmap -n -sn 10.0.0.0/24 -oG - | awk '/Up$/{print $2}' >" + 
		ouput_file)
	ip_lines = open(ouput_file, "r")
	ip_addresses = ip_lines.readlines()
	os.remove(ouput_file)
	return ip_addresses

def cache_IPs():
	global IP_CACHE
	IP_CACHE = get_IPs()


def perform_scan():
	pass


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
		# get ports for this IP
		port_service = {}
		for port, service in port_service.items():
			if(IP_DB.get(ip, {}).get(port) != NULL):
				# Found previous ip:port
			elif(SV_DB.get(service) != NULL):
				# Found service fingerprint
			elif(OS_DB.get(os_print) != NULL):
				# Found OS fingerprint
			else:
				# use default CONFIG['DEFAULT']['InitialNmapLevel']


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


