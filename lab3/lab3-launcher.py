#!/usr/bin/python
import os
import time
import sys
import select
from pbkdf2 import PBKDF2

def print_bad(msg):
    sys.stdout.write(" [-] {}\n".format(msg))
def print_good(msg):
    sys.stdout.write(" [+] {}\n".format(msg))
def print_warning(msg):
    sys.stdout.write(" [!] {}\n".format(msg))
def print_status(msg):
    sys.stdout.write(" [*] {}\n".format(msg))

def pmk(ssid, psk):
	return(PBKDF2(psk, ssid, 4096).read(32).hex())

def check_interface_operational_mode(interface, keyword):       
    res = os.popen('iwconfig {}'.format(interface)).read()
    return True if 'Mode:{}'.format(keyword) in res else False

def killProcess(process_name):        
	os.system('pkill {}'.format(process_name))

if __name__ == '__main__':
	count = 4
	target_seconds = 10
	ap_interface = 'wlan0'
	listen_interface = 'wlan1'
	client_interface = 'wlan2'
	adversary_interface = 'wlan3'
	client_conf = 'wpa_supplicant_client.lab3.conf'
	channel = 7

	try:

		if os.path.isfile('/usr/share/wordlists/rockyou.txt'):
			password=os.popen('strings /usr/share/wordlists/rockyou.txt -n 8 | head -n 100 | shuf -n 1').read().strip()
		elif os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
			password=os.popen('zcat /usr/share/wordlists/rockyou.txt.gz | strings -n 8 | head -n 100 | shuf -n 1').read().strip()
		else:
			print_bad('rockyou.txt not found in /usr/share/wordlists/rockyou.txt(.gz)')
			exit(0)

		print_status('Refresh mac80211_hwsim interfaces')
		os.system('modprobe -r mac80211_hwsim')
		for e in ['wpa_supplicant', 'hostapd']:
			killProcess(e)      
		print_status('Creating {} virtual wireless interfaces'.format(count))
		os.system('modprobe mac80211_hwsim radios={}'.format(count))
		time.sleep(3)

		print_status('Using interface {} to run listener'.format(listen_interface))
		os.system('nmcli dev set {} managed no;sleep 1'.format(listen_interface))
		while(not check_interface_operational_mode(listen_interface, 'Monitor')):  
			os.system('ifconfig {} down;sleep 1'.format(listen_interface))
			os.system('iwconfig {} mode Monitor;sleep 1'.format(listen_interface))
			os.system('iwconfig {} channel {};sleep 1'.format(listen_interface,channel))
			os.system('ifconfig {} up;sleep 1'.format(listen_interface))

		time.sleep(10)
		print_status('Using interface {} to connect client to AP\r\n'.format(client_interface))
		os.system('nmcli dev set {} managed no;sleep 1'.format(client_interface))

		print_status('Interface Summary:\r\n [*]\twlan0: unused\r\n [*]\twlan1: listener\r\n [*]\twlan2: client\r\n [*]\twlan3: attacking\r\n')
		print_status('The client will reconnect every {} seconds'.format(target_seconds))
		print_status('Run \'wireshark -i {} -k\' to see lab traffic'.format(listen_interface))
		print_warning('press enter to quit lab...')
		loop = True
		five_minutes_ago = time.time()
		while loop:
			if( time.time() - five_minutes_ago >= target_seconds):
				killProcess('wpa_supplicant')  
				time.sleep(1)
				os.system('/bin/bash -c "wpa_supplicant -B -i %s -c <(printf \'network={\\r\\n\\tssid=\\"Dagobah\\"\\r\\n\\tpsk=%s\\r\\n\\tscan_ssid=1\\r\\n}\') > /dev/null"' % (client_interface, pmk('Dagobah', password)))
				five_minutes_ago = time.time()
			ready, _, _ = select.select([sys.stdin], [], [], 0.1)
			if ready:
				loop = input()
		raise KeyboardInterrupt
	except KeyboardInterrupt:
		os.system('modprobe -r mac80211_hwsim')
		for e in ['wpa_supplicant', 'hostapd']:
			killProcess(e)   
