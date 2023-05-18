#!/usr/bin/python
import os
import time
import sys
import select

def print_bad(msg):
    sys.stdout.write(" [-] {}\n".format(msg))
def print_good(msg):
    sys.stdout.write(" [+] {}\n".format(msg))
def print_warning(msg):
    sys.stdout.write(" [!] {}\n".format(msg))
def print_status(msg):
    sys.stdout.write(" [*] {}\n".format(msg))

def check_interface_operational_mode(interface, keyword):   
    res = os.popen('iwconfig {}'.format(interface)).read()
    return True if 'Mode:{}'.format(keyword) in res else False

def killProcess(process_name):     
	os.system('pkill {}'.format(process_name))

if __name__ == '__main__':
	count = 5
	target_seconds = 600
	ap_interface = 'wlan0'
	listen_interface = 'wlan1'
	client_interface1 = 'wlan2'
	client_interface2 = 'wlan4'
	adversary_interface = 'wlan3'
	ap_conf = 'hostapd.conf'
	client_conf1 = 'wpa_supplicant_client1.lab4.conf'     
	client_conf2 = 'wpa_supplicant_client2.lab4.conf'    
	channel = 7

	try:
		if os.path.isfile('/usr/share/wordlists/rockyou.txt'):
			password=os.popen('strings /usr/share/wordlists/rockyou.txt -n 8 | head -n 10 | shuf -n 1').read().strip()
		elif os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
			password=os.popen('zcat /usr/share/wordlists/rockyou.txt.gz | strings -n 8 | head -n 100 | shuf -n 1').read().strip()
		else:
			print_bad('rockyou.txt not found in /usr/share/wordlists/rockyou.txt(.gz)')
			exit(0)


		print_status('Refresh mac80211_hwsim interfaces')
		os.system('modprobe -r mac80211_hwsim')
		for e in ['wpa_supplicant', 'hostapd', 'arping']:
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

		time.sleep(5)
		print_status('Using interface {} to run AP'.format(ap_interface))
		os.system('nmcli dev set {} managed no;sleep 1'.format(ap_interface))
		os.system('ifconfig {} down;sleep 1'.format(ap_interface))
		os.system('iwconfig {} mode Managed;sleep 1'.format(ap_interface))
		os.system('ifconfig {} up;sleep 1'.format(ap_interface))
		os.system('hostapd -B -i {} {}  > /dev/null;sleep 1'.format(ap_interface, ap_conf))

		os.system('/bin/bash -c "hostapd -B -i %s <(printf \'ssid=Kashyyk\\ncountry_code=AU\\nieee80211d=0\\nieee80211h=0\\nhw_mode=g\\nchannel=7\\nbeacon_int=100\\ndtim_period=2\\nmax_num_sta=255\\nrts_threshold=-1\\nfragm_threshold=-1\\nieee80211n=1\\nht_capab=[HT40-][HT40+][SHORT-GI-20][SHORT-GI-40]\\nrequire_ht=1\\nieee80211ac=0\\nrequire_vht=0\\nvht_oper_chwidth=1\\nauth_algs=3\\nwmm_ac_bk_cwmin=5\\nwmm_ac_bk_cwmax=10\\nwmm_ac_bk_aifs=7\\nwmm_ac_bk_txop_limit=0\\nwmm_ac_bk_acm=0\\nwmm_ac_be_aifs=3\\nwmm_ac_be_cwmin=5\\nwmm_ac_be_cwmax=7\\nwmm_ac_be_txop_limit=0\\nwmm_ac_be_acm=0\\nwmm_ac_vi_aifs=2\\nwmm_ac_vi_cwmin=4\\nwmm_ac_vi_cwmax=5\\nwmm_ac_vi_txop_limit=188\\nwmm_ac_vi_acm=0\\nwmm_ac_vo_aifs=2\\nwmm_ac_vo_cwmin=3\\nwmm_ac_vo_cwmax=4\\nwmm_ac_vo_txop_limit=47\\nwmm_ac_vo_acm=0\\nchannel=7\\nwpa=2\\nwpa_passphrase=\\"%s\\"\\nwpa_key_mgmt=WPA-PSK SAE\\nwpa_pairwise=CCMP\\n\') 2>&1 >/dev/null"' % ( ap_interface, password))

		time.sleep(10)
		print_status('Using interfaces {} and {} to connect clients to AP\r\n'.format(client_interface1, client_interface2))
		os.system('nmcli dev set {} managed no;sleep 1'.format(client_interface1))
		os.system('nmcli dev set {} managed no;sleep 1'.format(client_interface2))
		os.system('/bin/bash -c "wpa_supplicant -B -i {} -c <(wpa_passphrase Kashyyk {}) 2>&1 > /dev/null"'.format(client_interface1, password))
		os.system('/bin/bash -c "wpa_supplicant -B -i %s -c <(printf \'network={\\r\\n\\tssid=\\"Kashyyk\\"\\r\\n\\tkey_mgmt=SAE\\r\\n\\tsae_password=\\"%s\\"\\r\\n\\tieee80211w=0\\r\\n}\') 2>&1 > /dev/null"' % (client_interface2, password))
		os.system('arping 1.1.1.1 -i {} -S 8.8.8.8 > /dev/null &'.format(client_interface1))
		os.system('arping 1.1.1.1 -i {} -S 8.8.8.8 > /dev/null &'.format(client_interface2))

		print_status('Interface Summary:\r\n [*]\twlan0: AP\r\n [*]\twlan1: listener\r\n [*]\twlan2: client1\r\n [*]\twlan3: attacking\r\n [*]\twlan4: client2\r\n')
		print_status('The clients will reconnect every {} seconds'.format(target_seconds))
		print_status('Run \'wireshark -i {} -k\' to see lab traffic'.format(listen_interface))
		print_warning('press enter to quit lab...')
		loop = True
		five_minutes_ago = time.time()
		while loop:
			if( time.time() - five_minutes_ago >= target_seconds):
				killProcess('wpa_supplicant')  
				time.sleep(1)
				os.system('wpa_supplicant -B -i {} -c {} > /dev/null'.format(client_interface1, client_conf1))
				os.system('wpa_supplicant -B -i {} -c {} > /dev/null'.format(client_interface2, client_conf2))
				five_minutes_ago = time.time()
			ready, _, _ = select.select([sys.stdin], [], [], 0.1)
			if ready:
				loop = input()
		raise KeyboardInterrupt
	except KeyboardInterrupt:
		os.system('modprobe -r mac80211_hwsim')
		for e in ['wpa_supplicant', 'hostapd', 'arping']:
			killProcess(e)   
