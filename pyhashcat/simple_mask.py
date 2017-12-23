#!/usr/bin/env python

import os
import sys
from time import sleep
from pyhashcat import Hashcat

def cracked_callback(sender):
	print "CRACKED-", id(sender), "EVENT_CRACKER_HASH_CRACKED"
	

def finished_callback(sender):
	print "FIN-", id(sender), "EVENT_CRACKER_FINISHED"

def any_callback(sender):
	print "ANY-", id(sender), sender.status_get_status_string()
	
print "-------------------------------"
print "---- Simple pyhashcat Test ----"
print "-------------------------------"

hc = Hashcat()
# To view event types
# hc.event_types
print "[!] Hashcat object init with id: ", id(hc)
print "[!] cb_id cracked: ", hc.event_connect(callback=cracked_callback, signal="EVENT_CRACKER_HASH_CRACKED")
print "[!] cb_id finished: ", hc.event_connect(callback=finished_callback, signal="EVENT_CRACKER_FINISHED")
print "[!] cb_id any: ", hc.event_connect(callback=any_callback, signal="ANY")


hc.hash = "8743b52063cd84097a65d1633f5c74f5"
hc.mask = "?l?l?l?l?l?l?l"
hc.quiet = True
hc.potfile_disable = True
hc.outfile = os.path.join(os.path.expanduser('~'), "outfile.txt")
print "[+] Writing to ", hc.outfile
hc.attack_mode = 3
hc.hash_mode = 0
hc.workload_profile = 2

cracked = []
print "[+] Running hashcat"
if hc.hashcat_session_execute() >= 0:
	# hashcat should be running in a background thread
	# wait for it to finishing cracking
	i = 0
	while True:
		# do something else while cracking
		i += 1
		if i%4 == 0:
			ps = '-'
		elif i%4 == 1:
			ps = '\\'
		elif i%4 == 2:
			ps = '|'
		elif i%4 == 3:
			ps = '/'
		sys.stdout.write("%s\r" % ps)
		sys.stdout.flush()
		
		if hc.status_get_status_string() == "Cracked":
			break	

	while True:
		try:
			with open(hc.outfile, 'r') as f:
				cracked = [i.strip() for i in f.readlines()]
				break
		except:
			pass
		

	if len(cracked) > 0:
		for c in cracked:
			ahash, plain = c.split(hc.separator)
			print ahash, " --> ", plain
	else:
		print "No cracked hashes found"
else:
	print "STATUS: ", hc.status_get_status_string()

#sleep(5)

