import os
import sys
from time import sleep
from pyhashcat import hashcat

print "-------------------------------"
print "---- Simple pyhashcat Test ----"
print "-------------------------------"

hc = hashcat()
hc.hash = "8743b52063cd84097a65d1633f5c74f5"
hc.mask = "?l?l?l?l?l?l?l"
hc.quiet = True
hc.potfile_disable = True
hc.outfile = os.path.join(os.path.expanduser('~'), "outfile.txt")
hc.attack_mode = 3
hc.hash_mode = 0
hc.workload_profile = 3

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
			break;
	sleep(2)
	# go get the results
	with open(hc.outfile, 'r') as f:
		cracked = [i.strip() for i in f.readlines()]

	if len(cracked) > 0:
		for c in cracked:
			ahash, plain = c.split(hc.separator)
			print ahash, " --> ", plain
	else:
		print "No cracked hashes found"
else:
	print "STATUS: ", hc.status_get_status_string()

'''
 temporary hack to keep libhashcat from seg faulting.
 this should be taken care of when eventing is included.
'''
sleep(5)

