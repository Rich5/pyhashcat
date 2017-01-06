import os
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
	print "STATUS: ", hc.status_get_status_string() 
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


