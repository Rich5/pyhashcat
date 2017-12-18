import os
import sys
from time import sleep
from pyhashcat import Hashcat

def cracked_callback(sender):
    print id(sender), "EVENT_CRACKER_HASH_CRACKED"
    
def finished_callback(sender):
    global finished
    finished = True

def benchmark_status(sender):
    device_cnt = sender.status_get_device_info_cnt()
    print "HashType: ", str(sender.status_get_hash_type())

    for i in range(device_cnt):
        print "Speed.Dev.#", str(i), ".....: ", str(sender.status_get_speed_sec_dev(i)),"H/s (", str(sender.status_get_exec_msec_dev(i)), "ms)"

    
print "-------------------------------"
print "----  pyhashcat Benchmark  ----"
print "-------------------------------"

finished = False
hc = Hashcat()
hc.benchmark = True
hc.workload_profile = 2

print "[!] Hashcat object init with id: ", id(hc)
print "[!] cb_id finished: ", hc.event_connect(callback=finished_callback, signal="EVENT_OUTERLOOP_FINISHED")
print "[!] cb_id benchmark_status: ", hc.event_connect(callback=benchmark_status, signal="EVENT_CRACKER_FINISHED")

print "[!] Starting Benchmark Mode"

cracked = []
print "[+] Running hashcat"
if hc.hashcat_session_execute() >= 0:
    print"[.] Workload profile", str(hc.workload_profile)

    # hashcat should be running in a background thread
    # wait for it to finishing cracking
    while True:
        if finished:
            break



