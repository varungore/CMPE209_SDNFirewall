import subprocess as sub
import os
flow_monitor = {}
is_policy_set = {}
packet_count = {}
total_packet_count = 0
id = 0
threshold = 10

p = sub.Popen(('sudo', 'tcpdump', '-e',  '-l', '-i','s1-eth1'), stdout=sub.PIPE)
policy_file = open('./firewall/policies.csv', 'w')
log_file = open('./firewall/log.txt', 'w')
policy_file.write("id,mac_0,mac_1\n")

try:
    for row in p.stdout:
        policy_file = open('./firewall/policies.csv', 'a')
        #row1 = row.rstrip()   # process here
        row1 = row.split(" ")
        #print row1

	total_packet_count += 1 
	if row1[5] != "Broadcast,":
		key = "" + row1[1]+row1[5]
		#print key
		if not flow_monitor.has_key(key): 
		    flow_monitor[key] = 0
		flow_monitor[key] += 1
		if flow_monitor[key] > threshold:
		    #print "**********************************************"
		    #print flow_monitor[key]
		    if not is_policy_set.has_key(key):
		        is_policy_set[key] = 1
		        entry = ""+str(id)+","+row1[1]+","+row1[5]+"\n"
		        policy_file.write(entry)
		        id += 1
		
		policy_file.close()
		#os.system('sudo ovs-ofctl dump-flows s1')
		#os.system('sudo ovs-ofctl del-flows s1')
    print 'Batch Completed'
    os.system('sudo ovs-ofctl del-flows s1')
    policy_file.close()

except KeyboardInterrupt:
    policy_file.close()
    p.terminate()
