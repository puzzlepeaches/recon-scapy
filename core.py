#!/usr/bin/python2
# Coded by vay3t!

from scapy.all import *
from datetime import datetime
import IPy
import commands

global hosts

hosts = set()

def detect_iface():
	iface = commands.getoutput("route -n | grep UG | awk '{print $8}'")
	return iface

def detect_gateway():
	gateway = commands.getoutput("route -n | grep UG | awk '{print $2}'")
	return gateway

def detect_ip(iface):
	myip = commands.getoutput('ifconfig '+iface+' | grep "inet "').split()[1]
	return myip

def detect_netmask(iface):
	netmask = commands.getoutput('ifconfig '+iface+' | grep "inet "').split()[3]
	return netmask

def detect_network(iface,netmask):
	from netaddr import IPAddress
	bitNetmask = IPAddress(netmask).netmask_bits()
	network = commands.getoutput("route -n | grep "+iface+" | grep '"+netmask+"' | awk '{print $1}'")
	return network+"/"+str(bitNetmask)


iface = detect_iface()
myip = detect_ip(iface)

gateway = detect_gateway()

netmask = detect_netmask(iface)
network = detect_network(iface,netmask)

broadcast = "ff:ff:ff:ff:ff:ff"



def dns_dump(packet):
    # We're only interested packets with a DNS Round Robin layer
    if packet.haslayer(DNSRR):
        # If the an(swer) is a DNSRR, print the name it replied with.
        if isinstance(packet.an, DNSRR):
            print(packet.an.rrname[:-1])


def dns_sniff(packet):
	if IP in packet:
		ip_src = packet[IP].src
		ip_dst = packet[IP].dst   
		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			print str(ip_src) + " ---> " + str(ip_dst) + " : " + packet.getlayer(DNS).qd.qname[:-1]


def ip_dump_priv(packet):
	if packet.haslayer(IP):
		ipSrc = packet['IP'].src
		type_ipSrc = IPy.IP(ipSrc)

		ipDst = packet['IP'].dst
		type_ipDst = IPy.IP(ipDst)

		if type_ipSrc.iptype() == 'PRIVATE':
			if ipSrc not in hosts:
				hosts.add(ipSrc)
				print(ipSrc)
		if type_ipDst.iptype() == 'PRIVATE':
			if ipDst not in hosts:
				hosts.add(ipDst)
				print(ipDst)

def ip_port_viewer(packet):
	if packet.haslayer(IP):
		ipSrc = packet['IP'].src
		ipDst = packet['IP'].dst
		if packet.haslayer(TCP):
			portSrc = packet['TCP'].sport
			portDst = packet['TCP'].dport
			print ipSrc+":"+str(portSrc)+" ---> TCP ---> "+ipDst+":"+str(portDst)
		if packet.haslayer(UDP):
			portSrc = packet['UDP'].sport
			portDst = packet['UDP'].dport
			print ipSrc+":"+str(portSrc)+" ---> UDP ---> "+ipDst+":"+str(portDst)		
		

def arping_scan(network):
	conf.verb=0
	ans,uans = arping(network)
	for snd,rcv in ans:
		print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")

def arp_display(packet):
    if packet[ARP].op == 1: #who-has (request)
        print '[->] Request: {} is asking about {}'.format(packet[ARP].psrc, packet[ARP].pdst)
    if packet[ARP].op == 2: #is-at (response)
        print '[<-] Response: {} has address {}'.format(packet[ARP].hwsrc, packet[ARP].psrc)

def mac_recon(packet):
	if packet.haslayer(IP):
		ipSrc = packet['IP'].src
		type_ipSrc = IPy.IP(ipSrc)
		macSrc = packet['Ether'].src

		ipDst = packet['IP'].dst
		type_ipDst = IPy.IP(ipDst)
		macDst = packet['Ether'].dst

		if ipSrc != "0.0.0.0":
			if type_ipSrc.iptype() == 'PRIVATE':
				if macSrc != broadcast:
					complete_string = macSrc + " - " + ipSrc
					if complete_string not in hosts:
						hosts.add(complete_string)
						print(complete_string)
		if ipDst != "0.0.0.0":
			if type_ipDst.iptype() == 'PRIVATE':
				if macDst != broadcast:
					complete_string = macDst + " - " + ipDst
					if complete_string not in hosts:
						hosts.add(complete_string)
						print(complete_string)

	if packet.haslayer(ARP):
		macSrc = packet["ARP"].hwsrc
		ipSrc = packet["ARP"].psrc
		complete_string = macSrc + " - " + ipSrc
		if complete_string not in hosts:
			hosts.add(complete_string)
			print complete_string

# logs
def datenow():
    x = datetime.now()
    return x.strftime("[ %d/%m/%Y %H:%M:%S ] ")


# Poison detect
def check_spoof(source, mac, destination):
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0
    if not source in requests and source != myip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        # Logs ARP Reply
        print("{} ARP replies detected from MAC {}. Request count {}".format(datenow(),mac, replies_count[mac]))
        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            print("{} ARP Spoofing Detected from MAC Address {}".format(datenow(),mac)) # Logs the attack in the log file
            # Issue OS Notification
            print("[!] ARP Spoofing Detected -> {}".format(mac))
            # Add to sent list to prevent repeated notifications.
            notification_issued.append(mac)
    else:
        if source in requests:
            requests.remove(source)

def poison_detect(packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == myip:
        requests.append(dest)
    if operation == 'is-at':
        return check_spoof(source, source_mac, dest)
