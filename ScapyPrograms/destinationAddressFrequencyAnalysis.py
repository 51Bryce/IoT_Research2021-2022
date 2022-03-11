#By: Bryce Erdman
#This program counts how many times every source address appears in a pcap file.
from doctest import script_from_examples
from scapy.all import * #import scapy module
from scapy.all import DNS #import scapy module
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from collections import Counter

def analyze(filename):
    A = [] #IP destination addresses
    B = [] #DNS information
    C = [] #UDP destination port information
    packets = rdpcap(filename)
    #packets = rdpcap(fileName)
    for packet in packets: #for each packet in pcap file
        if(packet.haslayer(IP) and packet.haslayer(UDP)): #if the packet has a UDP and IP layer
            if(packet[IP].src == '192.168.2.159'): #filtering only packets that are coming FROM our router
                A.append(packet[IP].dst) #add the IP destination address to array
                C.append(packet[IP].dst) #IP ADDRESSES IN THE C ARRAY ARE USING A DESTINATION PORT
                C.append(packet[UDP].dport) #add the Destination port to array
        elif(packet.haslayer(IP)): #if the packet has an IP layer
            if(packet[IP].src == '192.168.2.159'): #filtering only packets that are coming FROM our router
                A.append(packet[IP].dst) #add the IP destination address to array

        if(packet.haslayer(DNSRR) and packet.haslayer(IP)): #if the packet has an DNS layer
            if(packet[IP].dst == '192.168.2.159'): #filtering only packets that are coming TO our router
                B.append(packet.qd.qname) #add the IP destination address to array
    #Array is complete
    print("IPv4 Addresses:\n",Counter(A),"\n") #count how many times every destination address occurs in array
    print("DNS Names:\n",Counter(B),"\n") #count how many times every dns name occurs in array
    print("UDP Destination Ports:\n",Counter(C)) #count how many times every udp destination port occurs in array
    print('\n*********************************************************')

def analyzeAll(): #put filepaths here for the pcap files you want to check
    filenames = ['C:\\UWW\\UndergraduateResearch\\iotPrivacy\\pcapFiles\\Unfiltered\\KardiaInstallation.pcapng',
    'C:\\UWW\\UndergraduateResearch\\iotPrivacy\\pcapFiles\\Unfiltered\\usingkardia.pcapng',
    'C:\\UWW\\UndergraduateResearch\\iotPrivacy\\pcapFiles\\Unfiltered\\FitBitMeasure1.pcapng',
    'C:\\UWW\\UndergraduateResearch\\iotPrivacy\\pcapFiles\\Unfiltered\\Qardio.pcapng']
    for filename in filenames:
        print('\n+++++++++++++++++++++++++ ',filename, '++++++++++++++++++++++++++++++++++++++++')
        analyze(filename)

analyzeAll()
