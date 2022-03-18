#By: Bryce Erdman
#Program Features:
    # - Counts how many times every destination address appears in a pcap file
    # - Lists destination ports used for IP address
    # - Gives description of every unique destination address (know where your data is going)
#Problems:
    # - Needs to precisely filter application data (there may be some external data from phone in pcap file)

from doctest import script_from_examples
from scapy.all import * #import scapy module
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from collections import Counter
import ipinfo
from ipinfo.handler_utils import cache_key

def analyze(filename):
    A = [] #IP destination addresses
    B = [] #UDP destination port information
    packets = rdpcap(filename)
    #packets = rdpcap(fileName)
    for packet in packets: #for each packet in pcap file
        if(packet.haslayer(IP) and packet.haslayer(UDP)): #if the packet has a UDP and IP layer
            if(packet[IP].src == '192.168.2.159'): #filtering only packets that are coming FROM our router
                A.append(packet[IP].dst) #add the IP destination address to array
                B.append(packet[IP].dst) #IP ADDRESSES IN THE C ARRAY ARE USING A DESTINATION PORT
                B.append(packet[UDP].dport) #add the Destination port to array

        elif(packet.haslayer(IP)): #if the packet has an IP layer
            if(packet[IP].src == '192.168.2.159'): #filtering only packets that are coming FROM our router
                A.append(packet[IP].dst) #add the IP destination address to array

    #Arrays are complete
    print("IPv4 Addresses:\n",Counter(A),"\n") #count how many times every destination address occurs in array
    print("UDP Destination Ports:\n",Counter(B),"\n") #count how many times every udp destination port occurs in array
    print("IP Address Information:")

    C = [] #Array of unique IP Addresses in pcap
    for i in A:
        if(i not in C): #Do not include our router
            C.append(i)

    #Retrieve and print information for all unique IP Addresses
    access_token = 'b9d4962ac9d5d0'
    handler = ipinfo.getHandler(access_token)
    for i in range(len(C)):
        ip_address = C[i]
        details = handler.getDetails(ip_address)
        print(details.all,"\n")
        i+=1

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
