#By: Bryce Erdman
#Program Features:
    # - Counts how many times every destination address appears in a pcap file
    # - Lists destination ports used for IP address
    # - Gives description of every unique destination address (know where your data is going)
#Problems:
    # - Needs to precisely filter application data (there may be some external data from phone in pcap file)
        # * Note: This problem is related to how we are capturing data, not the program itself

from doctest import script_from_examples
from scapy.all import * #import scapy module
from scapy.layers.inet import IP
from scapy.all import DNS
from collections import Counter
import ipinfo
from ipinfo.handler_utils import cache_key

def analyze(filename):
    A = [] #IP destination addresses
    B = [] #DNS information
    D = [] #Linking DNS to IP addr
    packets = rdpcap(filename)
    
    #Everything in for loop counts IP address frequency and destination port frequency
    for packet in packets: #for each packet in pcap file
        if(IP in packet and DNS in packet):
            if(packet[IP].src == '192.168.2.159'): #filtering only packets that are coming FROM our device
                    A.append(packet[IP].dst) #add the IP destination address to array
                    B.append(packet[DNSQR].qname) #add the DNS name to array
                    D.append(packet[IP].dst) 
                    D.append(packet[DNSQR].qname)

    #Arrays are complete
    print("IPv4 Addresses:\n",Counter(A),"\n") #count how many times every destination address occurs in array
    print("DNS:\n",Counter(B),"\n") #count how many times every udp destination port occurs in array
    print(D)
    
    print("IP Address Information:") #Everything below this line is how to the information on each IP address

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
    filenames = ['C:\\UWW\\UndergraduateResearch\\iotPrivacy\\pcapFiles\\Unfiltered\\Qardio.pcapng']
    for filename in filenames:
        print('\n+++++++++++++++++++++++++ ',filename, '++++++++++++++++++++++++++++++++++++++++')
        analyze(filename)

analyzeAll()