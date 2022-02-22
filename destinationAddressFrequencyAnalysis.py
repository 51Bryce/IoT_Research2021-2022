from doctest import script_from_examples
from scapy.all import * #import scapy module
from scapy.layers.inet import IP
from collections import Counter

A = []
packets = rdpcap(r"C:\UWW\UndergraduateResearch\iotPrivacy\pcapFiles\Unfiltered\KardiaInstallation.pcapng")
for packet in packets: #for each packet in pcap file
    if(packet.haslayer(IP)): #if the packet has an IP layer
        A.append(packet[IP].src) #add the IP source address to array
    #get some further information???
#Array is completed
print(Counter(A)) #count how many times every address occurs in array