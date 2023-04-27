from scapy.all import *

packets = rdpcap('ENEL573-50.pcap')

hackedMAC = []
hackedIP = []

numberSpoof = 0

i = 0

for packet in packets:
    if packet.haslayer('ARP'):          # only interested with packets using ARP protocol
        if packet['Ethernet'].src != packet['ARP'].hwsrc:
            hackerMAC = packet['ARP'].hwsrc
            numberSpoof += 1
            if hackedMAC.count(packets[i]['Ethernet'].src) == 0:
                hackedMAC.append(packets[i]['Ethernet'].src)
                hackedIP.append(packets[i]['ARP'].psrc)
    i += 1

for packet in packets:                      # used to find hacker's IP address
    if packet.haslayer('ARP'):
        if packet['Ethernet'].src == packet['ARP'].hwsrc:
            if packet['Ethernet'].src == hackerMAC:
                hackerIP = packet['ARP'].psrc

print("The MAC address of the hacker is: " + hackerMAC)
print("The IP address of the hacker is: " + hackerIP)
print()
print("The MAC address of the first target computer is: " + hackedMAC[0])
print("The IP address of the first target computer is: " + hackedIP[0])
print()
print("The MAC address of the second target computer is: " + hackedMAC[1])
print("The IP address of the second target computer is: " + hackedIP[1])
print()
print("The total number of spoofing packets from the hacker is: " + str(numberSpoof))

