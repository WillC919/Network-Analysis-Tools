External Libaraies Used:
- dpkt


To run the analysis_pcap_arp.py file simply type in the command prompt

C:\pathway\lee-william-assignment3> python analysis_pcap_arp.py

After entering the command above, it'll ask for the pathway for a pcap file you want to analyze.

Enter filename: assignment4_my_arp.pcap

After entering the pathway to the pcap file it should output something like this below

====================== ARP Exchange 1 ======================

----------------------- ARP Request ------------------------
Hardware Type:                   1
Protocol Type:                   0x0800
Hardware Size:                   6
Protocol Size:                   4
Opcode:                          1
Sender Mac Address:              4::56::e5::47::18::9b
Sender IP Address:               172.24.89.78
Target Mac Address:              0::0::0::0::0::0
Target IP Address:               172.24.80.1


----------------------- ARP Response -----------------------
Hardware Type:                   1
Protocol Type:                   0x0800
Hardware Size:                   6
Protocol Size:                   4
Opcode:                          2
Sender Mac Address:              aa::bb::cc::dd::ee::ff
Sender IP Address:               172.24.80.1
Target Mac Address:              4::56::e5::47::18::9b
Target IP Address:               172.24.89.78

If there is no complete ARP Packet Exchange in the pcap file, then it'll output "No Complete ARP Packets Exchange to analyze"


The logic behind the code for obtaining the headers for ARP Packet and printing out one ARP Packet Exhange follows these steps:

1. For each packet in the pcap file that was read using dpkt.pcap.Reader, check for the packet's length greater or equal to 28 bytes and Check if the packet at byte index 12 to 13 matches (these positions in the packet tell us what type the packet is) with the value 2054 (The value that indicates the packet is an ARP packet) to be considered an ARP packet.
2. Then parse down the packets of byte index position 14 to 42 into their respective ARP Header's attributes and convert the bytes to more human-readable values like integers.
	a. If the opcode is a request, value 1, and the packet is not an announcement (both the sender and the target address are the same), save the entire ARP's header information somwhere
	b. else If the opcode is a response, value 2, then find the earliest match with the ARP packet request's target address with this ARP packet response sender's address
		i. If there is a match, then save the current ARP Header's attributes near its respective match 
		ii. Then print out the entire exchange using the saved information