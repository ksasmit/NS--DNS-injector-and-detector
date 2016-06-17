					Name:Kumar Sasmit
					SBU ID: 110308698
					CSE508: Network Security, Spring 2016

					Homework 4: DNS Packet Injection
------------------------------------------------------------------------------------------------------------------------------------------
Short Description:
--------------------------


Part 1: On-path DNS packet injector

The dnsinjector "dnsinject" captures the trafic from the network interface in promiscuous mode and for injects forged response for selected DNS requests 

Format:
dnsinject [-i interface] [-f hostnames] expression

Where,

-i = interface (eg. eth0). If not specified all the interfaces are used for packet sniffing and injection

-f = takes a filename which has a list of pairs of IP and url addresses. The IP corresponding to a particular URL should be sent in the injected packet when a request for the URL is detected by the attacker. If the option is not specified, the injector sends replies to all DNS queries using his own IP.

10.6.6.6      foo.example.com
10.6.6.6      bar.example.com
192.168.66.6  www.cs.stonybrook.edu

<expression> = BPF filter. This is optional and includes information about victim(s) to be monitored. I have included only IP addresss for checks. This can be one or more strings separated by whitespaces (please check assumptions)





Part -2 DNS poisoning attack detector

It captures the traffic in promiscuous mode and detects any DNS poisoning attack attempts.

Format:
dnsdetect [-i interface] [-r tracefile] expression

Where,
-i = interface (e.g. eth0). If not specified all the interfaces are scanned.

-r = Read packets from <tracefile>. Tracefile must be in pcap format, otherwise an exception occurs.

<expression> is a BPF filter that specifies a subset of the traffic to be monitored. here ('udp port 53'). For detector it must be a single string (in quotes if multiple)

Once an attack is detected, dnsdetect prints Detected DNS transaction ID, attacked domain name, and the original and malicious IP addresses

DNS poisoning attempt
TXID xxxx Request www.xxxxx.com
Answer1 [List of IP addresses]
Answer2 [List of IP addresses]





Implementation Details:
---------------------------------------------------------------------------------------------------------
The Programs have been written in Python using Scapy library APIs

Part1:
All the packets are sniffed on the selcted interface(or all interfaces). The filter expression for udp has been hardcoded, Once found the call back function is called.
If the victim's IP has been entered, It is stored in a list. Also the hostname file is read for all the url to IP pairs. In the callback function, if the source ip from packet matches with that in the bpf filter, A forged packet with appropriate layers is created using scapy APIs and sent to the victim as response

Part2:
All the packets are sniffed at the victim in promiscous mode for online mode. For offline mode the pcap file is scanned(It must be an appropriate pcap format file). The callback function is called. A deque data-structure has been used which holds last 10 received packets.
A comparison of all fields is made in the callback function to detect if the packet is a forged response. Once found appropriate message with required details are printed on the stdout.
Whenever a packet is received it is compared with all the packets in the queue. When a packet is received with same destination IP, source port, Destination port,  transaction ID, Request URL, But different response IP and payload as compared to a packet already present in the queue, It is declared to be forged and the appropriate fields are printed to the stdout.



Assumptions:
------------------
**The IP address of the Injector machine has been hardcoded. For execution on any other system it should be changed accordingly before executing.

**BPF Filter for injector should be one or more strings separated by whitespace. Please do not enter 'udp port 53' as a part of BPF filter since the entire implementation is for UDP and DNS so it should not be a part of expression. Only source IP has been added for filtering. Other fields too can be included very easily by making single line changes in the code, But I have not included any field other than victim's IP.

**BPF filter for detector should include 'udp port 53' or any other filter as per the standards. No custom filter has been added



For compilation and Execution:
----------------
Injector:
For all interfaces:
sudo python dnsinject.py

For eth0 interface with hostname and bpf filter
sudo python dnsinject.py -i eth0 -f hostname 192.168.217.132

For eth0 interface and bpf filter
sudo python dnsinject.py -i eth0 192.168.217.132

For eth0 interface for all packets
sudo python dnsinject.py -i eth0


Detector:

For all interfaces and dns traffic
sudo python dnsdetect.py 'udp port 53'

For ens33 interface and dns traffic
sudo python dnsdetect.py -i ens33 'udp port 53'

For offline pcap file and dns traffic
sudo python dnsdetect.py -r mycap.pcap 'udp port 53'


To test run the following on detector side:
nslookup bar.example.com


Included files:
------------------
source file: dnsinject.py
dnsdetect.py
README.txt
hostname
hw4.pcapng(captured by wireshark, Not supported by scapy) This shows injection part
mycap.pcap(captured on the detector side, can be used with dnsdetector code as offline)
screenshots


Reference:
---------------
Various web resources for Python and Scapy

Scapy :
http://webcache.googleusercontent.com/search?q=cache:toxxyc2lBVEJ:danmcinerney.org/reliable-dns-spoofing-with-python-scapy-nfqueue/&num=1&hl=en&gl=us&strip=1&vwsrc=0