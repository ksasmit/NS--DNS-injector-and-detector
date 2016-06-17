#!/usr/bin/env python
import argparse
import logging
import os
from scapy.all import *
import sys, getopt
from collections import deque

packet_q = deque(maxlen = 10)

def dns_detect(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
        if len(packet_q)>0:
            for op in packet_q:
                if op[IP].dst == pkt[IP].dst and\
                op[IP].sport == pkt[IP].sport and\
                op[IP].dport == pkt[IP].dport and\
                op[DNSRR].rdata != pkt[DNSRR].rdata and\
                op[DNS].id == pkt[DNS].id and\
                op[DNS].qd.qname == pkt[DNS].qd.qname and\
                op[IP].payload != pkt[IP].payload:
                    print "DNS poisoning attempt detected"
                    print "TXID %s Request URL %s"%( op[DNS].id, op[DNS].qd.qname.rstrip('.'))
                    print "Answer1 [%s]"%op[DNSRR].rdata
                    print "Answer2 [%s]"%pkt[DNSRR].rdata
        packet_q.append(pkt)

def title():
    print "DNS detector"
    return

def main(argv):
    title()
    interface=''
    tracefile=''
    expression=''
    flagi=0
    flagt=0
    flage=0
    try:
        opts, args = getopt.getopt(argv, 'i:r::')
    except getopt.GetoptError:
        print "Invalid entry/entries"
        print "dnsdetect [-i interface] [-r tracefile] expression"
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-i':
            interface = arg
            flagi=1
        elif opt == '-r':
            tracefile = arg
            flagt =1
    
    if len(args) == 1:
        expression = args[0]
        flage=1
    elif len(args) >1:
        print "Too many expressions"
        sys.exit()
    if flagi ==1 and flagt ==1:
        print "Enter one argument only :either the interface or the pcap filename"
        sys.exit()
    elif flagi ==0 and flagt==1:
        print "Sniffing from the tracefile"
        sniff(filter=expression, offline = tracefile, store=0, prn=dns_detect)
    elif flagi==1:
        print "Sniffing on interface"
        sniff(filter=expression, iface=interface, store=0, prn=dns_detect)
    else:
        print "sniffing on all interfaces"
        sniff(filter=expression, store=0, prn=dns_detect)

    
if __name__ == '__main__':
    main(sys.argv[1:])