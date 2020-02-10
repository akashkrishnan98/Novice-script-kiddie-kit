#!/usr/bin/python

import scapy.all as scapy
import argparse


def get_ip_range():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the IP range")
    arguments= parser.parse_args()
    if not arguments:
        parser.error()
    else:
        return arguments.target


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict={"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(scan_result):
    print("IP Address\tMAC address\n----------------------------")
    for client in scan_result:
        print(client["ip"]+"\t"+client["mac"])


ip_range = get_ip_range()
scan_result = scan(ip_range)
print_result(scan_result)
