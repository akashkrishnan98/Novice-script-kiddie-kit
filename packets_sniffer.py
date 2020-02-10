import scapy.all as scapy
import scapy.layers.http as http

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_sniffed)

def packet_sniffed(packet):
    if packet.haslayer(http.HTTPRequest):
        path= packet['HTTP Request'].Path.decode()
        domain = packet['HTTP Request'].Host.decode()
        print(domain+path)
    if packet.haslayer(packet.Raw):
        credentials = packet['Raw'].load.decode()
        print(credentials.decode())


sniff_packets("eth0")