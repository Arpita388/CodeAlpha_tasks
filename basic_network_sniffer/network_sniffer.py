from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import datetime

# Function to process captured packets
def process_packet(packet):
    print("\n" + "=" * 60)
    print(f"Packet Captured At: {datetime.datetime.now()}")
    print("=" * 60)

    # IP Layer Information
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

    # TCP Information
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]

        print("\n[TCP Packet]")
        print(f"Source Port    : {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")

    # UDP Information
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]

        print("\n[UDP Packet]")
        print(f"Source Port    : {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")

    # ICMP Information
    elif packet.haslayer(ICMP):
        print("\n[ICMP Packet]")

    # ARP Information
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]

        print("\n[ARP Packet]")
        print(f"Source MAC     : {arp_layer.hwsrc}")
        print(f"Destination MAC: {arp_layer.hwdst}")

# Start sniffing packets
print("Starting Network Sniffer...")
print("Press CTRL + C to stop.\n")

sniff(prn=process_packet, store=False)