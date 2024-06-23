from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process each captured packet
def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(packet[IP].proto, str(packet[IP].proto))

    print(f"Source: {src_ip} | Destination: {dst_ip} | Protocol: {protocol}")

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        src_port = transport_layer.sport
        dst_port = transport_layer.dport
        layer_type = "TCP" if packet.haslayer(TCP) else "UDP"
        print(f"{layer_type} Src Port: {src_port} | {layer_type} Dst Port: {dst_port}")

        if packet.haslayer(Raw):
            try:
                payload_data = packet[Raw].load.decode('utf-8', 'ignore')
                print(f"{layer_type} Payload: {payload_data}")
            except UnicodeDecodeError:
                print(f"{layer_type} Payload: <unprintable>")

    print("-" * 40)

# Function to start packet sniffing
def start_sniffing(interface=None):
    iface_msg = f" on interface: {interface}" if interface else " on default interface"
    print(f"Sniffing{iface_msg}")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    import sys
    interface = sys.argv[1] if len(sys.argv) == 2 else None
    start_sniffing(interface)
