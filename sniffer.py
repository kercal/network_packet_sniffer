from scapy.all import sniff, IP, TCP, UDP, Raw

# Protocol number to name mapping
protocol_map = {
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    132: "SCTP"
}

# Function to process each captured packet
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        protocol_name = protocol_map.get(protocol, "Other")
        src_port = "-"
        dst_port = "-"

        if protocol_name == "TCP":
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Check if the packet contains HTTP data
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:  # HTTP typically runs on port 80
                if Raw in packet:
                    http_data = packet[Raw].load.decode(errors="ignore")  # Decode packet payload
                    if "HTTP" in http_data:  # Check if it's an HTTP packet
                        protocol_name = "HTTP"
                        print(f"{protocol_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
                        print(http_data)  # Print HTTP request/response data
                        with open("packet_log.txt", "a") as log_file:
                            log_file.write(f"{protocol_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}\n")
                            log_file.write(f"{http_data}\n\n")
                        return

        elif protocol_name == "UDP":
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(f"{protocol_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        # Log packet data to a file
        with open("packet_log.txt", "a") as log_file:
            log_file.write(f"{protocol_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}\n")

# Function to start sniffing
def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on interface {interface}")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    # Specify the network interface (e.g., 'eth0', 'wlan0')
    interface = "eth0"  # Change this to the correct interface for your system
    start_sniffing(interface)
