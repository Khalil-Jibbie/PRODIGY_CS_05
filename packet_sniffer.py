from scapy.all import sniff, IP, TCP, UDP
import sys

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine the protocol
        if proto == 6:
            protocol = "TCP"
            if TCP in packet:
                tcp_layer = packet[TCP]
                payload = bytes(tcp_layer.payload)
            else:
                payload = b''
        elif proto == 17:
            protocol = "UDP"
            if UDP in packet:
                udp_layer = packet[UDP]
                payload = bytes(udp_layer.payload)
            else:
                payload = b''
        else:
            protocol = "Other"
            payload = b''

        # Display packet information
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        print(f"Payload: {payload}\n")

def main(interface):
    print(f"Starting packet sniffer on interface {interface}...\n")
    # Sniff packets on the given interface, without a timeout
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    main(interface)
