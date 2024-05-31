import argparse
import socket
import threading
from scapy.all import *

# Function to handle packet forwarding
def forward_packet(packet, target_ip, target_port):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)

        if ip_layer.dst == target_ip and tcp_layer.dport == target_port:
            print(f"Intercepted packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            modified_packet = packet.copy()

            # Modify packet here if needed
            modified_packet.show()

            # Forward packet
            send(modified_packet)

def start_sniffing(interface, target_ip, target_port):
    sniff(iface=interface, prn=lambda packet: forward_packet(packet, target_ip, target_port))

def main():
    parser = argparse.ArgumentParser(description="Simple MITM Proxy")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-t", "--target-ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--target-port", type=int, required=True, help="Target port")
    args = parser.parse_args()

    print(f"Starting sniffing on {args.interface} for {args.target_ip}:{args.target_port}...")
    threading.Thread(target=start_sniffing, args=(args.interface, args.target_ip, args.target_port)).start()

if __name__ == "__main__":
    main()
