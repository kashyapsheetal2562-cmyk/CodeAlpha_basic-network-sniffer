from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[+] Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")

        # Check for TCP/UDP layers
        if TCP in packet:
            print(f"   TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"   UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

        # Print payload if available
        if Raw in packet:
            print(f"   Payload: {packet[Raw].load[:50]}")  # limit output

# Capture packets (Ctrl+C to stop)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
