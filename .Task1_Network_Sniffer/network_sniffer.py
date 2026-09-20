from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):
    print("\n" + "=" * 60)
    print("PACKET CAPTURED")
    print("=" * 60)

    if IP in packet:
        print(f"Source IP       : {packet[IP].src}")
        print(f"Destination IP  : {packet[IP].dst}")

        if TCP in packet:
            print("Protocol        : TCP")
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol        : UDP")
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol        : ICMP")

        else:
            print("Protocol        : Other")

        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            print(f"Payload         : {payload[:50]}")

    else:
        print("Non-IP packet captured")


print("=" * 60)
print("       CODEALPHA NETWORK SNIFFER")
print("=" * 60)
print("Capturing packets...")
print("Press CTRL+C to stop.")
print("=" * 60)

sniff(prn=packet_callback, store=False)
