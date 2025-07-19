from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if IP in packet and packet.haslayer(TCP):
        print("\n📦 New Packet Captured:")
        print(f"🔹 Source IP: {packet[IP].src}")
        print(f"🔹 Destination IP: {packet[IP].dst}")
        print(f"🔸 Protocol: TCP")
        print(f"    Source Port: {packet[TCP].sport}")
        print(f"    Destination Port: {packet[TCP].dport}")
        if packet.haslayer(Raw):
            try:
                print("🔍 Payload:", packet[Raw].load.decode(errors='ignore'))
            except:
                print("🔍 Payload (binary):", packet[Raw].load)

print("🔐 Sniffing 1 TCP packets...")
sniff(prn=process_packet, store=False, count=1, filter="tcp")
