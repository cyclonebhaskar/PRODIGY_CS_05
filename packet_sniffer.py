from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("--------------------------------------------------")
    
    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")
        print(f"Packet Length  : {len(packet)} bytes")

        # TCP Details
        if packet.haslayer(TCP):
            print("Protocol Type  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        # UDP Details
        elif packet.haslayer(UDP):
            print("Protocol Type  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

def main():
    print("Packet Sniffer Started (Educational Mode)")
    print("Capturing 10 packets...\n")
    
    sniff(prn=packet_callback, count=10)

if __name__ == "__main__":
    main()
