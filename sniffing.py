from scapy.all import sniff

def start_sniffing(callback):
    print("[*] Starting live packet sniffing...")
    sniff(prn=callback, store=0)
