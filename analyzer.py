from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.utils import PcapReader
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.dns import DNS 



def init_data(data:dict,ip:str="") -> dict:
    data.setdefault("IPs",{})
    if ip != "":
        data["IPs"][ip] = {
            "packet_count":1,
            "targeted_hosts":[],
            "ICMP_targets":[],
            "redirect_detected":False,
            "unreachable_count":0,
            "TCP_ports_scanned":[],
            "UDP_ports_scanned":[],
            "DNS_tuneling_atempts":0
        }
    return data

def analyze_pcap_IP(pac:Packet, data:dict) -> dict: # Note this func should run first in main.py
    if pac.haslayer(IP):
        # Grabbing the source and destination ip from the packet
        src_ip = pac[IP].src
        dst_ip = pac[IP].dst

        # Checking if the ip is already in the dict 
        if src_ip in data["IPs"]:
            data["IPs"][src_ip]["packet_count"] += 1
            # Checking if dst_ip is not in the list
            if dst_ip not in data["IPs"][src_ip]["targeted_hosts"]:
                data["IPs"][src_ip]["targeted_hosts"].append(dst_ip)
        else:
            data = init_data(data,src_ip)
            data["IPs"][src_ip]["targeted_hosts"].append(dst_ip)

    return data


def analyze_pcap_ICMP(pac:Packet,data:dict) -> dict:
    if pac.haslayer(ICMP) and pac.haslayer(IP): # i realized there is IPv6 which maybe doesnt have the IP layer thats why we check to prevet keyerros
        # Grabbing the source and destination ip from the packet
        src_ip = pac[IP].src
        dst_ip = pac[IP].dst
        src_type = pac[ICMP].type

        # making sure the key exists
        data["IPs"].setdefault(src_ip, {})

        # type 8 is echo request keeping a list of uniqe ip pinged
        if src_type == 8:
            data["IPs"][src_ip].setdefault("ICMP_targets", [])
            # checking if dst_ip already exists
            if dst_ip not in data["IPs"][src_ip]["ICMP_targets"]:
                data["IPs"][src_ip]["ICMP_targets"].append(dst_ip)

        # type 5 redirect possible man in the middle attack
        elif src_type == 5:
            data["IPs"][src_ip].setdefault("redirect_detected", False)
            data["IPs"][src_ip]["redirect_detected"] = True
        
        # type 3 destination unreachble possible DDOS attack
        elif src_type == 3:
            data["IPs"][src_ip].setdefault("unreachable_count", 0)
            # checking if the key exitsts
            data["IPs"][src_ip]["unreachable_count"] += 1

    return data


def analyze_pcap_TCP(pac:Packet,data:dict) -> dict:
    if pac.haslayer(TCP) and pac.haslayer(IP):
        src_ip = pac[IP].src
        flags_ip = pac[TCP].flags
        port = pac[TCP].dport
        data["IPs"].setdefault(src_ip, {})
        # Checking if the flag of packet is SYN
        if "S" in flags_ip:
            if port <=  32768: # This filters out dynamic ports
                data["IPs"][src_ip].setdefault("TCP_ports_scanned", [])
                # checking if port already exists
                if port not in data["IPs"][src_ip]["TCP_ports_scanned"]:
                    data["IPs"][src_ip]["TCP_ports_scanned"].append(port)

    return data


def analyze_pcap_UDP(pac:Packet,data:dict) -> dict:
    if pac.haslayer(UDP) and pac.haslayer(IP):
        src_ip = pac[IP].src
        port = pac[UDP].dport
        data["IPs"].setdefault(src_ip, {})

        if port <=  32768: # This filters out dynamic ports
            data["IPs"][src_ip].setdefault("UDP_ports_scanned", [])
            # checking if port already exists
            if port not in data["IPs"][src_ip]["UDP_ports_scanned"]:
                data["IPs"][src_ip]["UDP_ports_scanned"].append(port)

    return data
           


def analyze_pcap_DNS(pac:Packet,data:dict) -> dict:
    if pac.haslayer(DNS) and pac.haslayer(IP):
        src_ip = pac[IP].src
        data["IPs"].setdefault(src_ip, {})

        try: # DNS query might not be present if it is an answer
            dns_query = pac["DNS"].qd.qname
            data["IPs"][src_ip].setdefault("DNS_tuneling_atempts", 0)
            # checking query lentgh if it is equal or more than 200 possible dns tuneling atempt
            # if the dns tuenling atempt is lower then 200 bytes the tool wont catch it out of scope for v1
            if len(dns_query) >= 200:
                    data["IPs"][src_ip]["DNS_tuneling_atempts"] += 1

        except AttributeError: # If it is an answer we skip it
            pass
    return data 

def analyze_pcap_file(filename: str, data: dict) -> dict:
    with PcapReader(filename) as pcap_stream:
        for pac in pcap_stream:
            analyze_pcap_IP(pac, data)
            analyze_pcap_ICMP(pac, data)
            analyze_pcap_TCP(pac, data)
            analyze_pcap_UDP(pac, data)
            analyze_pcap_DNS(pac, data)
    return data
