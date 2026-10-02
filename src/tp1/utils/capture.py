import re

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap, sniff
from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap_file: str | None = None) -> None:
        self.pcap_file = pcap_file
        self.interface = None
        self.summary = ""
        self.packets = []
        self.alerts = []
        self.flag = None

    def capture_traffic(self) -> None:
        """
        Charge le trafic : depuis un PCAP (correction) ou en live (dev).
        """
        if self.pcap_file:
            logger.info(f"Lecture du fichier PCAP {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
        else:
            self.interface = choose_interface()
            logger.info(f"Capture live sur {self.interface}")
            self.packets = sniff(iface=self.interface, count=10)

        logger.info(f"{len(self.packets)} paquets chargés")

    def get_all_protocols(self) -> dict:
        """Compte chaque couche protocolaire présente dans les paquets."""
        counts = {}
        for pkt in self.packets:
            if pkt.haslayer(Ether):
                counts["ETHERNET"] = counts.get("ETHERNET", 0) + 1
            if pkt.haslayer(IP):
                counts["IP"] = counts.get("IP", 0) + 1
            if pkt.haslayer(ARP):
                counts["ARP"] = counts.get("ARP", 0) + 1
            if pkt.haslayer(TCP):
                counts["TCP"] = counts.get("TCP", 0) + 1
                if pkt.haslayer(Raw) and 80 in (pkt[TCP].sport, pkt[TCP].dport):
                    counts["HTTP"] = counts.get("HTTP", 0) + 1
            if pkt.haslayer(UDP):
                counts["UDP"] = counts.get("UDP", 0) + 1
            if pkt.haslayer(ICMP):
                counts["ICMP"] = counts.get("ICMP", 0) + 1
            if pkt.haslayer(DNS):
                counts["DNS"] = counts.get("DNS", 0) + 1
        return counts

    def sort_network_protocols(self) -> dict:
        protocols = self.get_all_protocols()
        return dict(sorted(protocols.items()))

    def _add_alert(self, attack_type: str, attacker: str) -> None:
        """Ajoute une alerte sans doublon."""
        alert = {"type": attack_type, "attacker": attacker}
        if alert not in self.alerts:
            self.alerts.append(alert)
            logger.warning(f"{attack_type} détecté : {attacker}")

    def analyse(self, protocols: str | None = None) -> None:
        """
        Analyse le trafic et détecte les attaques :
        - scan de ports
        - ARP spoofing
        - injection SQL (et extraction du flag)
        """
        self.alerts = []
        syn_ports = {}
        arp_macs = {}
        sql_patterns = [b"or 1=1", b"union select", b"sqlmap", b"' or '"]

        for pkt in self.packets:

            # Scan de ports : SYN seul vers un port
            if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
                src = pkt[IP].src
                port = pkt[TCP].dport
                syn_ports.setdefault(src, set()).add(port)

            # ARP spoofing : reponse ARP (op == 2)
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                arp_macs.setdefault(ip, set()).add(mac)

            # Injection SQL : motifs techniques dans le contenu HTTP
            if pkt.haslayer(Raw) and pkt.haslayer(IP):
                payload = bytes(pkt[Raw].load)
                data = payload.lower()
                if any(p in data for p in sql_patterns):
                    src = pkt[IP].src
                    self._add_alert("sql_injection", src)
                    # le vrai flag est dans le paquet d'attaque
                    match = re.search(rb"ESGI\{[^}]+\}", payload)
                    if match:
                        self.flag = match.group().decode()

        # Conclusion scan
        for ip, ports in syn_ports.items():
            if len(ports) > 20:
                self._add_alert("port_scan", ip)

        # Conclusion ARP spoofing
        for ip, macs in arp_macs.items():
            if len(macs) > 1:
                for mac in macs:
                    self._add_alert("arp_spoofing", mac)

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        summary = ""
        return summary