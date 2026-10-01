from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, rdpcap, TCP, UDP, ICMP, ARP, IP, Raw

class Capture:
    def __init__(self, pcap_file: str = None) -> None:
        self.pcap_file = pcap_file
        self.interface = None
        self.summary = ""
        self.packets = []
        self.alerts = []
    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        if self.pcap_file:
            logger.info(f"Lecture du fichier PCAP {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
        else:
            self.interface = choose_interface()
            logger.info(f"Capture live sur {self.interface}")
            self.packets = sniff(iface=self.interface, count=10)

        logger.info(f"{len(self.packets)} paquets chargés")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        protocols = self.get_all_protocols()

        return dict(sorted(protocols.items()))

    def get_all_protocols(self) -> str:
        counts = {}
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                proto = "TCP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
            elif pkt.haslayer(ARP):
                proto = "ARP"
            else:
                proto = "Other"

            counts[proto] = counts.get(proto, 0) + 1

        return counts

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
