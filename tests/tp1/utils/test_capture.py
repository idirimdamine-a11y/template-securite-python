from scapy.all import ARP, IP, TCP, Raw

from src.tp1.utils.capture import Capture


def test_capture_init():
    capture = Capture()
    assert capture.packets == []
    assert capture.alerts == []
    assert capture.flag is None
    assert capture.summary == ""


def test_get_all_protocols():
    capture = Capture()
    capture.packets = [IP() / TCP(), IP() / TCP(), ARP()]
    result = capture.get_all_protocols()
    assert result["TCP"] == 2
    assert result["ARP"] == 1


def test_sort_network_protocols():
    capture = Capture()
    capture.packets = [ARP(), IP() / TCP()]
    result = capture.sort_network_protocols()
    assert list(result.keys()) == ["ARP", "IP", "TCP"]

def test_add_alert_no_duplicate():
    capture = Capture()
    capture._add_alert("port_scan", "10.0.0.1")
    capture._add_alert("port_scan", "10.0.0.1")
    assert len(capture.alerts) == 1


def test_analyse_detects_port_scan():
    capture = Capture()
    capture.packets = [
        IP(src="10.0.0.9", dst="10.0.0.1") / TCP(dport=p, flags="S")
        for p in range(1000, 1025)
    ]
    capture.analyse()
    assert {"type": "port_scan", "attacker": "10.0.0.9"} in capture.alerts


def test_analyse_detects_arp_spoofing():
    capture = Capture()
    capture.packets = [
        ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
        ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb"),
    ]
    capture.analyse()
    types = [a["type"] for a in capture.alerts]
    assert "arp_spoofing" in types


def test_analyse_detects_sql_injection_and_flag():
    payload = b"GET /login?user=admin' OR 1=1-- &token=ESGI{test_flag} HTTP/1.1"
    capture = Capture()
    capture.packets = [IP(src="10.0.0.5") / TCP() / Raw(load=payload)]
    capture.analyse()
    assert {"type": "sql_injection", "attacker": "10.0.0.5"} in capture.alerts
    assert capture.flag == "ESGI{test_flag}"


def test_capture_traffic_from_pcap(tmp_path):
    from scapy.all import ICMP, IP, wrpcap
    pcap_path = tmp_path / "test.pcap"
    wrpcap(str(pcap_path), [IP() / ICMP()])
    capture = Capture(pcap_file=str(pcap_path))
    capture.capture_traffic()
    assert len(capture.packets) == 1

def test_get_summary():
    capture = Capture()
    capture.summary = "resume"
    assert capture.get_summary() == "resume"


def test_gen_summary():
    capture = Capture()
    assert capture._gen_summary() == ""