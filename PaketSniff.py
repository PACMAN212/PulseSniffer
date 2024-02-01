from io import StringIO
import sys
import re
import scapy.all as spy
import datetime
from PyQt5.QtCore import QObject, pyqtSignal
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

class PaketSniff(QObject):
    packet_received = pyqtSignal(dict, list, str)

    def __init__(self):
        super().__init__()
        self.all_detailed_packets = []
        self.all_summary_packets = []
        self.all_hex_packets = []
        self.packet_id = 0
        self.s_timeout = None
        self.s_count = 0
        self.filter = None
        self.s_stop = False
        self.start_time = datetime.datetime.today()
        self.all_sniffed_packets = []

    def start_sniffing(self):
        self.s_stop = False
        try:
            spy.sniff(
                prn=self.process_packet,
                timeout=self.s_timeout,
                count=self.s_count,
                stop_filter=self.should_stop,
                filter=self.filter
            )
        except NameError:
            pass
        print("Done Sniffing")

    def should_stop(self, _):
        return self.s_stop

    def stop_sniffing(self):
        self.s_stop = True

    def process_packet(self, sniffed_pkt):
        try:
            pkt_lines = self.get_show_data(sniffed_pkt)
            protocol_lines = [i for i, word in enumerate(pkt_lines) if re.search(r'###\[ .* \]###', word)]
            self.all_sniffed_packets.append(sniffed_pkt)
            if not protocol_lines or len(protocol_lines) < 2:
                print("Invalid packet format. Skipping...")
                return

            pkt_details = self.analyze_layers(protocol_lines, pkt_lines)
            hx = self.get_hex_data(sniffed_pkt, spy.hexdump)

            if not hx:
                print("Hex data not available. Skipping...")
                return

            hx = "\n".join(hx)
            sry = self.parse_summary(sniffed_pkt)

            self.all_detailed_packets.append(pkt_details)
            self.all_hex_packets.append(hx)
            self.all_summary_packets.append(sry)

            self.packet_id += 1
            self.packet_received.emit(
                self.all_summary_packets[-1],
                self.all_detailed_packets[-1],
                self.all_hex_packets[-1]
            )

        except Exception as e:
            print(f"Error processing packet {self.packet_id}: {e}")
            print(sniffed_pkt.show2())

    def analyze_layers(self, protocol_lines, pkt_lines):
        pkt_details = []
        for i in range(len(protocol_lines) - 1):
            single_layer = pkt_lines[protocol_lines[i]:protocol_lines[i + 1]]
            pkt_details.append(self.analyze_layer(single_layer))
        single_layer = pkt_lines[protocol_lines[-1]:]
        pkt_details.append(self.analyze_layer(single_layer))
        return pkt_details

    def analyze_layer(self, layer_list):
        if not layer_list or len(layer_list) < 2:
            return layer_list

        if layer_list[0] == "###[ Raw ]###":
            if "HTTP/1." in layer_list[1] or "GET" in layer_list[1] or "POST" in layer_list[1]:
                return self.parse_http(layer_list)

        for i in range(1, len(layer_list)):
            s = layer_list[i].split("=", 1)
            s = list(map(str.strip, s))
            if len(s) < 2:
                layer_list[i] = ("", s[0])
                continue
            layer_list[i] = (s[0], s[1])

        return layer_list

    def parse_http(self, raw_tcp):
        fields = raw_tcp[1].split("=", 1)[1].split("\\r\\n\\r\\n", 1)
        load = "" if len(fields) != 2 else fields[1]
        http = fields[0].split("\\r\\n")
        out = [("HTTP", x) for x in http]
        out.append(("Load", load))
        return ["HTTP"] + out

    def parse_summary(self, pkt):
        t = datetime.datetime.now().strftime("%H:%M:%S.%f")
        summary_dict = {
            "ID": self.packet_id,
            "Time": t,
            "Length": len(pkt),
            "Info": pkt.summary()
        }
        source, destination, protocol = self.extract_packet_info(pkt)
        summary_dict.update({
            "Source": source,
            "Destination": destination,
            "Protocol": protocol.strip()
        })
        return summary_dict

    def extract_packet_info(self, pkt):
        source, destination, protocol = "", "", ""
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer:
            source, destination = ip_layer.src, ip_layer.dst
            protocol = pkt.lastlayer().name.strip()
        else:
            ether_layer = pkt.getlayer(Ether)
            if ether_layer:
                source, destination = ether_layer.src, ether_layer.dst
                protocol = pkt.lastlayer().name.strip()
        return source, destination, protocol

    def read_pcap_file(self, file_path="example_network_traffic.pcap"):
        packets = spy.rdpcap(file_path)
        for one in packets:
            self.process_packet(one)

    def write_into_pcap(self, file_path_name="test.pcap"):
        spy.wrpcap(file_path_name, self.all_sniffed_packets)  # Tüm sniffed paketleri kaydettik
        print(f"Packets saved to {file_path_name}")

    def refresh(self):
        self.all_detailed_packets = []
        self.all_summary_packets = []
        self.all_hex_packets = []
        self.packet_id = 0

    def get_show_data(self, packet):
        s = StringIO()
        sys.stdout = s
        packet.show()
        sys.stdout = sys.__stdout__
        full_str_list = s.getvalue().splitlines()
        return full_str_list

    def get_hex_data(self, packet, func):
        s = StringIO()
        sys.stdout = s
        func(packet)
        sys.stdout = sys.__stdout__
        full_str_list = s.getvalue().splitlines()
        return full_str_list
