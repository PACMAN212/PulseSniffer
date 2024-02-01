import os
import sys
from PyQt5 import QtWidgets
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QApplication, QMessageBox
from MainWindow import MainWindow
from PaketSniff import PaketSniff
from threading import Thread

class GUI_Detail(object):
    def __init__(self):
        super().__init__()
        self.app = QtWidgets.QApplication(sys.argv)
        self.MainWindow = QtWidgets.QMainWindow()
        self.ui = MainWindow()
        self.ui.setupUi(self.MainWindow)
        self.ui.ListView.horizontalScrollBar().setValue(self.ui.ListView.verticalScrollBar().minimum())
        self.ethernet_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.ui.DetailView.setHeaderHidden(True)
        self.ui.DetailView.setColumnCount(1)
        self.ethernet_view.setText(0, "Ethernet")
        self.ethernet_details = QtWidgets.QTreeWidgetItem(self.ethernet_view)

        self.ip_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.ip_view.setText(0, "Internet Protocol Version 4")
        self.ip_details = QtWidgets.QTreeWidgetItem(self.ip_view)

        self.tcp_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.tcp_view.setText(0, "Transimission Control Protocol")
        self.tcp_details = QtWidgets.QTreeWidgetItem(self.tcp_view)

        self.http_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.http_view.setText(0, "Hypertext Transfer Protocol")
        self.http_details = QtWidgets.QTreeWidgetItem(self.http_view)
        self.http_view.setHidden(True)
        self.ethernet_view.setHidden(True)
        self.ip_view.setHidden(True)
        self.tcp_view.setHidden(True)

        self.ui.ListView.setHeaderLabels(["ID", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.ui.ListView.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.ui.actionExit.triggered.connect(self.MainWindow.close)
        self.ui.actionOpen.triggered.connect(self.select_file)
        self.ui.actionSave.triggered.connect(self.save_file)
        self.ui.actionNew.triggered.connect(self.refresh_session)
        self.ui.actionToggle_FullScreen.triggered.connect(self.toggle_full_screen)

        self.packets_details = []
        self.packets_summary = []
        self.packets_hex = []

        self.sniffer = PaketSniff()
        self.sniffer.packet_received.connect(self.view_packet)
        self.ui.start_btn.clicked.connect(self.start_sniff)
        self.ui.stop_btn.clicked.connect(self.stop_sniff)
        self.ui.filter_btn.clicked.connect(self.filter)
        self.ui.ListView.itemClicked.connect(self.view_packet_details)
        self.MainWindow.show()
        self.ui.stop_btn.setEnabled(False)
        self.sniff_thread = None
        self.ui.actionExit.triggered.connect(self.exit_application)

        self.protocol_colors = {
            'Ethernet': QColor(0, 0, 255),  # Mavi
            'IP': QColor(255, 0, 0),  # Kırmızı
            'TCP': QColor(255, 255, 0),  # Sarı
            'UDP': QColor(0, 255, 0),  # Yeşil
            'DNS': QColor(255, 165, 0),  # Turuncu
            'Raw': QColor(255, 69, 0),  # Kırmızı-Portakal
            'ARP': QColor(128, 0, 128),  # Mor
            'ICMP': QColor(0, 128, 128),  # Teal
            # Ek protokoller buraya eklenebilir
        }

    def view_packet(self, packet_summary, packet_detail, packet_hex):
        if packet_summary['ID'] == 0:
            self.http_view.setHidden(False)
            self.ethernet_view.setHidden(False)
            self.ip_view.setHidden(False)
            self.tcp_view.setHidden(False)

        new_packet = QtWidgets.QTreeWidgetItem(self.ui.ListView)
        new_packet.setText(0, str(packet_summary['ID']))
        new_packet.setText(1, str(packet_summary['Time']))
        new_packet.setText(2, str(packet_summary['Source']))
        new_packet.setText(3, str(packet_summary['Destination']))
        new_packet.setText(4, str(packet_summary['Protocol']))
        new_packet.setText(5, str(packet_summary['Length']))
        new_packet.setText(6, str(packet_summary['Info']))

        self.packets_summary.append(packet_summary)
        self.packets_details.append(packet_detail)
        self.packets_hex.append(packet_hex)
        if packet_summary['ID'] == 0:
            self.ui.ListView.setCurrentItem(new_packet)
            self.view_packet_details()

        protocol_color = self.protocol_colors.get(packet_summary['Protocol'],
                                                  QColor(255, 255, 255))  # Varsayılan: Beyaz
        for i in range(7):  # Toplam 7 sütun var
            new_packet.setBackground(i, protocol_color)

    def view_packet_details(self):
        s = self.ui.ListView.selectedItems()
        if s:
            packet_no = int(s[0].text(0))
            self.ui.DetailView.clear()
            packet_details = self.packets_details[packet_no]
            for protocol in packet_details:
                tmp = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
                tmp.setText(0, self.header_rename(protocol[0]))
                for i in range(1, len(protocol[1:])):
                    tmp2 = QtWidgets.QTreeWidgetItem(tmp)
                    tmp2.setText(0, protocol[i][0] + " : " + protocol[i][1])
            self.ui.HexView.setText(self.packets_hex[packet_no])

    def header_rename(self, header):
        header = header.replace(']', '').replace('[', '').replace('###', '').replace(' ', '')

        for detail in self.packets_details:
            for protocol in detail:
                if protocol[0].lower() == header.lower():
                    return protocol[0]

        protocol_mapping = {
            'Ethernet': "Ethernet",
            'IP': "Internet Protocol Version 4",
            'TCP': 'Transmission Control Protocol',
            'UDP': 'User Datagram Protocol',
            'DNS': 'Domain Name Server',
            'Raw': 'Hypertext Transfer Protocol',
        }

        return protocol_mapping.get(header, header)

    def start_sniff(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniffer.stop_sniffing()
            self.sniff_thread.join()

        self.sniff_thread = Thread(target=self.sniffer.start_sniffing)
        self.sniff_thread.start()

        self.ui.start_btn.setEnabled(False)
        self.ui.stop_btn.setEnabled(True)
        self.ui.filter_btn.setEnabled(False)

    def stop_sniff(self):
        self.sniffer.stop_sniffing()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()

        self.ui.start_btn.setEnabled(True)
        self.ui.stop_btn.setEnabled(False)
        self.ui.filter_btn.setEnabled(True)


    def receive_packets(self, sniffed_packets, detailed_packets, summary_packets):
        self.view_packet(sniffed_packets[1])

    def filter(self):
        filter_text = self.ui.lineEdit.text().lower()  # Filtre metnini küçük harfe çevir
        for i in range(self.ui.ListView.topLevelItemCount()):
            item = self.ui.ListView.topLevelItem(i)
            protocol = item.text(4).lower()  # Protokol adını küçük harfe çevir
            if filter_text in protocol:
                item.setHidden(False)
            else:
                item.setHidden(True)

    def select_file(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self.MainWindow, "Open a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        if file_name[0]:
            self.sniffer.read_pcap_file(file_path=file_name[0])

    def save_file(self):
        file_name = QtWidgets.QFileDialog.getSaveFileName(self.MainWindow, "Save into a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        if file_name[0]:
            self.sniffer.write_into_pcap(file_path_name=file_name[0])


    def refresh_session(self):
        # Detay görünümünü temizle
        self.ui.DetailView.clear()

        # Liste görünümünü temizle
        self.ui.ListView.clear()

        # Hex görünümünü temizle
        self.ui.HexView.clear()

        # İlgili listeleri sıfırla
        self.packets_details.clear()
        self.packets_summary.clear()
        self.packets_hex.clear()

        # Sniffer'ı sıfırla
        self.sniffer.refresh()

        # Programı yeniden başlat
        self.restart_program()

    def restart_program(self):
        QApplication.quit()  # Mevcut uygulamayı kapat
        python = sys.executable
        os.execl(python, python, *sys.argv)

    def exit_application(self):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Save Confirmation")
        msg_box.setText("Do you want to save the captured packets before exiting?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.Yes)

        reply = msg_box.exec()

        if reply == QMessageBox.Yes:
            self.save_file()
        elif reply == QMessageBox.No:
            self.MainWindow.close()

    def toggle_full_screen(self):
        if self.MainWindow.isFullScreen():
            self.MainWindow.showNormal()
        else:
            self.MainWindow.showFullScreen()


if __name__ == "__main__":
    temp = GUI_Detail()
    sys.exit(temp.app.exec_())
