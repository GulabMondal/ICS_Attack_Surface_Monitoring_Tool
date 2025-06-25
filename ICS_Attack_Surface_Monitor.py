import sys
import os
import socket
import threading
import time
import psutil

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QVBoxLayout,
    QWidget, QHBoxLayout, QPushButton, QLineEdit, QLabel, QSplitter, QComboBox
)
from PyQt5.QtCore import pyqtSignal, QObject, Qt

from scapy.all import sniff, TCP, Raw
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

ICS_PORTS = [502, 20000, 2404]
SUSPICIOUS_STRINGS = [b'write', b'coil', b'function', b'force', b'stop', b'start']
SUSPICIOUS_PROCESSES = ['nmap', 'wireshark', 'hping', 'netcat', 'hydra']

class Logger(QObject):
    log_signal = pyqtSignal(str)
    conn_signal = pyqtSignal(str)
    iplist_signal = pyqtSignal(list)

    def log(self, message):
        self.log_signal.emit(message)

    def update_conn(self, message):
        self.conn_signal.emit(message)

    def update_iplist(self, iplist):
        self.iplist_signal.emit(iplist)

logger = Logger()

class MonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ICS Attack Surface & Firewall GUI")
        self.setGeometry(100, 100, 1150, 700)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)

        self.conn_area = QTextEdit()
        self.conn_area.setReadOnly(True)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter port (e.g. 7777)")

        self.ip_filter_input = QLineEdit()
        self.ip_filter_input.setPlaceholderText("Allowed IPs comma-separated (e.g. 192.168.1.10)")

        self.start_button = QPushButton("Start Port Server")
        self.stop_button = QPushButton("Stop Port Server")
        self.stop_button.setEnabled(False)

        self.ip_dropdown = QComboBox()
        self.block_button = QPushButton("Block Selected IP")

        self.start_button.clicked.connect(self.start_firewall_server)
        self.stop_button.clicked.connect(self.stop_firewall_server)
        self.block_button.clicked.connect(self.block_selected_ip)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Port:"))
        top_layout.addWidget(self.port_input)
        top_layout.addWidget(QLabel("Allowlist IPs:"))
        top_layout.addWidget(self.ip_filter_input)
        top_layout.addWidget(self.start_button)
        top_layout.addWidget(self.stop_button)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(QLabel("Block IP:"))
        bottom_layout.addWidget(self.ip_dropdown)
        bottom_layout.addWidget(self.block_button)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.text_area)
        splitter.addWidget(self.conn_area)
        splitter.setSizes([400, 300])

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
        main_layout.addWidget(QLabel("Live Logs and Connections"))
        main_layout.addWidget(splitter)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        logger.log_signal.connect(self.append_log)
        logger.conn_signal.connect(self.update_connection_list)
        logger.iplist_signal.connect(self.update_ip_dropdown)

        self.server_socket = None
        self.server_thread = None
        self.allowed_ips = []
        self.blocked_ips = set()

        threading.Thread(target=self.track_connections, daemon=True).start()

    def append_log(self, message):
        self.text_area.append(message)

    def update_connection_list(self, content):
        self.conn_area.setPlainText(content)

    def update_ip_dropdown(self, iplist):
        self.ip_dropdown.clear()
        self.ip_dropdown.addItems(sorted(set(iplist)))

    def start_firewall_server(self):
        try:
            port = int(self.port_input.text())
            ip_str = self.ip_filter_input.text()
            self.allowed_ips = [ip.strip() for ip in ip_str.split(",") if ip.strip()]
            self.server_thread = threading.Thread(target=self.run_server, args=(port,), daemon=True)
            self.server_thread.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            logger.log(f"[Firewall] Server started on port {port}")
        except Exception as e:
            logger.log(f"[Error] Could not start server: {e}")

    def stop_firewall_server(self):
        if self.server_socket:
            self.server_socket.close()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        logger.log("[Firewall] Server stopped.")

    def run_server(self, port):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            while True:
                client_socket, addr = self.server_socket.accept()
                client_ip = addr[0]
                if client_ip in self.blocked_ips:
                    logger.log(f"[Blocked] Permanently blocked IP tried to connect: {client_ip}")
                    client_socket.close()
                    continue
                if self.allowed_ips and client_ip not in self.allowed_ips:
                    logger.log(f"[Blocked] Unauthorized connection from {client_ip}")
                    client_socket.send(b"Access Denied\n")
                    client_socket.close()
                else:
                    logger.log(f"[Allowed] Connection accepted from {client_ip}")
                    client_socket.send(b"Connected to ICS HMI\n")
        except OSError:
            pass
        except Exception as e:
            logger.log(f"[Server Error] {e}")

    def block_selected_ip(self):
        ip_to_block = self.ip_dropdown.currentText()
        if ip_to_block:
            self.blocked_ips.add(ip_to_block)
            logger.log(f"[Manual Block] IP blocked from future connections: {ip_to_block}")
            self.terminate_ip(ip_to_block)

    def terminate_ip(self, ip):
        found = False
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.ip == ip:
                try:
                    if conn.pid and conn.pid > 0:
                        p = psutil.Process(conn.pid)
                        p.terminate()
                        logger.log(f"[Kill] Connection from {ip} terminated (PID {conn.pid})")
                        found = True
                except Exception as e:
                    logger.log(f"[Kill Error] Could not terminate {ip}: {e}")
        if not found:
            logger.log(f"[Info] No associated PID found for {ip}, possibly already closed or system-owned.")

    def track_connections(self):
        while True:
            connections = psutil.net_connections(kind='inet')
            output_lines = []
            remote_ips = []
            for conn in connections:
                if conn.raddr:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                    proc = "-"
                    try:
                        proc = psutil.Process(conn.pid).name() if conn.pid else "-"
                    except:
                        pass
                    remote_ips.append(conn.raddr.ip)
                    line = f"{laddr}  <==>  {raddr}   |  {conn.status}  |  {proc}"
                    output_lines.append(line)
            logger.update_conn("\n".join(output_lines))
            logger.update_iplist(remote_ips)
            time.sleep(10)

def packet_callback(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport in ICS_PORTS or packet[TCP].sport in ICS_PORTS:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                for sig in SUSPICIOUS_STRINGS:
                    if sig in payload:
                        logger.log(f"[Network Alert] Suspicious payload on port {packet[TCP].dport}: {payload}")
                        break

def monitor_network():
    sniff(filter="tcp", prn=packet_callback, store=False)

class ICSFileMonitor(FileSystemEventHandler):
    def on_modified(self, event): logger.log(f"[File Alert] Modified: {event.src_path}")
    def on_created(self, event): logger.log(f"[File Alert] Created: {event.src_path}")
    def on_deleted(self, event): logger.log(f"[File Alert] Deleted: {event.src_path}")

def monitor_files(path):
    observer = Observer()
    observer.schedule(ICSFileMonitor(), path=path, recursive=True)
    observer.start()

def monitor_ports():
    open_ports = []
    for conn in psutil.net_connections():
        if conn.status == 'LISTEN':
            try:
                open_ports.append(conn.laddr.port)
            except:
                continue
    for port in open_ports:
        if port in ICS_PORTS:
            logger.log(f"[Port Info] ICS Port Open: {port}")
        elif port not in [22, 80, 443]:
            logger.log(f"[Port Alert] Unexpected open port: {port}")

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if any(p in proc.info['name'].lower() for p in SUSPICIOUS_PROCESSES):
                logger.log(f"[Process Alert] Suspicious tool running: {proc.info}")
        except:
            continue

def start_monitoring():
    scada_dir = r"C:\\ICS\\Config" if os.name == 'nt' else "/opt/scada/config"
    if os.path.exists(scada_dir):
        threading.Thread(target=monitor_files, args=(scada_dir,), daemon=True).start()
    else:
        logger.log(f"[Warning] SCADA config path not found: {scada_dir}")
    threading.Thread(target=monitor_network, daemon=True).start()

    while True:
        monitor_ports()
        monitor_processes()
        time.sleep(10)

def main():
    app = QApplication(sys.argv)
    window = MonitorWindow()
    window.show()
    threading.Thread(target=start_monitoring, daemon=True).start()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
