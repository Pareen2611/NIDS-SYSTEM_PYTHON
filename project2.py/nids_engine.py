
import csv
import os
import ipaddress
from datetime import datetime
from collections import defaultdict, deque


class NIDSEngine:

    def __init__(self):
        self.events_file = "events.csv"

        self.total_events = 0
        self.total_attacks = 0
        self.blocked_ips = set()

        self.ip_events = defaultdict(deque)
        self.ip_ports = defaultdict(deque)

        self.dos_threshold = 20
        self.port_scan_threshold = 5

        self.create_log_file()

    def create_log_file(self):

        if not os.path.exists(self.events_file):

            with open(self.events_file, "w", newline="") as file:

                writer = csv.writer(file)

                writer.writerow([
                    "Timestamp",
                    "Source IP",
                    "Destination Port",
                    "Status",
                    "Alert"
                ])

    def save_event(self, ip, port, status, alert):

        with open(self.events_file, "a", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                port,
                status,
                alert
            ])

    def process_event(self, source_ip, destination_port):

        try:
            ipaddress.ip_address(source_ip)

        except ValueError:
            return "INVALID", "Invalid IP address"

        if not 1 <= destination_port <= 65535:
            return "INVALID", "Invalid destination port"

        if source_ip in self.blocked_ips:
            return "BLOCKED", "IP address is blocked"

        now = datetime.now()

        self.total_events += 1

        events = self.ip_events[source_ip]

        while events and (now - events[0]).total_seconds() > 10:
            events.popleft()

        events.append(now)

        ports = self.ip_ports[source_ip]

        while ports and (now - ports[0][1]).total_seconds() > 60:
            ports.popleft()

        ports.append((destination_port, now))

        if len(events) >= self.dos_threshold:

            status = "ATTACK"
            alert = "Possible DoS activity detected"

        elif len(set(p[0] for p in ports)) >= self.port_scan_threshold:

            status = "ATTACK"
            alert = "Possible Port Scan detected"

        elif destination_port in [21, 22, 23, 3389]:

            status = "WARNING"
            alert = "Suspicious service port observed"

        else:

            status = "NORMAL"
            alert = "Normal network activity"

        if status == "ATTACK":
            self.total_attacks += 1

        self.save_event(source_ip, destination_port, status, alert)

        return status, alert

    def block_ip(self, ip):

        try:
            ipaddress.ip_address(ip)

        except ValueError:
            return False

        self.blocked_ips.add(ip)
        return True

    def show_statistics(self):

        print("\n========== NIDS STATISTICS ==========")

        print("Total Events       :", self.total_events)
        print("Attacks Detected   :", self.total_attacks)
        print("Blocked IPs        :", len(self.blocked_ips))

        print("=====================================")

    def show_blocked_ips(self):

        print("\n========== BLOCKED IP ADDRESSES ==========")

        if not self.blocked_ips:
            print("No IP addresses blocked.")

        else:
            for ip in sorted(self.blocked_ips):
                print("Blocked:", ip)

        print("==========================================")
