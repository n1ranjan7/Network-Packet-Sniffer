
import socket
import struct
import logging
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "network_log.txt"

LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)


class PacketSniffer:

    def __init__(self):
        self.total_packets = 0
        self.protocols = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()

    def parse_packet(self, packet):

        if len(packet) < 20:
            return

        # Parse IPv4 header
        version_ihl = packet[0]

        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20 or len(packet) < ihl:
            return

        total_length = struct.unpack("!H", packet[2:4])[0]

        protocol = packet[9]

        source_ip = socket.inet_ntoa(packet[12:16])
        destination_ip = socket.inet_ntoa(packet[16:20])

        if total_length < ihl:
            return

        fragment_info = struct.unpack("!H", packet[6:8])[0]

        fragment_offset = fragment_info & 0x1FFF

        protocol_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, "OTHER")

        self.total_packets += 1
        self.protocols[protocol_name] += 1
        self.source_ips[source_ip] += 1
        self.destination_ips[destination_ip] += 1

        source_port = "-"
        destination_port = "-"

        # Parse transport headers only in initial fragments.
        if fragment_offset == 0:

            transport = packet[ihl:]

            if protocol == 6 and len(transport) >= 20:

                source_port, destination_port = struct.unpack(
                    "!HH", transport[:4]
                )

            elif protocol == 17 and len(transport) >= 8:

                source_port, destination_port = struct.unpack(
                    "!HH", transport[:4]
                )

        # Display metadata only; never display payload contents.
        message = (
            f"Protocol={protocol_name} | "
            f"Source={source_ip}:{source_port} | "
            f"Destination={destination_ip}:{destination_port} | "
            f"IP Length={total_length}"
        )

        print(message)
        logging.info(message)

    def show_statistics(self):

        print("\n========== NETWORK STATISTICS ==========")

        print("Total packets:", self.total_packets)

        print("\nProtocol statistics:")

        for protocol, count in self.protocols.items():
            print(f"{protocol}: {count}")

        print("\nTop source IP addresses:")

        for ip, count in self.source_ips.most_common(5):
            print(f"{ip}: {count}")

        print("\nTop destination IP addresses:")

        for ip, count in self.destination_ips.most_common(5):
            print(f"{ip}: {count}")

        print("========================================")

        logging.info(
            f"SUMMARY | Total={self.total_packets} | "
            f"Protocols={dict(self.protocols)}"
        )

    def start(self, interface=None, packet_limit=0):

        try:
            # IPv4 raw socket: receives IP packet headers.
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )

            if interface is None:
                raise ValueError(
                    "Specify an authorized local interface IP"
                )

            sock.bind((interface, 0))

            print("Network Packet Sniffer Started")
            print("Interface:", interface)
            print("Logging to:", LOG_FILE)
            print("Press Ctrl+C to stop.\n")

            while True:

                packet, address = sock.recvfrom(65535)

                self.parse_packet(packet)

                if packet_limit:
                    if self.total_packets >= packet_limit:
                        break

        except KeyboardInterrupt:
            print("\nCapture stopped.")

        except PermissionError:
            print(
                "Permission denied. Run with administrator "
                "or appropriate raw-socket privileges."
            )

        except OSError as error:
            print("Socket error:", error)

        except ValueError as error:
            print("Configuration error:", error)

        finally:
            if "sock" in locals():
                sock.close()

            self.show_statistics()


def main():

    parser = argparse.ArgumentParser(
        description="IPv4 Network Packet Metadata Monitor"
    )

    parser.add_argument(
        "--interface",
        required=True,
        help="Authorized local interface IPv4 address"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture; 0 means continuous"
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("Count cannot be negative")

    sniffer = PacketSniffer()

    sniffer.start(
        interface=args.interface,
        packet_limit=args.count
    )


if __name__ == "__main__":
    main()
