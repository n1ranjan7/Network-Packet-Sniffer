
import socket
import struct

from sniffer import PacketSniffer


def create_test_packet(protocol, source_ip, destination_ip,
                       source_port, destination_port):

    if protocol == 6:
        # TCP header
        transport = struct.pack(
            "!HHIIHHHH",
            source_port,
            destination_port,
            0,
            0,
            5 << 12,
            8192,
            0,
            0
        )

    elif protocol == 17:
        # UDP header
        transport = struct.pack(
            "!HHHH",
            source_port,
            destination_port,
            8,
            0
        )

    else:
        transport = b""

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        1234,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip)
    )

    return ip_header + transport


def run_tests():

    sniffer = PacketSniffer()

    print("\n--- TCP HEADER TEST ---")

    tcp_packet = create_test_packet(
        6, "192.168.1.10", "192.168.1.20", 50000, 443
    )

    sniffer.parse_packet(tcp_packet)

    print("\n--- UDP HEADER TEST ---")

    udp_packet = create_test_packet(
        17, "192.168.1.10", "192.168.1.30", 53000, 53
    )

    sniffer.parse_packet(udp_packet)

    print("\n--- STATISTICS TEST ---")

    sniffer.show_statistics()

    assert sniffer.total_packets == 2
    assert sniffer.protocols["TCP"] == 1
    assert sniffer.protocols["UDP"] == 1

    print("\nALL PACKET PARSING TESTS PASSED")


if __name__ == "__main__":
    run_tests()
