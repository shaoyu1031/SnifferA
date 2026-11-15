import socket
import struct

from ipv6_headers import locate_ipv6_transport


def extract_tcp_info(data, link_type):
    """返回 TCP 连接信息；不支持、不完整或分片时返回 None。"""
    if link_type == "ethernet":
        if len(data) < 14:
            return None

        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14

        while ether_type in (0x8100, 0x88A8):
            if len(data) < offset + 4:
                return None
            ether_type = struct.unpack(
                "!H", data[offset + 2:offset + 4]
            )[0]
            offset += 4

    elif link_type == "loopback":
        if len(data) < 4 or struct.unpack("<I", data[:4])[0] != 2:
            return None
        ether_type = 0x0800
        offset = 4
    else:
        return None

    ip = data[offset:]

    if ether_type == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None

        header_length = (ip[0] & 15) * 4
        total_length = struct.unpack("!H", ip[2:4])[0]
        fragment = struct.unpack("!H", ip[6:8])[0]

        if (
            header_length < 20
            or total_length < header_length
            or len(ip) < total_length
            or ip[9] != 6
            or fragment & 0x3FFF
        ):
            return None

        source = socket.inet_ntoa(ip[12:16])
        destination = socket.inet_ntoa(ip[16:20])
        version = 4
        tcp = ip[header_length:total_length]

    elif ether_type == 0x86DD:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            return None

        declared_length = 40 + struct.unpack("!H", ip[4:6])[0]
        if len(ip) < declared_length:
            return None

        protocol, tcp, notes = locate_ipv6_transport(ip)
        if protocol != 6:
            return None

        source = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        destination = socket.inet_ntop(socket.AF_INET6, ip[24:40])
        version = 6
    else:
        return None

    if len(tcp) < 20:
        return None

    source_port, destination_port, sequence, acknowledgment = (
        struct.unpack("!HHII", tcp[:12])
    )
    header_length = (tcp[12] >> 4) * 4
    if header_length < 20 or len(tcp) < header_length:
        return None

    source_endpoint = (source, source_port)
    destination_endpoint = (destination, destination_port)

    # 排序使 A→B 和 B→A 得到同一个连接键。
    endpoints = tuple(sorted((source_endpoint, destination_endpoint)))
    key = (version, endpoints)

    flags = [
        name
        for mask, name in (
            (1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"),
            (16, "ACK"), (32, "URG"), (64, "ECE"), (128, "CWR"),
        )
        if tcp[13] & mask
    ]

    return {
        "key": key,
        "source": source_endpoint,
        "destination": destination_endpoint,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "flags": ",".join(flags) or "无",
        "payload": tcp[header_length:],
    }