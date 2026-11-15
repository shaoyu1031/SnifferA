import struct

from http_parser import parse_http_payload


def matches_protocol(data, selected, link_type="ethernet"):
    """根据链路层格式定位 IP，再筛选协议。"""
    if selected == "全部":
        return True

    if link_type == "ethernet":
        if len(data) < 14:
            return False

        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14

        while ether_type in (0x8100, 0x88A8):
            if len(data) < offset + 4:
                return False
            ether_type = struct.unpack(
                "!H", data[offset + 2:offset + 4]
            )[0]
            offset += 4

    elif link_type == "loopback":
        # 当前支持本机已验证的 IPv4 回环格式。
        if len(data) < 4:
            return False
        family = struct.unpack("<I", data[:4])[0]
        if family != 2:
            return False

        ether_type = 0x0800
        offset = 4

    else:
        return False

    transport = b""
    fragmented = False

    if ether_type == 0x0800:
        if len(data) < offset + 20:
            return False

        version = data[offset] >> 4
        header_length = (data[offset] & 0x0F) * 4
        total_length = struct.unpack(
            "!H", data[offset + 2:offset + 4]
        )[0]

        if (
            version != 4
            or header_length < 20
            or total_length < header_length
            or len(data) < offset + header_length
        ):
            return False

        if selected == "IPv4":
            return True

        protocol = data[offset + 9]

        flags_fragment = struct.unpack(
            "!H", data[offset + 6:offset + 8]
        )[0]
        # MF 或分片偏移非零，说明需要重组才能完整分析载荷。
        fragmented = bool(flags_fragment & 0x3FFF)

        end = min(len(data), offset + total_length)
        transport = data[offset + header_length:end]

    elif ether_type == 0x86DD:
        if len(data) < offset + 40:
            return False
        if data[offset] >> 4 != 6:
            return False

        if selected == "IPv6":
            return True

        protocol = data[offset + 6]
        payload_length = struct.unpack(
            "!H", data[offset + 4:offset + 6]
        )[0]

        # 仍只支持基本头部直接指向的上层协议。
        end = min(len(data), offset + 40 + payload_length)
        transport = data[offset + 40:end]

    else:
        return False

    if selected == "TCP":
        return protocol == 6
    if selected == "UDP":
        return protocol == 17
    if selected == "ICMPv4":
        return ether_type == 0x0800 and protocol == 1

    if selected == "HTTP":
        if protocol != 6 or fragmented or len(transport) < 20:
            return False

        tcp_header_length = (transport[12] >> 4) * 4
        if tcp_header_length < 20 or len(transport) < tcp_header_length:
            return False

        payload = transport[tcp_header_length:]
        return bool(parse_http_payload(payload))

    return False