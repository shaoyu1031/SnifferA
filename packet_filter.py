import struct


def matches_protocol(data, selected):
    """对以太网帧进行协议筛选。"""
    if selected == "全部":
        return True

    if len(data) < 14:
        return False

    ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14

    # 跳过一层或多层 VLAN 标签。
    while ether_type in (0x8100, 0x88A8):
        if len(data) < offset + 4:
            return False
        ether_type = struct.unpack(
            "!H", data[offset + 2:offset + 4]
        )[0]
        offset += 4

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
        return (
            (selected == "TCP" and protocol == 6)
            or (selected == "UDP" and protocol == 17)
            or (selected == "ICMPv4" and protocol == 1)
        )

    if ether_type == 0x86DD:
        if len(data) < offset + 40:
            return False
        if data[offset] >> 4 != 6:
            return False

        if selected == "IPv6":
            return True

        # 当前只判断基本头部直接指向的 TCP/UDP。
        next_header = data[offset + 6]
        return (
            (selected == "TCP" and next_header == 6)
            or (selected == "UDP" and next_header == 17)
        )

    return False