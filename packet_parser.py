import socket
import struct


def format_mac(data):
    """把 6 字节的 MAC 地址转换成便于阅读的形式。"""
    return ":".join(f"{byte:02x}" for byte in data)


def parse_ethernet_frame(data):
    """从原始字节中解析以太网、VLAN 和 IPv4。"""
    lines = []

    # 以太网头：目的 MAC 6 字节 + 源 MAC 6 字节 + 类型 2 字节
    if len(data) < 14:
        return "数据不足：以太网头至少需要 14 字节。"

    destination, source, ether_type = struct.unpack(
        "!6s6sH", data[:14]
    )

    lines.append("【以太网层】")
    lines.append(f"源 MAC：{format_mac(source)}")
    lines.append(f"目的 MAC：{format_mac(destination)}")
    lines.append(f"外层类型：0x{ether_type:04x}")

    offset = 14

    # VLAN 标签可能不止一层，每层增加 4 字节。
    while ether_type in (0x8100, 0x88A8):
        if len(data) < offset + 4:
            lines.append("数据不足：VLAN 标签不完整。")
            return "\n".join(lines)

        tag, ether_type = struct.unpack(
            "!HH", data[offset:offset + 4]
        )
        lines.append("【VLAN 标签】")
        lines.append(f"优先级：{(tag >> 13) & 0x07}")
        lines.append(f"VLAN ID：{tag & 0x0FFF}")
        lines.append(f"内部类型：0x{ether_type:04x}")
        offset += 4

    if ether_type != 0x0800:
        lines.append(
            f"当前版本暂未解析此网络层类型：0x{ether_type:04x}"
        )
        return "\n".join(lines)

    # IPv4 固定部分至少占 20 字节。
    if len(data) < offset + 20:
        lines.append("数据不足：IPv4 基本头部不完整。")
        return "\n".join(lines)

    fields = struct.unpack(
        "!BBHHHBBH4s4s", data[offset:offset + 20]
    )
    (
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum,
        source_ip, destination_ip,
    ) = fields

    version = version_ihl >> 4
    header_length = (version_ihl & 0x0F) * 4

    if version != 4 or header_length < 20:
        lines.append("无效的 IPv4 版本或头部长度。")
        return "\n".join(lines)

    if total_length < header_length:
        lines.append("无效的 IPv4 总长度。")
        return "\n".join(lines)

    if len(data) < offset + header_length:
        lines.append("数据不足：IPv4 头部或选项不完整。")
        return "\n".join(lines)

    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_names.get(protocol, "其他")
    fragment_offset = (flags_fragment & 0x1FFF) * 8

    lines.append("【IPv4 层】")
    lines.append(f"源 IP：{socket.inet_ntoa(source_ip)}")
    lines.append(f"目的 IP：{socket.inet_ntoa(destination_ip)}")
    lines.append(f"版本：{version}")
    lines.append(f"头部长度：{header_length} 字节")
    lines.append(f"IP 总长度：{total_length} 字节")
    lines.append(f"TTL：{ttl}")
    lines.append(f"上层协议：{protocol_name}（编号 {protocol}）")
    lines.append(f"标识：0x{identification:04x}")
    lines.append(f"禁止分片 DF：{(flags_fragment >> 14) & 1}")
    lines.append(f"更多分片 MF：{(flags_fragment >> 13) & 1}")
    lines.append(f"分片偏移：{fragment_offset} 字节")
    lines.append(f"头部校验和：0x{checksum:04x}（尚未验证）")

    if len(data) < offset + total_length:
        lines.append("提示：捕获的数据短于 IPv4 声明的总长度。")

    # 分片需要先重组，此阶段不解析分片中的传输层。
    more_fragments = (flags_fragment >> 13) & 1
    if more_fragments or fragment_offset != 0:
        lines.append("该 IPv4 数据报存在分片，暂不解析传输层。")
        return "\n".join(lines)

    # IP 总长度限定数据报边界，避免把以太网填充当作 TCP 数据。
    payload_start = offset + header_length
    payload_end = min(len(data), offset + total_length)
    transport_data = data[payload_start:payload_end]

    if protocol == 6:
        lines.extend(parse_tcp_segment(transport_data))

    return "\n".join(lines)

def parse_tcp_segment(data):
    """解析 TCP 头部，data 应从 TCP 的第一个字节开始。"""
    lines = ["【TCP 层】"]

    if len(data) < 20:
        lines.append("数据不足：TCP 基本头部至少需要 20 字节。")
        return lines

    (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        offset_flags,
        window,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIHHHH", data[:20])

    header_length = ((offset_flags >> 12) & 0x0F) * 4

    if header_length < 20:
        lines.append("无效的 TCP 头部长度。")
        return lines

    if len(data) < header_length:
        lines.append("数据不足：TCP 头部或选项不完整。")
        return lines

    flag_definitions = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    flag_names = [
        name for mask, name in flag_definitions
        if offset_flags & mask
    ]

    lines.append(f"源端口：{source_port}")
    lines.append(f"目的端口：{destination_port}")
    lines.append(f"序列号：{sequence}")
    lines.append(f"确认号：{acknowledgment}")
    lines.append(f"头部长度：{header_length} 字节")
    lines.append(f"标志位：{', '.join(flag_names) or '无'}")
    lines.append(f"窗口字段原始值：{window}")
    lines.append(f"校验和：0x{checksum:04x}（尚未验证）")
    lines.append(f"紧急指针：{urgent_pointer}")
    lines.append(f"选项长度：{header_length - 20} 字节")
    lines.append(f"本次捕获的 TCP 载荷长度：{len(data) - header_length} 字节")

    return lines