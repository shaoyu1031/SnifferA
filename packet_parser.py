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

    return "\n".join(lines)