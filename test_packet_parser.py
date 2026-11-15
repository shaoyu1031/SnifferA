import socket
import struct
import unittest

from packet_parser import (
    parse_ethernet_frame,
    parse_loopback_frame,
)


def make_ipv4(payload, protocol=17, flags_fragment=0):
    """构造用于解析测试的 IPv4 数据报，不计算校验和。"""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                   # IPv4，头部长度 20 字节
        0,
        20 + len(payload),
        123,
        flags_fragment,
        64,
        protocol,
        0,
        socket.inet_aton("192.0.2.1"),
        socket.inet_aton("192.0.2.2"),
    )
    return header + payload


def make_ethernet(payload, ether_type=0x0800, vlan=False):
    """构造以太网帧，可选择添加 VLAN 标签。"""
    destination = bytes.fromhex("020000000002")
    source = bytes.fromhex("020000000001")

    if vlan:
        return (
            destination
            + source
            + struct.pack("!H", 0x8100)
            + struct.pack("!HH", 7, ether_type)
            + payload
        )

    return (
        destination
        + source
        + struct.pack("!H", ether_type)
        + payload
    )


def make_udp(payload=b"hello"):
    return struct.pack(
        "!HHHH", 12345, 8000, 8 + len(payload), 0
    ) + payload


def make_tcp():
    # 20 字节 TCP 头，ACK 标志，无选项和载荷。
    return struct.pack(
        "!HHIIHHHH",
        12345, 8000, 100, 200,
        (5 << 12) | 0x10,
        4096, 0, 0,
    )


def make_ipv6(payload, next_header):
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
    ) + payload


class PacketParserTests(unittest.TestCase):
    def test_ipv4_udp_fields(self):
        """正常 IPv4 UDP 字段与载荷长度。"""
        raw = make_ethernet(make_ipv4(make_udp()))
        result = parse_ethernet_frame(raw)

        self.assertIn("源 IP：192.0.2.1", result)
        self.assertIn("目的 IP：192.0.2.2", result)
        self.assertIn("源端口：12345", result)
        self.assertIn("目的端口：8000", result)
        self.assertIn("声明的载荷长度：5 字节", result)

    def test_vlan_offset(self):
        """VLAN 标签不会导致 IP 和 UDP 字段错位。"""
        raw = make_ethernet(make_ipv4(make_udp()), vlan=True)
        result = parse_ethernet_frame(raw)

        self.assertIn("VLAN ID：7", result)
        self.assertIn("源 IP：192.0.2.1", result)
        self.assertIn("目的端口：8000", result)

    def test_truncated_prefixes(self):
        """将带 VLAN 的包逐字节截断，解析器不应抛异常。"""
        raw = make_ethernet(make_ipv4(make_udp()), vlan=True)

        for length in range(len(raw)):
            with self.subTest(captured_length=length):
                result = parse_ethernet_frame(raw[:length])
                self.assertIsInstance(result, str)
                self.assertTrue(result)

    def test_invalid_ipv4_header_length(self):
        """IPv4 头部长度小于 20 字节时，应拒绝解析。"""
        ip = bytearray(make_ipv4(make_udp()))
        ip[0] = 0x44
        result = parse_ethernet_frame(make_ethernet(bytes(ip)))

        self.assertIn("无效的 IPv4", result)
        self.assertNotIn("【UDP 层】", result)

    def test_invalid_ipv4_total_length(self):
        """IP 总长度小于头部长度时，应拒绝解析。"""
        ip = bytearray(make_ipv4(make_udp()))
        ip[2:4] = struct.pack("!H", 10)
        result = parse_ethernet_frame(make_ethernet(bytes(ip)))

        self.assertIn("无效的 IPv4 总长度", result)
        self.assertNotIn("【UDP 层】", result)

    def test_ipv4_fragment_not_parsed_as_tcp(self):
        """有分片的数据报不能直接当完整 TCP 段解析。"""
        for flags_fragment in (0x2000, 1):
            with self.subTest(flags_fragment=flags_fragment):
                ip = make_ipv4(
                    make_tcp(),
                    protocol=6,
                    flags_fragment=flags_fragment,
                )
                result = parse_ethernet_frame(make_ethernet(ip))
                self.assertIn("分片", result)
                self.assertNotIn("【TCP 层】", result)

    def test_ethernet_padding_excluded(self):
        """以太网填充不能被计入 UDP 载荷。"""
        raw = make_ethernet(make_ipv4(make_udp())) + b"\x00" * 18
        result = parse_ethernet_frame(raw)

        self.assertIn("本次捕获的 UDP 载荷长度：5 字节", result)

    def test_invalid_tcp_header_length(self):
        """TCP 声明头部长度不足时，应报无效长度。"""
        tcp = bytearray(make_tcp())
        tcp[12] = 0x40
        ip = make_ipv4(bytes(tcp), protocol=6)
        result = parse_ethernet_frame(make_ethernet(ip))

        self.assertIn("无效的 TCP 头部长度", result)

    def test_invalid_udp_length(self):
        """UDP 总长度不能小于 8 字节。"""
        udp = struct.pack("!HHHH", 12345, 8000, 7, 0)
        result = parse_ethernet_frame(
            make_ethernet(make_ipv4(udp))
        )

        self.assertIn("无效的 UDP 长度", result)

    def test_ipv6_tcp(self):
        """IPv6 直接承载 TCP 时，正确定位 TCP 头。"""
        raw = make_ethernet(
            make_ipv6(make_tcp(), 6),
            ether_type=0x86DD,
        )
        result = parse_ethernet_frame(raw)

        self.assertIn("源 IP：2001:db8::1", result)
        self.assertIn("【TCP 层】", result)
        self.assertIn("目的端口：8000", result)

    def test_ipv6_extension_not_misread(self):
        """未支持的扩展头不能被直接解释为 TCP。"""
        # 8 字节逐跳扩展头，其下一头部字段指向 TCP。
        extension = bytes([6, 0]) + b"\x00" * 6
        raw = make_ethernet(
            make_ipv6(extension + make_tcp(), 0),
            ether_type=0x86DD,
        )
        result = parse_ethernet_frame(raw)

        self.assertIn("尚未实现解析", result)
        self.assertNotIn("【TCP 层】", result)

    def test_ipv4_loopback(self):
        """回环头跳过 4 字节后，仍能正确解析 IP 和 UDP。"""
        raw = struct.pack("<I", 2) + make_ipv4(make_udp())
        result = parse_loopback_frame(raw)

        self.assertIn("【回环链路层】", result)
        self.assertIn("源 IP：192.0.2.1", result)
        self.assertIn("目的端口：8000", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)