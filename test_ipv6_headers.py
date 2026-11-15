import struct
import unittest

from ipv6_headers import locate_ipv6_transport
from packet_filter import matches_protocol
from test_packet_parser import make_ethernet, make_ipv6, make_tcp


class IPv6ExtensionTests(unittest.TestCase):
    def test_multiple_extensions_and_http(self):
        """逐跳选项、目的选项后面的 HTTP 能被定位和过滤。"""
        hop = bytes([60, 0]) + b"\x00" * 6
        destination = bytes([6, 0]) + b"\x00" * 6
        http = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
        tcp = make_tcp() + http
        ip = make_ipv6(hop + destination + tcp, 0)

        protocol, payload, notes = locate_ipv6_transport(ip)
        self.assertEqual(protocol, 6)
        self.assertEqual(payload, tcp)

        frame = make_ethernet(ip, ether_type=0x86DD)
        self.assertTrue(matches_protocol(frame, "TCP"))
        self.assertTrue(matches_protocol(frame, "HTTP"))
        self.assertFalse(matches_protocol(frame, "UDP"))

    def test_routing_header(self):
        """路由扩展头的长度用于定位，不解析其内部路由语义。"""
        routing = bytes([6, 0, 253, 0]) + b"\x00" * 4
        tcp = make_tcp()
        ip = make_ipv6(routing + tcp, 43)

        protocol, payload, notes = locate_ipv6_transport(ip)
        self.assertEqual(protocol, 6)
        self.assertEqual(payload, tcp)

    def test_truncated_extension(self):
        """声明 16 字节、实际仅有 8 字节的扩展头被拒绝。"""
        extension = bytes([6, 1]) + b"\x00" * 6
        ip = make_ipv6(extension, 0)

        protocol, payload, notes = locate_ipv6_transport(ip)
        self.assertIsNone(protocol)
        self.assertTrue(any("数据不足" in note for note in notes))
        frame = make_ethernet(ip, ether_type=0x86DD)
        self.assertFalse(matches_protocol(frame, "TCP"))

    def test_fragment_requires_reassembly(self):
        """首片和非首片都不冒充完整 TCP 数据。"""
        for fragment_bits in (1, 8):
            with self.subTest(fragment_bits=fragment_bits):
                fragment = struct.pack("!BBHI", 6, 0, fragment_bits, 123)
                ip = make_ipv6(fragment + make_tcp(), 44)

                protocol, payload, notes = locate_ipv6_transport(ip)
                self.assertIsNone(protocol)

                frame = make_ethernet(ip, ether_type=0x86DD)
                self.assertTrue(matches_protocol(frame, "IPv6"))
                self.assertFalse(matches_protocol(frame, "TCP"))

    def test_atomic_fragment(self):
        """偏移为零、M 为零时可以继续定位。"""
        fragment = struct.pack("!BBHI", 6, 0, 0, 123)
        tcp = make_tcp()
        protocol, payload, notes = locate_ipv6_transport(
            make_ipv6(fragment + tcp, 44)
        )
        self.assertEqual(protocol, 6)
        self.assertEqual(payload, tcp)

    def test_esp_stops(self):
        """不猜测 ESP 保护的数据内容。"""
        protocol, payload, notes = locate_ipv6_transport(
            make_ipv6(b"\x00" * 16, 50)
        )
        self.assertIsNone(protocol)

    def test_extension_limit(self):
        """过长扩展链应停止处理。"""
        extensions = (
            (bytes([60, 0]) + b"\x00" * 6) * 16
            + bytes([6, 0]) + b"\x00" * 6
        )
        protocol, payload, notes = locate_ipv6_transport(
            make_ipv6(extensions + make_tcp(), 60)
        )
        self.assertIsNone(protocol)
        self.assertTrue(any("16 层限制" in note for note in notes))


if __name__ == "__main__":
    unittest.main(verbosity=2)