from scapy.all import Ether, IP, conf, sniff

from packet_parser import parse_ethernet_frame


def main():
    interfaces = list(conf.ifaces.values())

    for number, interface in enumerate(interfaces, start=1):
        print(
            f"{number}. {interface.name} | "
            f"{interface.description} | {interface.ip}"
        )

    try:
        choice = int(input("\n请输入接口编号："))
        if not 1 <= choice <= len(interfaces):
            print("编号超出范围。")
            return
    except ValueError:
        print("请输入整数编号。")
        return

    protocol_choice = input(
        "\n选择测试协议：0=不限，1=IPv4 TCP，2=IPv4 UDP，3=ICMPv4："
    ).strip()

    if protocol_choice not in ("0", "1", "2", "3"):
        print("请输入 0、1、2 或 3。")
        return

    target_protocol = {"1": 6, "2": 17, "3": 1}.get(protocol_choice)

    def matches(packet):
        # 当前手写解析器以以太网帧为入口。
        if not isinstance(packet, Ether):
            return False

        if target_protocol is None:
            return True

        # 从链路层往内寻找网络层，同时兼容 VLAN 标签。
        layer = packet.payload
        while layer.__class__.__name__ in ("Dot1Q", "Dot1AD"):
            layer = layer.payload

        if not isinstance(layer, IP):
            return False

        # 当前版本不处理 IPv4 分片。
        return (
            layer.proto == target_protocol
            and layer.frag == 0
            and (int(layer.flags) & 1) == 0
        )

    selected = interfaces[choice - 1]
    print(f"\n已选择：{selected.name}")
    print("等待符合条件的数据包，最多 30 秒。")
    if protocol_choice == "2":
        print("请在另一个终端执行：nslookup example.com")
    elif protocol_choice == "3":
        print("请在另一个终端执行 ping -4 加上本机 IPv4 默认网关地址。")
    elif protocol_choice == "1":
        print("请访问网页，产生 TCP 流量。")

    try:
        packets = sniff(
            iface=selected,
            count=1,
            timeout=30,
            lfilter=matches,
        )
    except Exception as error:
        print(f"抓包失败：{type(error).__name__}: {error}")
        return

    if not packets:
        print("没有捕获到符合条件的数据包，请检查接口并重试。")
        return

    packet = packets[0]
    raw_data = bytes(packet)

    print(f"\n捕获帧长度：{len(raw_data)} 字节")
    print("\n=== 自己编写的解析结果 ===")
    print(parse_ethernet_frame(raw_data))

    print("\n=== Scapy 解析结果，供初步对照 ===")
    packet.show()


if __name__ == "__main__":
    main()