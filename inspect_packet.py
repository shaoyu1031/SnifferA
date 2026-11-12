from scapy.all import Ether, conf, sniff

from packet_parser import parse_ethernet_frame


def main():
    interfaces = list(conf.ifaces.values())

    for number, interface in enumerate(interfaces, start=1):
        print(
            f"{number}. {interface.name} | "
            f"{interface.description} | {interface.ip}"
        )

    try:
        choice = int(input("\n请输入接口编号:"))
        if not 1 <= choice <= len(interfaces):
            print("编号超出范围。")
            return
    except ValueError:
        print("请输入整数编号。")
        return

    selected = interfaces[choice - 1]
    print(f"\n已选择:{selected.name}")
    print("等待一个以太网帧，最多等待 30 秒，请访问一个网页。")

    try:
        packets = sniff(
            iface=selected,
            count=1,
            timeout=30,
            lfilter=lambda packet: isinstance(packet, Ether),
        )
    except Exception as error:
        print(f"抓包失败：{type(error).__name__}: {error}")
        return

    if not packets:
        print("未捕获到以太网帧，请检查接口并重试。")
        return

    packet = packets[0]
    raw_data = bytes(packet)

    print(f"\n捕获帧长度:{len(raw_data)} 字节")
    print("\n=== 自己编写的解析结果 ===")
    print(parse_ethernet_frame(raw_data))

    print("\n=== Scapy 解析结果，供初步对照 ===")
    packet.show()


if __name__ == "__main__":
    main()