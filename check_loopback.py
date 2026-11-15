from scapy.all import IP, TCP, conf, sniff


def main():
    interfaces = list(conf.ifaces.values())

    for number, interface in enumerate(interfaces, start=1):
        print(f"{number}. {interface.name} | {interface.description}")

    try:
        choice = int(input("\n请选择回环接口编号："))
        if not 1 <= choice <= len(interfaces):
            print("编号超出范围。")
            return
    except ValueError:
        print("请输入整数编号。")
        return

    print("等待本机 HTTP 数据，最多 30 秒。")
    print("请在另一个终端执行 curl 命令。")

    def matches(packet):
        return (
            IP in packet
            and TCP in packet
            and packet[IP].src == "127.0.0.1"
            and packet[IP].dst == "127.0.0.1"
            and (
                packet[TCP].sport == 8000
                or packet[TCP].dport == 8000
            )
            and len(bytes(packet[TCP].payload)) > 0
        )

    try:
        packets = sniff(
            iface=interfaces[choice - 1],
            count=1,
            timeout=30,
            lfilter=matches,
        )
    except Exception as error:
        print(f"抓包失败：{type(error).__name__}: {error}")
        return

    if not packets:
        print("未捕获到符合条件的数据，请检查接口和服务是否运行。")
        return

    packet = packets[0]
    print("\n最外层类型：", type(packet).__name__)
    print("最外层名称：", packet.name)
    print("摘要：", packet.summary())
    print("原始字节前 24 字节：", bytes(packet)[:24].hex(" "))
    print("TCP 载荷开头：", repr(bytes(packet[TCP].payload)[:160]))


if __name__ == "__main__":
    main()