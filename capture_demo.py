import sys
from datetime import datetime

import scapy
from scapy.all import conf, sniff


def main():
    print("=== 运行环境 ===")
    print("Python 版本：", sys.version.split()[0])
    print("Python 路径：", sys.executable)
    print("Scapy 版本：", scapy.__version__)
    print("pcap 抓包后端：", conf.use_pcap)

    interfaces = list(conf.ifaces.values())
    if not interfaces:
        print("没有发现网络接口，请检查 Npcap 安装。")
        return

    print("\n=== 可用网络接口 ===")
    for number, interface in enumerate(interfaces, start=1):
        print(f"\n选择编号：{number}")
        print(f"  名称：{interface.name}")
        print(f"  描述：{interface.description}")
        print(f"  IPv4：{interface.ip}")

    try:
        choice = int(input("\n请输入要抓包的接口编号："))
        if not 1 <= choice <= len(interfaces):
            print("编号不在列表范围内，请重新运行。")
            return
    except ValueError:
        print("请输入整数编号，请重新运行。")
        return

    selected = interfaces[choice - 1]
    print(f"\n已选择：{selected.name}")
    print(f"接口描述：{selected.description}")
    print("开始抓包：最多 20 个包，或等待 30 秒后结束。")
    print("现在可以打开浏览器，访问一个网页。\n")

    packet_count = 0

    def show_packet(packet):
        nonlocal packet_count
        packet_count += 1
        timestamp = datetime.fromtimestamp(float(packet.time))
        time_text = timestamp.strftime("%H:%M:%S.%f")[:-3]
        print(
            f"[{packet_count:02d}] {time_text} "
            f"长度={len(packet)} 字节 | {packet.summary()}"
        )

    try:
        sniff(
            iface=selected,
            prn=show_packet,
            count=20,
            timeout=30,
            store=False,
        )
    except Exception as error:
        print(f"\n抓包失败：{type(error).__name__}: {error}")
        return

    print(f"\n抓包结束，共捕获 {packet_count} 个数据包。")
    if packet_count == 0:
        print("本次没有收到数据，请检查接口选择，并在抓包期间产生网络流量。")


if __name__ == "__main__":
    main()