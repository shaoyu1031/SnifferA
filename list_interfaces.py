import sys

import scapy
from scapy.all import conf


def main():
    print("Python 路径：", sys.executable)
    print("Scapy 版本：", scapy.__version__)
    print("是否启用 pcap 抓包后端：", conf.use_pcap)
    print("\n当前可用的网络接口：")

    conf.ifaces.show()


if __name__ == "__main__":
    main()