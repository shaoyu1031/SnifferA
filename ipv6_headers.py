import struct


def locate_ipv6_transport(data):
    """输入完整 IPv6 字节，返回：协议编号、上层数据、说明列表。

    无法安全定位上层时，协议编号返回 None。
    """
    notes = []

    def stop(message):
        return None, b"", notes + [message]

    if len(data) < 40 or data[0] >> 4 != 6:
        return stop("IPv6 基本头部不完整或版本无效。")

    payload_length = struct.unpack("!H", data[4:6])[0]
    if payload_length == 0:
        return stop("载荷长度为 0，暂不处理 Jumbo Payload。")

    end = min(len(data), 40 + payload_length)
    next_header = data[6]
    offset = 40
    count = 0

    names = {
        0: "逐跳选项",
        43: "路由扩展头",
        60: "目的选项",
    }

    while True:
        if next_header in (6, 17, 58):
            notes.append(f"最终上层协议编号：{next_header}")
            return next_header, data[offset:end], notes

        if next_header == 59:
            return stop("无下一头部，不继续解析。")

        if next_header not in (0, 43, 44, 60):
            return stop(
                f"下一头部 {next_header} 尚未支持，停止解析。"
            )

        count += 1
        if count > 16:
            return stop("扩展头超过本程序的 16 层限制。")

        if next_header == 44:
            if end - offset < 8:
                return stop("数据不足：IPv6 分片头不完整。")

            following, reserved, fragment, identifier = struct.unpack(
                "!BBHI", data[offset:offset + 8]
            )
            fragment_offset = ((fragment >> 3) & 0x1FFF) * 8
            more = fragment & 1
            notes.append(
                f"【IPv6 分片头】偏移={fragment_offset} 字节，"
                f"M={more}，标识={identifier}"
            )

            if reserved != 0 or fragment & 0x06:
                return stop("分片头保留位非零，停止解析。")

            if fragment_offset != 0 or more:
                return stop("需要 IPv6 分片重组，暂不解析上层。")

            # 偏移为 0 且 M=0 的原子分片，可以继续定位。
            offset += 8
            next_header = following
            continue

        if end - offset < 2:
            return stop("数据不足：扩展头长度字段不完整。")

        if next_header == 0 and offset != 40:
            return stop("逐跳选项头位置异常，应紧随 IPv6 基本头部。")

        following = data[offset]
        length = (data[offset + 1] + 1) * 8

        if end - offset < length:
            return stop("数据不足：扩展头声明长度超出可用数据。")

        notes.append(
            f"【{names[next_header]}】长度={length} 字节，"
            f"下一头部={following}"
        )

        offset += length
        next_header = following