import re


REQUEST_LINE = re.compile(
    rb"([!#$%&'*+\-.^_`|~0-9A-Za-z]+) ([^\x00-\x20\x7f]+) HTTP/(1\.[01])"
)
RESPONSE_LINE = re.compile(
    rb"HTTP/(1\.[01]) ([1-5][0-9]{2}) ([\x09\x20-\x7e\x80-\xff]*)"
)
HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def parse_http_payload(payload):
    """识别从载荷起始位置开始的 HTTP/1.x 头部。

    返回展示用的文本行；无法识别时返回空列表。
    不进行 TCP 重组或正文解码。
    """
    max_header_size = 16384

    # 只在有限范围内寻找第一行，避免处理过大的输入。
    first_end = payload.find(b"\r\n", 0, max_header_size)
    if first_end < 0:
        return []

    first_line = payload[:first_end]
    request = REQUEST_LINE.fullmatch(first_line)
    response = RESPONSE_LINE.fullmatch(first_line)

    if request:
        method, target, version = request.groups()
        lines = [
            "【HTTP/1.x 请求】",
            f"方法：{method.decode('ascii')}",
            f"请求目标：{target.decode('ascii', errors='replace')}",
            f"版本：HTTP/{version.decode('ascii')}",
        ]
    elif response:
        version, status, reason = response.groups()
        lines = [
            "【HTTP/1.x 响应】",
            f"版本：HTTP/{version.decode('ascii')}",
            f"状态码：{status.decode('ascii')}",
            f"原因短语：{reason.decode('iso-8859-1')}",
        ]
    else:
        return []

    header_end = payload.find(b"\r\n\r\n", 0, max_header_size)
    if header_end < 0:
        lines.append(
            "已识别起始行，但头部未完整捕获或超过 16 KiB；"
            "当前不进行 TCP 重组。"
        )
        return lines

    # 先验证字段格式，再展示，避免将任意文本当成有效头部。
    fields = []
    for raw_line in payload[:header_end].split(b"\r\n")[1:]:
        name, separator, value = raw_line.partition(b":")
        if not separator or not HEADER_NAME.fullmatch(name):
            return lines + ["头字段格式异常，停止解析。"]

        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            return lines + ["头字段包含非法控制字符，停止解析。"]

        # 只去掉字段值两端的空格（32）和制表符（9）。
        clean_value = value.strip(bytes([32, 9]))
        fields.append(
            f"{name.decode('ascii')}: "
            f"{clean_value.decode('iso-8859-1')}"
        )

    lines.append("头字段：")
    lines.extend(fields or ["（无）"])
    lines.append(
        f"头部结束后，本次 TCP 载荷剩余 {len(payload) - header_end - 4} 字节"
        "（不代表完整正文长度）。"
    )
    return lines