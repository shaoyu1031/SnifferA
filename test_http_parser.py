from http_parser import parse_http_payload


request = (
    b"GET /demo HTTP/1.1\r\n"
    b"Host: localhost:8000\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"hello"
)

request_result = parse_http_payload(request)
assert "方法：GET" in request_result
assert "请求目标：/demo" in request_result
assert "Host: localhost:8000" in request_result

response_result = parse_http_payload(response)
assert "状态码：200" in response_result
assert "Content-Type: text/plain" in response_result

# 普通二进制内容不能被识别为 HTTP。
assert parse_http_payload(b"\x16\x03\x03\x00\x10random-data") == []

# 起始行被截断时，不声称已经识别成功。
assert parse_http_payload(b"GET /demo HT") == []

# 起始行完整、头部未完整时，应明确提示。
partial = parse_http_payload(
    b"GET /demo HTTP/1.1\r\nHost: local"
)
assert any("未完整捕获" in line for line in partial)

# 非法头字段不应被当作正常字段展示。
invalid = parse_http_payload(
    b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n"
)
assert any("格式异常" in line for line in invalid)

print("=== 请求样本 ===")
print("\n".join(request_result))
print("\n=== 响应样本 ===")
print("\n".join(response_result))
print("\n6 项检查通过：请求、响应、非HTTP内容、截断起始行、不完整头部、非法字段。")