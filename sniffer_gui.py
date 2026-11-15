import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from scapy.all import Ether, Loopback, conf, sniff
from packet_parser import parse_ethernet_frame, parse_loopback_frame
from packet_filter import matches_protocol

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SnifferA 网络嗅探器")
        self.root.geometry("1150x760")

        self.interfaces = list(conf.ifaces.values())
        self.packet_queue = queue.Queue(maxsize=1000)
        self.errors = queue.SimpleQueue()
        self.stop_event = threading.Event()
        self.worker = None
        self.packets = {}
        self.limit = 500
        self.closing = False

        toolbar = ttk.Frame(root, padding=8)
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="网络接口：").pack(side="left")

        labels = [
            f"{item.name} | {item.description}"
            for item in self.interfaces
        ]
        self.interface_box = ttk.Combobox(
            toolbar, values=labels, state="readonly", width=65
        )
        self.interface_box.pack(side="left", padx=5)

        if labels:
            default = next(
                (
                    index for index, item in enumerate(self.interfaces)
                    if item.name == "WLAN"
                ),
                0,
            )
            self.interface_box.current(default)

        self.start_button = ttk.Button(
            toolbar, text="开始抓包", command=self.start_capture
        )
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(
            toolbar, text="停止抓包",
            command=self.stop_capture, state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        filter_bar = ttk.Frame(root, padding=(8, 0, 8, 5))
        filter_bar.pack(fill="x")

        ttk.Label(filter_bar, text="协议过滤：").pack(side="left")

        self.filter_box = ttk.Combobox(
            filter_bar,
            values=("全部", "TCP", "UDP", "ICMPv4", "IPv4", "IPv6"),
            state="readonly",
            width=15,
        )
        self.filter_box.current(0)
        self.filter_box.pack(side="left", padx=5)

        ttk.Label(
            filter_bar,
            text="开始前选择；收到数据包后进行软件过滤",
        ).pack(side="left", padx=8)
        capture_bar = ttk.Frame(root, padding=(8, 0, 8, 5))
        capture_bar.pack(fill="x")

        ttk.Label(
            capture_bar, text="抓包表达式："
        ).pack(side="left")

        self.capture_filter_entry = ttk.Entry(capture_bar, width=45)
        self.capture_filter_entry.pack(side="left", padx=5)

        ttk.Label(
            capture_bar, text="可留空；例如 tcp port 8000"
        ).pack(side="left", padx=8)
        panes = ttk.Panedwindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8, pady=5)

        list_frame = ttk.Frame(panes)
        panes.add(list_frame, weight=3)

        self.table = ttk.Treeview(
            list_frame,
            columns=("number", "time", "length", "summary"),
            show="headings",
            selectmode="browse",
        )

        for key, title, width in [
            ("number", "序号", 60),
            ("time", "时间", 120),
            ("length", "长度/字节", 90),
            ("summary", "数据包摘要", 800),
        ]:
            self.table.heading(key, text=title)
            self.table.column(key, width=width, stretch=(key == "summary"))

        scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.table.yview
        )
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(side="left", fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self.show_details)

        notebook = ttk.Notebook(panes)
        panes.add(notebook, weight=2)

        self.details = ScrolledText(
            notebook, wrap="word", font=("Consolas", 11)
        )
        self.hex_view = ScrolledText(
            notebook, wrap="none", font=("Consolas", 11)
        )
        notebook.add(self.details, text="自编协议解析")
        notebook.add(self.hex_view, text="原始字节")
        self.details.configure(state="disabled")
        self.hex_view.configure(state="disabled")

        self.status = tk.StringVar(value="就绪：请选择网卡并开始抓包。")
        ttk.Label(root, textvariable=self.status, padding=8).pack(
            fill="x"
        )

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self.poll)

    @staticmethod
    def set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def start_capture(self):
        if self.worker is not None:
            return

        index = self.interface_box.current()
        if index < 0:
            messagebox.showerror("无法开始", "请先选择网络接口。")
            return

        # 每次开始新会话时清空上一轮结果。
        self.table.delete(*self.table.get_children())
        self.packets.clear()
        self.set_text(self.details, "")
        self.set_text(self.hex_view, "")
        self.packet_queue = queue.Queue(maxsize=1000)
        self.errors = queue.SimpleQueue()
        self.stop_event.clear()

        selected = self.interfaces[index]
        selected_filter = self.filter_box.get()
        capture_filter = self.capture_filter_entry.get().strip()
        self.capture_filter_entry.configure(state="disabled")
        self.filter_box.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.interface_box.configure(state="disabled")
        self.status.set(
            f"正在抓包：{selected.name}；本次最多显示 {self.limit} 个包。"
        )

        self.worker = threading.Thread(
            target=self.capture_worker,
            args=(selected, selected_filter, capture_filter),
            daemon=True,
        )
        self.worker.start()

    def capture_worker(self, interface, selected_filter, capture_filter):
        def receive(packet):
            if self.stop_event.is_set():
                return

            if selected_filter != "全部":
                if not isinstance(packet, Ether):
                    return
                if not matches_protocol(bytes(packet), selected_filter):
                    return

            # 队列满时等待界面消费，同时允许停止。
            while not self.stop_event.is_set():
                try:
                    self.packet_queue.put(packet, timeout=0.1)
                    return
                except queue.Full:
                    continue

        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=interface,
                    filter=capture_filter or None,
                    prn=receive,
                    store=False,
                    timeout=1,
                    stop_filter=lambda packet: self.stop_event.is_set(),
                )
        except Exception as error:
            self.errors.put(f"{type(error).__name__}: {error}")
            self.stop_event.set()

    def stop_capture(self):
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("正在停止，请稍候……")

    def poll(self):
        # 限制每轮更新数量，给窗口处理其他事件的机会。
        for _ in range(100):
            try:
                packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            if len(self.packets) >= self.limit:
                continue

            number = len(self.packets) + 1
            item_id = str(number)
            self.packets[item_id] = packet

            timestamp = datetime.fromtimestamp(float(packet.time))
            self.table.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    number,
                    timestamp.strftime("%H:%M:%S.%f")[:-3],
                    len(packet),
                    packet.summary(),
                ),
            )

            if number == self.limit:
                self.stop_capture()

        if self.worker is not None and not self.worker.is_alive():
            if self.packet_queue.empty():
                self.worker = None
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.interface_box.configure(state="readonly")
                self.filter_box.configure(state="readonly")
                self.capture_filter_entry.configure(state="normal")

                try:
                    error = self.errors.get_nowait()
                except queue.Empty:
                    error = None

                if error:
                    self.status.set(f"抓包失败：{error}")
                    if not self.closing:
                        messagebox.showerror("抓包失败", error)
                else:
                    self.status.set(
                        f"已停止，本次显示 {len(self.packets)} 个包。"
                        "再次开始会清空当前结果。"
                    )

        if self.closing and self.worker is None:
            self.root.destroy()
            return

        self.root.after(100, self.poll)

    def show_details(self, event=None):
        selected = self.table.selection()
        if not selected:
            return

        packet = self.packets[selected[0]]
        raw_data = bytes(packet)

        try:
            if isinstance(packet, Ether):
                result = parse_ethernet_frame(raw_data)
            elif isinstance(packet, Loopback):
                result = parse_loopback_frame(raw_data)
            else:
                result = "当前包的链路层格式尚未支持。"
        except Exception as error:
            result = (
                f"解析失败：{type(error).__name__}: {error}\n"
                "请保留该结果用于排查。"
            )

        self.set_text(self.details, result)

        rows = []
        for offset in range(0, len(raw_data), 16):
            chunk = raw_data[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in chunk
            )
            rows.append(
                f"{offset:04x}  {hex_part:<47}  {ascii_part}"
            )
        self.set_text(self.hex_view, "\n".join(rows))

    def close(self):
        self.closing = True
        if self.worker is not None:
            self.stop_capture()
        else:
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()