#!/usr/bin/env python3
import argparse
import re
import select
import socket
import time


ANSI_RE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
OSC_RE = re.compile(rb"\x1b\].*?(?:\x07|\x1b\\)")
IAC_RE = re.compile(rb"\xff[\xfb-\xfe].")
PROMPT_RE = re.compile(rb"\[[^\]\r\n]+\]\s*>\s*")


def clean(data: bytes) -> bytes:
    data = IAC_RE.sub(b"", data)
    data = OSC_RE.sub(b"", data)
    data = ANSI_RE.sub(b"", data)
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


class Console:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setblocking(False)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def read(self) -> bytes:
        chunks = []
        readable, _, _ = select.select([self.sock], [], [], 0.2)
        if not readable:
            return b""
        while True:
            readable, _, _ = select.select([self.sock], [], [], 0)
            if not readable:
                break
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        self.sock.close()


def wait_prompt(tn: Console, timeout: int = 30, prompts: int = 1) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = tn.read()
        if chunk:
            buf += chunk
            if len(PROMPT_RE.findall(clean(buf))) >= prompts:
                return buf
        else:
            time.sleep(0.15)
    raise TimeoutError(clean(buf[-1000:]).decode(errors="replace"))


def login(tn: Console) -> None:
    buf = b""
    deadline = time.time() + 30
    sent_probe = False
    passwords = [b"", b"eve"]
    pass_idx = 0
    while time.time() < deadline:
        chunk = tn.read()
        if chunk:
            buf += chunk
            low = clean(buf).lower()
            if b"login:" in low:
                tn.write(b"admin\r\n")
                buf = b""
            elif b"password:" in low:
                tn.write(passwords[min(pass_idx, len(passwords) - 1)] + b"\r\n")
                pass_idx += 1
                buf = b""
            elif b"software license" in low and b"[y/n]" in low:
                tn.write(b"n\r\n")
                buf = b""
            elif b"press enter" in low or b"press any key" in low:
                tn.write(b"\r\n")
                buf = b""
            elif PROMPT_RE.search(clean(buf)):
                return
        elif not sent_probe:
            tn.write(b"\x03\r\n")
            sent_probe = True
            time.sleep(0.2)
        else:
            time.sleep(0.2)
    raise TimeoutError(clean(buf[-1000:]).decode(errors="replace"))


def run(tn: Console, command: str) -> str:
    tn.write(command.encode("utf-8") + b"\r\n")
    return clean(wait_prompt(tn, timeout=45, prompts=2)).decode(errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("commands", nargs="+")
    parser.add_argument("--host", default="192.168.95.129")
    args = parser.parse_args()

    tn = Console(args.host, args.port)
    try:
        login(tn)
        for command in args.commands:
            print(f"### {command}")
            print(run(tn, command).strip())
        tn.write(b"/quit\r\n")
    finally:
        tn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
