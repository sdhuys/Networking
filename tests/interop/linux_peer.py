#!/usr/bin/env python3
"""Linux side of the interop tests: uses the kernel's TCP over tap0.

  linux_peer.py client <stack-ip> <port> <bytes> <conns>
      Connects to the stack's echo server, sends random data while reading the echo,
      checks the echo is identical. Exit code 0 if every connection matched.
  linux_peer.py echo-server <bind-ip> <port> <conns>
      Accepts <conns> connections from the stack and echoes each until EOF.
"""
import os
import socket
import sys
import threading
import time


def client(ip, port, nbytes, conns):
    failures = 0
    for i in range(conns):
        data = os.urandom(nbytes)
        s = socket.create_connection((ip, port), timeout=30)
        s.settimeout(60)
        sent_err = []

        def send():
            try:
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
            except OSError as e:
                sent_err.append(e)

        t = threading.Thread(target=send)
        t0 = time.time()
        t.start()
        got = bytearray()
        try:
            while True:
                chunk = s.recv(1 << 16)
                if not chunk:
                    break
                got += chunk
        except OSError as e:
            print(f"CONN {i} ERROR {e!r} after {len(got)} bytes", flush=True)
        t.join()
        s.close()
        ok = not sent_err and bytes(got) == data
        rate = nbytes / max(time.time() - t0, 1e-6) / 1e6
        print(f"CONN {i} {'OK' if ok else 'MISMATCH'} sent={nbytes} echoed={len(got)} "
              f"{rate:.2f} MB/s {sent_err or ''}", flush=True)
        failures += not ok
    return 1 if failures else 0


def echo_server(ip, port, conns):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((ip, port))
    ls.listen(16)
    ls.settimeout(60)
    print("READY", flush=True)
    for i in range(conns):
        c, _ = ls.accept()
        c.settimeout(60)
        total = 0
        try:
            while True:
                chunk = c.recv(1 << 16)
                if not chunk:
                    break
                c.sendall(chunk)
                total += len(chunk)
            c.shutdown(socket.SHUT_WR)
            # wait for the stack's FIN so the close is clean
            while c.recv(1 << 16):
                pass
        except OSError as e:
            print(f"ECHO {i} ERROR {e!r} after {total} bytes", flush=True)
            return 1
        c.close()
        print(f"ECHOED {i} {total}", flush=True)
    return 0


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "client":
        sys.exit(client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])))
    if mode == "echo-server":
        sys.exit(echo_server(sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))
    print(__doc__)
    sys.exit(2)
