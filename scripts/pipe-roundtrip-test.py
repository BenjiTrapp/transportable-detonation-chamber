"""Manual round-trip test of the named pipe interception API on the Windows VM.

Run ON the VM with the web UI's venv python (the UI must be running):

    C:\\DetonationChamberUI\\venv\\Scripts\\python.exe pipe-roundtrip-test.py

It creates its own echo server and client through `Win32PipeBackend` and
drives the live API at http://127.0.0.1:9000:

  1. observe/attach on \\tdc_test, client sends 3 messages -> "OK 3/3"
  2. hold/attach, client message edited via the API, server sees the edit -> "OK edit"
  3. arm/exact/squat on \\tdc_squat, then the real server starts -> "OK squat"

The echo server keeps a spare instance like many real servers do. Windows
gives a client the oldest free instance, so a connection can bypass the
proxy; the script then reconnects and reports how many attempts it took.
"""

import base64
import json
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, r"C:\DetonationChamberUI")
from pipe_backends import Win32PipeBackend  # noqa: E402

API = "http://127.0.0.1:9000/api/pipes/intercept"
b = Win32PipeBackend()


def call(method, path="", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def wait_for(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    return cond()


class EchoServer:
    """A real pipe server: always one listening instance, echoes every read."""

    def __init__(self, name, first=True):
        self.name = name
        self.received = []
        self.stop = threading.Event()
        self.handles = []
        if first and not wait_for(lambda: not b.exists(name), 3.0):
            print(f"note: {name} still exists after 3 s (leftover instance)")
        self.h = b.create_server(name, "byte", first)
        self.handles.append(self.h)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stop.is_set():
            if not b.accept(self.h, 0.25):
                continue
            conn = self.h
            self.h = b.create_server(self.name, "byte", False)
            self.handles.append(self.h)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, h):
        while not self.stop.is_set():
            data = b.read(h, 0.25)
            if data is None:
                break
            if data:
                self.received.append(data)
                b.write(h, data)
        b.close(h)

    def close(self):
        self.stop.set()
        for h in self.handles:
            b.close(h)


def recv(h, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = b.read(h, 0.25)
        if data is None or data:
            return data
    return b""


def messages(sid):
    return call("GET", f"/{sid}/messages?limit=1000")[1]["messages"]


def held(sid, direction):
    return [m for m in messages(sid) if m["dir"] == direction and m["state"] == "held"]


def recorded(sid, data):
    return any(m["dir"] == "c2s" and base64.b64decode(m["data_b64"]) == data
               for m in messages(sid))


ATTEMPTS = 5


def connect_through_proxy(sid, name, first, check):
    """Connect and send `first` until the connection lands on the proxy.

    Windows hands a client the oldest free server instance, so whether the
    proxy's instance or the real server's spare one is taken depends on which
    was created first. A connection that bypassed the proxy is closed and retried.
    """
    for attempt in range(1, ATTEMPTS + 1):
        c = b.connect(name, 5.0)
        b.write(c, first)
        if wait_for(lambda: check(sid, first), 1.5):
            print(f"  connection {attempt} went through the proxy")
            return c, attempt
        print(f"  connection {attempt} bypassed the proxy (went to the real server)")
        recv(c, 1.0)
        b.close(c)
        time.sleep(0.3)
    return None, ATTEMPTS


def test_observe():
    server = EchoServer(r"\tdc_test")
    try:
        st, s = call("POST", body={"pattern": r"\tdc_test", "mode": "observe",
                                   "how": "attach", "match": "exact"})
        print("start observe:", st, s.get("state"), s.get("pipe_mode"), s.get("error", ""))
        if st != 201:
            return
        sid = s["id"]
        c, _ = connect_through_proxy(sid, r"\tdc_test", b"msg1", recorded)
        if c is None:
            print("FAIL 0/3: no connection went through the proxy")
            return
        ok = 1 if recv(c) == b"msg1" else 0
        for i in range(2, 4):
            msg = f"msg{i}".encode()
            b.write(c, msg)
            if recv(c) == msg:
                ok += 1
        b.close(c)
        wait_for(lambda: len([m for m in messages(sid) if m["dir"] == "c2s"]) >= 3, 3.0)
        msgs = messages(sid)
        seen = [base64.b64decode(m["data_b64"]) for m in msgs if m["dir"] == "c2s"]
        echoed = [base64.b64decode(m["data_b64"]) for m in msgs if m["dir"] == "s2c"]
        print(f"echo ok {ok}/3, api c2s={seen}, s2c={echoed}, server got {server.received}")
        n = sum(1 for i in range(1, 4) if f"msg{i}".encode() in seen and f"msg{i}".encode() in echoed)
        print(f"{'OK' if n == 3 and ok == 3 else 'FAIL'} {n}/3")
        call("DELETE", f"/{sid}")
    finally:
        server.close()


def test_edit():
    server = EchoServer(r"\tdc_test")
    try:
        st, s = call("POST", body={"pattern": r"\tdc_test", "mode": "hold",
                                   "how": "attach", "match": "exact", "hold_timeout": 60})
        print("start hold:", st, s.get("state"), s.get("error", ""))
        if st != 201:
            return
        sid = s["id"]
        c, _ = connect_through_proxy(sid, r"\tdc_test", b"original",
                                     lambda sid, data: held(sid, "c2s"))
        item = held(sid, "c2s") if c is not None else None
        if not item:
            print("FAIL edit: no held c2s message; messages:", messages(sid),
                  "server got", server.received)
        else:
            server.received.clear()
            seq = item[0]["seq"]
            st, rec = call("POST", f"/{sid}/messages/{seq}",
                           {"action": "edit", "data_b64": base64.b64encode(b"EDITED!").decode()})
            print("edit:", st, rec.get("state"), rec.get("error", ""))
            got = wait_for(lambda: server.received)
            back = wait_for(lambda: held(sid, "s2c"))
            if back:
                call("POST", f"/{sid}/messages/{back[0]['seq']}", {"action": "forward"})
            echo = recv(c)
            print(f"server got {got}, client echo {echo!r}")
            print("OK edit" if got == [b"EDITED!"] and echo == b"EDITED!" else "FAIL edit")
        if c is not None:
            b.close(c)
        call("DELETE", f"/{sid}")
    finally:
        server.close()


def test_squat():
    st, s = call("POST", body={"pattern": r"\tdc_squat", "mode": "observe",
                               "how": "arm", "match": "exact", "squat": True})
    print("start squat:", st, s.get("state"), s.get("error", ""))
    if st != 201:
        print("FAIL squat")
        return
    sid = s["id"]
    server = None
    try:
        try:
            server = EchoServer(r"\tdc_squat", first=False)
        except OSError as e:
            print(f"FAIL squat: real server cannot create its instance: {e}")
            return
        c = b.connect(r"\tdc_squat", 5.0)
        b.write(c, b"squatted")
        echo = recv(c, 8.0)
        b.close(c)
        wait_for(lambda: messages(sid), 3.0)
        seen = [base64.b64decode(m["data_b64"]) for m in messages(sid)]
        print(f"client echo {echo!r}, api {seen}, server got {server.received}")
        print("OK squat" if echo == b"squatted" and b"squatted" in seen else "FAIL squat")
    finally:
        call("DELETE", f"/{sid}")
        if server:
            server.close()


if __name__ == "__main__":
    for t in (test_observe, test_edit, test_squat):
        try:
            t()
        except Exception as e:  # noqa: BLE001 - report and go on with the next check
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
