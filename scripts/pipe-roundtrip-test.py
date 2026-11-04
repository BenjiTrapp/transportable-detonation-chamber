"""Manual round-trip test of the named pipe interception API on the Windows VM.

Run ON the VM with the web UI's venv python (the UI must be running):

    C:\\DetonationChamberUI\\venv\\Scripts\\python.exe pipe-roundtrip-test.py

It creates its own echo server and clients through `Win32PipeBackend` and
drives the live API at http://127.0.0.1:9000:

  1. observe/attach on \\tdc_test, one client sends 3 messages -> "OK 3/3",
     then CONNECTIONS more clients connect one after another; every one must
     go through the proxy -> "OK bypass 0/N"
  2. hold/attach, client message edited via the API, server sees the edit -> "OK edit"
  3. arm/exact/squat on \\tdc_squat, then the real server starts -> "OK squat"

The echo server keeps a spare instance like many real servers do, and Windows
gives a client the oldest free instance. A connection made after the session
became active that reaches the real server directly is a bypass and FAILS.
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
CONNECTIONS = 10
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
    """A real pipe server: always one spare listening instance, echoes every read."""

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


def active(sid):
    """The session is "starting" until its first upstream is open."""
    return wait_for(lambda: call("GET", f"/{sid}")[1].get("state") == "active", 10.0)


def test_observe():
    server = EchoServer(r"\tdc_test")
    try:
        st, s = call("POST", body={"pattern": r"\tdc_test", "mode": "observe",
                                   "how": "attach", "match": "exact"})
        print("start observe:", st, s.get("state"), s.get("pipe_mode"), s.get("error", ""))
        if st != 201:
            print("FAIL 0/3")
            return
        sid = s["id"]
        print("active:", bool(active(sid)))
        c = b.connect(r"\tdc_test", 5.0)
        ok = 0
        for i in range(1, 4):
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

        bypassed = []
        for i in range(CONNECTIONS):
            msg = f"conn{i}".encode()
            c = b.connect(r"\tdc_test", 5.0)
            b.write(c, msg)
            echo = recv(c)
            b.close(c)
            if echo != msg or not wait_for(lambda: recorded(sid, msg), 2.0):
                bypassed.append(i)
        meta = call("GET", f"/{sid}")[1]
        print(f"connections: {CONNECTIONS}, bypassed: {bypassed}, "
              f"self_connect_retries: {meta.get('self_connect_retries')}")
        print(f"{'OK' if not bypassed else 'FAIL'} bypass {len(bypassed)}/{CONNECTIONS}")
        call("DELETE", f"/{sid}")
    finally:
        server.close()


def test_edit():
    server = EchoServer(r"\tdc_test")
    c = None
    try:
        st, s = call("POST", body={"pattern": r"\tdc_test", "mode": "hold",
                                   "how": "attach", "match": "exact", "hold_timeout": 60})
        print("start hold:", st, s.get("state"), s.get("error", ""))
        if st != 201:
            print("FAIL edit")
            return
        sid = s["id"]
        print("active:", bool(active(sid)))
        c = b.connect(r"\tdc_test", 5.0)
        b.write(c, b"original")
        item = wait_for(lambda: held(sid, "c2s"), 3.0)
        if not item:
            print("FAIL edit: bypass, no held c2s message; server got", server.received)
        else:
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
        call("DELETE", f"/{sid}")
    finally:
        if c is not None:
            b.close(c)
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
