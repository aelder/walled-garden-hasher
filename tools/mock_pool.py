#!/usr/bin/env python3
"""A mock Verus PBaaS stratum pool.

Exists so the client's protocol handling and -- more importantly -- its submit
framing can be exercised without pointing anything at a real pool. It validates
what the miner sends rather than just accepting it, so a malformed share fails
the test instead of being silently swallowed the way a real pool would.

  usage: mock_pool.py [--port N] [--solution-version V] [--reject stale|bad]
"""
import argparse
import json
import socket
import sys
import threading

XNONCE1 = "a1b2c3d4"          # 4 bytes, as most Verus pools issue
TARGET = "00000fff" + "ff" * 28   # easy: anything under it is a share


def make_solution(version):
    """1344 bytes. Byte 0 is the solution version; byte 5 non-zero marks a
    PBaaS descriptor, which is what switches the miner to the zeroed-header
    preimage."""
    sol = bytearray(1344)
    sol[0] = version
    sol[5] = 1 if version >= 7 else 0
    for i in range(8, 1344):
        sol[i] = (i * 7) & 0xFF
    return sol.hex()


def notify(job_id, solution_version):
    return {
        "id": None,
        "method": "mining.notify",
        "params": [
            job_id,
            "04000000",                 # version
            "aa" * 32,                  # prevhash
            "bb" * 32,                  # merkle root
            "cc" * 32,                  # reserved / sapling
            "5f000000",                 # ntime
            "1d00ffff",                 # nbits
            True,                       # clean
            make_solution(solution_version),
        ],
    }


class Session(threading.Thread):
    def __init__(self, conn, args):
        super().__init__(daemon=True)
        self.conn, self.args = conn, args
        self.problems = []
        self.submits = 0
        self.done = threading.Event()

    def send(self, obj):
        self.conn.sendall((json.dumps(obj) + "\n").encode())

    def check_submit(self, params):
        """The part that matters: a real pool rejects silently, so be loud."""
        if len(params) != 5:
            self.problems.append("submit needs 5 params, got %d" % len(params))
            return False
        user, job_id, timehex, noncestr, solhex = params
        ok = True
        if len(timehex) != 8:
            self.problems.append("timehex must be 8 hex chars, got %r" % timehex)
            ok = False
        # The pool owns xnonce1 and re-derives it, so the miner must send only
        # the remainder of the 32-byte nonce.
        expect = (32 - len(XNONCE1) // 2) * 2
        if len(noncestr) != expect:
            self.problems.append(
                "nonce must be %d hex chars (32 bytes minus xnonce1), got %d"
                % (expect, len(noncestr)))
            ok = False
        if not solhex.startswith("fd4005"):
            self.problems.append("solution must carry the fd4005 CompactSize prefix")
            ok = False
        if len(solhex) != 6 + 1344 * 2:
            self.problems.append("solution must be 3 + 1344 bytes, got %d hex chars"
                                 % len(solhex))
            ok = False
        for name, v in (("nonce", noncestr), ("solution", solhex)):
            if any(c not in "0123456789abcdefABCDEF" for c in v):
                self.problems.append("%s is not hex" % name)
                ok = False
        if not user:
            self.problems.append("empty worker name")
            ok = False
        return ok

    def run(self):
        buf = b""
        job = "job00000000000001"
        try:
            while True:
                data = self.conn.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    msg = json.loads(line)
                    m, mid = msg.get("method"), msg.get("id")

                    if m == "mining.subscribe":
                        self.send({"id": mid, "result": [[], XNONCE1, 4], "error": None})
                    elif m == "mining.authorize":
                        self.send({"id": mid, "result": True, "error": None})
                        self.send({"id": None, "method": "mining.set_target",
                                   "params": [TARGET]})
                        self.send(notify(job, self.args.solution_version))
                    elif m == "mining.submit":
                        self.submits += 1
                        good = self.check_submit(msg.get("params", []))
                        if self.args.reject == "stale":
                            self.send({"id": mid, "result": False,
                                       "error": [21, "Job not found (stale)", None]})
                        elif self.args.reject == "bad":
                            self.send({"id": mid, "result": False,
                                       "error": [20, "Other/Unknown", None]})
                        else:
                            self.send({"id": mid, "result": good, "error": None})
                        if not self.args.persist:
                            self.done.set()
                    else:
                        self.send({"id": mid, "result": True, "error": None})
        except (ConnectionError, json.JSONDecodeError, OSError):
            pass
        finally:
            self.done.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=13956)
    ap.add_argument("--solution-version", type=int, default=7)
    ap.add_argument("--reject", choices=["stale", "bad"], default=None)
    ap.add_argument("--persist", action="store_true",
                    help="keep serving after the first share, for UI testing")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    srv.settimeout(args.timeout)
    print("mock pool on 127.0.0.1:%d (solution v%d)" % (args.port, args.solution_version),
          flush=True)

    try:
        conn, _ = srv.accept()
    except socket.timeout:
        print("FAIL: no client connected")
        return 1
    s = Session(conn, args)
    s.start()
    s.done.wait(args.timeout)
    s.join(timeout=2)

    print("submits seen: %d" % s.submits)
    for p in s.problems:
        print("PROBLEM: %s" % p)
    if s.submits == 0:
        print("FAIL: client never submitted a share")
        return 1
    if s.problems:
        print("FAIL: %d malformed submit(s)" % len(s.problems))
        return 1
    print("OK: submit framing valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
