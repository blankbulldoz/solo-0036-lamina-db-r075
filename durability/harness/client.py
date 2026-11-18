"""Process control and HTTP client for LaminaDB durability probes.

The client deliberately distinguishes three observation classes, because the
durability contract treats them differently:

  * "2xx"          a durable result was published before the answer was sent
  * "error"        a domain error answer arrived (no publish, or an explicitly
                   uncertain storage result)
  * "no_response"  the transport failed or the answer was never read; the
                   caller cannot know whether the commit reached stable storage

Nothing here retries a commit. A retried commit would erase the very boundary
this package exists to observe. Retry is expressed only as an explicit
experiment step (see E2R), so that its duplicate effect becomes visible.
"""

import http.client
import json
import os
import signal
import socket
import subprocess
import time

API = "/v1/lamina"


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def classify(status):
    if status is None:
        return "no_response"
    if 200 <= status < 300:
        return "2xx"
    return "error"


def observation(status, body, elapsed, error, path):
    """One HTTP call, tagged with the observation class the contract needs."""
    return {
        "status": status,
        "body": body,
        "class": classify(status),
        "elapsed_ms": round(elapsed * 1000.0, 3),
        "error": error,
        "path": path,
    }


def error_code(obs):
    """Domain error code, if the answer carried one."""
    body = obs.get("body")
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"].get("code")
    return None


class Conn:
    """Keep-alive HTTP connection. Reconnects only for idempotent GETs."""

    def __init__(self, host, port, timeout=60.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn = None

    def _connection(self):
        if self._conn is None:
            self._conn = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout
            )
        return self._conn

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def request(self, method, path, body=None, timeout=None, retry_get=False):
        started = time.monotonic()
        attempts = 2 if (retry_get and method == "GET") else 1
        last = None
        for attempt in range(attempts):
            raw = None
            if body is not None:
                raw = json.dumps(body, ensure_ascii=False).encode()
            try:
                conn = self._connection()
                conn.timeout = timeout or self.timeout
                conn.request(method, path, body=raw,
                             headers={"Content-Type": "application/json"})
                response = conn.getresponse()
                payload = response.read()
                status = response.status
                try:
                    decoded = json.loads(payload) if payload else None
                except json.JSONDecodeError:
                    decoded = {"_raw": payload.decode("utf-8", "replace")}
                return observation(status, decoded,
                                   time.monotonic() - started, None, path)
            except Exception as exc:  # transport failure
                last = exc
                self.close()
                if attempt + 1 < attempts:
                    time.sleep(0.02)
        return observation(None, None, time.monotonic() - started,
                           f"{type(last).__name__}: {last}", path)

    def get(self, path, timeout=None):
        return self.request("GET", path, timeout=timeout, retry_get=True)

    def post(self, path, body=None, timeout=None):
        return self.request("POST", path, body=body, timeout=timeout)


class Server:
    """One laminad process over one data directory."""

    def __init__(self, binary, root, restore=None, log_path=None,
                 env=None):
        self.binary = binary
        self.root = root
        self.restore = restore
        self.log_path = log_path or (root.rstrip("/") + ".server.log")
        self.env = dict(os.environ)
        if env:
            self.env.update(env)
        self.proc = None
        self.port = None
        self.conn = None
        self._log = None

    # -- lifecycle ------------------------------------------------------------

    def start(self, deadline=60.0):
        """Start the process and wait for /health.

        A startup refusal (for example a rejected restore image or a corrupt
        journal) is a normal observation, not an exception.
        """
        if self.proc is not None and self.proc.poll() is None:
            raise RuntimeError("server already running")
        self.port = free_port()
        args = [self.binary, "-data", self.root,
                "-listen", f"127.0.0.1:{self.port}"]
        if self.restore:
            args += ["-restore", self.restore]
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        self._log = open(self.log_path, "ab")
        self._log.write(("### start %s %s\n"
                         % (time.strftime("%H:%M:%S"), " ".join(args))
                         ).encode())
        self._log.flush()
        self.proc = subprocess.Popen(args, stdout=self._log,
                                     stderr=subprocess.STDOUT,
                                     env=self.env)
        self.conn = Conn("127.0.0.1", self.port)
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                return {"ok": False, "error": self.log_tail(),
                        "port": self.port, "exit": self.proc.returncode}
            result = self.conn.get(API + "/health", timeout=2.0)
            if result["status"] == 200:
                return {"ok": True, "error": None, "port": self.port,
                        "exit": None}
            time.sleep(0.01)
        self.kill()
        return {"ok": False, "error": "health timeout\n" + self.log_tail(),
                "port": self.port, "exit": None}

    def wait(self, timeout=30.0):
        if self.proc is None:
            return None
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return "timeout"

    def stop(self, sig=signal.SIGTERM, timeout=30.0):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(sig)
        rc = self.wait(timeout)
        self._close_log()
        return rc

    def kill(self):
        return self.stop(signal.SIGKILL, timeout=30.0)

    def terminate(self):
        return self.stop(signal.SIGTERM, timeout=30.0)

    def _close_log(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if self._log is not None:
            try:
                self._log.close()
            except Exception:
                pass
            self._log = None

    def log_tail(self, limit=4000):
        try:
            with open(self.log_path, "rb") as handle:
                return handle.read()[-limit:].decode("utf-8", "replace")
        except OSError:
            return ""

    # -- API ------------------------------------------------------------------

    def begin(self, read_only=False):
        return self.conn.post(API + "/transactions", {"read_only": read_only})

    def put(self, tx, relation, row, insert_only=False):
        return self.conn.post(
            f"{API}/transactions/{tx}/put",
            {"relation": relation, "row": row, "insert_only": insert_only},
        )

    def delete(self, tx, relation, key):
        return self.conn.post(
            f"{API}/transactions/{tx}/delete",
            {"relation": relation, "key": key},
        )

    def commit(self, tx, timeout=60.0):
        return self.conn.post(
            f"{API}/transactions/{tx}/commit", timeout=timeout
        )

    def rollback(self, tx):
        return self.conn.post(f"{API}/transactions/{tx}/rollback")

    def query(self, relation, **kwargs):
        body = {"relation": relation, "limit": 10000}
        body.update(kwargs)
        return self.conn.post(API + "/query", body)

    def changes(self, after=0, limit=1000):
        return self.conn.get(
            f"{API}/changes?after={after}&limit={limit}"
        )

    def stats(self):
        return self.conn.get(API + "/stats")

    def create_relation(self, name, columns, primary="k"):
        return self.conn.post(
            API + "/relations",
            {"name": name, "primary": primary, "columns": columns},
        )

    def checkpoint(self):
        return self.conn.post(API + "/checkpoint", {})

    def vacuum(self, horizon):
        return self.conn.post(API + "/vacuum", {"horizon": horizon})

    def backup_bytes(self, timeout=60.0):
        """GET /backup returns raw image bytes, not JSON."""
        started = time.monotonic()
        try:
            conn = self.conn._connection()
            conn.timeout = timeout
            conn.request("GET", API + "/backup")
            response = conn.getresponse()
            data = response.read()
            return {"status": response.status, "data": data, "error": None,
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
        except Exception as exc:
            self.conn.close()
            return {"status": None, "data": None,
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}


def abandon_commit(port, tx, timeout=10.0):
    """Send a commit and close the socket without reading the answer.

    The server still processes the request; the caller simply owns no
    observation. This is the natural producer of the "no response" class.
    """
    request = (
        f"POST {API}/transactions/{tx}/commit HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\nContent-Length: 0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.sendall(request)
        sock.close()
        return {"sent": True, "error": None,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
    except Exception as exc:
        return {"sent": False, "error": f"{type(exc).__name__}: {exc}",
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}


def can_connect(port, timeout=1.0):
    """Can a new connection be established? Used to read the shutdown drain."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.close()
        return {"accepted": True, "error": None}
    except Exception as exc:
        return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}


# -- state readers used by every verification step ---------------------------

def read_stats(server):
    obs = server.stats()
    return obs["body"] if obs["status"] == 200 else {
        "status": obs["status"], "error": obs["body"]}


def read_changes(server, after=0, limit=1000):
    obs = server.changes(after, limit)
    if obs["status"] == 200:
        return obs["body"]
    return {"status": obs["status"], "error": obs["body"]}


def read_rows(server, relation, at=None, limit=10000):
    kwargs = {"limit": limit}
    if at is not None:
        kwargs["at"] = at
    obs = server.query(relation, **kwargs)
    if obs["status"] == 200:
        body = obs["body"] or {}
        return {"status": 200, "rows": body.get("rows", []),
                "truncated": body.get("truncated")}
    return {"status": obs["status"], "rows": None, "error": obs["body"]}


def row_keys(rows_body):
    rows = rows_body.get("rows") or []
    return sorted(row.get("k") for row in rows
                  if isinstance(row, dict) and "k" in row)


def commit_writes(changes_body):
    """Per commit record: (sequence, transaction, sorted keys)."""
    out = []
    if not isinstance(changes_body, dict):
        return out
    for record in changes_body.get("records") or []:
        if record.get("kind") != "commit":
            continue
        keys = sorted(w.get("key") for w in record.get("writes") or [])
        out.append((record.get("sequence"), record.get("transaction"), keys))
    return out


def journal_size(root):
    try:
        return os.path.getsize(os.path.join(root, "journal.lmw"))
    except OSError:
        return None
