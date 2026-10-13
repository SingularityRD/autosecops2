"""Air-gap socket guard, loaded into every Python process of a guarded run.

Put this folder first on PYTHONPATH and set ``AIRGAP_GUARD_LOG`` to a file:
Python imports ``sitecustomize`` at start-up, before any application code, so
every later ``socket``/``subprocess`` use goes through the wrappers below. Child
Python processes inherit PYTHONPATH and are guarded too.

A destination is allowed when it is this machine (loopback, a Unix socket) or
listed in ``AIRGAP_EGRESS_ALLOWLIST`` (comma-separated host or host:port). Any
other attempt is written to the log as one JSON line and refused the way a
firewalled network would refuse it -- a resolver error for a name, ECONNREFUSED
for an address -- so the application takes its normal failure path rather than
crashing on something it never sees in production.

Launching a command-line tool that reaches the network on its own (git, npx,
pip, curl, ...) is logged too; it is not blocked, because the tool is not
Python and the guard cannot follow it.

Without ``AIRGAP_GUARD_LOG`` this module does nothing.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
import traceback

_LOG = os.environ.get("AIRGAP_GUARD_LOG")
_NET_COMMANDS = {
    "git", "npx", "npm", "pip", "pip3", "uv", "uvx", "curl", "wget", "docker",
    "ssh", "scp", "rsync", "nc", "helm", "kubectl",
}  # fmt: skip
_lock = threading.Lock()


def _allowlist():
    raw = os.environ.get("AIRGAP_EGRESS_ALLOWLIST", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


_ALLOWED = _allowlist()


def _record(event, target, **extra):
    frames = [
        f"{f.filename}:{f.lineno}:{f.name}"
        for f in traceback.extract_stack()[:-2]
        if "sitecustomize" not in f.filename
    ][-8:]
    line = {
        "ts": time.time(),
        "pid": os.getpid(),
        "argv": sys.argv[:3],
        "event": event,
        "target": target,
        "stack": frames,
    }
    line.update(extra)
    try:
        with _lock, open(_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
    except OSError:
        pass


def _host_is_local(host) -> bool:
    if host is None:
        return True  # getaddrinfo(None, port): a wildcard bind address
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.split("%", 1)[0]  # IPv6 zone id
    if host in ("", "localhost", "localhost.localdomain", "ip6-localhost"):
        return True
    if host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _allowed(host, port=None) -> bool:
    if _host_is_local(host):
        return True
    h = (host.decode() if isinstance(host, bytes) else str(host)).lower().strip("[]")
    return h in _ALLOWED or (port is not None and f"{h}:{port}" in _ALLOWED)


def _inet_target(sock, address):
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return None  # AF_UNIX, AF_NETLINK, ...: never leaves the machine
    if isinstance(address, tuple) and address:
        return address[0], (address[1] if len(address) > 1 else None)
    return None


def _install():
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyname_ex = socket.gethostbyname_ex

    def connect(self, address):
        target = _inet_target(self, address)
        if target and not _allowed(*target):
            _record("connect", f"{target[0]}:{target[1]}")
            raise ConnectionRefusedError(
                errno.ECONNREFUSED, "refused by the air-gap guard"
            )
        return real_connect(self, address)

    def connect_ex(self, address):
        target = _inet_target(self, address)
        if target and not _allowed(*target):
            _record("connect", f"{target[0]}:{target[1]}")
            return errno.ECONNREFUSED
        return real_connect_ex(self, address)

    def sendto(self, data, *args):
        address = args[-1] if args else None
        target = _inet_target(self, address)
        if target and not _allowed(*target):
            _record("sendto", f"{target[0]}:{target[1]}")
            raise ConnectionRefusedError(
                errno.ECONNREFUSED, "refused by the air-gap guard"
            )
        return real_sendto(self, data, *args)

    def getaddrinfo(host, port, *args, **kwargs):
        if not _allowed(host, port):
            _record("dns", f"{host}:{port}")
            raise socket.gaierror(socket.EAI_NONAME, "refused by the air-gap guard")
        return real_getaddrinfo(host, port, *args, **kwargs)

    def gethostbyname(host):
        if not _allowed(host):
            _record("dns", str(host))
            raise socket.gaierror(socket.EAI_NONAME, "refused by the air-gap guard")
        return real_gethostbyname(host)

    def gethostbyname_ex(host):
        if not _allowed(host):
            _record("dns", str(host))
            raise socket.gaierror(socket.EAI_NONAME, "refused by the air-gap guard")
        return real_gethostbyname_ex(host)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.getaddrinfo = getaddrinfo
    socket.gethostbyname = gethostbyname
    socket.gethostbyname_ex = gethostbyname_ex

    real_popen_init = subprocess.Popen.__init__

    def popen_init(self, args, *a, **kw):
        try:
            argv = [args] if isinstance(args, (str, bytes)) else list(args)
            head = argv[0] if argv else ""
            if isinstance(head, bytes):
                head = head.decode("utf-8", "replace")
            head = str(head)
            if kw.get("shell") or isinstance(args, (str, bytes)):
                head = head.split()[0] if head.split() else head
            name = os.path.basename(head)
            if name in _NET_COMMANDS:
                _record("exec", " ".join(str(x) for x in argv)[:200])
        except Exception:  # noqa: BLE001 - the guard must never break a launch
            pass
        return real_popen_init(self, args, *a, **kw)

    subprocess.Popen.__init__ = popen_init
    _record("armed", sys.executable)


if _LOG:
    _install()
