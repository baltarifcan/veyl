#!/usr/bin/env python3
"""connect-bridge: an HTTP CONNECT front-end for the veyl/ciadpi SOCKS bypass.

Why this exists: Discord's macOS updater (Contents/Resources/updater.node, Rust +
reqwest) does its own networking. It honours HTTPS_PROXY / NO_PROXY but was built
without SOCKS support, and reqwest's macOS system-proxy lookup only reads the
HTTP/HTTPS proxy keys -- never the SOCKS one. So while the Chromium half of
Discord goes through the system SOCKS proxy and works, the updater's manifest
fetch from updates.discord.com leaves raw, the DPI resets the TLS handshake, and
the update fails with hyper error -9806 "connection closed via error".

This gives such clients something they will use. Routing per CONNECT target:

  * host in --direct-file (if given) -> always direct
  * anything else                    -> through ciadpi SOCKS5

Everything goes through ciadpi because it runs in auto-detect mode: it tries
each connection undesynced and only retries with a desync once the DPI actually
resets it, so routing an unblocked host through it is a no-op. That is what
removes the hostlist -- a newly blocked domain starts working here with nothing
to edit.

--direct-file is an escape hatch for hosts that must never be desynced even if
they look blocked. It is normally unset, and note it only covers traffic that
reaches *this* bridge -- the system SOCKS path does not consult it.

Hostnames are passed to ciadpi as SOCKS5 domain targets (ATYP 0x03) so it can
match and desync by SNI.
"""

import argparse
import errno
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080

CONNECT_TIMEOUT = 15
IDLE_TIMEOUT = 300
BUF = 65536


def log(msg):
    sys.stderr.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stderr.flush()


class HostLists(object):
    """Suffix list from an optional file, reloaded when its mtime changes."""

    def __init__(self, direct_file=None):
        self._direct_file = direct_file
        self._lock = threading.Lock()
        self._cache = {}   # path -> (mtime, [entries])

    def entries(self, path):
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            with self._lock:
                self._cache[path] = (None, [])
            return []
        with self._lock:
            cached = self._cache.get(path)
            if cached and cached[0] == mtime:
                return cached[1]
        entries = []
        try:
            with open(path, "r") as fh:
                for line in fh:
                    line = line.strip().lower().rstrip(".")
                    if line and not line.startswith("#"):
                        entries.append(line)
        except OSError as exc:
            log("warn: cannot read %s: %s" % (path, exc))
        with self._lock:
            self._cache[path] = (mtime, entries)
        return entries

    @staticmethod
    def _matches(host, entries):
        host = host.lower().rstrip(".")
        for entry in entries:
            if host == entry or host.endswith("." + entry):
                return True
        return False

    def route(self, host):
        """Return 'direct' or 'socks' for this hostname.

        Default is 'socks' now that ciadpi runs in auto-detect mode: it tries
        every connection undesynced first and only retries with a desync after
        the DPI actually resets it, so sending unblocked hosts through it is a
        no-op. Routing everything through means a newly-blocked domain starts
        working here without anyone editing a list -- which was the whole point
        of dropping the hostlist.

        The direct list is still honoured and still checked first: it is for
        hosts that must never be desynced even if they *look* blocked. If ciadpi
        is not running, dial_socks5 falls back to direct on its own.
        """
        if self._direct_file and self._matches(host, self.entries(self._direct_file)):
            return "direct"
        return "socks"


def dial_direct(host, port):
    return socket.create_connection((host, port), CONNECT_TIMEOUT)


SOCKS5_ERRORS = {
    1: "general failure", 2: "connection not allowed", 3: "network unreachable",
    4: "host unreachable", 5: "connection refused", 6: "TTL expired",
    7: "command not supported", 8: "address type not supported",
}


def dial_socks5(host, port):
    """CONNECT through ciadpi, passing the hostname so it can desync by SNI."""
    sock = socket.create_connection((SOCKS_HOST, SOCKS_PORT), CONNECT_TIMEOUT)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        sock.sendall(b"\x05\x01\x00")
        greeting = recv_exact(sock, 2)
        if greeting[0:1] != b"\x05" or greeting[1:2] != b"\x00":
            raise IOError("SOCKS5 greeting rejected: %r" % greeting)

        target = host.encode("idna") if not is_ip_literal(host) else host.encode()
        if len(target) > 255:
            raise IOError("hostname too long for SOCKS5")
        sock.sendall(b"\x05\x01\x00\x03" + struct.pack("!B", len(target)) +
                     target + struct.pack("!H", port))

        reply = recv_exact(sock, 4)
        if reply[0:1] != b"\x05":
            raise IOError("bad SOCKS5 reply version: %r" % reply)
        code = reply[1]
        if code != 0:
            raise IOError("SOCKS5 refused: %s" % SOCKS5_ERRORS.get(code, "code %d" % code))
        atyp = reply[3:4]
        if atyp == b"\x01":
            recv_exact(sock, 4 + 2)
        elif atyp == b"\x04":
            recv_exact(sock, 16 + 2)
        elif atyp == b"\x03":
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        else:
            raise IOError("bad SOCKS5 address type: %r" % atyp)
        return sock
    except Exception:
        sock.close()
        raise


def recv_exact(sock, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise IOError("SOCKS5 peer closed mid-handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def is_ip_literal(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, ValueError):
            continue
    return False


def split_authority(authority):
    """Parse 'host:port' from a CONNECT target, incl. [v6]:port form."""
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise ValueError("unterminated IPv6 literal")
        host = authority[1:end]
        rest = authority[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        return host, port
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        return host, int(port)
    return authority, 443


def relay(a, b):
    """Pump bytes both ways until either side closes or goes idle."""
    socks = [a, b]
    for sock in socks:
        sock.settimeout(None)
    try:
        while True:
            readable, _, errored = select.select(socks, [], socks, IDLE_TIMEOUT)
            if errored or not readable:
                return
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(BUF)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Handler(socketserver.StreamRequestHandler):
    timeout = CONNECT_TIMEOUT

    def handle(self):
        try:
            request_line = self.rfile.readline(8192)
        except OSError:
            return
        if not request_line:
            return
        parts = request_line.decode("latin-1").split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            self.reply(501, "Not Implemented")
            log("rejected non-CONNECT request: %r" % request_line[:60])
            return

        # Drain the request headers; CONNECT carries no body.
        while True:
            line = self.rfile.readline(8192)
            if not line or line in (b"\r\n", b"\n"):
                break

        try:
            host, port = split_authority(parts[1])
        except ValueError:
            self.reply(400, "Bad Request")
            return

        route = self.server.hostlists.route(host)
        try:
            upstream = dial_socks5(host, port) if route == "socks" else dial_direct(host, port)
        except Exception as exc:
            if route == "socks":
                # ciadpi down (veyl toggled off?) -- direct is better than nothing.
                log("socks dial failed for %s:%d (%s); falling back to direct" % (host, port, exc))
                try:
                    upstream = dial_direct(host, port)
                except Exception as exc2:
                    log("direct fallback failed for %s:%d: %s" % (host, port, exc2))
                    self.reply(502, "Bad Gateway")
                    return
            else:
                log("direct dial failed for %s:%d: %s" % (host, port, exc))
                self.reply(502, "Bad Gateway")
                return

        try:
            self.reply(200, "Connection established")
            relay(self.connection, upstream)
        finally:
            upstream.close()

    def reply(self, code, text):
        try:
            self.wfile.write(("HTTP/1.1 %d %s\r\n\r\n" % (code, text)).encode())
            self.wfile.flush()
        except OSError:
            pass

    def handle_error(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, OSError) and exc.errno in (errno.EPIPE, errno.ECONNRESET):
            return
        log("handler error: %r" % (exc,))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=1085)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--direct-file", default=None,
                        help="file of hosts to always dial direct (optional)")
    args = parser.parse_args()

    server = Server((args.bind, args.port), Handler)
    server.hostlists = HostLists(args.direct_file)
    log("connect-bridge listening on %s:%d -> ciadpi %s:%d (direct: %s)"
        % (args.bind, args.port, SOCKS_HOST, SOCKS_PORT, args.direct_file or "none"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
