#!/usr/bin/env python3
"""
Local DoH-to-DNS proxy (hardened).

Accepts plain DNS over UDP *and* TCP on 127.0.0.1:53 and forwards each query to
Cloudflare's DoH endpoint at https://1.1.1.1/dns-query, using SNI
'cloudflare-dns.com' while connecting to a literal IP -- so it never needs DNS
to bootstrap, and cert validation still passes. Intended to be the system
resolver behind a DPI/DNS-sinkhole bypass (see the repository README).

Design goals (this rewrite):
  * BOUNDED concurrency. A fixed worker pool + in-flight cap, instead of one
    unbounded OS thread per UDP packet. The old version spawned a thread per
    datagram; when upstream stalled, threads (and the kernel sockets they each
    opened) piled up without limit and wedged the network stack hard enough
    that the watchdog killed configd and the machine froze. This version sheds
    load instead of melting down.
  * CACHING. Answers are cached honouring their DNS TTL, so repeated lookups
    are answered locally in microseconds instead of a ~0.6-5s round trip.
  * CONNECTION REUSE. A small keep-alive pool of HTTPS connections per upstream
    replaces the fresh TLS handshake that the old version did on every query.
  * FAST FAILOVER. Short timeouts + a per-upstream circuit breaker, so a dead
    upstream is skipped for a cooldown window rather than costing every query a
    multi-second stall.
  * SINGLE-FLIGHT. A burst of identical concurrent queries collapses to one
    upstream fetch.

No external dependencies -- Python 3 stdlib only. Targets macOS's bundled
Python 3.9 at /usr/bin/python3.
"""
import http.client
import os
import selectors
import socket
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# ---- configuration -------------------------------------------------------

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("DOH_LISTEN_PORT", "53"))

UPSTREAM_PORT = 443

# (ip, SNI, path) per upstream. Each entry connects to a literal IP while
# presenting a real hostname for SNI and cert validation, so the proxy never
# needs DNS to bootstrap itself.
#
# Provider diversity is deliberate, and the ORDER matters: consecutive entries
# are different providers, so the two attempts a single query gets (see
# MAX_UPSTREAM_ATTEMPTS) land on two independent network paths. With Cloudflare
# as the only provider, one degraded path to 1.1.1.1/1.0.0.1 parked *every*
# upstream at once, the proxy had nowhere left to ask, and DNS died outright --
# the upstream failure of 2026-08-24. Listing 1.1.1.1 and 1.0.0.1 back to back
# would have reproduced it, since both share that path.
#
# CONSTRAINT: every upstream here MUST answer plain HTTP/1.1, because
# http.client speaks nothing else and this file is stdlib-only by design.
# Verified 2026-08-24 with an HTTP/1.1 POST of application/dns-message:
# Cloudflare, Google, OpenDNS and AdGuard all return 200. Quad9 does NOT --
# 9.9.9.9 and 149.112.112.112 both return "505 HTTP Version Not Supported" to
# any HTTP/1.1 request and only work over HTTP/2, so Quad9 cannot be used from
# here at all. Do not add it back without an HTTP/2 client; a 505 counts as a
# hard failure in Upstream.query, so a Quad9 entry is worse than no entry --
# it burns one of the two attempts on a guaranteed miss.
UPSTREAMS = [
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query"),
    ("8.8.8.8", "dns.google", "/dns-query"),
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query"),
    ("8.8.4.4", "dns.google", "/dns-query"),
    ("208.67.222.222", "doh.opendns.com", "/dns-query"),
]

# Per-attempt upstream timeout. These were 2.0/2.5, sized for a healthy path
# where a full DoH round trip measures ~0.4s. That is comfortable on a fast link
# and fatal on a slow one: on a high-latency mobile link the RTT to Cloudflare ran 400ms+ with
# ~100ms jitter and packet loss, so the TLS handshake alone blew past 2s and
# three strikes parked every upstream within seconds. The ceiling has to fit the
# worst link this machine actually uses, not the best one.
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 6.0

# Upstreams tried sequentially per query. Deliberately fewer than
# len(UPSTREAMS): at an 11s worst case per attempt, walking the whole list would
# hang a 55s tail on one lookup, long after every client has given up. Two
# covers "this provider is down, try another"; the circuit breaker handles the
# rest by parking bad upstreams so the *next* query already starts elsewhere.
MAX_UPSTREAM_ATTEMPTS = 2

# How long a single-flight follower waits on the leader. This MUST cover the
# leader's realistic worst case. When it was shorter (READ+CONNECT, 4.5s) than
# the leader's true ceiling, followers gave up and each promoted ITSELF to
# leader -- multiplying upstream load at the exact moment upstream was already
# failing, which is the opposite of what single-flight is for.
LEADER_WAIT = (CONNECT_TIMEOUT + READ_TIMEOUT) * MAX_UPSTREAM_ATTEMPTS + 0.5

# Idle ceiling between messages on one DNS-over-TCP connection. Kept short
# because each open connection holds a pool worker (see _handle_tcp).
TCP_IDLE_TIMEOUT = 2.0

# How long to wait for a TCP client's FIRST message. This used to borrow
# LEADER_WAIT, which only coincidentally resembled a sane value; now that
# LEADER_WAIT tracks the (larger) upstream budget, reusing it here would let one
# silent client hold a pool worker for ~22s and starve MAX_WORKERS -- exactly
# what _handle_tcp's short idle ceiling exists to prevent. A client that has
# opened a connection sends its query promptly or it is not worth waiting for.
TCP_FIRST_TIMEOUT = 5.0

# Concurrency. Workers actually talking upstream are bounded; excess UDP load is
# dropped (clients retry) rather than spawning unbounded threads + sockets.
MAX_WORKERS = 24
MAX_INFLIGHT = 64

# Connection pool: idle keep-alive connections kept per upstream IP.
POOL_PER_UPSTREAM = 6

# Circuit breaker: after this many consecutive failures an upstream is parked.
CB_FAIL_THRESHOLD = 3
CB_COOLDOWN = 10.0

# Cache TTL clamps (seconds). We never trust a TTL of 0 to mean "never cache"
# here -- a tiny floor massively cuts repeat-lookup latency for chatty clients
# (game launchers, browsers) while staying correct enough for a stub resolver.
CACHE_MIN_TTL = 5
CACHE_MAX_TTL = 3600
NEG_TTL = 15            # a *successful* answer that carries no usable TTL

# Hard-failure caching. Previously nothing was cached when every upstream
# failed, so each client retry paid the full multi-second upstream cost and the
# retries themselves sustained the outage; a few-second link flap became minutes
# of dead DNS. Caching the SERVFAIL turns a retry storm into cheap local
# answers and lets the proxy drain. Short, so recovery is picked up at once.
FAIL_TTL = 3
CACHE_MAX_ENTRIES = 8192

# Error-log rate limiting (the old version wrote one line per failed query,
# producing a 135KB log of identical messages during the outage).
LOG_THROTTLE = 5.0

_SSL_CTX = ssl.create_default_context()


# ---- logging -------------------------------------------------------------

_log_lock = threading.Lock()
_log_last = {}        # message -> last-emitted monotonic time
_log_suppressed = {}  # message -> count suppressed since last emit


def log(msg, throttle=False):
    now = time.monotonic()
    with _log_lock:
        if throttle:
            last = _log_last.get(msg, 0.0)
            if now - last < LOG_THROTTLE:
                _log_suppressed[msg] = _log_suppressed.get(msg, 0) + 1
                return
            n = _log_suppressed.pop(msg, 0)
            _log_last[msg] = now
            if n:
                msg = "%s (+%d more in last %.0fs)" % (msg, n, LOG_THROTTLE)
        print("[doh-proxy] " + msg, file=sys.stderr, flush=True)


# ---- minimal DNS wire parsing -------------------------------------------
# Just enough to derive a cache key (question section) and a TTL. We never
# rewrite RDATA; responses are cached and replayed verbatim except the 2-byte
# transaction ID, which is per-client.

class DNSFormatError(Exception):
    pass


def _read_name(buf, off):
    """Advance past a (possibly compressed) name; return offset after it.

    We only need the end offset within the record stream. A compression
    pointer (0xC0) terminates the in-stream name after its 2 bytes.
    """
    n = len(buf)
    while True:
        if off >= n:
            raise DNSFormatError("name overruns packet")
        length = buf[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:
            return off + 2          # pointer: name ends here in-stream
        off += 1 + length


def parse_question(buf):
    """Return (cache_key, qname_lower, qtype, qend_offset) or None.

    cache_key is bytes that uniquely identify the question independent of the
    transaction ID. Only single-question queries are cached (the norm).
    """
    if len(buf) < 12:
        raise DNSFormatError("short header")
    qdcount = struct.unpack_from("!H", buf, 4)[0]
    if qdcount != 1:
        return None
    off = 12
    name_start = off
    labels = []
    n = len(buf)
    while True:
        if off >= n:
            raise DNSFormatError("question name overruns")
        length = buf[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            raise DNSFormatError("compression in question")
        off += 1
        if off + length > n:
            raise DNSFormatError("label overruns")
        labels.append(buf[off:off + length].lower())
        off += length
    if off + 4 > n:
        raise DNSFormatError("missing qtype/qclass")
    qtype, qclass = struct.unpack_from("!HH", buf, off)
    qend = off + 4
    qname = b".".join(labels)
    # key = normalized name + qtype + qclass (case-insensitive on name)
    key = qname + struct.pack("!HH", qtype, qclass)
    return key, qname, qtype, qend


def _skip_rr(buf, off):
    off = _read_name(buf, off)
    if off + 10 > len(buf):
        raise DNSFormatError("rr header overruns")
    rdlength = struct.unpack_from("!H", buf, off + 8)[0]
    ttl = struct.unpack_from("!I", buf, off + 4)[0]
    off += 10 + rdlength
    if off > len(buf):
        raise DNSFormatError("rdata overruns")
    return off, ttl


def response_min_ttl(buf):
    """Minimum TTL across answer/authority/additional records (excluding OPT).

    Returns None if the message can't be parsed; the caller then uses NEG_TTL.
    """
    try:
        _, _, ancount, nscount, arcount = struct.unpack_from("!HHHHH", buf, 2)
        # walk past the question(s)
        qdcount = struct.unpack_from("!H", buf, 4)[0]
        off = 12
        for _ in range(qdcount):
            off = _read_name(buf, off) + 4  # name + qtype + qclass
        ttls = []
        for _ in range(ancount + nscount + arcount):
            name_off = off
            off, ttl = _skip_rr(buf, off)
            # crude OPT(41) detection: type is 2 bytes right after the name
            type_off = _read_name(buf, name_off)
            rrtype = struct.unpack_from("!H", buf, type_off)[0]
            if rrtype != 41:  # ignore EDNS OPT pseudo-RR TTL
                ttls.append(ttl)
        if not ttls:
            return None
        return max(CACHE_MIN_TTL, min(CACHE_MAX_TTL, min(ttls)))
    except (DNSFormatError, struct.error):
        return None


def edns_udp_size(buf):
    """Requestor's advertised UDP payload size, or 512 if no EDNS OPT present."""
    try:
        qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHH", buf, 4)
        off = 12
        for _ in range(qdcount):
            off = _read_name(buf, off) + 4
        for _ in range(ancount + nscount):
            off, _ = _skip_rr(buf, off)
        for _ in range(arcount):
            name_off = off
            type_off = _read_name(buf, name_off)
            rrtype = struct.unpack_from("!H", buf, type_off)[0]
            if rrtype == 41:  # OPT: CLASS field carries the UDP payload size
                cls = struct.unpack_from("!H", buf, type_off + 2)[0]
                return max(512, cls)
            off, _ = _skip_rr(buf, off)
    except (DNSFormatError, struct.error):
        pass
    return 512


def make_truncated(buf, qend):
    """Build a TC=1 response so an oversized UDP answer prompts a TCP retry."""
    out = bytearray(buf[:qend])
    # flags: QR=1, copy opcode/RD from request, RA=1, TC=1
    rd = buf[2] & 0x01
    out[2] = 0x80 | (buf[2] & 0x78) | (0x02 if rd else 0x00) | 0x02
    out[3] = 0x80  # RA=1, rcode=0
    struct.pack_into("!HHHH", out, 4, 1, 0, 0, 0)  # qd=1, an=ns=ar=0
    return bytes(out)


def make_servfail(buf):
    """Minimal SERVFAIL so clients get a fast answer instead of timing out."""
    if len(buf) < 12:
        return None
    try:
        _, _, qtype, qend = (parse_question(buf) or (None, None, None, None))
    except DNSFormatError:
        qend = None
    end = qend if qend else 12
    out = bytearray(buf[:end])
    rd = buf[2] & 0x01
    out[2] = 0x80 | (buf[2] & 0x78) | (0x02 if rd else 0x00)
    out[3] = 0x80 | 0x02  # RA=1, RCODE=2 (SERVFAIL)
    struct.pack_into("!HHHH", out, 4, 1 if qend else 0, 0, 0, 0)
    return bytes(out)


def set_id(resp, req):
    """Return resp with its transaction ID replaced by the request's ID."""
    if len(resp) < 2 or len(req) < 2:
        return resp
    return req[:2] + resp[2:]


# ---- upstream connection pool + circuit breaker -------------------------

class DoHConnection(http.client.HTTPSConnection):
    """HTTPS connection to a literal IP that presents a real SNI for TLS."""

    def __init__(self, real_ip, sni):
        super().__init__(sni, UPSTREAM_PORT,
                         timeout=CONNECT_TIMEOUT, context=_SSL_CTX)
        self._real_ip = real_ip
        self._sni = sni

    def connect(self):
        raw = socket.create_connection((self._real_ip, self.port), CONNECT_TIMEOUT)
        raw.settimeout(READ_TIMEOUT)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._context.wrap_socket(raw, server_hostname=self._sni)


class Upstream:
    def __init__(self, ip, sni, path):
        self.ip = ip
        self.sni = sni
        self.path = path
        self._idle = []
        self._lock = threading.Lock()
        self._fails = 0
        self._down_until = 0.0

    def available(self):
        return time.monotonic() >= self._down_until

    def _get(self):
        """Return (connection, came_from_pool)."""
        with self._lock:
            if self._idle:
                return self._idle.pop(), True
        return DoHConnection(self.ip, self.sni), False

    def _put(self, conn):
        with self._lock:
            if len(self._idle) < POOL_PER_UPSTREAM:
                self._idle.append(conn)
                return
        conn.close()

    def _record_ok(self):
        self._fails = 0
        # Un-park too: a success proves the upstream is back, and leaving
        # _down_until in the future would keep available() reporting it down.
        self._down_until = 0.0

    def _record_fail(self):
        self._fails += 1
        if self._fails >= CB_FAIL_THRESHOLD:
            self._down_until = time.monotonic() + CB_COOLDOWN

    def query(self, dns_wire):
        """One upstream attempt, retried only if a POOLED socket was at fault.

        The retry exists for exactly one case: a keep-alive connection the peer
        closed while it sat idle. Retrying a socket we just opened ourselves
        cannot help -- that failure is real -- and retrying it anyway doubled
        the cost of every query during an outage.
        """
        last_exc = None
        for attempt in (0, 1):
            conn, from_pool = self._get()
            try:
                conn.request("POST", self.path, body=dns_wire, headers={
                    "Host": self.sni,
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "User-Agent": "doh-local/2",
                    "Connection": "keep-alive",
                })
                resp = conn.getresponse()
                body = resp.read()
                if resp.status == 200 and body:
                    self._put(conn)
                    self._record_ok()
                    return body
                conn.close()
                last_exc = "HTTP %d" % resp.status
                break  # a real HTTP error won't be fixed by reconnecting
            except (OSError, http.client.HTTPException) as e:
                conn.close()
                last_exc = e
                if not from_pool:
                    break       # we opened this socket: the fault is real
                continue        # reused-but-closed socket: retry once, fresh
        self._record_fail()
        raise IOError("upstream %s failed: %s" % (self.ip, last_exc))


_UPSTREAMS = [Upstream(ip, sni, path) for ip, sni, path in UPSTREAMS]


def resolve_upstream(dns_wire):
    """Try each healthy upstream; raise IOError if all fail."""
    errs = []
    healthy = [u for u in _UPSTREAMS if u.available()]
    if healthy:
        # Cap the walk: see MAX_UPSTREAM_ATTEMPTS. Entries are provider-
        # interleaved, so the first two healthy ones are normally two different
        # providers rather than two IPs behind the same degraded path.
        ordered = healthy[:MAX_UPSTREAM_ATTEMPTS]
    else:
        # Every upstream is parked. The old code fell back to trying ALL of
        # them, which silently defeated the circuit breaker in the one scenario
        # it was written for. Probe a single upstream -- whichever is closest to
        # leaving cooldown -- so a query costs one attempt instead of four while
        # recovery is still noticed.
        ordered = [min(_UPSTREAMS, key=lambda u: u._down_until)]
    for up in ordered:
        try:
            return up.query(dns_wire)
        except IOError as e:
            errs.append(str(e))
    raise IOError("; ".join(errs) or "no upstream")


# ---- cache + single-flight ----------------------------------------------

class Cache:
    def __init__(self):
        self._d = {}            # key -> (expiry_monotonic, response_wire)
        self._lock = threading.Lock()

    def get(self, key):
        now = time.monotonic()
        with self._lock:
            ent = self._d.get(key)
            if not ent:
                return None
            exp, resp = ent
            if exp <= now:
                self._d.pop(key, None)
                return None
            return resp

    def put(self, key, resp, ttl):
        exp = time.monotonic() + ttl
        with self._lock:
            if len(self._d) >= CACHE_MAX_ENTRIES:
                # cheap eviction: drop ~1/8 of entries (oldest expiries first)
                for k in sorted(self._d, key=lambda k: self._d[k][0])[:CACHE_MAX_ENTRIES // 8]:
                    self._d.pop(k, None)
            self._d[key] = (exp, resp)


_CACHE = Cache()
_inflight = {}                  # key -> threading.Event
_inflight_lock = threading.Lock()


def lookup(dns_wire):
    """Resolve a query to a response wire (ID = 0), using cache + single-flight.

    Returns response bytes (transaction ID zeroed; caller splices client ID).
    """
    try:
        parsed = parse_question(dns_wire)
    except DNSFormatError:
        parsed = None

    if parsed is None:
        # Unparseable or multi-question: forward uncached, don't cache.
        resp = resolve_upstream(dns_wire)
        return set_id(resp, b"\x00\x00")

    key = parsed[0]
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    # Single-flight: collapse concurrent identical misses to one fetch.
    while True:
        with _inflight_lock:
            cached = _CACHE.get(key)
            if cached is not None:
                return cached
            ev = _inflight.get(key)
            if ev is None:
                ev = threading.Event()
                _inflight[key] = ev
                leader = True
                break
            leader = False
        ev.wait(timeout=LEADER_WAIT)
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        # leader failed or timed out; loop and try to become leader ourselves

    try:
        try:
            resp = resolve_upstream(dns_wire)
        except IOError:
            # Cache the failure (see FAIL_TTL). Without this, every client retry
            # re-paid the full upstream cost and mDNSResponder's own retries kept
            # the proxy saturated long after the link had recovered.
            sf = make_servfail(dns_wire)
            if sf:
                _CACHE.put(key, set_id(sf, b"\x00\x00"), FAIL_TTL)
            raise
        resp = set_id(resp, b"\x00\x00")    # normalize stored ID to 0
        ttl = response_min_ttl(resp)
        _CACHE.put(key, resp, ttl if ttl is not None else NEG_TTL)
        return resp
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        ev.set()


# ---- UDP + TCP front end -------------------------------------------------

_inflight_count = 0
_inflight_count_lock = threading.Lock()


def _handle_udp(server_sock, data, addr):
    global _inflight_count
    try:
        resp = lookup(data)
        reply = set_id(resp, data)
        if len(reply) > edns_udp_size(data):
            try:
                qend = parse_question(data)[3]
                reply = make_truncated(data, qend)
            except (DNSFormatError, TypeError):
                pass
        server_sock.sendto(reply, addr)
    except IOError as e:
        log(str(e), throttle=True)
        sf = make_servfail(data)
        if sf:
            try:
                server_sock.sendto(sf, addr)
            except OSError:
                pass
    except Exception as e:  # never let a worker die silently
        log("udp handler error: %r" % e, throttle=True)
    finally:
        with _inflight_count_lock:
            _inflight_count -= 1


def _handle_tcp(conn):
    """Serve one TCP client (DNS-over-TCP: 2-byte length prefix per message).

    Each connection holds a pool worker for as long as it stays open, so the
    idle ceiling between messages is short on purpose: a handful of idle
    keep-alive clients would otherwise starve MAX_WORKERS and stall every UDP
    query on the machine.
    """
    first = True
    try:
        while True:
            conn.settimeout(TCP_FIRST_TIMEOUT if first else TCP_IDLE_TIMEOUT)
            first = False
            hdr = _recv_exact(conn, 2)
            if not hdr:
                return
            (mlen,) = struct.unpack("!H", hdr)
            data = _recv_exact(conn, mlen)
            if not data or len(data) != mlen:
                return
            try:
                resp = lookup(data)
                reply = set_id(resp, data)
            except IOError as e:
                log(str(e), throttle=True)
                reply = make_servfail(data) or b""
            conn.sendall(struct.pack("!H", len(reply)) + reply)
    except (OSError, struct.error):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _recv_exact(conn, n):
    chunks = []
    got = 0
    while got < n:
        b = conn.recv(n - got)
        if not b:
            return b"".join(chunks) if chunks else None
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def main():
    global _inflight_count

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((LISTEN_ADDR, LISTEN_PORT))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((LISTEN_ADDR, LISTEN_PORT))
    tcp.listen(128)

    sel = selectors.DefaultSelector()
    sel.register(udp, selectors.EVENT_READ, "udp")
    sel.register(tcp, selectors.EVENT_READ, "tcp")

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="doh")

    log("listening on %s:%d (UDP+TCP) -> %s | attempts=%d timeouts=%.1f/%.1fs "
        "workers=%d cache=on"
        % (LISTEN_ADDR, LISTEN_PORT,
           ", ".join("%s(%s)" % (ip, sni) for ip, sni, _ in UPSTREAMS),
           MAX_UPSTREAM_ATTEMPTS, CONNECT_TIMEOUT, READ_TIMEOUT, MAX_WORKERS))

    dropped = 0
    last_drop_log = 0.0
    try:
        while True:
            for key, _ in sel.select():
                if key.data == "udp":
                    try:
                        data, addr = udp.recvfrom(65535)
                    except OSError:
                        continue
                    with _inflight_count_lock:
                        if _inflight_count >= MAX_INFLIGHT:
                            dropped += 1
                            now = time.monotonic()
                            if now - last_drop_log > LOG_THROTTLE:
                                log("overloaded: dropped %d UDP queries (client will retry)"
                                    % dropped, throttle=False)
                                dropped = 0
                                last_drop_log = now
                            continue
                        _inflight_count += 1
                    pool.submit(_handle_udp, udp, data, addr)
                else:
                    try:
                        conn, _ = tcp.accept()
                    except OSError:
                        continue
                    pool.submit(_handle_tcp, conn)
    except KeyboardInterrupt:
        pass
    finally:
        pool.shutdown(wait=False)


if __name__ == "__main__":
    main()
