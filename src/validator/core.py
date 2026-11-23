import re
import time
import zlib
import socket
import asyncio
import json
import logging
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse
from dataclasses import dataclass
from src.validator.geo import GeoIPResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Candidate pre-filtering
# ---------------------------------------------------------------------------

NON_PUBLIC_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),       # "this" network
    ipaddress.ip_network("10.0.0.0/8"),      # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
]


def is_public_ip(ip: str) -> bool:
    """True only for routable public IPv4 addresses. IPv6 is rejected (the
    validator engine is IPv4-only) and every private/reserved range is
    excluded, so hosts that could never be reachable proxies are filtered
    out before they consume probe time."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    return not any(addr in net for net in NON_PUBLIC_NETS)

# Default echo endpoints: the runner's public IP is fetched THROUGH the proxy
# from each endpoint in turn until one answers. A single endpoint (previously
# api.ipify.org alone) was a silent single point of failure: when it rate-
# limited or dropped traffic, most of the pool got published as "unverified".
DEFAULT_EXIT_ENDPOINTS = [
    "http://api.ipify.org/?format=json",
    "http://ip-api.com/json?fields=query",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com/",
]

# Module-level DNS cache for exit-endpoint hosts (SOCKS4 needs IP addressing;
# resolving 4 fixed hosts once beats resolving per candidate).
_DNS_CACHE: Dict[str, Optional[str]] = {}


def _resolve_host(host: str) -> Optional[str]:
    """Resolves an IPv4 for host, cached. None when resolution fails."""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except Exception:
        ip = None
    _DNS_CACHE[host] = ip
    return ip


_EXIT_IP_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3})\b")


@dataclass
class ProxyInfo:
    address: str
    protocol: str       # "http" | "socks4" | "socks5"
    anonymity: str      # "elite" | "anonymous" | "transparent" | "unknown"
    latency: float      # in seconds (honest end-to-end RTT when verified)
    ssl_supported: bool
    country_code: str
    country_name: str
    is_valid: bool = True
    verified_exit: bool = False  # traffic was proven to exit via the proxy
    # --- premium tier (exit-verified + stable streak + fast) ---
    premium: bool = False
    # --- targeted validation (feature A) ---
    target_ok: bool = False      # reached the --target site through this proxy
    target_latency: float = 0.0  # seconds to first byte of the target probe
    # --- ASN / hosting classification (feature B) ---
    hosting: str = "unknown"     # "residential" | "datacenter" | "unknown"
    as_name: str = ""
    org: str = ""

class ProxyValidator:
    def __init__(self, test_urls: list, ssl_test_url: str, connect_timeout: float, read_timeout: float, timeout: float, user_agent: str, geo_resolver: GeoIPResolver, dry_run: bool = False, verify_exit: bool = True, exit_endpoints: Optional[list] = None):
        self.test_urls = test_urls
        self.ssl_test_url = ssl_test_url
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = timeout
        self.user_agent = user_agent
        self.geo_resolver = geo_resolver
        self.dry_run = dry_run
        self.verify_exit = verify_exit
        self.my_ip: Optional[str] = None
        self.active_test_url = test_urls[0] if test_urls else "http://httpbin.org/headers"
        # Parsed echo endpoints for exit verification: [{host, port, path}]
        self.exit_endpoints: List[dict] = []
        for url in (exit_endpoints or DEFAULT_EXIT_ENDPOINTS):
            try:
                parsed = urlparse(url if "://" in url else f"http://{url}")
                host = parsed.hostname
                if not host:
                    continue
                self.exit_endpoints.append({
                    "host": host,
                    "port": parsed.port or 80,
                    "path": parsed.path or "/" + (f"?{parsed.query}" if parsed.query else ""),
                })
                if parsed.query:
                    self.exit_endpoints[-1]["path"] = (parsed.path or "/") + f"?{parsed.query}"
            except Exception:
                continue
        if not self.exit_endpoints:
            self.exit_endpoints = [{"host": "api.ipify.org", "port": 80, "path": "/?format=json"}]

    # ------------------------------------------------------------------
    # Low-level socket helpers (shared by every probe path)
    # ------------------------------------------------------------------

    def _new_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        return sock

    @staticmethod
    def _close_socket(sock: Optional[socket.socket]) -> None:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    async def _connect(self, sock: socket.socket, host: str, port: int, timeout: float) -> bool:
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
            return True
        except Exception:
            return False

    async def _send(self, sock: socket.socket, data: bytes) -> bool:
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendall(sock, data)
            return True
        except Exception:
            return False

    async def _recv(self, sock: socket.socket, size: int, timeout: float) -> bytes:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(loop.sock_recv(sock, size), timeout=timeout)
        except Exception:
            return b""

    async def _read_response(self, sock: socket.socket, max_bytes: int, timeout: float, deadline: Optional[float] = None, sock_recv=None) -> bytes:
        """
        Reads until EOF or max_bytes; timeouts yield partial data, never raise.
        A deadline (monotonic timestamp) hard-caps total wall time, so a
        slow-drip peer can never hold a worker slot longer than budgeted.
        """
        loop = asyncio.get_running_loop()
        recv = sock_recv or loop.sock_recv
        resp = b""
        while len(resp) < max_bytes:
            chunk_timeout = timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                chunk_timeout = min(timeout, remaining)
            try:
                chunk = await asyncio.wait_for(recv(sock, 4096), timeout=chunk_timeout)
            except Exception:
                break
            if not chunk:
                break
            resp += chunk
        return resp

    async def select_active_reflector(self) -> None:
        """
        Queries endpoints in test_urls list and selects the first working one.
        """
        for url in self.test_urls:
            try:
                without_proto = url.split("://", 1)[1]
                host = without_proto.split("/", 1)[0]
                path = "/" + without_proto.split("/", 1)[1] if "/" in without_proto else "/"
            except Exception:
                continue

            sock = self._new_socket()
            try:
                if not await self._connect(sock, host, 80, 3.0):
                    continue
                req = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                if not await self._send(sock, req.encode("utf-8")):
                    continue
                resp = await self._recv(sock, 256, 3.0)
                if not (b"HTTP/1.1 200" in resp or b"HTTP/1.0 200" in resp or b"HTTP/1.1 30" in resp):
                    continue
                # Prove the endpoint actually ECHOES request data: anonymity
                # grading depends on reflected headers, so a reflector that
                # only serves a 200 landing page is useless and must not be
                # selected (it would silently break half the pool).
                get_req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nX-Ping: proxyman\r\n\r\n".encode("utf-8")
                if not await self._send(sock, get_req):
                    continue
                echoed = await self._read_response(sock, 8192, 3.0)
                if b"X-Ping: proxyman" not in echoed:
                    continue
                self.active_test_url = url
                logger.info("[+] Active proxy reflection endpoint selected: %s", self.active_test_url)
                return
            except Exception:
                pass
            finally:
                self._close_socket(sock)

        logger.warning("[!] Warning: All reflector URLs unreachable. Defaulting to: %s", self.active_test_url)

    async def fetch_my_ip(self) -> None:
        """
        Queries api.ipify.org to get the runner's public IP.
        Reuses socket helpers to keep it dependency-free.
        """
        sock = self._new_socket()
        try:
            if not await self._connect(sock, "api.ipify.org", 80, 5.0):
                return
            req = b"GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"
            if not await self._send(sock, req):
                return
            resp = await self._read_response(sock, 8192, 5.0)

            # Simple body split
            if b"\r\n\r\n" in resp:
                body = resp.split(b"\r\n\r\n", 1)[1]
                self.my_ip = json.loads(body.decode("utf-8")).get("ip")
                logger.info("[+] External Runner IP: %s", self.my_ip)
        except Exception as e:
            logger.warning("[!] Warning: Failed to query runner public IP: %s", e)
        finally:
            self._close_socket(sock)

    async def check_socks5_handshake(self, ip: str, port: int) -> bool:
        """SOCKS5 greeting (no-auth); True when the server accepts."""
        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return False
            if not await self._send(sock, b"\x05\x01\x00"):  # SOCKS5 greeting, no auth
                return False
            resp = await self._recv(sock, 2, self.read_timeout)
            return len(resp) == 2 and resp[0] == 5 and resp[1] == 0
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    async def check_socks4_handshake(self, ip: str, port: int) -> bool:
        """SOCKS4 CONNECT to 8.8.8.8:80; True when the target is reachable."""
        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return False
            if not await self._send(sock, b"\x04\x01\x00\x50\x08\x08\x08\x08\x00"):
                return False
            resp = await self._recv(sock, 8, self.read_timeout)
            return len(resp) >= 2 and resp[0] == 0 and resp[1] == 90
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    async def verify_exit_ip(self, ip: str, port: int, protocol: str) -> Optional[str]:
        """
        Routes one request THROUGH the proxy to each echo endpoint in turn
        and returns the exit IP the endpoint observed. None when the proxy
        could not route traffic to ANY endpoint. Multiple endpoints remove
        the single-point-of-failure that used to downgrade the pool to
        "unverified" whenever one echo host misbehaved.
        """
        for ep in self.exit_endpoints:
            exit_ip = await self._exit_via_endpoint(ip, port, protocol, ep)
            if exit_ip is not None:
                return exit_ip
        return None

    async def _exit_via_endpoint(self, ip: str, port: int, protocol: str, ep: dict) -> Optional[str]:
        """One exit-verification attempt through one echo endpoint."""
        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return None

            if protocol == "socks5":
                # SOCKS5 greeting (no-auth) + CONNECT using domain addressing
                if not await self._send(sock, b"\x05\x01\x00"):
                    return None
                resp = await self._recv(sock, 2, self.read_timeout)
                if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
                    return None
                host_b = ep["host"].encode("utf-8")
                packet = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + ep["port"].to_bytes(2, "big")
                if not await self._send(sock, packet):
                    return None
                resp = await self._recv(sock, 10, self.read_timeout)
                if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                    return None
                req = (
                    f"GET {ep['path']} HTTP/1.1\r\n"
                    f"Host: {ep['host']}\r\n"
                    f"User-Agent: {self.user_agent}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")

            elif protocol == "http":
                # HTTP proxy: absolute-URI form request through the proxy
                req = (
                    f"GET http://{ep['host']}:{ep['port']}{ep['path']} HTTP/1.1\r\n"
                    f"Host: {ep['host']}\r\n"
                    f"User-Agent: {self.user_agent}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")

            elif protocol == "socks4":
                # SOCKS4 has no domain addressing: CONNECT to the endpoint's
                # resolved IP (DNS cached), then speak plain HTTP to it.
                target_ip = _resolve_host(ep["host"])
                if not target_ip:
                    return None
                packet = b"\x04\x01" + ep["port"].to_bytes(2, "big") + socket.inet_aton(target_ip) + b"\x00"
                if not await self._send(sock, packet):
                    return None
                resp = await self._recv(sock, 8, self.read_timeout)
                if len(resp) < 2 or resp[0] != 0 or resp[1] != 90:
                    return None
                req = (
                    f"GET {ep['path']} HTTP/1.1\r\n"
                    f"Host: {ep['host']}\r\n"
                    f"User-Agent: {self.user_agent}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")

            else:
                return None

            if not await self._send(sock, req):
                return None
            resp = await self._read_response(
                sock, 4096, self.read_timeout, deadline=time.monotonic() + self.total_timeout
            )
            if b"\r\n\r\n" not in resp:
                return None
            status_line = resp.split(b"\r\n", 1)[0]
            if b" 200" not in status_line:
                return None
            body = resp.split(b"\r\n\r\n", 1)[1]
            return self._extract_exit_ip(body)
        except Exception:
            return None
        finally:
            self._close_socket(sock)

    @staticmethod
    def _extract_exit_ip(body: bytes) -> Optional[str]:
        """Pulls the first public IPv4 out of an echo response body.
        Works for ipify/ip-api JSON, ifconfig.me and amazonaws plain text."""
        m = _EXIT_IP_RE.search(body)
        if not m:
            return None
        try:
            ip = m.group(1).decode("ascii")
        except Exception:
            return None
        return ip if is_public_ip(ip) else None

    async def probe_target(self, ip: str, port: int, protocol: str, url: str) -> Optional[float]:
        """
        Feature A: routes a probe to `url` THROUGH the proxy and returns the
        round-trip latency (seconds), or None when the proxy could not reach
        the site at network level (dead / blocked / filtered).

        For HTTPS targets the probe establishes the tunnel only (SOCKS5
        CONNECT / HTTP CONNECT to host:443): the tunnel being granted proves
        network-level reachability without a TLS handshake (a plain GET over
        a TLS port only ever saw protocol garbage before). For HTTP targets
        a full GET is issued and ANY HTTP status counts as reached: a 403
        from the site's edge still proves the proxy can route to it.
        """
        if protocol not in ("socks5", "http"):
            return None
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            scheme = (parsed.scheme or "http").lower()
            target_port = parsed.port or (443 if scheme == "https" else 80)
        except Exception:
            return None
        if not host:
            return None

        sock = self._new_socket()
        start = time.monotonic()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return None

            if protocol == "socks5":
                # SOCKS5 greeting + CONNECT (domain addressing ATYP=3)
                if not await self._send(sock, b"\x05\x01\x00"):
                    return None
                resp = await self._recv(sock, 2, self.read_timeout)
                if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
                    return None
                host_b = host.encode("utf-8")
                packet = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + target_port.to_bytes(2, "big")
                if not await self._send(sock, packet):
                    return None
                resp = await self._recv(sock, 10, self.read_timeout)
                if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                    return None
                if scheme == "https":
                    # Tunnel granted -> site reachable at network level
                    return round(time.monotonic() - start, 3)
            elif scheme == "https":
                # HTTP proxy: CONNECT tunnel; granted (200) = reachable
                req = (
                    f"CONNECT {host}:{target_port} HTTP/1.1\r\n"
                    f"Host: {host}:{target_port}\r\n"
                    f"User-Agent: {self.user_agent}\r\n\r\n"
                )
                if not await self._send(sock, req.encode("utf-8")):
                    return None
                resp = await self._recv(sock, 1024, self.read_timeout)
                first_line = resp.split(b"\r\n", 1)[0]
                if b" 200" not in first_line:
                    return None
                return round(time.monotonic() - start, 3)

            # Plain HTTP target: full GET through the tunnel
            # (http proxies use absolute-URI form)
            if protocol == "http":
                req = f"GET {url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {self.user_agent}\r\nConnection: close\r\n\r\n"
            else:
                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {self.user_agent}\r\nConnection: close\r\n\r\n"
            if not await self._send(sock, req.encode("utf-8")):
                return None
            resp = await self._read_response(
                sock, 2048, self.read_timeout, deadline=start + self.total_timeout
            )
            latency = time.monotonic() - start
            if latency > self.total_timeout:
                return None
            if not (b"HTTP/" in resp):
                return None
            return round(latency, 3)
        except Exception:
            return None
        finally:
            self._close_socket(sock)

    @staticmethod
    def _parse_ipify(data: bytes) -> Optional[str]:
        try:
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)[1]
                ip = json.loads(body.decode("utf-8", errors="ignore")).get("ip")
                return ip if isinstance(ip, str) else None
        except Exception:
            pass
        return None

    async def check_http_ssl_tunnel(self, ip: str, port: int) -> bool:
        """
        Checks if the HTTP proxy supports CONNECT tunnel for SSL traffic.
        Uses the configured ssl_test_url host/port (default www.google.com:443).
        """
        # Parse host[:port] from the configured SSL test URL
        try:
            without_proto = self.ssl_test_url.split("://", 1)[1]
            host_part = without_proto.split("/", 1)[0]
            if ":" in host_part:
                host, port_str = host_part.rsplit(":", 1)
                ssl_port = int(port_str)
            else:
                host, ssl_port = host_part, 443
        except Exception:
            host, ssl_port = "www.google.com", 443

        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return False
            req = f"CONNECT {host}:{ssl_port} HTTP/1.1\r\nHost: {host}:{ssl_port}\r\nUser-Agent: {self.user_agent}\r\n\r\n"
            if not await self._send(sock, req.encode("utf-8")):
                return False
            resp = await self._recv(sock, 1024, self.read_timeout)
            return b"HTTP/1.1 200" in resp or b"HTTP/1.0 200" in resp or b"established" in resp.lower()
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    async def check_http_proxy(self, ip: str, port: int) -> Optional[ProxyInfo]:
        """
        Checks HTTP proxy connectivity, latency, anonymity and HTTPS support.
        Reuses socket streams for maximum I/O performance.
        """
        sock = None
        start_time = time.monotonic()
        
        try:
            sock = self._new_socket()
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return None
            
            # Parse host from active test URL
            without_proto = self.active_test_url.split("://", 1)[1]
            host = without_proto.split("/", 1)[0]

            # Send HTTP request to reflecting endpoint
            req = (
                f"GET {self.active_test_url} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"Connection: close\r\n\r\n"
            )
            if not await self._send(sock, req.encode("utf-8")):
                return None

            # Read complete response bytes (hard-capped by total_timeout)
            resp = await self._read_response(
                sock, 65536, self.read_timeout, deadline=start_time + self.total_timeout
            )
            self._close_socket(sock)
            sock = None
            
            latency = time.monotonic() - start_time
            if latency > self.total_timeout:
                return None
                
            # Verify HTTP 200 status
            if b"HTTP/1.1 200" not in resp and b"HTTP/1.0 200" not in resp:
                return None
                
            # Parse body JSON
            anonymity = "elite"
            if b"\r\n\r\n" in resp:
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    resp_json = json.loads(body.decode("utf-8", errors="ignore"))
                    headers_reflected = resp_json.get("headers", {})
                    
                    # Grade anonymity
                    proxy_headers = ["via", "x-forwarded-for", "forwarded", "client-ip", "x-proxy-id", "proxy-connection"]
                    has_proxy_headers = any(h in [k.lower() for k in headers_reflected.keys()] for h in proxy_headers)
                    
                    real_ip_leak = False
                    if self.my_ip:
                        real_ip_leak = any(self.my_ip in str(val) for val in headers_reflected.values())
                        
                    if real_ip_leak:
                        anonymity = "transparent"
                    elif has_proxy_headers:
                        anonymity = "anonymous"
                    else:
                        anonymity = "elite"
                except Exception:
                    anonymity = "unknown"

            # Enforce premium quality: Discard transparent and unknown proxies
            if anonymity in ["transparent", "unknown"]:
                return None

            # Check HTTPS connectivity
            ssl_supported = await self.check_http_ssl_tunnel(ip, port)

            # Exit-IP verification: prove traffic routes through the proxy
            # and our real IP does not leak via the tunnel itself.
            verified_exit = False
            if self.verify_exit:
                exit_ip = await self.verify_exit_ip(ip, port, "http")
                if exit_ip is not None:
                    if self.my_ip and exit_ip == self.my_ip:
                        return None
                    verified_exit = bool(self.my_ip and exit_ip != self.my_ip)

            geo = self.geo_resolver.get_country_info(ip)
            
            return ProxyInfo(
                address=f"{ip}:{port}",
                protocol="http",
                anonymity=anonymity,
                latency=round(latency, 3),
                ssl_supported=ssl_supported,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                verified_exit=verified_exit,
            )
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    async def tcp_port_probe(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        """Fast raw-socket connectivity probe (discards dead hosts cheaply)."""
        sock = self._new_socket()
        try:
            return await self._connect(sock, ip, port, timeout)
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    def _ssl_target(self) -> tuple:
        """(host, port) parsed from the configured ssl_test_url."""
        try:
            without_proto = self.ssl_test_url.split("://", 1)[1]
            host_part = without_proto.split("/", 1)[0]
            if ":" in host_part:
                host, port_str = host_part.rsplit(":", 1)
                return host, int(port_str)
            return host_part, 443
        except Exception:
            return "www.google.com", 443

    async def check_socks5_ssl_connect(self, ip: str, port: int) -> bool:
        """Honest SSL capability for SOCKS5: a full SOCKS5 CONNECT to the
        configured ssl_test_url host:443. The tunnel being granted proves the
        proxy can carry TLS traffic (previously hardcoded True)."""
        host, ssl_port = self._ssl_target()
        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return False
            if not await self._send(sock, b"\x05\x01\x00"):
                return False
            resp = await self._recv(sock, 2, self.read_timeout)
            if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
                return False
            host_b = host.encode("utf-8")
            packet = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + ssl_port.to_bytes(2, "big")
            if not await self._send(sock, packet):
                return False
            resp = await self._recv(sock, 10, self.read_timeout)
            return len(resp) >= 2 and resp[0] == 5 and resp[1] == 0
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    async def check_socks4_ssl_connect(self, ip: str, port: int) -> bool:
        """Honest SSL capability for SOCKS4: CONNECT to the ssl target's
        resolved IP :443 and require the granted (90) reply."""
        host, ssl_port = self._ssl_target()
        target_ip = _resolve_host(host)
        if not target_ip:
            return False
        sock = self._new_socket()
        try:
            if not await self._connect(sock, ip, port, self.connect_timeout):
                return False
            packet = b"\x04\x01" + ssl_port.to_bytes(2, "big") + socket.inet_aton(target_ip) + b"\x00"
            if not await self._send(sock, packet):
                return False
            resp = await self._recv(sock, 8, self.read_timeout)
            return len(resp) >= 2 and resp[0] == 0 and resp[1] == 90
        except Exception:
            return False
        finally:
            self._close_socket(sock)

    async def check_socks5_proxy(self, ip: str, port: int) -> Optional[ProxyInfo]:
        """
        SOCKS5 probe: handshake + latency + geo + honest SSL + exit-IP
        verification. A handshake proves the port speaks SOCKS5; exit
        verification proves traffic actually routes through it and that our
        real IP does not leak. When the exit round trip succeeds, latency is
        reported as that honest end-to-end RTT (what a consumer experiences),
        not the handshake time.
        """
        start_time = time.monotonic()
        if not await self.check_socks5_handshake(ip, port):
            return None
        latency = time.monotonic() - start_time
        if latency > self.total_timeout:
            return None
        geo = self.geo_resolver.get_country_info(ip)

        verified_exit = False
        if self.verify_exit:
            t0 = time.monotonic()
            exit_ip = await self.verify_exit_ip(ip, port, "socks5")
            if exit_ip is not None:
                if self.my_ip and exit_ip == self.my_ip:
                    return None  # transparent: leaks our real IP
                # Only claim verified when the runner IP is KNOWN: without it
                # we cannot tell a transparent exit (== our IP) from a real one.
                verified_exit = bool(self.my_ip and exit_ip != self.my_ip)
                if verified_exit:
                    latency = time.monotonic() - t0  # honest end-to-end RTT

        ssl_supported = await self.check_socks5_ssl_connect(ip, port)

        return ProxyInfo(
            address=f"{ip}:{port}",
            protocol="socks5",
            anonymity="elite",  # SOCKS5 relays no HTTP headers by design
            latency=round(latency, 3),
            ssl_supported=ssl_supported,
            country_code=geo["country_code"],
            country_name=geo["country_name"],
            verified_exit=verified_exit,
        )

    async def check_socks4_proxy(self, ip: str, port: int) -> Optional[ProxyInfo]:
        """
        SOCKS4 probe: handshake + honest SSL + exit-IP verification via a
        CONNECT to the echo endpoint's resolved IP (SOCKS4 has no domain
        addressing). Previously SOCKS4 shipped as handshake-validated only;
        now it carries a real verified_exit flag like everything else.
        """
        start_time = time.monotonic()
        if not await self.check_socks4_handshake(ip, port):
            return None
        latency = time.monotonic() - start_time
        if latency > self.total_timeout:
            return None
        geo = self.geo_resolver.get_country_info(ip)

        verified_exit = False
        if self.verify_exit:
            t0 = time.monotonic()
            exit_ip = await self.verify_exit_ip(ip, port, "socks4")
            if exit_ip is not None:
                if self.my_ip and exit_ip == self.my_ip:
                    return None
                verified_exit = bool(self.my_ip and exit_ip != self.my_ip)
                if verified_exit:
                    latency = time.monotonic() - t0

        ssl_supported = await self.check_socks4_ssl_connect(ip, port)

        return ProxyInfo(
            address=f"{ip}:{port}",
            protocol="socks4",
            anonymity="elite",
            latency=round(latency, 3),
            ssl_supported=ssl_supported,
            country_code=geo["country_code"],
            country_name=geo["country_name"],
            verified_exit=verified_exit,
        )

    async def validate_single_proxy(self, raw_proxy: str) -> Optional[ProxyInfo]:
        """
        Probes the target proxy candidates across protocols concurrently.
        First executes a fast TCP port probe to discard dead hosts, then runs
        the SOCKS5/SOCKS4/HTTP probes in parallel and returns the best match
        (precedence: SOCKS5 > SOCKS4 > HTTP).
        """
        try:
            ip, port_str = raw_proxy.split(":")
            port = int(port_str)
        except ValueError:
            return None

        if not is_public_ip(ip):
            return None  # private/reserved ranges can never be public proxies

        if self.dry_run:
            # Synthetic rehearsal: deterministic ~60% live rate, zero I/O.
            # Enables exercising the full pipeline locally (queueing, pool
            # state, storage) without any network dependency.
            await asyncio.sleep(0.02)
            if zlib.crc32(ip.encode("utf-8")) % 10 < 6:
                return ProxyInfo(
                    address=raw_proxy,
                    protocol="http",
                    anonymity="elite",
                    latency=round(0.05 + (port % 500) / 1000, 3),
                    ssl_supported=True,
                    country_code="XX",
                    country_name="DryRun"
                )
            return None

        # Pass 1: Fast TCP Port Probe (2.0s connect timeout)
        if not await self.tcp_port_probe(ip, port):
            return None  # Discard dead candidate immediately

        # Pass 2: Deep verification - probe all protocols concurrently.
        # Most proxy ports answer only one protocol; probing them in parallel
        # instead of sequentially cuts wall time roughly in half on valid hosts.
        socks5_info, socks4_info, http_info = await asyncio.gather(
            self.check_socks5_proxy(ip, port),
            self.check_socks4_proxy(ip, port),
            self.check_http_proxy(ip, port),
        )

        # Precedence: SOCKS5 > SOCKS4 > HTTP
        return socks5_info or socks4_info or http_info
