"""Validator tests: parallel probe precedence and deterministic dry-run."""
import asyncio
from unittest.mock import AsyncMock, patch

from src.validator.core import ProxyValidator, ProxyInfo


class DummyGeo:
    def get_country_info(self, ip):
        return {"country_code": "US", "country_name": "United States"}


def _validator(dry_run=False, geo=None):
    return ProxyValidator(
        test_urls=["http://httpbin.org/headers"],
        ssl_test_url="https://www.google.com",
        connect_timeout=0.5,
        read_timeout=1.0,
        timeout=3.0,
        user_agent="test",
        geo_resolver=geo or DummyGeo(),
        dry_run=dry_run,
    )


def test_http_alive_returns_http():
    async def main():
        v = _validator()
        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_handshake", AsyncMock(return_value=False)), \
             patch.object(v, "check_socks4_handshake", AsyncMock(return_value=False)), \
             patch.object(v, "check_http_proxy", AsyncMock(return_value=ProxyInfo(
                 "1.2.3.4:8080", "http", "elite", 0.25, True, "US", "United States"))):
            info = await v.validate_single_proxy("1.2.3.4:8080")
        assert info is not None and info.protocol == "http"
    asyncio.run(main())


def test_socks5_precedence_over_http():
    async def main():
        v = _validator()
        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_proxy", AsyncMock(return_value=ProxyInfo(
                 "5.6.7.8:1080", "socks5", "elite", 0.12, True, "US", "United States"))), \
             patch.object(v, "check_socks4_proxy", AsyncMock(return_value=None)), \
             patch.object(v, "check_http_proxy", AsyncMock(return_value=None)):
            info = await v.validate_single_proxy("5.6.7.8:1080")
        assert info is not None and info.protocol == "socks5"
    asyncio.run(main())


def test_all_dead_returns_none():
    async def main():
        v = _validator()
        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_proxy", AsyncMock(return_value=None)), \
             patch.object(v, "check_socks4_proxy", AsyncMock(return_value=None)), \
             patch.object(v, "check_http_proxy", AsyncMock(return_value=None)):
            info = await v.validate_single_proxy("3.4.5.6:9999")
        assert info is None
    asyncio.run(main())


def test_dead_port_skips_deep_checks():
    async def main():
        v = _validator()
        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=False)), \
             patch.object(v, "check_socks5_proxy", AsyncMock(side_effect=AssertionError("must not run"))):
            info = await v.validate_single_proxy("7.7.7.7:8080")
        assert info is None
    asyncio.run(main())


def test_dry_run_deterministic_and_network_free():
    async def main():
        addrs = [f"45.0.{i // 250}.{i % 250}:{8000 + (i % 100)}" for i in range(50)]
        v1, v2 = _validator(dry_run=True, geo=None), _validator(dry_run=True, geo=None)
        r1 = [await v1.validate_single_proxy(a) for a in addrs]
        r2 = [await v2.validate_single_proxy(a) for a in addrs]

        # deterministic: same verdicts across two independent instances
        v1_verdicts = [x is not None for x in r1]
        assert v1_verdicts == [x is not None for x in r2]

        # mixes of live and dead (not all or nothing)
        assert any(v1_verdicts) and not all(v1_verdicts)

        for info in r1:
            if info:
                assert info.protocol == "http" and info.anonymity == "elite"
                assert info.country_code == "XX"
    asyncio.run(main())

def test_parse_ipify():
    from src.validator.core import ProxyValidator
    assert ProxyValidator._parse_ipify(b"HTTP/1.1 200 OK\r\n\r\n{\"ip\":\"77.88.99.1\"}") == "77.88.99.1"
    assert ProxyValidator._parse_ipify(b"HTTP/1.1 500\r\n\r\nboom") is None
    assert ProxyValidator._parse_ipify(b"") is None


def test_exit_verification_http_paths():
    async def main():
        v = _validator()
        v.my_ip = "9.9.9.9"
        v.active_test_url = "http://httpbin.org/headers"
        base = ProxyInfo("1.2.3.4:8080", "http", "elite", 0.25, True, "US", "United States")

        # validate_single_proxy passes ProxyInfo through unchanged (verification
        # happens inside the probe methods themselves)
        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_handshake", AsyncMock(return_value=False)), \
             patch.object(v, "check_socks4_handshake", AsyncMock(return_value=False)), \
             patch.object(v, "check_http_proxy", AsyncMock(return_value=base)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="5.5.5.5")):
            info = await v.validate_single_proxy("1.2.3.4:8080")
        assert info is not None and info.verified_exit is False

        # check_http_proxy itself: verified_exit flag flows
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_read_response", AsyncMock(return_value=b'HTTP/1.1 200\r\n\r\n{"headers":{"Host":"httpbin.org"}}')), \
             patch.object(v, "check_http_ssl_tunnel", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="5.5.5.5")):
            info = await v.check_http_proxy("1.2.3.4", 8080)
        assert info is not None and info.verified_exit is True, info

        # exit equals our IP -> transparent -> dropped
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_read_response", AsyncMock(return_value=b'HTTP/1.1 200\r\n\r\n{"headers":{"Host":"httpbin.org"}}')), \
             patch.object(v, "check_http_ssl_tunnel", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="9.9.9.9")):
            info = await v.check_http_proxy("1.2.3.4", 8080)
        assert info is None, "real-IP leak must be dropped"

        # exit check failed -> kept but honestly unverified
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_read_response", AsyncMock(return_value=b'HTTP/1.1 200\r\n\r\n{"headers":{"Host":"httpbin.org"}}')), \
             patch.object(v, "check_http_ssl_tunnel", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value=None)):
            info = await v.check_http_proxy("1.2.3.4", 8080)
        assert info is not None and info.verified_exit is False
    asyncio.run(main())


def test_exit_verification_socks5_paths():
    async def main():
        v = _validator()
        v.my_ip = "9.9.9.9"
        v.active_test_url = "http://httpbin.org/headers"

        with patch.object(v, "tcp_port_probe", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_proxy", AsyncMock(return_value=ProxyInfo(
                 "5.6.7.8:1080", "socks5", "elite", 0.12, True, "US", "United States", verified_exit=True))), \
             patch.object(v, "check_socks4_proxy", AsyncMock(return_value=None)), \
             patch.object(v, "check_http_proxy", AsyncMock(return_value=None)):
            info = await v.validate_single_proxy("5.6.7.8:1080")
        assert info is not None and info.verified_exit is True

        # transparent leak through sock5 -> dropped
        with patch.object(v, "check_socks5_handshake", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_ssl_connect", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="9.9.9.9")):
            info = await v.check_socks5_proxy("5.6.7.8", 1080)
        assert info is None, "leaking socks5 must be dropped"

        # honest RTT: verified exit latency replaces handshake latency
        with patch.object(v, "check_socks5_handshake", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_ssl_connect", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="5.5.5.5")):
            info = await v.check_socks5_proxy("5.6.7.8", 1080)
        assert info is not None and info.verified_exit is True
        assert info.ssl_supported is True  # honest flag from the CONNECT probe
    asyncio.run(main())


def test_read_response_deadline_bounds_wall_time():
    import time as time_mod

    async def slow_recv(sock, n):
        await asyncio.sleep(0.02)
        return b"x" * n

    async def fast_recv(sock, n):
        return b"x" * n

    async def main():
        v = _validator()

        # slow drip, deadline = now + 0.03 -> only ~2 chunks, returns fast
        start = time_mod.monotonic()
        data = await v._read_response(object(), 65536, 1.0,
                                      deadline=time_mod.monotonic() + 0.03,
                                      sock_recv=slow_recv)
        elapsed = time_mod.monotonic() - start
        assert 0 < len(data) < 65536, f"got {len(data)} bytes"
        assert elapsed < 0.5, f"took {elapsed:.2f}s (deadline ignored!)"
        print(f"✅ slow-drip bounded: {len(data)} bytes in {elapsed*1000:.0f}ms")

        # deadline already expired -> immediate empty result, no single recv
        data = await v._read_response(object(), 65536, 1.0,
                                      deadline=time_mod.monotonic() - 1.0,
                                      sock_recv=fast_recv)
        assert data == b""
        print("✅ expired deadline -> immediate return")

        # no deadline -> normal full read
        data = await v._read_response(object(), 65536, 1.0, sock_recv=fast_recv)
        assert len(data) == 65536
        print("✅ no deadline -> full read")

    asyncio.run(main())


def test_verified_requires_known_runner_ip():
    """Without my_ip, exit checks must NEVER mark a proxy verified."""
    async def main():
        v = _validator()
        v.my_ip = None  # fetch_my_ip failed

        with patch.object(v, "check_socks5_handshake", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_ssl_connect", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="5.5.5.5")):
            info = await v.check_socks5_proxy("1.2.3.4", 1080)
        assert info is not None and info.verified_exit is False, info

        v.my_ip = "9.9.9.9"
        with patch.object(v, "check_socks5_handshake", AsyncMock(return_value=True)), \
             patch.object(v, "check_socks5_ssl_connect", AsyncMock(return_value=True)), \
             patch.object(v, "verify_exit_ip", AsyncMock(return_value="5.5.5.5")):
            info = await v.check_socks5_proxy("1.2.3.4", 1080)
        assert info is not None and info.verified_exit is True, info
    asyncio.run(main())


def test_extract_exit_ip_formats():
    """The exit-IP extractor must handle every echo endpoint format."""
    from src.validator.core import ProxyValidator as PV
    # ipify JSON
    assert PV._extract_exit_ip(b'{"ip":"77.88.99.1"}') == "77.88.99.1"
    # ip-api JSON (fields=query)
    assert PV._extract_exit_ip(b'{"query":"12.34.56.78"}') == "12.34.56.78"
    # ifconfig.me / checkip.amazonaws.com plain text
    assert PV._extract_exit_ip(b"98.76.54.32\n") == "98.76.54.32"
    assert PV._extract_exit_ip(b"98.76.54.32") == "98.76.54.32"
    # private IPs must never be accepted as exit proof
    assert PV._extract_exit_ip(b"192.168.1.5") is None
    assert PV._extract_exit_ip(b"10.0.0.1") is None
    # garbage
    assert PV._extract_exit_ip(b"") is None
    assert PV._extract_exit_ip(b"no ip here") is None


def test_exit_endpoints_parsed():
    """Multiple echo endpoints are parsed and available for rotation."""
    v = _validator()
    hosts = [ep["host"] for ep in v.exit_endpoints]
    assert "api.ipify.org" in hosts
    assert "ifconfig.me" in hosts
    assert all(ep["port"] == 80 for ep in v.exit_endpoints)

    custom = ProxyValidator(
        test_urls=["http://httpbin.org/headers"],
        ssl_test_url="https://www.google.com",
        connect_timeout=0.5, read_timeout=1.0, timeout=3.0,
        user_agent="test", geo_resolver=DummyGeo(),
        exit_endpoints=["http://example.com:8080/ip?x=1"],
    )
    assert custom.exit_endpoints == [{"host": "example.com", "port": 8080, "path": "/ip?x=1"}]


def test_socks5_ssl_connect_honest_flag():
    """ssl_supported for SOCKS5 comes from a real CONNECT probe, not a constant."""
    async def main():
        v = _validator()
        v.my_ip = "9.9.9.9"

        # granted CONNECT -> True
        replies = [b"\x05\x00", b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"]
        async def fake_recv(sock, n, timeout):
            return replies.pop(0)
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_recv", fake_recv):
            assert await v.check_socks5_ssl_connect("1.2.3.4", 1080) is True

        # refused CONNECT -> False
        replies = [b"\x05\x00", b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"]
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_recv", fake_recv):
            assert await v.check_socks5_ssl_connect("1.2.3.4", 1080) is False
    asyncio.run(main())


def test_probe_target_https_is_connect_only():
    """HTTPS targets are probed via tunnel establishment, not plain GETs
    (a GET over a TLS port only ever saw protocol garbage before)."""
    async def main():
        v = _validator()

        sent = []
        async def capture_send(sock, data):
            sent.append(data)
            return True

        # SOCKS5 to an https target: greeting ok, CONNECT granted
        replies = iter([b"\x05\x00", b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"])
        async def fake_recv(sock, n, timeout):
            return next(replies)
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", capture_send), \
             patch.object(v, "_recv", fake_recv), \
             patch.object(v, "_read_response", AsyncMock(side_effect=AssertionError("GET must not be sent"))):
            lat = await v.probe_target("1.2.3.4", 1080, "socks5", "https://www.example.com/")
        assert lat is not None and lat >= 0
        # only greeting + CONNECT packets were sent (no HTTP GET)
        assert all(b"GET" not in p for p in sent), sent
        assert b"www.example.com" in sent[1]

        # HTTP proxy to an https target: CONNECT granted -> reachable
        sent.clear()
        async def recv_connect(sock, n, timeout):
            return b"HTTP/1.1 200 Connection established\r\n\r\n"
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", capture_send), \
             patch.object(v, "_recv", recv_connect):
            lat = await v.probe_target("1.2.3.4", 8080, "http", "https://www.example.com/")
        assert lat is not None
        assert sent[0].startswith(b"CONNECT www.example.com:443")

        # HTTP proxy to an https target: CONNECT refused -> unreachable
        async def recv_refuse(sock, n, timeout):
            return b"HTTP/1.1 403 Forbidden\r\n\r\n"
        with patch.object(v, "_connect", AsyncMock(return_value=True)), \
             patch.object(v, "_send", AsyncMock(return_value=True)), \
             patch.object(v, "_recv", recv_refuse):
            lat = await v.probe_target("1.2.3.4", 8080, "http", "https://www.example.com/")
        assert lat is None
    asyncio.run(main())


def test_ssl_tunnel_uses_configured_url():
    async def main():
        v = ProxyValidator(
            test_urls=["http://httpbin.org/headers"],
            ssl_test_url="https://example.com:8443/check",
            connect_timeout=0.5, read_timeout=1.0, timeout=3.0,
            user_agent="test", geo_resolver=DummyGeo(),
        )
        v._connect = AsyncMock(return_value=True)
        v._send = AsyncMock(return_value=True)
        v._recv = AsyncMock(return_value=b"HTTP/1.1 200 Connection established")

        sent = []
        async def capture_send(sock, data):
            sent.append(data)
            return True
        v._send = capture_send

        assert await v.check_http_ssl_tunnel("1.2.3.4", 8080) is True
        assert b"CONNECT example.com:8443" in sent[0], sent
        print("✅ CONNECT uses configured ssl_test_url host:port")
    asyncio.run(main())
