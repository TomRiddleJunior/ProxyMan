"""Scraper tests: retry/backoff helper and robust HTML table parsing."""
import asyncio
from unittest.mock import AsyncMock

from src.scraper.base import get_with_retry, scrape_html_table


class FakeResp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


def test_retry_recovers_from_429():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(side_effect=[FakeResp(429), FakeResp(429), FakeResp(200)])
        r = await get_with_retry(client, "http://x", base_delay=0.01)
        assert r.status_code == 200
        assert client.get.call_count == 3
    asyncio.run(main())


def test_retry_recovers_from_network_error():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(side_effect=[OSError("boom"), FakeResp(200)])
        r = await get_with_retry(client, "http://x", base_delay=0.01)
        assert r.status_code == 200
    asyncio.run(main())


def test_persistent_5xx_returns_last_response():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResp(503))
        r = await get_with_retry(client, "http://x", retries=2, base_delay=0.01)
        assert r.status_code == 503
        assert client.get.call_count == 2
    asyncio.run(main())


def test_persistent_network_error_raises():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(side_effect=OSError("dead"))
        try:
            await get_with_retry(client, "http://x", retries=2, base_delay=0.01)
            assert False, "should raise"
        except OSError:
            pass
    asyncio.run(main())


def test_success_does_not_retry():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResp(200))
        await get_with_retry(client, "http://x", base_delay=0.01)
        assert client.get.call_count == 1
    asyncio.run(main())


HTML = """<html><body><table>
<tr><th>IP Address</th><th>Port</th><th>Code</th><th>Country</th></tr>
<tr><td>192.168.1.10</td><td>8080</td><td>US</td><td>United States</td></tr>
<tr><td>10.0.0.1</td><td>3128</td><td>DE</td><td>Germany</td><td>elite</td></tr>
<tr><td>not-an-ip</td><td>99999</td><td>XX</td><td>Nowhere</td></tr>
<tr><td>172.16.5.9</td><td>INVALID</td><td>FR</td><td>France</td></tr>
<tr><td>2001:db8::1</td><td>8080</td><td>ZZ</td><td>V6</td></tr>
<tr><td colspan="4">footer junk</td></tr>
</table></body></html>"""


def test_html_table_parser_ignores_junk():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResp(200, HTML))
        results = set()
        await scrape_html_table(client, "https://fake.example.com", results)
        assert results == {"192.168.1.10:8080", "10.0.0.1:3128"}
    asyncio.run(main())


def test_html_table_parser_handles_request_failure():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResp(500))
        results = set()
        await scrape_html_table(client, "https://down.example.com", results)  # must not raise
        assert results == set()
    asyncio.run(main())