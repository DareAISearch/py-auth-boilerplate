import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from py_auth_boilerplate.http_client import http_fetch


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached-target")

    def log_message(self, format_: str, *args: object) -> None:
        pass


@pytest.fixture
def redirect_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


class TestHttpFetch:
    async def test_does_not_follow_a_redirect_response(self, redirect_server: str) -> None:
        # httpx.AsyncClient follows redirects by default; a JWKS/IAM endpoint redirecting must
        # surface as a failed (3xx) response, not be silently chased.
        response = await http_fetch(f"{redirect_server}/redirect")
        assert response.status_code == 302
        assert response.is_success is False
        assert response.headers["location"] == "/target"

    async def test_still_resolves_normally_for_a_non_redirecting_request(self, redirect_server: str) -> None:
        response = await http_fetch(f"{redirect_server}/target")
        assert response.status_code == 200
        assert response.text == "reached-target"
