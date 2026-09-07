"""HTTP Repeater — Burp Repeater replacement.

CLI tool for manual request replay and modification.
Zero dependencies (uses urllib from stdlib).

Usage:
    from hunter.core.repeater import Repeater
    
    r = Repeater()
    resp = r.send("GET https://example.com/api/users?id=1")
    resp = r.send("POST https://example.com/login", body='{"user":"admin"}')
    resp = r.replay_with(resp, id="2")  # Change param and resend
"""
import urllib.request
import urllib.parse
import urllib.error
import http.client
import ssl
import json
import gzip
import io
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Response:
    """HTTP response with all metadata."""
    url: str
    status: int
    headers: dict
    body: str
    size: int
    time: float
    request: dict = field(default_factory=dict)

    @property
    def json(self):
        try:
            return json.loads(self.body)
        except:
            return None

    @property
    def content_type(self):
        return self.headers.get("Content-Type", self.headers.get("content-type", ""))

    def contains(self, text: str) -> bool:
        return text.lower() in self.body.lower()

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body[:1000],
            "size": self.size,
            "time": round(self.time, 3),
        }


class Repeater:
    """HTTP request repeater — like Burp Repeater but CLI.
    
    Usage:
        r = Repeater()
        
        # Simple GET
        resp = r.send("GET https://example.com/api/users?id=1")
        
        # POST with body
        resp = r.send("POST https://example.com/login", 
                      headers={"Content-Type": "application/json"},
                      body='{"user":"admin","pass":"test"}')
        
        # Raw HTTP request
        resp = r.send_raw("GET /api/users?id=1 HTTP/1.1\\r\\nHost: example.com\\r\\n")
        
        # Replay with modified params
        resp2 = r.replay_with(resp, params={"id": "2"})
    """

    def __init__(self, timeout: int = 10, follow_redirects: bool = True):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.history: list[Response] = []
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def send(self, method: str, url: str, headers: dict = None, body: str = None) -> Response:
        """Send an HTTP request.
        
        Args:
            method: GET, POST, PUT, DELETE, etc.
            url: Full URL
            headers: Optional headers dict
            body: Optional request body
            
        Returns:
            Response object
        """
        import time

        headers = headers or {}
        headers.setdefault("User-Agent", "Hunter/3.0")

        if body and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body.encode()))

        req = urllib.request.Request(url, data=body.encode() if body else None, headers=headers, method=method)

        start = time.time()
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx)
            elapsed = time.time() - start
            resp_body = resp.read().decode(errors="ignore")
            resp_headers = dict(resp.headers)

            result = Response(
                url=url,
                status=resp.status,
                headers=resp_headers,
                body=resp_body,
                size=len(resp_body),
                time=elapsed,
                request={"method": method, "url": url, "headers": headers, "body": body}
            )
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            resp_body = e.read().decode(errors="ignore") if e.fp else ""
            result = Response(
                url=url,
                status=e.code,
                headers=dict(e.headers) if e.headers else {},
                body=resp_body,
                size=len(resp_body),
                time=elapsed,
                request={"method": method, "url": url, "headers": headers, "body": body}
            )
        except Exception as e:
            elapsed = time.time() - start
            result = Response(
                url=url, status=0, headers={}, body=str(e), size=0, time=elapsed,
                request={"method": method, "url": url, "headers": headers, "body": body}
            )

        self.history.append(result)
        return result

    def send_raw(self, raw_request: str, host: str = None, port: int = 443, ssl: bool = True) -> Response:
        """Send a raw HTTP request string.
        
        Args:
            raw_request: Raw HTTP request (method, headers, body)
            host: Target host
            port: Target port
            ssl: Use HTTPS
        """
        import time

        lines = raw_request.strip().split("\n")
        first_line = lines[0].strip()
        method, path, _ = first_line.split(" ", 2)

        headers = {}
        body = None
        in_body = False
        for line in lines[1:]:
            line = line.strip()
            if in_body:
                body = line
            elif line == "":
                in_body = True
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
                if k.strip().lower() == "host":
                    host = v.strip()

        url = f"{'https' if ssl else 'http'}://{host}{path}"
        return self.send(method, url, headers, body)

    def replay_with(self, original: Response, **changes) -> Response:
        """Replay a request with modifications.
        
        Args:
            original: Original response to replay
            **changes: Parameters to change (headers, body, params, etc.)
            
        Returns:
            New response
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        req = original.request
        url = req["url"]
        headers = dict(req.get("headers", {}))
        body = req.get("body")

        # Modify URL params
        if "params" in changes:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.update(changes["params"])
            new_query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        # Modify headers
        if "headers" in changes:
            headers.update(changes["headers"])

        # Modify body
        if "body" in changes:
            body = changes["body"]

        # Modify URL
        if "url" in changes:
            url = changes["url"]

        return self.send(req["method"], url, headers, body)

    def compare(self, resp1: Response, resp2: Response) -> dict:
        """Compare two responses — like Burp Comparer.
        
        Returns dict with differences.
        """
        diffs = {
            "status_changed": resp1.status != resp2.status,
            "size_changed": resp1.size != resp2.size,
            "size_diff": resp2.size - resp1.size,
            "status_diff": f"{resp1.status} → {resp2.status}",
            "body_changes": [],
        }

        # Line-by-line diff
        lines1 = resp1.body.splitlines()
        lines2 = resp2.body.splitlines()
        for i, (l1, l2) in enumerate(zip(lines1, lines2)):
            if l1 != l2:
                diffs["body_changes"].append({
                    "line": i,
                    "before": l1[:100],
                    "after": l2[:100],
                })

        return diffs

    def last(self) -> Optional[Response]:
        """Get last response."""
        return self.history[-1] if self.history else None
