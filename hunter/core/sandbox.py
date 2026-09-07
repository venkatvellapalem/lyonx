"""Lightweight sandbox — mock vulnerable HTTP server for safe payload testing.

ZERO dependencies (stdlib only). ZERO config. ~5MB RAM.

Agents test payloads locally before hitting real targets.
Simulates: SQLi, XSS, SSRF, LFI, open redirect, SSTI, CORS.
"""
import http.server
import threading
import time
import json
import re
import urllib.parse
from typing import Optional


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Mock vulnerable web server for testing payloads."""

    def log_message(self, format, *args):
        pass  # Suppress logs

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        # Simulate different vulnerable endpoints
        if path == "/sqli":
            self._handle_sqli(params)
        elif path == "/xss":
            self._handle_xss(params)
        elif path == "/redirect":
            self._handle_redirect(params)
        elif path == "/lfi":
            self._handle_lfi(params)
        elif path == "/ssti":
            self._handle_ssti(params)
        elif path == "/ssrf":
            self._handle_ssrf(params)
        elif path == "/cors":
            self._handle_cors(params)
        elif path == "/idor":
            self._handle_idor(params)
        elif path == "/headers":
            self._handle_headers()
        elif path == "/robots.txt":
            self._respond(200, "User-agent: *\nDisallow: /admin\nDisallow: /secret")
        elif path == "/admin":
            self._respond(403, "Forbidden")
        elif path == "/.git/config":
            self._respond(200, "[core]\n\trepositoryformatversion = 0")
        elif path == "/api/users":
            self._respond(200, json.dumps([{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]))
        elif path == "/login":
            self._respond(200, '<form method="POST"><input name="username"><input name="password" type="password"></form>')
        else:
            self._respond(200, "<html><body><h1>Test Target</h1><p>Welcome to the sandbox.</p></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(body)

        if parsed.path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            if username == "admin" and password == "admin":
                self._respond(200, "Login successful")
            else:
                self._respond(401, "Invalid credentials")
        elif parsed.path == "/api/reflect":
            # Reflects input for XSS testing
            data = params.get("input", [""])[0]
            self._respond(200, f"<p>You said: {data}</p>")
        else:
            self._respond(404, "Not found")

    def _handle_sqli(self, params):
        """Simulate SQL injection vulnerability."""
        user_id = params.get("id", [""])[0]

        if not user_id:
            self._respond(200, "Please provide an id parameter")
            return

        # Simulate SQL error on special characters
        if any(c in user_id for c in ["'", '"', ";", "--", "/*", "UNION", "SELECT", "OR 1=1"]):
            self._respond(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server")
        elif user_id.isdigit():
            self._respond(200, json.dumps({"id": user_id, "name": "testuser", "email": "test@example.com"}))
        else:
            self._respond(200, "User not found")

    def _handle_xss(self, params):
        """Simulate reflected XSS vulnerability."""
        q = params.get("q", [""])[0]
        # Reflected without sanitization
        self._respond(200, f"<html><body><h1>Search Results</h1><p>You searched for: {q}</p></body></html>")

    def _handle_redirect(self, params):
        """Simulate open redirect vulnerability."""
        url = params.get("url", params.get("next", params.get("redirect", [""])))[0]
        if url:
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        else:
            self._respond(200, "No redirect URL specified")

    def _handle_lfi(self, params):
        """Simulate local file inclusion vulnerability."""
        file_param = params.get("file", params.get("page", params.get("include", [""])))[0]
        if not file_param:
            self._respond(200, "Please provide a file parameter")
            return

        # Simulate reading /etc/passwd
        if "etc/passwd" in file_param or "etc/shadow" in file_param:
            self._respond(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        elif "proc/self" in file_param:
            self._respond(200, "HOME=/root\nPATH=/usr/bin:/bin")
        elif "win.ini" in file_param.lower() or "boot.ini" in file_param.lower():
            self._respond(200, "[boot loader]\n[operating systems]")
        else:
            self._respond(200, f"File not found: {file_param}")

    def _handle_ssti(self, params):
        """Simulate server-side template injection."""
        name = params.get("name", params.get("input", [""]))[0]
        if not name:
            self._respond(200, "Hello World")
            return

        # Simulate Jinja2 SSTI
        if "{{7*7}}" in name:
            self._respond(200, "Hello 49")
        elif "{{" in name and "}}" in name:
            # Evaluate simple expressions
            expr = re.search(r'\{\{(.*?)\}\}', name)
            if expr:
                try:
                    result = str(eval(expr.group(1)))
                    self._respond(200, f"Hello {result}")
                except:
                    self._respond(200, f"Hello {name}")
            else:
                self._respond(200, f"Hello {name}")
        elif "${" in name:
            self._respond(200, f"Hello 49")  # Simulate MVEL evaluation
        else:
            self._respond(200, f"Hello {name}")

    def _handle_ssrf(self, params):
        """Simulate SSRF vulnerability."""
        url = params.get("url", params.get("target", params.get("fetch", [""])))[0]
        if not url:
            self._respond(200, "Please provide a URL parameter")
            return

        # Simulate cloud metadata access
        if "169.254.169.254" in url or "metadata.google" in url:
            self._respond(200, '{"ami-id":"ami-12345","instance-id":"i-12345","instance-type":"t2.micro"}')
        elif "localhost" in url or "127.0.0.1" in url:
            self._respond(200, "Internal service response")
        elif url.startswith("file://"):
            self._respond(200, "root:x:0:0:root:/root:/bin/bash")
        else:
            self._respond(200, f"Fetched content from {url}")

    def _handle_cors(self, params):
        """Simulate CORS misconfiguration."""
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def _handle_idor(self, params):
        """Simulate IDOR vulnerability."""
        user_id = params.get("id", ["1"])[0]
        # Any ID returns data (no auth check)
        users = {"1": {"name": "admin", "email": "admin@test.com", "role": "admin"},
                 "2": {"name": "user", "email": "user@test.com", "role": "user"}}
        user = users.get(user_id, {"name": f"user_{user_id}", "email": f"user_{user_id}@test.com", "role": "user"})
        self._respond(200, json.dumps(user))

    def _handle_headers(self):
        """Simulate missing security headers."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.4")
        # Intentionally missing security headers
        self.end_headers()
        self.wfile.write(b"<html><body>Test</body></html>")

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class Sandbox:
    """Lightweight sandbox for safe payload testing.
    
    Usage:
        sandbox = Sandbox()
        sandbox.start()
        
        # Test payloads
        result = sandbox.test("sqli", {"id": "' OR 1=1--"})
        print(result)  # {"vulnerable": true, "evidence": "SQL syntax error"}
        
        sandbox.stop()
    """

    def __init__(self, port: int = 0):
        self.port = port
        self.server = None
        self.thread = None
        self.base_url = None

    def start(self) -> str:
        """Start the sandbox server. Returns the base URL."""
        self.server = http.server.HTTPServer(("127.0.0.1", self.port), VulnerableHandler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        return self.base_url

    def stop(self):
        """Stop the sandbox server."""
        if self.server:
            self.server.shutdown()
            self.server = None

    def test(self, vuln_type: str, params: dict = None) -> dict:
        """Test a vulnerability type in the sandbox.
        
        Args:
            vuln_type: sqli, xss, redirect, lfi, ssti, ssrf, cors, idor
            params: Parameters to inject
            
        Returns:
            Result dict with vulnerable, evidence, etc.
        """
        import urllib.request

        if not self.base_url:
            self.start()

        params = params or {}
        endpoint_map = {
            "sqli": "/sqli",
            "xss": "/xss",
            "redirect": "/redirect",
            "lfi": "/lfi",
            "ssti": "/ssti",
            "ssrf": "/ssrf",
            "cors": "/cors",
            "idor": "/idor",
        }

        endpoint = endpoint_map.get(vuln_type, "/")
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}{endpoint}?{query}"

        try:
            req = urllib.request.Request(url)
            if vuln_type == "cors":
                req.add_header("Origin", "https://evil.com")

            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode(errors="ignore")
            status = resp.status

            return self._analyze_response(vuln_type, params, body, status)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="ignore") if e.fp else ""
            return self._analyze_response(vuln_type, params, body, e.code)
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}

    def test_payload(self, url: str, payload: str, param: str, vuln_type: str) -> dict:
        """Test a specific payload in the sandbox.
        
        Args:
            url: Original URL (for pattern matching)
            payload: The payload to test
            param: Parameter name to inject into
            vuln_type: Type of vulnerability
            
        Returns:
            Result dict
        """
        return self.test(vuln_type, {param: payload})

    def test_payloads(self, vuln_type: str, param: str, payloads: list[str]) -> list[dict]:
        """Test multiple payloads and return results.
        
        Args:
            vuln_type: Vulnerability type
            param: Parameter name
            payloads: List of payloads to test
            
        Returns:
            List of result dicts
        """
        results = []
        for payload in payloads:
            result = self.test(vuln_type, {param: payload})
            result["payload"] = payload
            results.append(result)
        return results

    def _analyze_response(self, vuln_type: str, params: dict, body: str, status: int) -> dict:
        """Analyze response to determine if vulnerability exists."""
        evidence = ""

        if vuln_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ORA-", "SQL Server"]
            for err in sql_errors:
                if err.lower() in body.lower():
                    evidence = err
                    break
            if status == 500 and any(c in str(params) for c in ["'", '"', ";"]):
                evidence = "SQL error on special characters"

        elif vuln_type == "xss":
            for val in params.values():
                if val in body and ("<script>" in val or "onerror" in val or "onload" in val):
                    evidence = f"Payload reflected: {val[:50]}"
                    break

        elif vuln_type == "redirect":
            # Check if we got a redirect
            if status in (301, 302):
                evidence = "Redirect response"

        elif vuln_type == "lfi":
            if "root:" in body or "daemon:" in body:
                evidence = "File contents leaked"
            elif "[boot loader]" in body:
                evidence = "Windows file leaked"

        elif vuln_type == "ssti":
            if "49" in body:
                evidence = "Template expression evaluated (7*7=49)"

        elif vuln_type == "ssrf":
            if "ami-id" in body or "instance-id" in body:
                evidence = "Cloud metadata accessible"
            elif "Internal service" in body:
                evidence = "Internal service reached"

        elif vuln_type == "cors":
            if "Access-Control-Allow-Origin" in str(body):
                evidence = "CORS misconfiguration"

        elif vuln_type == "idor":
            if status == 200:
                evidence = "User data returned without auth"

        return {
            "vulnerable": bool(evidence),
            "evidence": evidence,
            "status": status,
            "body_length": len(body),
        }

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
