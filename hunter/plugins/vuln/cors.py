"""CORS misconfiguration testing."""
import urllib.request
from .. import Plugin, Budget


class CORSPlugin(Plugin):
    name = "vuln.cors"
    description = "CORS misconfiguration detection"
    category = "vuln"

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        if not live_urls:
            return self.state

        targets = live_urls[:50]
        self.log(f"Testing {len(targets)} hosts for CORS misconfigs concurrently...")

        def check_cors(url):
            findings = []
            # Test evil origin
            try:
                req = urllib.request.Request(url, headers={"Origin": "https://evil.com", "User-Agent": "Hunter/3.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == "https://evil.com":
                        sev = "critical" if acac.lower() == "true" else "high"
                        findings.append((url, sev, "Reflects arbitrary origin with credentials" if sev == "critical" else "Reflects arbitrary origin"))
                    elif acao == "*":
                        findings.append((url, "low", "Wildcard origin (*)"))
            except Exception:
                pass

            # Test null origin
            try:
                req = urllib.request.Request(url, headers={"Origin": "null", "User-Agent": "Hunter/3.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    if acao == "null":
                        findings.append((url, "medium", "Accepts null origin"))
            except Exception:
                pass

            return findings

        results = self.probe_urls_concurrent(targets, check_cors, max_workers=15)
        vulnerable = []
        for url, sev, msg in results:
            vulnerable.append(f"{url} | {msg}")
            self.add_finding("cors", sev, url, msg)

        self.save_lines(vulnerable, str(self.output_dir / "cors_vulnerable.txt"))
        self.state.set_state(self.name, "findings", vulnerable)
        self.log(f"CORS issues: {len(vulnerable)}")
        return self.state
