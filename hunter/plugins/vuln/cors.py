"""CORS misconfiguration testing."""
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
        self.log(f"Testing {len(targets)} hosts for CORS misconfigs...")

        vulnerable = []
        for i, url in enumerate(targets):
            self.progress(i, len(targets))

            # Test with evil origin
            out = self.run_tool([
                "curl", "-sI", "-H", "Origin: https://evil.com",
                "--max-time", "5", url
            ], timeout=10)

            if "access-control-allow-origin: https://evil.com" in out.lower():
                vulnerable.append(f"{url} | Reflects arbitrary origin")
                self.add_finding("cors", "high", url, "Reflects evil.com origin")
            elif "access-control-allow-origin: *" in out.lower():
                vulnerable.append(f"{url} | Wildcard origin (*)")

            # Test null origin
            out2 = self.run_tool([
                "curl", "-sI", "-H", "Origin: null",
                "--max-time", "5", url
            ], timeout=10)

            if "access-control-allow-origin: null" in out2.lower():
                vulnerable.append(f"{url} | Accepts null origin")
                self.add_finding("cors", "medium", url, "Accepts null origin")

        self.save_lines(vulnerable, str(self.output_dir / "cors_vulnerable.txt"))
        self.state.set_state(self.name, "findings", vulnerable)
        self.log(f"CORS issues: {len(vulnerable)}")
        return self.state
