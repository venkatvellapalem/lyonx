"""Security header analysis."""
from .. import Plugin, Budget


class HeaderPlugin(Plugin):
    name = "vuln.headers"
    description = "Security header analysis and info disclosure"
    category = "vuln"

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        if not live_urls:
            return self.state

        targets = live_urls[:50]
        self.log(f"Analyzing headers on {len(targets)} hosts...")

        missing = []
        info_disclosure = []

        for url in targets:
            out = self.run_tool(["curl", "-sI", "-L", "--max-time", "5", url], timeout=10)
            if not out:
                continue

            lines = out.lower().splitlines()
            host = url.split("/")[2] if "/" in url else url

            # Check missing security headers
            for header in self.SECURITY_HEADERS:
                found = any(header.lower() in line for line in lines)
                if not found:
                    missing.append(f"{host} | Missing: {header}")

            # Check info disclosure
            for header in self.INFO_HEADERS:
                for line in lines:
                    if line.startswith(header.lower()):
                        info_disclosure.append(f"{host} | {line.strip()}")

        # Deduplicate
        missing = sorted(set(missing))
        info_disclosure = sorted(set(info_disclosure))

        self.save_lines(missing, str(self.output_dir / "missing_headers.txt"))
        self.save_lines(info_disclosure, str(self.output_dir / "info_disclosure.txt"))

        for entry in info_disclosure:
            self.add_finding("info_disclosure", "low", entry.split("|")[0].strip(), entry)

        self.state.set_state(self.name, "missing", missing)
        self.state.set_state(self.name, "info_disclosure", info_disclosure)
        self.log(f"Missing headers: {len(missing)} | Info disclosure: {len(info_disclosure)}")
        return self.state
