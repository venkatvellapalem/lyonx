"""Security header analysis."""
import urllib.request
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
        self.log(f"Analyzing headers on {len(targets)} hosts concurrently...")

        def analyze_host(url):
            missing_local = []
            info_local = []
            host = url.split("/")[2] if "/" in url else url
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Hunter/3.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    for header in self.SECURITY_HEADERS:
                        if header.lower() not in resp_headers:
                            missing_local.append(f"{host} | Missing: {header}")
                    for header in self.INFO_HEADERS:
                        if header.lower() in resp_headers:
                            info_local.append(f"{host} | {header}: {resp_headers[header.lower()]}")
            except Exception:
                # Fallback to curl
                out = self.run_tool(["curl", "-sI", "--max-time", "5", url], timeout=8)
                if out:
                    lines = out.lower().splitlines()
                    for header in self.SECURITY_HEADERS:
                        if not any(header.lower() in line for line in lines):
                            missing_local.append(f"{host} | Missing: {header}")
                    for header in self.INFO_HEADERS:
                        for line in lines:
                            if line.startswith(header.lower()):
                                info_local.append(f"{host} | {line.strip()}")
            return (missing_local, info_local)

        results = self.probe_urls_concurrent(targets, analyze_host, max_workers=15)
        missing = []
        info_disclosure = []
        for m_list, i_list in results:
            missing.extend(m_list)
            info_disclosure.extend(i_list)

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
