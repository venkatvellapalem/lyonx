"""JavaScript analysis — extract endpoints, secrets, API keys."""
from .. import Plugin, Budget
import re


class JSAnalysisPlugin(Plugin):
    name = "recon.js_analysis"
    description = "JS file analysis for secrets and endpoints"
    category = "recon"

    def run(self, budget: Budget):
        js_urls = self.state.get_state("recon.url_discovery", "js_urls", [])
        if not js_urls:
            self.log("No JS files to analyze", "warn")
            return self.state

        self.log(f"Analyzing {len(js_urls)} JS files...")
        
        secrets = []
        endpoints = []
        api_keys = []

        secret_pattern = re.compile(
            r'(api[_-]?key|apikey|secret|token|password|auth|bearer|aws[_-]?access|'
            r'private[_-]?key|client[_-]?secret)["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{8,}["\']',
            re.I
        )
        endpoint_pattern = re.compile(r'["\'`\'`]/api/[^"\'`\s]+["\'`\'`]')
        url_pattern = re.compile(r'https?://[^\s"\'`\'`]+')
        param_url_pattern = re.compile(r'https?://[^\s"\'`\'`]+\?[^\s"\'`\'`]+')

        def fetch_js(url):
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={"User-Agent": "Hunter/3.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return (url, resp.read().decode("utf-8", errors="ignore"))
            except Exception:
                # Fallback to run_tool
                txt = self.run_tool(["curl", "-sL", "--max-time", "10", url], timeout=12)
                return (url, txt)

        js_results = self.probe_urls_concurrent(js_urls[:100], fetch_js, max_workers=10)

        for js_url, content in js_results:
            if not content:
                continue

            # Extract secrets
            for match in secret_pattern.finditer(content):
                secrets.append(f"{js_url}: {match.group()[:100]}")

            # Extract API endpoints
            for match in endpoint_pattern.finditer(content):
                endpoints.append(match.group().strip("\"'`"))
            
            # Extract full URLs
            for match in url_pattern.finditer(content):
                endpoints.append(match.group())
            
            # Extract URLs with params
            for match in param_url_pattern.finditer(content):
                api_keys.append(match.group())

        # Deduplicate
        secrets = list(set(secrets))
        endpoints = list(set(endpoints))
        api_keys = list(set(api_keys))

        self.save_lines(sorted(secrets), str(self.output_dir / "js_secrets.txt"))
        self.save_lines(sorted(endpoints), str(self.output_dir / "js_endpoints.txt"))
        self.save_lines(sorted(api_keys), str(self.output_dir / "js_api_urls.txt"))

        # Report secrets as findings
        for secret in secrets:
            if ": " in secret:
                source_url, snippet = secret.split(": ", 1)
            else:
                source_url, snippet = js_url, secret
            self.add_finding("secret_exposure", "high", source_url, snippet)

        self.state.set_state(self.name, "secrets", secrets)
        self.state.set_state(self.name, "endpoints", endpoints)
        self.log(f"Secrets: {len(secrets)} | Endpoints: {len(endpoints)}")
        return self.state
