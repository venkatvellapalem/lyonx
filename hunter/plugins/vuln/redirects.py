"""Open redirect detection."""
import re
import urllib.request
from .. import Plugin, Budget


class RedirectPlugin(Plugin):
    name = "vuln.redirects"
    description = "Open redirect detection"
    category = "vuln"

    REDIRECT_PARAMS = re.compile(
        r'[?&](url|redirect|next|return|goto|target|dest|destination|redir|'
        r'redirect_uri|return_url|return_to|continue|forward|feed|page|link|href|to)=',
        re.I
    )

    def run(self, budget: Budget):
        param_urls = self.state.get_state("recon.param_mining", "redirect_urls", [])
        if not param_urls:
            all_param_urls = self.state.get_state("recon.param_mining", "param_urls", [])
            param_urls = [u for u in all_param_urls if self.REDIRECT_PARAMS.search(u)]

        if not param_urls:
            self.log("No redirect-parameter URLs found", "warn")
            return self.state

        targets = param_urls[:100]
        self.log(f"Testing {len(targets)} URLs for open redirects concurrently...")

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_302
            http_error_303 = http_error_302
            http_error_307 = http_error_302
            http_error_308 = http_error_302

        opener = urllib.request.build_opener(NoRedirectHandler)

        def check_redirect(url):
            test_url = re.sub(
                r'([?&](?:url|redirect|next|return|goto|target|dest|destination|redir|'
                r'redirect_uri|return_url|return_to|continue|forward|feed|page|link|href|to)=)[^&]*',
                r'\1https://evil.com',
                url, flags=re.I
            )
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Hunter/3.0"})
                resp = opener.open(req, timeout=5)
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    return (url, test_url, location)
            except Exception:
                out = self.run_tool(["curl", "-sI", "--max-time", "5", test_url], timeout=8)
                if out and "location:" in out.lower() and "evil.com" in out.lower():
                    return (url, test_url, "evil.com")
            return None

        results = self.probe_urls_concurrent(targets, check_redirect, max_workers=15)
        vulnerable = []
        for res in results:
            if res:
                url, test_url, loc = res
                vulnerable.append(url)
                self.add_finding("open_redirect", "medium", url, f"Redirects to: {loc}")

        self.save_lines(vulnerable, str(self.output_dir / "open_redirects.txt"))
        self.state.set_state(self.name, "findings", vulnerable)
        self.log(f"Open redirects: {len(vulnerable)}")
        return self.state
