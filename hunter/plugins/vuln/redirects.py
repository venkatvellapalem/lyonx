"""Open redirect detection."""
from .. import Plugin, Budget
import re


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
            # Also check all param URLs
            all_param_urls = self.state.get_state("recon.param_mining", "param_urls", [])
            param_urls = [u for u in all_param_urls if self.REDIRECT_PARAMS.search(u)]

        if not param_urls:
            self.log("No redirect-parameter URLs found", "warn")
            return self.state

        targets = param_urls[:100]
        self.log(f"Testing {len(targets)} URLs for open redirects...")

        vulnerable = []
        for i, url in enumerate(targets):
            self.progress(i, len(targets))

            # Replace param value with evil URL
            test_url = re.sub(
                r'([?&](?:url|redirect|next|return|goto|target|dest|destination|redir|'
                r'redirect_uri|return_url|return_to|continue|forward|feed|page|link|href|to)=)[^&]*',
                r'\1https://evil.com',
                url, flags=re.I
            )

            out = self.run_tool([
                "curl", "-sI", "-L", "--max-time", "5", test_url
            ], timeout=10)

            if out and "location:" in out.lower() and "evil.com" in out.lower():
                vulnerable.append(url)
                self.add_finding("open_redirect", "medium", url, f"Redirects to: {test_url}")

        self.save_lines(vulnerable, str(self.output_dir / "open_redirects.txt"))
        self.state.set_state(self.name, "findings", vulnerable)
        self.log(f"Open redirects: {len(vulnerable)}")
        return self.state
