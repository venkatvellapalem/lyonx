"""Subdomain takeover detection."""
from .. import Plugin, Budget


class TakeoverPlugin(Plugin):
    name = "intel.takeover"
    description = "Subdomain takeover vulnerability detection"
    category = "intel"

    VULNERABLE_CNAME = {
        "amazonaws.com": "S3 bucket",
        "herokuapp.com": "Heroku",
        "github.io": "GitHub Pages",
        "azurewebsites.net": "Azure",
        "cloudfront.net": "CloudFront",
        "shopify.com": "Shopify",
        "fastly.net": "Fastly",
        "pantheon.io": "Pantheon",
        "ghost.io": "Ghost",
        "surge.sh": "Surge",
        "bitbucket.io": "Bitbucket",
        "wordpress.com": "WordPress",
        "tumblr.com": "Tumblr",
        "zendesk.com": "Zendesk",
        "readme.io": "Readme",
        "ghost.io": "Ghost",
        "cargocollective.com": "Cargo",
        "hatena.ne.jp": "Hatena",
        "launchrock.com": "Launchrock",
        "feedpress.me": "Feedpress",
        "ghost.io": "Ghost",
        "helpjuice.com": "Helpjuice",
        "helpscoutdocs.com": "HelpScout",
        "statuspage.io": "StatusPage",
        "pingdom.com": "Pingdom",
        "tictail.com": "Tictail",
        "campaignmonitor.com": "Campaign Monitor",
        "canny.io": "Canny",
        "amazoncognito.com": "Cognito",
    }

    def run(self, budget: Budget):
        resolved = self.state.get_state("recon.dns", "resolved", [])
        if not resolved:
            return self.state

        self.log(f"Checking {len(resolved)} hosts for takeover candidates...")

        candidates = []
        vulnerable = []

        for line in resolved:
            parts = line.split()
            if len(parts) < 2:
                continue
            host = parts[0]
            
            # Check if CNAME points to vulnerable service
            for service, name in self.VULNERABLE_CNAME.items():
                if service in line.lower():
                    candidates.append(f"{host} → {name} ({service})")

        if candidates:
            self.log(f"Found {len(candidates)} takeover candidates")
            self.save_lines(candidates, str(self.output_dir / "takeover_candidates.txt"))

            # Verify candidates — check if the service responds with an error
            for candidate in candidates[:20]:
                host = candidate.split(" → ")[0].strip()
                out = self.run_tool([
                    "curl", "-sI", "-L", "--max-time", "5",
                    f"https://{host}"
                ], timeout=10)

                if out:
                    first_line = out.splitlines()[0] if out.splitlines() else ""
                    # NXDOMAIN or 404 on the service could indicate takeover
                    if any(code in first_line for code in ["404", "410", "502", "503"]):
                        vulnerable.append(candidate)
                        self.add_finding("subdomain_takeover", "high", host, candidate)

            self.save_lines(vulnerable, str(self.output_dir / "takeover_vulnerable.txt"))

        self.state.set_state(self.name, "candidates", candidates)
        self.state.set_state(self.name, "vulnerable", vulnerable)
        self.log(f"Candidates: {len(candidates)} | Potentially vulnerable: {len(vulnerable)}")
        return self.state
