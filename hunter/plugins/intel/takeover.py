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

    TAKEOVER_FINGERPRINTS = {
        "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
        "herokuapp.com": ["Heroku | No such app", "no such app", "herokucdn.com/error-pages/no-such-app.html"],
        "github.io": ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"],
        "azurewebsites.net": ["404 Web Site not found", "app service - error 404"],
        "shopify.com": ["Sorry, this shop is currently unavailable"],
        "fastly.net": ["Fastly error: unknown domain"],
        "pantheon.io": ["404 error: Register domain to site"],
        "ghost.io": ["The thing you were looking for is no longer here"],
        "surge.sh": ["project not found"],
        "bitbucket.io": ["Repository not found"],
        "zendesk.com": ["Help Center Closed"],
        "canny.io": ["There is no such company at this domain"],
    }

    def run(self, budget: Budget):
        raw_records = self.state.get_state("recon.dns", "raw_records", [])
        resolved = self.state.get_state("recon.dns", "resolved", [])
        lines = raw_records if raw_records else resolved
        if not lines:
            return self.state

        self.log(f"Checking {len(lines)} DNS records for takeover candidates...")

        candidates = []
        vulnerable = []

        for line in lines:
            line_lower = line.lower()
            parts = line.split()
            host = parts[0] if parts else ""
            if not host:
                continue

            # Check if record mentions a vulnerable service CNAME
            for service, name in self.VULNERABLE_CNAME.items():
                if service in line_lower:
                    candidates.append(f"{host} → {name} ({service})")
                    break

        candidates = sorted(set(candidates))

        if candidates:
            self.log(f"Found {len(candidates)} takeover candidates")
            self.save_lines(candidates, str(self.output_dir / "takeover_candidates.txt"))

            # Verify candidates — check if response body matches provider's unclaimed fingerprint
            for candidate in candidates[:30]:
                host = candidate.split(" → ")[0].strip()
                matched_service = ""
                for s in self.VULNERABLE_CNAME:
                    if s in candidate:
                        matched_service = s
                        break

                fingerprints = self.TAKEOVER_FINGERPRINTS.get(matched_service, [])
                out = self.run_tool([
                    "curl", "-sL", "--max-time", "6",
                    f"http://{host}"
                ], timeout=10)

                if out and fingerprints:
                    for fp in fingerprints:
                        if fp.lower() in out.lower():
                            vulnerable.append(f"{candidate} [Evidence: {fp}]")
                            self.add_finding("subdomain_takeover", "high", host, f"{candidate} (Evidence: {fp})")
                            break

            self.save_lines(vulnerable, str(self.output_dir / "takeover_vulnerable.txt"))

        self.state.set_state(self.name, "candidates", candidates)
        self.state.set_state(self.name, "vulnerable", vulnerable)
        self.log(f"Candidates: {len(candidates)} | Confirmed vulnerable: {len(vulnerable)}")
        return self.state
