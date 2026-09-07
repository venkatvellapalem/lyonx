"""WAF detection."""
from .. import Plugin, Budget


class WAFDetectPlugin(Plugin):
    name = "intel.waf_detect"
    description = "Web Application Firewall detection"
    category = "intel"

    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "akamai": ["akamai", "x-akamai"],
        "aws-waf": ["awswaf", "x-amzn-requestid"],
        "imperva": ["incapsula", "x-cdn: imperva"],
        "sucuri": ["sucuri", "x-sucuri"],
        "wordfence": ["wordfence"],
        "modsecurity": ["mod_security", "modsecurity"],
        "barracuda": ["barracuda"],
        "f5-bigip": ["bigip", "f5"],
        "citrix": ["netscaler", "citrix"],
    }

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        if not live_urls:
            return self.state

        targets = live_urls[:10]
        self.log(f"Detecting WAF on {len(targets)} hosts...")

        detected_wafs = {}

        for url in targets:
            # Normal request
            out = self.run_tool(["curl", "-sI", "--max-time", "5", url], timeout=10)
            if not out:
                continue

            out_lower = out.lower()
            host = url.split("/")[2] if "/" in url else url

            for waf, sigs in self.WAF_SIGNATURES.items():
                if any(s in out_lower for s in sigs):
                    detected_wafs[host] = waf
                    break

            # WAF trigger test — send a malicious-looking request
            if host not in detected_wafs:
                test_url = f"{url}/../../../etc/passwd"
                out2 = self.run_tool(["curl", "-sI", "--max-time", "5", test_url], timeout=10)
                if out2 and any(code in out2 for code in ["403", "406", "501"]):
                    if "cloudflare" in out2.lower():
                        detected_wafs[host] = "cloudflare"
                    elif "akamai" in out2.lower():
                        detected_wafs[host] = "akamai"
                    else:
                        detected_wafs[host] = "unknown-waf"

        self.state.set_state(self.name, "detected", detected_wafs)
        if detected_wafs:
            for host, waf in detected_wafs.items():
                self.log(f"WAF: {host} → {waf}")
        else:
            self.log("No WAF detected")
        return self.state
