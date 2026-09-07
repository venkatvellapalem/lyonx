"""Content discovery fuzzing with ffuf."""
from .. import Plugin, Budget
import re


class FuzzPlugin(Plugin):
    name = "vuln.fuzz"
    description = "Directory/file fuzzing with ffuf"
    category = "vuln"
    required_tools = ["ffuf"]

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        if not live_urls:
            return self.state

        wordlist = self.config.get_wordlist("common")
        if not wordlist:
            self.log("No wordlist found, skipping fuzzing", "warn")
            return self.state

        targets = live_urls[:30]
        self.log(f"Fuzzing {len(targets)} hosts...")

        all_found = []
        for i, url in enumerate(targets):
            self.progress(i, len(targets))
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url.replace("https://", "").replace("http://", ""))
            
            out = self.run_tool([
                "ffuf", "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-t", str(min(budget.threads, 20)),
                "-mc", "200,301,302,403,401",
                "-fs", "0",
                "-o", str(self.output_dir / f"{safe_name}.json"),
                "-of", "json",
                "-s"
            ], timeout=120)

            if out:
                found = [l.strip() for l in out.splitlines() if l.strip()]
                all_found.extend(found)

        # Parse JSON results
        import json
        all_urls = []
        for json_file in self.output_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                for r in data.get("results", []):
                    all_urls.append(r.get("url", ""))
            except Exception:
                pass

        all_urls = sorted(set(all_urls))
        self.save_lines(all_urls, str(self.output_dir / "fuzz_found.txt"))

        self.state.set_state(self.name, "found", all_urls)
        self.log(f"Found: {len(all_urls)} paths")
        return self.state
