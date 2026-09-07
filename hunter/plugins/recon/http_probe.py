"""HTTP probing — discover live hosts and tech stack."""
from .. import Plugin, Budget
import re


class HttpProbePlugin(Plugin):
    name = "recon.http_probe"
    description = "HTTP probing with tech detection"
    category = "recon"
    required_tools = ["httpx"]

    def run(self, budget: Budget):
        resolved = self.state.get_state("recon.dns", "resolved", [])
        if not resolved:
            self.log("No resolved hosts", "warn")
            return self.state

        self.log(f"Probing {len(resolved)} hosts...")
        input_data = "\n".join(resolved[:2000])  # Cap for performance
        
        out = self.run_pipe(input_data, [
            "httpx", "-silent",
            "-status-code", "-title", "-tech-detect", "-cdn", "-ip", "-server",
            "-follow-redirects",
            "-threads", str(budget.threads),
        ], timeout=600)

        lines = [l.strip() for l in out.splitlines() if l.strip()]
        self.save_lines(lines, str(self.output_dir / "alive_full.txt"))

        # Extract clean URLs
        urls = []
        for line in lines:
            match = re.search(r'(https?://[^\s\[\]]+)', line)
            if match:
                urls.append(match.group(1))
        
        urls = self.dedup.dedup_urls(urls)
        self.save_lines(urls, str(self.output_dir / "live_urls.txt"))

        # Extract tech stack
        tech = []
        for line in lines:
            brackets = re.findall(r'\[([^\]]+)\]', line)
            tech.extend(brackets)
        
        from collections import Counter
        tech_counts = Counter(tech)
        tech_lines = [f"{cnt:>5d}  {t}" for t, cnt in tech_counts.most_common()]
        self.save_lines(tech_lines, str(self.output_dir / "tech_stack.txt"))

        self.state.set_state(self.name, "live_urls", urls)
        self.state.set_state(self.name, "live_count", len(urls))
        self.state.set_state(self.name, "tech_stack", dict(tech_counts.most_common()))
        self.log(f"Live hosts: {len(urls)} | Technologies: {len(tech_counts)}")
        return self.state
