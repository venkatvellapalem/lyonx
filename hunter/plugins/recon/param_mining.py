"""Parameter mining — find injectable URLs and hidden params."""
from .. import Plugin, Budget
import re
from urllib.parse import urlparse, parse_qs


class ParamMiningPlugin(Plugin):
    name = "recon.param_mining"
    description = "Parameter extraction and injectable URL identification"
    category = "recon"

    # Parameters likely to be injectable
    INJECTABLE_PARAMS = {
        "id", "user", "uid", "pid", "cat", "item", "page", "search", "query",
        "name", "email", "order", "sort", "type", "ref", "lang", "file", "path",
        "include", "cmd", "exec", "run", "ping", "host", "ip", "url", "uri",
        "callback", "jsonp", "redirect", "next", "return", "goto", "target",
        "dest", "action", "input", "data", "json", "xml", "q", "s", "keyword",
    }

    def run(self, budget: Budget):
        param_urls = self.state.get_state("recon.url_discovery", "param_urls", [])
        if not param_urls:
            self.log("No URLs with parameters found", "warn")
            return self.state

        self.log(f"Mining parameters from {len(param_urls)} URLs...")

        # Use ParamSpider if available
        extra_params = []
        if self.tool_available("arjun"):
            import sqlite3
            conn = sqlite3.connect(str(self.state.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT target FROM scans WHERE id = ?", (self.state.scan_id,)).fetchone()
            target = row["target"] if row else ""
            conn.close()

            self.log("Running Arjun for hidden parameter discovery...")
            out = self.run_tool(["arjun", "-u", f"https://{target}", "--stable", "-oJ", str(self.output_dir / "arjun.json")], timeout=120)
            if out:
                self.log("Arjun completed")

        # Analyze parameters
        param_freq = {}
        injectable_urls = []
        redirect_urls = []
        interesting_urls = []

        for url in param_urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=False)
                
                for param_name in params:
                    # Count frequency
                    param_freq[param_name] = param_freq.get(param_name, 0) + 1
                    
                    # Check if injectable
                    if param_name.lower() in self.INJECTABLE_PARAMS:
                        injectable_urls.append(url)
                    
                    # Check if redirect-related
                    if param_name.lower() in {"url", "redirect", "next", "return", "goto", "target", "dest", "redirect_uri", "return_url"}:
                        redirect_urls.append(url)
            except Exception:
                continue

        # Sort by frequency
        param_freq_sorted = sorted(param_freq.items(), key=lambda x: -x[1])
        param_lines = [f"{cnt:>5d}  {name}" for name, cnt in param_freq_sorted]

        # Deduplicate
        injectable_urls = list(set(injectable_urls))
        redirect_urls = list(set(redirect_urls))

        self.save_lines(param_lines, str(self.output_dir / "param_frequency.txt"))
        self.save_lines(sorted(injectable_urls), str(self.output_dir / "injectable_urls.txt"))
        self.save_lines(sorted(redirect_urls), str(self.output_dir / "redirect_params.txt"))

        self.state.set_state(self.name, "param_urls", param_urls)
        self.state.set_state(self.name, "injectable_urls", sorted(injectable_urls))
        self.state.set_state(self.name, "redirect_urls", sorted(redirect_urls))
        self.state.set_state(self.name, "param_frequency", dict(param_freq_sorted))
        self.log(f"Unique params: {len(param_freq)} | Injectable: {len(injectable_urls)} | Redirect: {len(redirect_urls)}")
        return self.state
