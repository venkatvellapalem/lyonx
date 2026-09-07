"""URL and endpoint discovery plugin."""
from .. import Plugin, Budget
import re


class URLDiscoveryPlugin(Plugin):
    name = "recon.url_discovery"
    description = "URL harvesting from archives, crawling, JS"
    category = "recon"

    def run(self, budget: Budget):
        import sqlite3
        conn = sqlite3.connect(str(self.state.db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT target FROM scans WHERE id = ?", (self.state.scan_id,)).fetchone()
        target = row["target"] if row else ""
        conn.close()

        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        all_urls = set()

        # gau
        if self.tool_available("gau"):
            self.log("Fetching from gau (archives)...")
            out = self.run_tool(["gau", target, "--threads", "10"], timeout=120)
            urls = [l.strip() for l in out.splitlines() if l.strip()]
            all_urls.update(urls)
            self.log(f"gau: {len(urls)} URLs")

        # waybackurls
        if self.tool_available("waybackurls"):
            self.log("Fetching from waybackurls...")
            out = self.run_tool(["waybackurls", target], timeout=120)
            urls = [l.strip() for l in out.splitlines() if l.strip()]
            all_urls.update(urls)
            self.log(f"waybackurls: {len(urls)} URLs")

        # katana crawl
        if self.tool_available("katana") and live_urls:
            self.log(f"Crawling with katana (depth={self.config.crawl_depth})...")
            # Crawl first few live URLs
            crawl_targets = live_urls[:20]
            for url in crawl_targets:
                out = self.run_tool([
                    "katana", "-u", url,
                    "-d", str(self.config.crawl_depth),
                    "-silent", "-jc"
                ], timeout=60)
                urls = [l.strip() for l in out.splitlines() if l.strip()]
                all_urls.update(urls)
            self.log(f"katana crawled: {len(all_urls)} total URLs")

        # Deduplicate
        unique = self.dedup.dedup_urls(list(all_urls))
        
        # Categorize URLs
        param_urls = [u for u in unique if "?" in u and "=" in u]
        api_urls = [u for u in unique if re.search(r'/api/|/v\d|/rest/|/graphql|/swagger|/json|/xml', u, re.I)]
        js_urls = [u for u in unique if re.search(r'\.js(\?|$)', u, re.I)]

        # Extract endpoints (paths)
        endpoints = set()
        for url in unique:
            match = re.search(r'https?://[^/]+(/[^\?\s#]+)', url)
            if match:
                endpoints.add(match.group(1))

        self.save_lines(sorted(unique), str(self.output_dir / "all_urls.txt"))
        self.save_lines(sorted(param_urls), str(self.output_dir / "param_urls.txt"))
        self.save_lines(sorted(api_urls), str(self.output_dir / "api_endpoints.txt"))
        self.save_lines(sorted(js_urls), str(self.output_dir / "js_urls.txt"))
        self.save_lines(sorted(endpoints), str(self.output_dir / "endpoints.txt"))

        self.state.set_state(self.name, "all_urls", sorted(unique))
        self.state.set_state(self.name, "param_urls", sorted(param_urls))
        self.state.set_state(self.name, "api_endpoints", sorted(api_urls))
        self.state.set_state(self.name, "js_urls", sorted(js_urls))
        self.state.set_state(self.name, "endpoints", sorted(endpoints))
        self.log(f"Total: {len(unique)} URLs | Params: {len(param_urls)} | API: {len(api_urls)} | JS: {len(js_urls)}")
        return self.state
