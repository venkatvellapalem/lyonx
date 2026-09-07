"""Subdomain enumeration plugin."""
import sqlite3
from .. import Plugin, Budget


class SubdomainPlugin(Plugin):
    name = "recon.subdomains"
    description = "Passive + permutation subdomain enumeration"
    category = "recon"
    required_tools = ["subfinder"]

    def run(self, budget: Budget):
        # Get target from scan record
        conn = sqlite3.connect(str(self.state.db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT target FROM scans WHERE id = ?", (self.state.scan_id,)).fetchone()
        target = row["target"] if row else ""
        conn.close()

        if not target:
            self.log("No target found in scan record", "error")
            return self.state

        all_subs = set()

        # subfinder
        self.log("Running subfinder...")
        out = self.run_tool(
            ["subfinder", "-d", target, "-silent", "-all"],
            timeout=180
        )
        subs = [l.strip() for l in out.splitlines() if l.strip() and "." in l]
        all_subs.update(subs)
        self.log(f"subfinder: {len(subs)} subs")

        # assetfinder
        if self.tool_available("assetfinder"):
            self.log("Running assetfinder...")
            out = self.run_tool(["assetfinder", "--subs-only", target], timeout=60)
            subs = [l.strip() for l in out.splitlines() if l.strip() and "." in l]
            all_subs.update(subs)
            self.log(f"assetfinder: {len(subs)} subs")

        # Deduplicate
        unique = self.dedup.dedup_hosts(list(all_subs))
        self.save_lines(sorted(unique), str(self.output_dir / "all_subs.txt"))
        self.log(f"Unique subdomains: {len(unique)}")

        # Permutation with alterx (only if we have a reasonable number)
        if self.tool_available("alterx") and 0 < len(unique) <= 5000:
            self.log("Generating permutations with alterx...")
            input_data = "\n".join(unique[:2000])  # Cap input to alterx
            out = self.run_pipe(input_data, ["alterx", "-silent"], timeout=120)
            if out:
                perms = [l.strip() for l in out.splitlines() if l.strip() and "." in l]
                all_subs.update(perms)
                unique = self.dedup.dedup_hosts(list(all_subs))
                self.save_lines(sorted(unique), str(self.output_dir / "final_subs.txt"))
                self.log(f"With permutations: {len(unique)} subs")
        else:
            self.save_lines(sorted(unique), str(self.output_dir / "final_subs.txt"))

        self.state.set_state(self.name, "subdomains", sorted(unique))
        self.state.set_state(self.name, "count", len(unique))
        return self.state
