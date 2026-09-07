"""DNS resolution plugin."""
from .. import Plugin, Budget
import re


class DNSPlugin(Plugin):
    name = "recon.dns"
    description = "DNS resolution with wildcard filtering"
    category = "recon"
    required_tools = ["dnsx"]

    def run(self, budget: Budget):
        subs = self.state.get_state("recon.subdomains", "subdomains", [])
        if not subs:
            self.log("No subdomains to resolve", "warn")
            return self.state

        # Cap at reasonable number for DNS resolution
        subs = subs[:5000]
        self.log(f"Resolving {len(subs)} subdomains...")
        input_data = "\n".join(subs)
        
        out = self.run_pipe(input_data, [
            "dnsx", "-silent", "-a", "-aaaa", "-cname", "-resp"
        ], timeout=600)
        
        resolved = [l.strip() for l in out.splitlines() if l.strip()]
        self.save_lines(resolved, str(self.output_dir / "resolved.txt"))
        
        # Extract unique IPs
        ips = set()
        for line in resolved:
            for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
                ips.add(ip)
        
        self.save_lines(sorted(ips), str(self.output_dir / "ips.txt"))
        
        # Get resolved hostnames
        resolved_hosts = []
        for line in resolved:
            host = line.split()[0] if line.split() else ""
            if host:
                resolved_hosts.append(host)
        
        self.state.set_state(self.name, "resolved", resolved_hosts)
        self.state.set_state(self.name, "ips", sorted(ips))
        self.state.set_state(self.name, "resolved_count", len(resolved_hosts))
        self.log(f"Resolved: {len(resolved_hosts)} hosts, {len(ips)} unique IPs")
        return self.state
