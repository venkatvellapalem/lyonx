"""Port scanning plugin."""
from .. import Plugin, Budget


class PortScanPlugin(Plugin):
    name = "recon.ports"
    description = "Fast port scanning with naabu"
    category = "recon"
    required_tools = ["naabu"]

    def run(self, budget: Budget):
        ips = self.state.get_state("recon.dns", "ips", [])
        if not ips:
            self.log("No IPs to scan", "warn")
            return self.state

        self.log(f"Scanning {len(ips)} IPs (top 1000 ports)...")
        input_data = "\n".join(ips)
        
        out = self.run_pipe(input_data, [
            "naabu", "-silent", "-top-ports", "1000",
            "-exclude-cdn", "-c", str(budget.threads)
        ], timeout=600)

        ports = [l.strip() for l in out.splitlines() if l.strip()]
        self.save_lines(ports, str(self.output_dir / "open_ports.txt"))

        # Identify interesting services
        interesting_patterns = {
            "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
            "53": "DNS", "110": "POP3", "143": "IMAP", "445": "SMB",
            "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL",
            "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
            "6379": "Redis", "8080": "HTTP-Alt", "8443": "HTTPS-Alt",
            "9090": "Admin", "27017": "MongoDB",
        }
        
        interesting = []
        for line in ports:
            port = line.split(":")[-1] if ":" in line else ""
            if port in interesting_patterns:
                interesting.append(f"{line} ({interesting_patterns[port]})")
        
        self.save_lines(interesting, str(self.output_dir / "interesting_ports.txt"))

        self.state.set_state(self.name, "all_ports", ports)
        self.state.set_state(self.name, "interesting", interesting)
        self.state.set_state(self.name, "count", len(ports))
        self.log(f"Open ports: {len(ports)} | Interesting: {len(interesting)}")
        return self.state
