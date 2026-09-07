"""Fast port scanning plugin with RustScan, Naabu, and Nmap fallback."""
import re
import socket
from .. import Plugin, Budget


class PortScanPlugin(Plugin):
    name = "recon.ports"
    description = "Fast port scanning with RustScan, Naabu, or Nmap"
    category = "recon"
    required_tools = []  # Handled dynamically via fallback chain

    INTERESTING_PATTERNS = {
        "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
        "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS",
        "445": "SMB", "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL",
        "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
        "6379": "Redis", "8080": "HTTP-Alt", "8443": "HTTPS-Alt",
        "9090": "Admin", "27017": "MongoDB",
    }

    def should_run(self) -> bool:
        return True

    def run(self, budget: Budget):
        ips = self.state.get_state("recon.dns", "ips", [])
        if not ips:
            # Fallback to resolved hosts if no IPs
            resolved = self.state.get_state("recon.dns", "resolved", [])
            ips = resolved[:50] if resolved else []

        if not ips:
            self.log("No targets/IPs to scan for ports", "warn")
            return self.state

        target_list = ips[:100]  # Cap for safety
        ports = []

        if self.tool_available("rustscan"):
            ports = self._scan_rustscan(target_list, budget)
        elif self.tool_available("naabu"):
            ports = self._scan_naabu(target_list, budget)
        elif self.tool_available("nmap"):
            ports = self._scan_nmap(target_list, budget)
        else:
            self.log("Neither rustscan, naabu, nor nmap available. Using socket probe...", "warn")
            ports = self._scan_socket(target_list, budget)

        # Deduplicate
        ports = sorted(set(ports))
        self.save_lines(ports, str(self.output_dir / "open_ports.txt"))

        # Identify interesting services
        interesting = []
        for line in ports:
            port = line.split(":")[-1] if ":" in line else ""
            if port in self.INTERESTING_PATTERNS:
                interesting.append(f"{line} ({self.INTERESTING_PATTERNS[port]})")

        self.save_lines(interesting, str(self.output_dir / "interesting_ports.txt"))

        self.state.set_state(self.name, "all_ports", ports)
        self.state.set_state(self.name, "interesting", interesting)
        self.state.set_state(self.name, "count", len(ports))
        self.log(f"Open ports: {len(ports)} | Interesting: {len(interesting)}")
        return self.state

    def _scan_rustscan(self, ips: list[str], budget: Budget) -> list[str]:
        """Scan using RustScan in greppable mode."""
        self.log(f"Scanning {len(ips)} targets with RustScan...")
        ports = []
        # Batch IPs into comma-separated groups of 10
        chunk_size = 10
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i:i + chunk_size]
            addr_str = ",".join(chunk)
            out = self.run_tool([
                "rustscan", "-a", addr_str,
                "-g", "--top",
                "-t", "1500",
                "-b", "2000",
            ], timeout=180)
            
            for line in out.splitlines():
                line = line.strip()
                # Greppable format: "45.33.32.156 -> [80,443]"
                if "->" in line:
                    parts = line.split("->")
                    host = parts[0].strip()
                    found_ports = re.findall(r'\d+', parts[1])
                    for p in found_ports:
                        ports.append(f"{host}:{p}")
                elif ":" in line and not line.startswith("["):
                    ports.append(line)
        return ports

    def _scan_naabu(self, ips: list[str], budget: Budget) -> list[str]:
        """Scan using Naabu."""
        self.log(f"Scanning {len(ips)} targets with Naabu...")
        input_data = "\n".join(ips)
        out = self.run_pipe(input_data, [
            "naabu", "-silent", "-top-ports", "1000",
            "-exclude-cdn", "-c", str(budget.threads)
        ], timeout=300)
        return [l.strip() for l in out.splitlines() if l.strip()]

    def _scan_nmap(self, ips: list[str], budget: Budget) -> list[str]:
        """Scan using Nmap greppable output."""
        self.log(f"Scanning {len(ips)} targets with Nmap...")
        ports = []
        chunk_size = 10
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i:i + chunk_size]
            out = self.run_tool([
                "nmap", "-sT", "-T4", "--top-ports", "100",
                "-oG", "-",
            ] + chunk, timeout=180)
            for line in out.splitlines():
                if "Ports:" in line:
                    # Line format: Host: 45.33.32.156 () Ports: 80/open/tcp//http///, 443/open/tcp//https///
                    host_match = re.search(r'Host:\s+([^\s]+)', line)
                    if host_match:
                        host = host_match.group(1)
                        ports_part = line.split("Ports:")[1]
                        for entry in ports_part.split(","):
                            p_match = re.search(r'(\d+)/open', entry)
                            if p_match:
                                ports.append(f"{host}:{p_match.group(1)}")
        return ports

    def _scan_socket(self, targets: list[str], budget: Budget) -> list[str]:
        """Pure python fallback socket probe for common ports."""
        common_ports = [80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017]
        found = []
        for target in targets[:10]:
            for port in common_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.4)
                    res = s.connect_ex((target, port))
                    s.close()
                    if res == 0:
                        found.append(f"{target}:{port}")
                except Exception:
                    pass
        return found
