"""Plugin base class and loader."""
import time
import subprocess
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from ..core.config import Config
from ..core.state import ScanState, Finding
from ..core.dedup import Deduplicator
from ..core.resource import ResourceManager, Budget


class Plugin(ABC):
    """Base class for all Hunter plugins.
    
    Subclass this and implement:
        - name: str (plugin identifier, e.g. "recon.subdomains")
        - description: str (human-readable description)
        - run(state, budget) -> state (main logic)
    """

    name: str = ""
    description: str = ""
    category: str = ""  # recon, vuln, intel, post

    def __init__(self, config: Config, state: ScanState, dedup: Deduplicator,
                 resource: ResourceManager):
        self.config = config
        self.state = state
        self.dedup = dedup
        self.resource = resource
        self.output_dir = Path(state.base_dir) / self.name.replace(".", "/")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def run(self, budget: Budget) -> ScanState:
        """Execute the plugin. Must return the updated state."""
        ...

    def should_run(self) -> bool:
        """Check if this plugin should run (override for conditional logic)."""
        return True

    def log(self, message: str, level: str = "info"):
        """Log a message."""
        prefix = {"info": "[*]", "success": "[+]", "warn": "[!]", "error": "[-]"}.get(level, "[*]")
        print(f"  {prefix} [{self.name}] {message}")

    def run_tool(self, cmd: list[str], timeout: int = None, input_data: str = None) -> str:
        """Run an external tool and return stdout.
        
        Args:
            cmd: Command and arguments
            timeout: Max seconds to run
            input_data: Data to pipe to stdin
            
        Returns:
            stdout string
        """
        timeout = timeout or self.config.timeout
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log(f"Tool timed out: {cmd[0]}", "warn")
            return ""
        except FileNotFoundError:
            self.log(f"Tool not found: {cmd[0]}", "error")
            return ""
        except Exception as e:
            self.log(f"Tool error: {cmd[0]}: {e}", "error")
            return ""

    def run_tool_to_file(self, cmd: list[str], output_path: str, timeout: int = None) -> bool:
        """Run a tool and write stdout to a file."""
        output = self.run_tool(cmd, timeout)
        if output:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(output)
            return True
        return False

    def run_pipe(self, input_data: str, cmd: list[str], timeout: int = None) -> str:
        """Pipe input_data through a command."""
        return self.run_tool(cmd, timeout=timeout, input_data=input_data)

    def file_lines(self, path: str) -> list[str]:
        """Read a file and return non-empty lines."""
        try:
            return [l.strip() for l in Path(path).read_text().splitlines() if l.strip()]
        except (FileNotFoundError, IOError):
            return []

    def save_lines(self, lines: list[str], path: str):
        """Write lines to a file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("\n".join(lines) + "\n" if lines else "")
        self.state.add_artifact(Path(path).name, path, self.name)

    def save_text(self, text: str, path: str):
        """Write text to a file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text)
        self.state.add_artifact(Path(path).name, path, self.name)

    def add_finding(self, finding_type: str, severity: str, url: str, evidence: str = ""):
        """Add a finding if it's unique."""
        if self.dedup.is_unique_finding(finding_type, url, evidence):
            finding = Finding(
                type=finding_type,
                severity=severity,
                url=url,
                evidence=evidence,
                plugin=self.name
            )
            self.state.add_finding(finding)
            self.log(f"Finding: {severity.upper()} {finding_type} at {url}", "success")

    def count_lines(self, path: str) -> int:
        """Count lines in a file."""
        return len(self.file_lines(path))

    def tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        return shutil.which(tool) is not None

    def progress(self, current: int, total: int, label: str = ""):
        """Print progress update."""
        if total > 0 and (current % max(1, total // 10) == 0 or current == total):
            pct = (current / total) * 100
            self.log(f"Progress: {current}/{total} ({pct:.0f}%) {label}")


def load_plugins() -> dict[str, type[Plugin]]:
    """Discover and load all plugin classes."""
    import importlib
    import pkgutil

    plugins = {}
    plugin_packages = [
        "hunter.plugins.recon",
        "hunter.plugins.vuln",
        "hunter.plugins.intel",
        "hunter.plugins.post",
    ]

    for package_name in plugin_packages:
        try:
            package = importlib.import_module(package_name)
            for _, module_name, _ in pkgutil.iter_modules(package.__path__):
                try:
                    module = importlib.import_module(f"{package_name}.{module_name}")
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and issubclass(attr, Plugin)
                                and attr is not Plugin and attr.name):
                            plugins[attr.name] = attr
                except Exception as e:
                    print(f"  [!] Failed to load {package_name}.{module_name}: {e}")
        except ImportError:
            pass

    return plugins
