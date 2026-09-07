"""Configuration management."""
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field


DEFAULT_CONFIG = {
    "threads": 25,
    "crawl_depth": 3,
    "max_targets": 100,
    "timeout": 30,
    "aggressive": False,
    "skip_phases": [],
    "wordlist": None,
    "webhook": None,
    "output_format": "json",
    "resource_budget": "auto",
    "hunter_bin": os.path.expanduser("~/Hunter/bin"),
    "wordlist_dir": os.path.expanduser("~/Hunter/wordlists"),
    "nuclei_templates": os.path.expanduser("~/nuclei-templates"),
    "log_level": "info",
}


@dataclass
class Config:
    """Scan configuration."""
    threads: int = 25
    crawl_depth: int = 3
    max_targets: int = 100
    timeout: int = 30
    aggressive: bool = False
    skip_phases: list = field(default_factory=list)
    wordlist: str = None
    webhook: str = None
    output_format: str = "json"
    resource_budget: str = "auto"
    hunter_bin: str = os.path.expanduser("~/Hunter/bin")
    wordlist_dir: str = os.path.expanduser("~/Hunter/wordlists")
    nuclei_templates: str = os.path.expanduser("~/nuclei-templates")
    log_level: str = "info"

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**{**DEFAULT_CONFIG, **data})

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        return cls(**{**DEFAULT_CONFIG, **data})

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    DEFAULT_DISCOVERY_WORDS = [
        "admin", "api", "v1", "v2", "v3", "login", "dashboard", "auth",
        "user", "users", "register", "signup", "settings", "profile",
        "test", "dev", "staging", "demo", "beta", "backup", "bak", "old",
        "config", "secrets", "env", "git", "swagger", "docs", "graphql",
        "robots.txt", "sitemap.xml", ".env", "console", "portal", "internal",
    ]

    def get_wordlist(self, name: str = "common") -> str:
        """Get path to a wordlist, creating a default one if missing."""
        if self.wordlist and Path(self.wordlist).exists():
            return self.wordlist
        wl_path = Path(self.wordlist_dir) / "discovery" / f"{name}.txt"
        if wl_path.exists():
            return str(wl_path)
        try:
            wl_path.parent.mkdir(parents=True, exist_ok=True)
            wl_path.write_text("\n".join(self.DEFAULT_DISCOVERY_WORDS) + "\n")
            return str(wl_path)
        except Exception:
            return None
