"""Secret and exposed file scanning."""
import urllib.request
import re
from .. import Plugin, Budget


class SecretsPlugin(Plugin):
    name = "intel.secrets"
    description = "Exposed files, .git repos, and credential scanning"
    category = "intel"

    # Specific fingerprint indicators to prevent SPA false positives
    PATH_INDICATORS = {
        ".git/config": ["[core]", "repositoryformatversion"],
        ".git/HEAD": ["ref: refs/heads/"],
        ".env": ["DB_", "APP_", "SECRET", "KEY=", "API_", "PASSWORD="],
        ".env.local": ["DB_", "APP_", "SECRET", "KEY=", "API_"],
        ".env.production": ["DB_", "APP_", "SECRET", "KEY=", "API_"],
        ".htaccess": ["RewriteEngine", "Deny from", "AuthType"],
        ".htpasswd": [":$apr1$", ":{SHA}", ":$2y$"],
        "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
        "config.php": ["<?php", "$config", "database"],
        "settings.py": ["DATABASES", "SECRET_KEY", "INSTALLED_APPS"],
        "database.yml": ["development:", "production:", "adapter:"],
        "secrets.yml": ["production:", "secret_key_base:"],
        ".aws/credentials": ["aws_access_key_id", "aws_secret_access_key"],
        ".ssh/id_rsa": ["-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"],
        "docker-compose.yml": ["version:", "services:", "image:"],
        ".svn/entries": ["dir\n", "svn:"],
        "web.config": ["<configuration>", "<system.webServer>"],
        "phpinfo.php": ["phpinfo()", "PHP Version"],
        "info.php": ["phpinfo()", "PHP Version"],
        ".DS_Store": ["Bud1"],
        ".bash_history": ["cd ", "ls", "sudo ", "ssh "],
        ".npmrc": ["_authToken", "//registry."],
        "package.json": ["\"name\":", "\"version\":", "\"dependencies\":"],
    }

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        all_urls = self.state.get_state("recon.url_discovery", "all_urls", [])
        if not live_urls:
            return self.state

        self.log("Scanning for exposed files and secrets (concurrent + false-positive verified)...")

        exposed = []
        git_exposed = []
        hosts = list(set([u.rstrip("/") for u in live_urls[:20]]))

        tasks = []
        for host in hosts:
            for path, indicators in self.PATH_INDICATORS.items():
                tasks.append((host, path, indicators))

        def probe_path(item):
            host, path, indicators = item
            url = f"{host}/{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Hunter/3.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        body = resp.read(2048).decode("utf-8", errors="ignore")
                        # Skip generic HTML error pages unless specifically targeting package.json/phpinfo
                        if "<html" in body.lower() and "<!doctype html" in body.lower() and not any(p in path for p in ["phpinfo", "package.json"]):
                            return None
                        # Verify against content indicators
                        if any(ind.lower() in body.lower() for ind in indicators):
                            return (url, path, body[:150])
            except Exception:
                pass
            return None

        # Run probes concurrently with 20 workers
        results = self.probe_urls_concurrent(tasks, probe_path, max_workers=20)

        for res in results:
            if not res:
                continue
            url, path, snippet = res
            exposed.append(url)
            if ".git" in path:
                git_exposed.append(url)
                self.add_finding("git_exposure", "critical", url, f"Verified .git content: {snippet}")
            elif ".env" in path:
                self.add_finding("env_exposure", "critical", url, f"Verified .env content: {snippet}")
            elif any(p in path for p in [".htpasswd", "wp-config", "config.php", "database.yml"]):
                self.add_finding("config_exposure", "high", url, f"Verified sensitive config: {snippet}")
            else:
                self.add_finding("file_exposure", "medium", url, f"Exposed: {path}")

        # Scan existing URLs for sensitive patterns
        sensitive_pattern = re.compile(
            r'\.env|\.git|\.svn|\.htaccess|\.htpasswd|wp-config|config\.php|'
            r'settings\.py|database\.yml|secrets\.yml|credentials|\.aws|\.ssh|'
            r'\.docker|backup\.|dump\.sql|db\.sql',
            re.I
        )
        sensitive_urls = [u for u in all_urls if sensitive_pattern.search(u)]

        all_exposed = sorted(set(exposed + sensitive_urls))
        self.save_lines(all_exposed, str(self.output_dir / "exposed_files.txt"))
        self.save_lines(git_exposed, str(self.output_dir / "git_exposed.txt"))

        self.state.set_state(self.name, "exposed", all_exposed)
        self.state.set_state(self.name, "git_exposed", git_exposed)
        self.log(f"Exposed files: {len(all_exposed)} | .git: {len(git_exposed)}")
        return self.state
