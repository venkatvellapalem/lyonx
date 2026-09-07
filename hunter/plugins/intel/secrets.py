"""Secret and exposed file scanning."""
from .. import Plugin, Budget


class SecretsPlugin(Plugin):
    name = "intel.secrets"
    description = "Exposed files, .git repos, and credential scanning"
    category = "intel"

    SENSITIVE_PATHS = [
        ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
        ".htaccess", ".htpasswd", "wp-config.php", "config.php",
        "settings.py", "database.yml", "secrets.yml", "credentials",
        ".aws/credentials", ".ssh/id_rsa", "docker-compose.yml",
        ".svn/entries", "web.config", "phpinfo.php", "info.php",
        ".DS_Store", "Thumbs.db", "backup.zip", "backup.tar.gz",
        "db.sql", "dump.sql", ".bash_history", ".npmrc",
        "package.json", "composer.json", "Gemfile",
    ]

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        all_urls = self.state.get_state("recon.url_discovery", "all_urls", [])
        if not live_urls:
            return self.state

        self.log("Scanning for exposed files and secrets...")

        exposed = []
        git_exposed = []

        # Check sensitive paths on live hosts
        hosts = list(set([u.rstrip("/") for u in live_urls[:30]]))

        for host in hosts:
            for path in self.SENSITIVE_PATHS:
                url = f"{host}/{path}"
                out = self.run_tool([
                    "curl", "-sI", "-L", "--max-time", "5", url
                ], timeout=10)

                if not out:
                    continue

                first_line = out.splitlines()[0] if out.splitlines() else ""
                if "200 OK" in first_line:
                    exposed.append(url)
                    if ".git" in path:
                        git_exposed.append(url)
                        self.add_finding("git_exposure", "critical", url, "Exposed .git directory")
                    elif ".env" in path:
                        self.add_finding("env_exposure", "critical", url, "Exposed .env file")
                    elif any(p in path for p in [".htpasswd", "wp-config", "config.php", "database.yml"]):
                        self.add_finding("config_exposure", "high", url, f"Exposed: {path}")

        # Scan existing URLs for sensitive patterns
        import re
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
