"""Cross-phase deduplication to avoid scanning duplicate URLs/hosts."""
import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class Deduplicator:
    """Smart deduplication for URLs, hosts, and findings."""

    def __init__(self):
        self._seen_urls: set[str] = set()
        self._seen_hosts: set[str] = set()
        self._seen_findings: set[str] = set()

    def url_key(self, url: str) -> str:
        """Generate a normalized key for URL dedup.
        
        Strips tracking params, normalizes path, sorts query params.
        """
        try:
            parsed = urlparse(url.strip())
            # Normalize host
            host = parsed.netloc.lower().rstrip(".")
            # Normalize path
            path = parsed.path.rstrip("/") or "/"
            # Sort and filter query params
            params = parse_qs(parsed.query, keep_blank_values=False)
            # Remove tracking params
            tracking = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                       "utm_content", "fbclid", "gclid", "ref", "_ga", "mc_cid"}
            params = {k: v for k, v in params.items() if k.lower() not in tracking}
            sorted_params = urlencode(sorted(params.items()), doseq=True)
            return f"{host}{path}?{sorted_params}"
        except Exception:
            return url.strip().lower()

    def is_unique_url(self, url: str) -> bool:
        """Check if URL is unique (not seen before)."""
        key = self.url_key(url)
        if key in self._seen_urls:
            return False
        self._seen_urls.add(key)
        return True

    def is_unique_host(self, host: str) -> bool:
        """Check if host is unique."""
        h = host.strip().lower().rstrip(".")
        if h in self._seen_hosts:
            return False
        self._seen_hosts.add(h)
        return True

    def is_unique_finding(self, finding_type: str, url: str, evidence: str = "") -> bool:
        """Check if finding is unique."""
        key = f"{finding_type}:{self.url_key(url)}:{evidence[:100]}"
        h = hashlib.md5(key.encode()).hexdigest()
        if h in self._seen_findings:
            return False
        self._seen_findings.add(h)
        return True

    def dedup_urls(self, urls: list[str]) -> list[str]:
        """Deduplicate a list of URLs, preserving order."""
        result = []
        for url in urls:
            if self.is_unique_url(url):
                result.append(url)
        return result

    def dedup_hosts(self, hosts: list[str]) -> list[str]:
        """Deduplicate a list of hosts."""
        result = []
        for host in hosts:
            if self.is_unique_host(host):
                result.append(host)
        return result

    def filter_urls_by_extension(self, urls: list[str], exclude: list[str] = None) -> list[str]:
        """Filter out URLs with static file extensions."""
        if exclude is None:
            exclude = [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                       ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
                       ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz"]
        result = []
        for url in urls:
            path = urlparse(url).path.lower()
            if not any(path.endswith(ext) for ext in exclude):
                result.append(url)
        return result

    def extract_params(self, urls: list[str]) -> dict[str, list[str]]:
        """Extract unique parameters from URLs, grouped by name."""
        params: dict[str, list[str]] = {}
        for url in urls:
            try:
                parsed = urlparse(url)
                for name, values in parse_qs(parsed.query).items():
                    if name not in params:
                        params[name] = []
                    params[name].extend(values)
            except Exception:
                continue
        return params

    def stats(self) -> dict:
        """Get dedup statistics."""
        return {
            "unique_urls": len(self._seen_urls),
            "unique_hosts": len(self._seen_hosts),
            "unique_findings": len(self._seen_findings)
        }
