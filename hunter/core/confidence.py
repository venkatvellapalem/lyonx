"""Confidence scoring for findings — reduces false positives.

UNIQUE feature: Each finding gets a confidence score (0-100)
based on multiple factors. Agents can filter by confidence.
"""


class ConfidenceScorer:
    """Score findings by confidence to reduce false positives.
    
    Factors:
        - Tool reliability (nuclei high, sqlmap high, manual medium)
        - Evidence quality (full evidence > partial > no evidence)
        - Cross-validation (found by multiple tools = higher confidence)
        - Context (parameter present, tech stack match)
    """

    # Base confidence by tool
    TOOL_CONFIDENCE = {
        "nuclei": 85,
        "sqlmap": 90,
        "dalfox": 75,
        "gitleaks": 95,
        "trufflehog": 90,
        "nuclei_js": 80,
        "cors": 70,
        "open_redirect": 75,
        "subdomain_takeover": 80,
        "git_exposure": 95,
        "env_exposure": 95,
        "config_exposure": 90,
        "secret_exposure": 85,
        "info_disclosure": 60,
        "manual": 50,
    }

    # Severity multipliers
    SEVERITY_MULTIPLIER = {
        "critical": 1.1,
        "high": 1.0,
        "medium": 0.9,
        "low": 0.8,
        "info": 0.7,
    }

    def __init__(self):
        self._tool_findings: dict[str, set[str]] = {}  # tool -> set of URLs

    def score(self, finding_type: str, severity: str, url: str,
              evidence: str = "", tools_found_by: list[str] = None) -> int:
        """Calculate confidence score for a finding.
        
        Returns:
            Score from 0-100
        """
        # Base score from tool
        base = self.TOOL_CONFIDENCE.get(finding_type, 50)

        # Severity adjustment
        multiplier = self.SEVERITY_MULTIPLIER.get(severity, 0.8)
        score = base * multiplier

        # Evidence quality bonus
        if evidence and len(evidence) > 100:
            score += 5
        if evidence and len(evidence) > 500:
            score += 5

        # Cross-validation bonus (found by multiple tools)
        if tools_found_by and len(tools_found_by) > 1:
            score += min(10, len(tools_found_by) * 3)

        # Track for cross-validation
        self._tool_findings.setdefault(finding_type, set()).add(url)

        return min(100, max(0, int(score)))

    def get_cross_validated(self) -> dict[str, list[str]]:
        """Find URLs found by multiple tools."""
        url_tools: dict[str, set[str]] = {}
        for tool, urls in self._tool_findings.items():
            for url in urls:
                url_tools.setdefault(url, set()).add(tool)
        return {url: sorted(tools) for url, tools in url_tools.items() if len(tools) > 1}

    def filter_by_confidence(self, findings: list[dict], min_confidence: int = 50) -> list[dict]:
        """Filter findings by minimum confidence score."""
        scored = []
        for f in findings:
            conf = self.score(
                f.get("type", ""),
                f.get("severity", ""),
                f.get("url", ""),
                f.get("evidence", "")
            )
            f["confidence"] = conf
            if conf >= min_confidence:
                scored.append(f)
        return sorted(scored, key=lambda x: -x["confidence"])
