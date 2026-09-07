"""Skill generator — agents learn from successful scans and create reusable skills.

UNIQUE feature: Hunter learns patterns that work and auto-applies them.
No other bug bounty tool does this.

How it works:
1. Scan finds SQLi on ?id= param → save as skill
2. Next scan sees ?id= param → auto-apply skill (faster, more accurate)
3. Skills track success_rate and get smarter over time
"""
import json
import time
import hashlib
from pathlib import Path
from typing import Optional


SKILLS_DIR = Path.home() / "Hunter" / "skills"


class Skill:
    """A reusable attack pattern learned from successful scans."""

    def __init__(self, name: str, vuln_type: str, pattern: dict,
                 payloads: list[str], success_rate: float = 0.0,
                 times_applied: int = 0, times_successful: int = 0,
                 severity: str = "high", evidence_patterns: list[str] = None,
                 created_from: str = "", created_at: float = None):
        self.name = name
        self.vuln_type = vuln_type
        self.pattern = pattern  # What to match (e.g., {"param": "id", "type": "numeric"})
        self.payloads = payloads
        self.success_rate = success_rate
        self.times_applied = times_applied
        self.times_successful = times_successful
        self.severity = severity
        self.evidence_patterns = evidence_patterns or []
        self.created_from = created_from
        self.created_at = created_at or time.time()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vuln_type": self.vuln_type,
            "pattern": self.pattern,
            "payloads": self.payloads,
            "success_rate": round(self.success_rate, 3),
            "times_applied": self.times_applied,
            "times_successful": self.times_successful,
            "severity": self.severity,
            "evidence_patterns": self.evidence_patterns,
            "created_from": self.created_from,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Skill":
        return cls(**data)

    def matches(self, url: str, param: str = None, response: str = None) -> bool:
        """Check if this skill matches a given target."""
        from urllib.parse import urlparse, parse_qs

        p = self.pattern

        # Check URL pattern
        if "url_contains" in p:
            if p["url_contains"] not in url:
                return False

        # Check param pattern
        if param and "param" in p:
            if p["param"] != param and p["param"] != "*":
                return False

        # Check param type
        if param and "param_type" in p:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if param in params:
                val = params[param][0] if params[param] else ""
                if p["param_type"] == "numeric" and not val.isdigit():
                    return False
                if p["param_type"] == "email" and "@" not in val:
                    return False

        # Check response pattern
        if response and "response_contains" in p:
            if p["response_contains"] not in response:
                return False

        return True

    def record_result(self, success: bool):
        """Record whether this skill worked on a target."""
        self.times_applied += 1
        if success:
            self.times_successful += 1
        self.success_rate = self.times_successful / self.times_applied if self.times_applied > 0 else 0


class SkillDB:
    """Skill database — stores and retrieves learned skills."""

    def __init__(self, skills_dir: str = None):
        self.skills_dir = Path(skills_dir or SKILLS_DIR)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self._skills: dict[str, Skill] = {}
        self._load_all()

    def _load_all(self):
        """Load all skills from disk."""
        for f in self.skills_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                skill = Skill.from_dict(data)
                self._skills[skill.name] = skill
            except Exception:
                pass

    def save(self, skill: Skill):
        """Save a skill to disk."""
        self._skills[skill.name] = skill
        path = self.skills_dir / f"{skill.name}.json"
        path.write_text(json.dumps(skill.to_dict(), indent=2))

    def get(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def find_matching(self, url: str, param: str = None) -> list[Skill]:
        """Find skills that match a given target."""
        return [s for s in self._skills.values() if s.matches(url, param)]

    def all(self) -> list[Skill]:
        return list(self._skills.values())

    def top_skills(self, n: int = 10) -> list[Skill]:
        """Get top skills by success rate."""
        return sorted(self._skills.values(), key=lambda s: -s.success_rate)[:n]

    def stats(self) -> dict:
        skills = list(self._skills.values())
        return {
            "total": len(skills),
            "avg_success_rate": sum(s.success_rate for s in skills) / len(skills) if skills else 0,
            "total_applied": sum(s.times_applied for s in skills),
            "total_successful": sum(s.times_successful for s in skills),
        }


class SkillGenerator:
    """Generate skills from successful scan findings.
    
    When a scan finds a vulnerability, this class:
    1. Analyzes the finding pattern
    2. Creates a reusable skill
    3. Saves it for future scans
    """

    def __init__(self, db: SkillDB = None):
        self.db = db or SkillDB()

    def learn_from_finding(self, finding_type: str, url: str, param: str,
                           payload: str, evidence: str, severity: str) -> Skill:
        """Create a skill from a successful finding."""
        from urllib.parse import urlparse, parse_qs

        # Analyze the pattern
        pattern = {}
        parsed = urlparse(url)

        # Determine param type
        params = parse_qs(parsed.query)
        if param in params:
            val = params[param][0] if params[param] else ""
            if val.isdigit():
                pattern["param_type"] = "numeric"
            elif "@" in val:
                pattern["param_type"] = "email"
            elif val.startswith("http"):
                pattern["param_type"] = "url"
            else:
                pattern["param_type"] = "string"

        pattern["param"] = param

        # Generate skill name
        name = f"{finding_type}_{pattern.get('param_type', 'any')}_{param}"
        name = hashlib.md5(name.encode()).hexdigest()[:12]

        # Check if skill already exists
        existing = self.db.get(name)
        if existing:
            existing.record_result(True)
            if payload not in existing.payloads:
                existing.payloads.append(payload)
            self.db.save(existing)
            return existing

        # Create new skill
        skill = Skill(
            name=name,
            vuln_type=finding_type,
            pattern=pattern,
            payloads=[payload],
            success_rate=1.0,
            times_applied=1,
            times_successful=1,
            severity=severity,
            evidence_patterns=[evidence[:100]] if evidence else [],
            created_from=url,
        )

        self.db.save(skill)
        return skill

    def get_payloads_for(self, url: str, param: str, vuln_type: str) -> list[str]:
        """Get learned payloads for a target, sorted by success rate."""
        matching = self.db.find_matching(url, param)
        type_matching = [s for s in matching if s.vuln_type == vuln_type]

        # Sort by success rate, get unique payloads
        sorted_skills = sorted(type_matching, key=lambda s: -s.success_rate)
        payloads = []
        seen = set()
        for skill in sorted_skills:
            for p in skill.payloads:
                if p not in seen:
                    payloads.append(p)
                    seen.add(p)
        return payloads

    def auto_apply(self, url: str, param: str) -> list[dict]:
        """Auto-apply all matching skills to a target.
        
        Returns list of attack steps with learned payloads.
        """
        matching = self.db.find_matching(url, param)
        steps = []
        for skill in matching:
            steps.append({
                "skill": skill.name,
                "vuln_type": skill.vuln_type,
                "url": url,
                "param": param,
                "payloads": skill.payloads,
                "success_rate": skill.success_rate,
                "severity": skill.severity,
            })
        return steps

    def generate_from_state(self, state) -> list[Skill]:
        """Generate skills from all findings in a scan state."""
        findings = state.get_findings()
        skills = []

        for f in findings:
            if f.severity in ("critical", "high"):
                # Try to extract param from URL
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(f.url)
                params = parse_qs(parsed.query)

                for param in params:
                    skill = self.learn_from_finding(
                        finding_type=f.type,
                        url=f.url,
                        param=param,
                        payload="",  # Would need to track this
                        evidence=f.evidence,
                        severity=f.severity,
                    )
                    skills.append(skill)

        return skills
