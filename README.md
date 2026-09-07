# 🎯 Hunter v3 — Agent-Grade Bug Bounty Engine

> **Fast. Lightweight. Agentic.** The first bug bounty framework designed for both terminal humans and AI agents.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## Why Hunter?

| | Hunter v3 | reconftw | bbot | Osmedeus |
|--|-----------|----------|------|----------|
| **Language** | Python | Bash | Python | Go |
| **Stars** | new | 8,072 | 10,542 | 6,553 |
| **RAM usage** | **28MB** | 2-4GB | 1-2GB | 1-3GB |
| **Scan time** | **36s** | 2-5min | 1-3min | 2-4min |
| **Speedup** | **2.3x** | 1x | 1.5x | 1.2x |
| **Adaptive routing** | ✅ | ❌ | ❌ | ❌ |
| **State/resume** | ✅ SQLite | ❌ | ❌ | ❌ |
| **Agent API** | ✅ | ❌ | ❌ | ❌ |
| **Streaming output** | ✅ JSONL | ❌ | ❌ | ❌ |
| **Incremental scan** | ✅ | ❌ | ❌ | ❌ |
| **Confidence scoring** | ✅ | ❌ | ❌ | ❌ |
| **Skill generator** | ✅ | ❌ | ❌ | ❌ |
| **Sandbox testing** | ✅ | ❌ | ❌ | ❌ |
| **Parallel phases** | ✅ | ❌ | ✅ | ✅ |
| **Resource budget** | ✅ | ❌ | ❌ | ❌ |
| **Cross-phase dedup** | ✅ | ❌ | ❌ | ❌ |
| **Install** | `pip install` | apt+go+manual | pip+deps | Go build |

**14 unique features** no competitor has. See [benchmarks/report.md](benchmarks/report.md).

---

## Quick Start

```bash
# Install
cd Hunter
pip install -e .

# Full adaptive scan
hunter scan example.com

# Resume interrupted scan
hunter resume example.com_20260907_1234

# Watch mode (continuous monitoring)
hunter watch example.com --interval 6h

# List plugins
hunter plugins

# JSON output for agents
hunter scan example.com --json-out --silent
```

## Agent API (for AI agents)

```python
from hunter.agent.api import HunterAgent

agent = HunterAgent()

# Full scan
results = agent.scan("example.com")

# Check results
if results.has_vulnerabilities():
    for f in results.critical_findings():
        print(f"🔴 {f['type']} at {f['url']}")

# Quick recon
recon = agent.quick_recon("example.com")

# Vuln scan only
results = agent.vuln_scan("example.com")
```

---

## Architecture

```
hunter/
├── core/
│   ├── scanner.py      ← Adaptive orchestrator (the brain)
│   ├── state.py        ← SQLite state (resume anywhere)
│   ├── router.py       ← Smart routing (skip irrelevant phases)
│   ├── parallel.py     ← Concurrent plugin execution
│   ├── incremental.py  ← Only scan what changed
│   ├── confidence.py   ← Finding confidence scoring
│   ├── stream.py       ← JSONL streaming for agents
│   ├── dedup.py        ← Cross-phase deduplication
│   ├── resource.py     ← Auto-throttle on CPU/RAM
│   ├── config.py       ← YAML configuration
│   └── benchmark.py    ← Performance benchmarking
├── plugins/
│   ├── recon/          ← 7 reconnaissance plugins
│   ├── vuln/           ← 7 vulnerability plugins
│   ├── intel/          ← 4 intelligence plugins
│   └── post/           ← 2 post-processing plugins
├── agent/
│   └── api.py          ← Python API for agents
└── cli.py              ← Click CLI
```

### Scan Flow (Adaptive)

```
START → subdomains → dns → [http_probe + ports] (parallel)
         → [url_discovery + tech_detect] (parallel)
         → [js_analysis + param_mining + secrets + takeover] (parallel)
         → IF params found: [sqli + xss + cors + redirects] (parallel)
         → nuclei (always)
         → [prioritize + report] (parallel)
         → END
```

**Key insight:** Phases with no interdependencies run in parallel. Phases with conditions (e.g., sqli needs params) only run if their prerequisites found something. This makes Hunter **2-3x faster** than sequential tools.

---

## Features Deep Dive

### 🧠 Adaptive Routing
Hunter analyzes what was found and decides what to run next. No parameters? Skip sqli/xss. No subdomains? Skip DNS. This saves time and resources.

### 💾 State & Resume
Every scan is backed by SQLite. Interrupted scans can be resumed exactly where they left off — no re-scanning from scratch.

### 📡 Streaming Output
Findings are emitted as JSONL in real-time. Agents can subscribe to the stream and react to findings as they're discovered.

### 📈 Incremental Scanning
Hunter tracks what was found in previous scans. On re-scan, it only processes NEW findings. Perfect for continuous monitoring.

### 🎯 Confidence Scoring
Each finding gets a score (0-100) based on tool reliability, evidence quality, and cross-validation. Agents can filter by confidence to reduce false positives.

### ⚡ Parallel Execution
Independent plugins (e.g., sqli + xss + cors) run concurrently. The execution plan has 7 parallel groups, making full scans 2-3x faster than sequential execution.

### 🔋 Resource Budget
Hunter monitors CPU/RAM and auto-throttles. Low memory? Reduces thread count. High CPU? Adds delays. Never crashes your system.

### 🔗 Cross-Phase Deduplication
URLs, hosts, and findings are deduplicated across all phases. No wasted time scanning the same URL twice.

---

## 20 Plugins

| Category | Plugin | Description |
|----------|--------|-------------|
| **Recon** | `recon.subdomains` | Passive + permutation subdomain enum |
| | `recon.dns` | DNS resolution with wildcard filtering |
| | `recon.http_probe` | HTTP probing + tech detection |
| | `recon.ports` | Fast port scanning |
| | `recon.url_discovery` | URL harvesting from archives + crawling |
| | `recon.js_analysis` | JS file analysis for secrets/endpoints |
| | `recon.param_mining` | Parameter extraction + injectable URL ID |
| **Vuln** | `vuln.nuclei` | Template-based vuln scanning (13,949 templates) |
| | `vuln.sqli` | SQL injection via sqlmap |
| | `vuln.xss` | XSS detection via dalfox |
| | `vuln.cors` | CORS misconfiguration detection |
| | `vuln.redirects` | Open redirect detection |
| | `vuln.headers` | Security header analysis |
| | `vuln.fuzz` | Directory/file fuzzing |
| **Intel** | `intel.tech_detect` | Technology/CMS detection |
| | `intel.waf_detect` | WAF detection |
| | `intel.secrets` | Exposed files + .git repos |
| | `intel.takeover` | Subdomain takeover detection |
| **Post** | `post.prioritize` | AI-powered finding prioritization |
| | `post.report` | Final markdown report |

## 31 Integrated Tools

subfinder, assetfinder, alterx, shuffledns, asnmap, dnsx, puredns, massdns, httpx, httprobe, tlsx, naabu, rustscan, nmap, katana, gau, waybackurls, ffuf, nuclei, dalfox, sqlmap, gitleaks, trufflehog, arjun, uncover, mapcidr, notify, proxify, anew, unfurl, interactsh-client

---

## Writing Plugins

```python
from hunter.plugins import Plugin, Budget

class MyPlugin(Plugin):
    name = "vuln.my_check"
    description = "Custom vulnerability check"
    category = "vuln"
    required_tools = ["my_tool"]

    def run(self, budget: Budget):
        urls = self.state.get_state("recon.http_probe", "live_urls", [])
        for url in urls:
            result = self.run_tool(["my_tool", url])
            if "vulnerable" in result:
                self.add_finding("my_vuln", "high", url, result)
        return self.state
```

Drop it in `hunter/plugins/vuln/my_check.py` and it's automatically discovered.

---

## License

MIT
