"""End-to-end test — verify the full pipeline works."""
import sys
import os
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hunter.core.scanner import Scanner
from hunter.core.config import Config
from hunter.core.state import ScanState, Finding
from hunter.core.dedup import Deduplicator
from hunter.core.resource import ResourceManager
from hunter.core.router import Router
from hunter.core.incremental import IncrementalScanner
from hunter.core.confidence import ConfidenceScorer
from hunter.core.stream import StreamOutput
from hunter.core.parallel import ParallelExecutor
from hunter.plugins import load_plugins


def test_scanner_init():
    """Test Scanner initialization."""
    with tempfile.TemporaryDirectory() as tmp:
        s = Scanner("test.example.com", output_dir=tmp)
        assert s.target == "test.example.com"
        assert s.scan_id is not None
        assert s.output_dir.exists()
        s.state.close()
        print("  ✓ Scanner init")


def test_state_full_cycle():
    """Test complete state lifecycle."""
    with tempfile.TemporaryDirectory() as tmp:
        state = ScanState("test_cycle", tmp)
        state.init_scan("example.com")

        # Add findings
        for i in range(10):
            f = Finding(
                type=["sqli", "xss", "cors"][i % 3],
                severity=["critical", "high", "medium"][i % 3],
                url=f"https://example.com/vuln{i}",
                evidence=f"Evidence for vuln{i}",
                plugin="test"
            )
            state.add_finding(f)

        # State storage
        state.set_state("recon", "subdomains", ["a.example.com", "b.example.com"])
        state.set_state("recon", "live_urls", ["https://a.example.com"])
        state.mark_phase_complete("recon.subdomains")

        # Verify
        assert len(state.get_findings()) == 10
        assert len(state.get_findings(severity="critical")) > 0
        assert state.get_state("recon", "subdomains") == ["a.example.com", "b.example.com"]
        assert state.is_phase_complete("recon.subdomains")

        state.complete_scan()
        summary = state.summary()
        assert summary["status"] == "completed"
        assert summary["total_findings"] == 10
        state.close()
        print("  ✓ State full cycle")


def test_dedup_comprehensive():
    """Test deduplication across URLs, hosts, findings."""
    d = Deduplicator()

    # URL dedup with tracking param removal
    urls = [
        "https://example.com/page?utm_source=test&id=1",
        "https://example.com/page?id=1&utm_source=different",
        "https://example.com/page?id=2",
        "https://example.com/other",
    ]
    deduped = d.dedup_urls(urls)
    assert len(deduped) == 3  # First two are same after removing utm

    # Host dedup
    hosts = ["example.com", "EXAMPLE.COM", "test.com"]
    deduped_hosts = d.dedup_hosts(hosts)
    assert len(deduped_hosts) == 2

    # Finding dedup
    assert d.is_unique_finding("sqli", "https://example.com/vuln", "evidence1")
    assert not d.is_unique_finding("sqli", "https://example.com/vuln", "evidence1")
    assert d.is_unique_finding("xss", "https://example.com/vuln", "evidence2")

    print("  ✓ Dedup comprehensive")


def test_incremental():
    """Test incremental scanning."""
    with tempfile.TemporaryDirectory() as tmp:
        inc = IncrementalScanner("example.com", tmp)

        # First scan
        assert inc.should_rescan()
        inc.update_history("scan1", {
            "subdomains": ["a.example.com", "b.example.com"],
            "urls": ["https://a.example.com", "https://b.example.com"]
        })

        # Check known artifacts
        known = inc.get_known_artifacts()
        assert "a.example.com" in known["subdomains"]
        assert len(known["subdomains"]) == 2

        # Second scan with new items
        new_subs = inc.find_new_items(
            ["a.example.com", "b.example.com", "c.example.com"],
            "subdomains"
        )
        assert new_subs == ["c.example.com"]

        # Diff summary
        diff = inc.get_diff_summary(
            ["a.example.com", "c.example.com"],
            ["https://a.example.com", "https://c.example.com"]
        )
        assert "c.example.com" in diff["new_subdomains"]
        assert "b.example.com" in diff["gone_subdomains"]

        print("  ✓ Incremental scanning")


def test_confidence():
    """Test confidence scoring."""
    scorer = ConfidenceScorer()

    # High confidence
    score1 = scorer.score("sqlmap", "critical", "https://example.com/vuln", "SELECT * FROM users")
    assert score1 >= 80

    # Medium confidence
    score2 = scorer.score("cors", "medium", "https://example.com/api", "")
    assert 50 <= score2 <= 80

    # Low confidence
    score3 = scorer.score("info_disclosure", "low", "https://example.com", "Server: Apache")
    assert score3 < 70

    # Cross-validation bonus
    scorer.score("tool1", "high", "https://example.com/vuln")
    scorer.score("tool2", "high", "https://example.com/vuln")
    cross = scorer.get_cross_validated()
    assert "https://example.com/vuln" in cross

    print("  ✓ Confidence scoring")


def test_stream():
    """Test streaming output."""
    with tempfile.TemporaryDirectory() as tmp:
        stream_path = os.path.join(tmp, "test.jsonl")
        events = []

        with StreamOutput(output_file=stream_path, callback=lambda e: events.append(e)) as stream:
            stream.scan_start("example.com", "test_scan", ["recon.subdomains"])
            stream.finding("sqli", "critical", "https://example.com/vuln", "evidence", "sqlmap", 90)
            stream.progress("recon.subdomains", 50, 100)
            stream.phase_end("recon.subdomains", 5.2, 3)
            stream.scan_end(30.0, 5, {"total_findings": 5})

        assert len(events) == 5
        assert events[0]["type"] == "scan_start"
        assert events[1]["type"] == "finding"
        assert events[1]["data"]["severity"] == "critical"

        # Verify file was written
        assert os.path.exists(stream_path)
        with open(stream_path) as f:
            lines = f.readlines()
        assert len(lines) == 5

        print("  ✓ Streaming output")


def test_parallel_plan():
    """Test parallel execution planning."""
    all_plugins = [
        "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports",
        "recon.url_discovery", "recon.js_analysis", "recon.param_mining",
        "vuln.nuclei", "vuln.sqli", "vuln.xss", "vuln.cors",
        "post.prioritize", "post.report"
    ]

    plan = ParallelExecutor.get_execution_plan(all_plugins)
    assert len(plan) > 0

    # Verify dependencies: dns should be after subdomains
    dns_group = next(i for i, g in enumerate(plan) if "recon.dns" in g)
    sub_group = next(i for i, g in enumerate(plan) if "recon.subdomains" in g)
    assert dns_group > sub_group

    # Verify parallel: sqli and xss should be in same group
    sqli_group = next(i for i, g in enumerate(plan) if "vuln.sqli" in g)
    xss_group = next(i for i, g in enumerate(plan) if "vuln.xss" in g)
    assert sqli_group == xss_group

    print("  ✓ Parallel execution planning")


def test_resource_budget():
    """Test resource budget management."""
    config = Config(threads=30)
    rm = ResourceManager(config)

    budget = rm.get_budget()
    assert budget.threads > 0
    assert budget.threads <= 30

    # Test tool availability
    tools = rm.get_available_tools()
    assert "subfinder" in tools
    assert "nuclei" in tools

    print("  ✓ Resource budget")


def test_router_conditions():
    """Test router conditional execution."""
    with tempfile.TemporaryDirectory() as tmp:
        state = ScanState("router_test", tmp)
        state.init_scan("test.com")

        router = Router()

        # With no params, sqli should be skipped
        order = router.get_execution_order(state, [
            "recon.subdomains", "recon.dns", "recon.http_probe",
            "recon.url_discovery", "recon.param_mining",
            "vuln.sqli", "vuln.nuclei"
        ])
        assert "vuln.sqli" not in order  # No params = skip sqli
        assert "vuln.nuclei" in order    # Always runs

        state.close()
        print("  ✓ Router conditions")


def test_plugin_system():
    """Test plugin loader and instantiation."""
    plugins = load_plugins()

    # Verify all expected plugins exist
    expected = [
        "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports",
        "recon.url_discovery", "recon.js_analysis", "recon.param_mining",
        "vuln.nuclei", "vuln.sqli", "vuln.xss", "vuln.cors",
        "vuln.redirects", "vuln.headers", "vuln.fuzz",
        "intel.tech_detect", "intel.waf_detect", "intel.secrets", "intel.takeover",
        "post.prioritize", "post.report"
    ]

    for name in expected:
        assert name in plugins, f"Missing plugin: {name}"

    # Verify plugin metadata
    for name, cls in plugins.items():
        assert cls.name, f"{name} missing name"
        assert cls.description, f"{name} missing description"
        assert cls.category, f"{name} missing category"

    print(f"  ✓ Plugin system ({len(plugins)} plugins)")


def test_agent_api():
    """Test agent API imports and instantiation."""
    from hunter import Scanner, ScanState, Config
    from hunter.agent.api import HunterAgent, ScanResults

    agent = HunterAgent()
    assert agent.config is not None

    print("  ✓ Agent API")


if __name__ == "__main__":
    print("\n  === HUNTER v3 END-TO-END TESTS ===\n")

    tests = [
        test_scanner_init,
        test_state_full_cycle,
        test_dedup_comprehensive,
        test_incremental,
        test_confidence,
        test_stream,
        test_parallel_plan,
        test_resource_budget,
        test_router_conditions,
        test_plugin_system,
        test_agent_api,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1

    print(f"\n  Results: {passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)
