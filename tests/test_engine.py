"""Minimal self-checks for Hunter core."""
import sys
import os

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_state():
    from hunter.core.state import ScanState, Finding
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmp:
        state = ScanState("test_scan", tmp)
        state.init_scan("example.com")

        # Test findings
        f = Finding(type="test", severity="high", url="https://example.com/vuln")
        state.add_finding(f)
        findings = state.get_findings()
        assert len(findings) == 1
        assert findings[0].type == "test"

        # Test state storage
        state.set_state("test_phase", "key1", ["a", "b", "c"])
        val = state.get_state("test_phase", "key1")
        assert val == ["a", "b", "c"]

        # Test phase completion
        state.mark_phase_complete("test_phase")
        assert state.is_phase_complete("test_phase")
        assert not state.is_phase_complete("other_phase")

        state.complete_scan()
        summary = state.summary()
        assert summary["status"] == "completed"
        assert summary["total_findings"] == 1
        state.close()


def test_dedup():
    from hunter.core.dedup import Deduplicator

    d = Deduplicator()
    assert d.is_unique_url("https://example.com/page")
    assert not d.is_unique_url("https://example.com/page")
    assert d.is_unique_url("https://example.com/other")

    urls = [
        "https://example.com/page?utm_source=test&a=1",
        "https://example.com/page?a=1&utm_source=different",
    ]
    deduped = d.dedup_urls(urls)
    assert len(deduped) == 1  # Same after removing tracking params


def test_config():
    from hunter.core.config import Config

    c = Config(threads=50, aggressive=True)
    assert c.threads == 50
    assert c.aggressive is True

    d = c.to_dict()
    assert d["threads"] == 50


def test_resource():
    from hunter.core.resource import ResourceManager, Budget
    from hunter.core.config import Config

    rm = ResourceManager(Config())
    budget = rm.get_budget()
    assert isinstance(budget, Budget)
    assert budget.threads > 0


def test_router():
    from hunter.core.router import Router

    r = Router(skip_phases=["vuln.fuzz"])
    assert r.should_skip("vuln.fuzz")
    assert not r.should_skip("vuln.nuclei")


def test_plugin_loader():
    from hunter.plugins import load_plugins

    plugins = load_plugins()
    assert len(plugins) > 0
    assert "recon.subdomains" in plugins
    assert "vuln.nuclei" in plugins


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
