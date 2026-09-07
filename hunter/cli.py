"""Click CLI for Hunter v3."""
import click
import json
import sys
from pathlib import Path

from .core.scanner import Scanner
from .core.config import Config


@click.group()
@click.version_option(version="3.0.0", prog_name="hunter")
def cli():
    """Hunter v3 — Agent-Grade Bug Bounty Engine."""
    pass


@cli.command()
@click.argument("target")
@click.option("--threads", "-t", default=25, help="Concurrency")
@click.option("--depth", "-d", default=3, help="Crawl depth")
@click.option("--phases", "-p", default=None, help="Comma-separated phases")
@click.option("--skip", "-s", default=None, help="Comma-separated phases to skip")
@click.option("--aggressive", is_flag=True, help="Aggressive mode")
@click.option("--config", "-c", default=None, help="Config YAML")
@click.option("--output", "-o", default=None, help="Output directory")
@click.option("--json-out", is_flag=True, help="JSON output")
@click.option("--resume", is_flag=True, help="Resume last scan")
def scan(target, threads, depth, phases, skip, aggressive, config, output, json_out, resume):
    """Run a full adaptive scan."""
    cfg = Config.from_yaml(config) if config else Config()
    cfg.threads = threads
    cfg.crawl_depth = depth
    cfg.aggressive = aggressive
    if skip:
        cfg.skip_phases = [s.strip() for s in skip.split(",")]
    phase_list = [p.strip() for p in phases.split(",")] if phases else None
    scanner = Scanner(target, config=cfg, output_dir=output)
    state = scanner.scan(phases=phase_list, resume=resume)
    if json_out:
        click.echo(json.dumps({"summary": state.summary(), "findings": [f.__dict__ for f in state.get_findings()]}, indent=2))
    state.close()


@cli.command()
@click.argument("scan_id")
@click.option("--json-out", is_flag=True)
def resume(scan_id, json_out):
    """Resume an interrupted scan."""
    try:
        scanner = Scanner.resume_scan(scan_id)
        state = scanner.resume()
        if json_out:
            click.echo(json.dumps({"summary": state.summary(), "findings": [f.__dict__ for f in state.get_findings()]}, indent=2))
        state.close()
    except FileNotFoundError:
        click.echo(f"  [-] Scan '{scan_id}' not found.", err=True)
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--interval", "-i", default="6h")
@click.option("--webhook", "-w", default=None)
@click.option("--threads", "-t", default=25)
def watch(target, interval, webhook, threads):
    """Continuously monitor target."""
    import time
    def parse_interval(s):
        s = s.strip().lower()
        if s.endswith("h"): return int(s[:-1]) * 3600
        if s.endswith("d"): return int(s[:-1]) * 86400
        if s.endswith("m"): return int(s[:-1]) * 60
        return int(s)
    interval_sec = parse_interval(interval)
    cfg = Config(threads=threads, webhook=webhook)
    click.echo(f"  [hunter] Watching {target} every {interval}")
    while True:
        scanner = Scanner(target, config=cfg)
        state = scanner.scan()
        state.close()
        click.echo(f"  [hunter] Next scan in {interval}")
        time.sleep(interval_sec)


@cli.command()
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "text"]), default="text")
def plugins(fmt):
    """List available plugins."""
    from .plugins import load_plugins
    loaded = load_plugins()
    if fmt == "json":
        click.echo(json.dumps([{"name": n, "description": p.description} for n, p in loaded.items()], indent=2))
    else:
        cats = {}
        for name, p in loaded.items():
            cats.setdefault(p.category, []).append((name, p.description))
        for cat, items in sorted(cats.items()):
            click.echo(f"\n  {cat.upper()}")
            for name, desc in items:
                click.echo(f"    {name:30s} {desc}")


@cli.command()
@click.argument("scan_id", required=False)
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "text"]), default="text")
def status(scan_id, fmt):
    """Show scan status or list scans."""
    from .core.state import ScanState
    results_dir = Path.home() / "Hunter" / "results"
    if scan_id:
        matches = list(results_dir.rglob(f"*/{scan_id}/state.db"))
        if not matches:
            click.echo(f"  [-] Scan '{scan_id}' not found.")
            return
        state = ScanState(scan_id, str(matches[0].parent))
        s = state.summary()
        state.close()
        if fmt == "json":
            click.echo(json.dumps(s, indent=2))
        else:
            click.echo(f"\n  Scan: {scan_id}\n  Target: {s['target']}\n  Status: {s['status']}\n  Findings: {s['total_findings']}")
    else:
        if not results_dir.exists():
            click.echo("  No scans found.")
            return
        dbs = list(results_dir.rglob("state.db"))
        for db in dbs[-10:]:
            sid = db.parent.name
            state = ScanState(sid, str(db.parent))
            s = state.summary()
            state.close()
            icon = {"completed": "✓", "running": "●", "interrupted": "✗"}.get(s["status"], "?")
            click.echo(f"  {icon} {s['scan_id']:40s} {s['target']:30s} findings={s['total_findings']}")


@cli.command()
@click.argument("target")
@click.option("--json-out", is_flag=True)
def plan(target, json_out):
    """Generate pre-computed attack plan."""
    from .agent.api import HunterAgent
    agent = HunterAgent()
    click.echo(f"  [hunter] Generating attack plan for {target}...")
    steps = agent.get_attack_plan(target)
    if json_out:
        click.echo(json.dumps(steps, indent=2))
    else:
        click.echo(f"\n  Attack Plan: {len(steps)} steps\n")
        for i, step in enumerate(steps[:30], 1):
            sev = step.get("severity", "?")
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
            click.echo(f"  {i:3d}. {icon} {step['action']:25s} {step['target'][:60]}")


@cli.command()
@click.argument("vuln_type", required=False)
def payloads(vuln_type):
    """Show pre-built attack payloads."""
    from .core.payloads import Payloads
    if vuln_type:
        items = Payloads.get(vuln_type)
        if not items:
            click.echo(f"  Unknown type: {vuln_type}. Available: {', '.join(Payloads.all_types())}")
            return
        click.echo(f"\n  {vuln_type.upper()} Payloads ({len(items)}):\n")
        for p in items:
            click.echo(f"    {p}")
    else:
        click.echo("\n  Available payload types:\n")
        for t in Payloads.all_types():
            click.echo(f"    {t:12s} ({len(Payloads.get(t))} payloads)")
        click.echo("\n  Usage: hunter payloads sqli")


@cli.command()
@click.argument("target")
@click.option("--compact", is_flag=True, help="Minimal token output")
@click.option("--json-out", is_flag=True, help="JSON output")
def agent(target, compact, json_out):
    """Agent-optimized scan with minimal token output."""
    from .agent.api import HunterAgent
    a = HunterAgent()
    results = a.scan(target)
    if compact:
        click.echo(results.to_one_line())
    elif json_out:
        click.echo(results.to_json(compact=True))
    else:
        click.echo(f"\n  Target: {target}")
        click.echo(f"  Findings: {len(results.findings)}")
        click.echo(f"  Critical: {len(results.critical_findings())}")
        click.echo(f"  High: {len(results.high_findings())}")
        actions = results.action_items()
        if actions:
            click.echo(f"\n  Action Items ({len(actions)}):\n")
            for act in actions[:20]:
                click.echo(f"    {act}")


@cli.command()
@click.option("--list", "list_skills", is_flag=True)
@click.option("--top", default=10)
@click.option("--json-out", is_flag=True)
def skills(list_skills, top, json_out):
    """Manage learned attack skills."""
    from .core.skills import SkillDB
    db = SkillDB()
    if json_out:
        click.echo(json.dumps([s.to_dict() for s in db.all()], indent=2))
        return
    all_skills = db.all()
    if not all_skills:
        click.echo("  No skills learned yet. Run scans to build skills.")
        return
    click.echo(f"\n  Skills ({len(all_skills)} total):\n")
    for skill in db.top_skills(top):
        rate = f"{skill.success_rate*100:.0f}%"
        click.echo(f"  {skill.name:20s} {skill.vuln_type:12s} rate={rate:>4s} applied={skill.times_applied:4d} sev={skill.severity}")
    stats = db.stats()
    click.echo(f"\n  Total applied: {stats['total_applied']} | Success rate: {stats['avg_success_rate']*100:.1f}%")


@cli.command()
@click.argument("vuln_type", required=False)
@click.option("--test-all", is_flag=True)
def sandbox(vuln_type, test_all):
    """Test payloads in the local sandbox."""
    from .core.sandbox import Sandbox
    from .core.payloads import Payloads
    with Sandbox() as sb:
        click.echo(f"  Sandbox running at {sb.base_url}")
        if test_all:
            types = ["sqli", "xss", "redirect", "lfi", "ssti", "ssrf", "cors", "idor"]
            for vt in types:
                result = sb.test(vt, {"id": "' OR 1=1--"} if vt == "sqli" else {"q": "<script>alert(1)</script>"})
                icon = "✓" if result["vulnerable"] else "✗"
                click.echo(f"    {icon} {vt:12s} vulnerable={result['vulnerable']} evidence={result.get('evidence', '')}")
        elif vuln_type:
            items = Payloads.get(vuln_type)
            if items:
                click.echo(f"\n  Testing {len(items)} {vuln_type} payloads:\n")
                for p in items[:10]:
                    param = "id" if vuln_type == "sqli" else "q"
                    result = sb.test(vuln_type, {param: p})
                    icon = "✓" if result["vulnerable"] else "✗"
                    click.echo(f"    {icon} {p[:60]}")
            else:
                click.echo(f"  Unknown type: {vuln_type}")
        else:
            click.echo("  Usage: hunter sandbox sqli\n         hunter sandbox --test-all")


@cli.command()
@click.argument("url", required=False)
@click.option("--method", "method", default="GET")
@click.option("--header", "-H", multiple=True)
@click.option("--body", "-d", default=None)
@click.option("--raw", default=None)
@click.option("--json-out", is_flag=True)
def repeater(url, method, header, body, raw, json_out):
    """Send HTTP requests — like Burp Repeater."""
    from .core.repeater import Repeater
    r = Repeater()
    headers = {}
    for h in header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if raw:
        resp = r.send_raw(raw)
    elif url:
        resp = r.send(method, url, headers or None, body)
    else:
        click.echo("  Usage: hunter repeater GET https://example.com")
        return
    if json_out:
        click.echo(json.dumps(resp.to_dict(), indent=2))
    else:
        click.echo(f"\n  {resp.status} {resp.url}")
        click.echo(f"  Size: {resp.size} bytes | Time: {resp.time:.3f}s")
        click.echo(f"\n  Response:\n")
        click.echo(resp.body[:2000])


@cli.command()
@click.argument("tokens_file", required=False)
@click.option("--stdin", is_flag=True)
@click.option("--json-out", is_flag=True)
def sequencer(tokens_file, stdin, json_out):
    """Analyze token randomness — like Burp Sequencer."""
    from .core.sequencer import Sequencer
    tokens = []
    if stdin:
        tokens = [l.strip() for l in sys.stdin if l.strip()]
    elif tokens_file:
        with open(tokens_file) as f:
            tokens = [l.strip() for l in f if l.strip()]
    else:
        click.echo("  Usage: hunter sequencer tokens.txt")
        return
    s = Sequencer()
    result = s.analyze(tokens)
    if json_out:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"\n  Token Analysis ({result['count']} tokens):")
        click.echo(f"  {'='*40}")
        click.echo(f"  Length:     {result['min_length']}-{result['max_length']} (avg {result['avg_length']})")
        click.echo(f"  Unique:     {result['unique_count']}/{result['count']} ({result['uniqueness_ratio']:.1%})")
        click.echo(f"  Entropy:    {result['entropy_per_char']:.3f} bits/char")
        click.echo(f"  Total:      {result['total_entropy']:.2f} bits")
        click.echo(f"  Verdict:    {result['verdict']}")
        if result.get('issues'):
            click.echo(f"\n  Issues:")
            for issue in result['issues']:
                click.echo(f"    ⚠ {issue}")


@cli.command()
@click.argument("data", required=False)
@click.option("--encode", "enc", default=None)
@click.option("--decode", "dec", default=None)
@click.option("--hash", "hash_algo", default=None)
@click.option("--transform", default=None)
@click.option("--detect", is_flag=True)
@click.option("--jwt", is_flag=True)
@click.option("--all", "all_enc", is_flag=True)
def decoder(data, enc, dec, hash_algo, transform, detect, jwt, all_enc):
    """Encode/decode data — like Burp Decoder."""
    from .core.decoder import Decoder
    if not data:
        data = sys.stdin.read().strip()
    if not data:
        click.echo("  Usage: hunter decoder 'hello' --encode base64")
        return
    d = Decoder()
    if jwt:
        click.echo(json.dumps(d.jwt_decode(data), indent=2))
    elif detect:
        possible = d.detect(data)
        click.echo(f"  Detected: {', '.join(possible) if possible else 'Unknown'}")
    elif all_enc:
        click.echo(f"\n  Encodings:")
        for k, v in d.all_encode(data).items():
            click.echo(f"    {k:12s} {v}")
        click.echo(f"\n  Hashes:")
        for k, v in d.all_hash(data).items():
            click.echo(f"    {k:12s} {v}")
    elif enc:
        click.echo(d.encode(data, enc))
    elif dec:
        click.echo(d.decode(data, dec))
    elif hash_algo:
        click.echo(d.hash(data, hash_algo))
    elif transform:
        click.echo(d.transform(data, transform))
    else:
        click.echo(f"  Encodings: {', '.join(d.ENCODINGS)}")
        click.echo(f"  Hashes:    {', '.join(d.HASHES)}")
        click.echo(f"  Transforms:{', '.join(d.TRANSFORMS)}")
