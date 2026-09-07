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
    """Hunter v3 — Agent-Grade Bug Bounty Engine.
    
    Adaptive scanning with smart routing, state management, and agent API.
    """
    pass


@cli.command()
@click.argument("target")
@click.option("--threads", "-t", default=25, help="Concurrency level")
@click.option("--depth", "-d", default=3, help="Crawl depth")
@click.option("--adaptive/--all", default=True, help="Adaptive mode (skip irrelevant phases)")
@click.option("--phases", "-p", default=None, help="Comma-separated phases to run")
@click.option("--skip", "-s", default=None, help="Comma-separated phases to skip")
@click.option("--aggressive", is_flag=True, help="Aggressive scanning mode")
@click.option("--config", "-c", default=None, help="Config YAML file")
@click.option("--output", "-o", default=None, help="Output directory")
@click.option("--json-out", is_flag=True, help="JSON output to stdout")
@click.option("--silent", is_flag=True, help="Minimal output")
def scan(target, threads, depth, adaptive, phases, skip, aggressive, config, output, json_out, silent):
    """Run a full adaptive scan against TARGET."""
    cfg = Config.from_yaml(config) if config else Config()
    cfg.threads = threads
    cfg.crawl_depth = depth
    cfg.aggressive = aggressive
    if skip:
        cfg.skip_phases = [s.strip() for s in skip.split(",")]

    phase_list = [p.strip() for p in phases.split(",")] if phases else None

    scanner = Scanner(target, config=cfg, output_dir=output)
    state = scanner.scan(phases=phase_list)

    if json_out:
        summary = state.summary()
        findings = [f.__dict__ for f in state.get_findings()]
        output_data = {"summary": summary, "findings": findings}
        click.echo(json.dumps(output_data, indent=2))
    
    state.close()


@cli.command()
@click.argument("scan_id")
@click.option("--json-out", is_flag=True, help="JSON output")
def resume(scan_id, json_out):
    """Resume an interrupted scan."""
    try:
        scanner = Scanner.resume_scan(scan_id)
        state = scanner.resume()

        if json_out:
            summary = state.summary()
            findings = [f.__dict__ for f in state.get_findings()]
            click.echo(json.dumps({"summary": summary, "findings": findings}, indent=2))
        
        state.close()
    except FileNotFoundError:
        click.echo(f"  [-] Scan '{scan_id}' not found.", err=True)
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--interval", "-i", default="6h", help="Monitoring interval (e.g. 6h, 1d)")
@click.option("--webhook", "-w", default=None, help="Webhook URL for notifications")
@click.option("--threads", "-t", default=25, help="Concurrency level")
def watch(target, interval, webhook, threads):
    """Continuously monitor TARGET for changes."""
    import time
    
    def parse_interval(s):
        s = s.strip().lower()
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        elif s.endswith("d"):
            return int(s[:-1]) * 86400
        elif s.endswith("m"):
            return int(s[:-1]) * 60
        return int(s)
    
    interval_sec = parse_interval(interval)
    cfg = Config(threads=threads, webhook=webhook)
    scan_num = 0
    
    click.echo(f"  [hunter] Watching {target} every {interval}")
    if webhook:
        click.echo(f"  [hunter] Webhook: {webhook}")
    
    while True:
        scan_num += 1
        click.echo(f"\n  [hunter] Watch scan #{scan_num} starting...")
        
        scanner = Scanner(target, config=cfg)
        state = scanner.scan()
        summary = state.summary()
        
        if summary["total_findings"] > 0:
            click.echo(f"  [hunter] ⚠ {summary['total_findings']} findings!")
            if webhook:
                _post_webhook(webhook, summary, state.get_findings())
        
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
        info = [{"name": n, "description": p.description, "category": p.category}
                for n, p in loaded.items()]
        click.echo(json.dumps(info, indent=2))
    else:
        categories = {}
        for name, plugin in loaded.items():
            cat = plugin.category or "other"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((name, plugin.description))
        
        for cat, items in sorted(categories.items()):
            click.echo(f"\n  {cat.upper()}")
            for name, desc in items:
                click.echo(f"    {name:30s} {desc}")


@cli.command()
@click.argument("scan_id", required=False)
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "text", "md"]), default="text")
def status(scan_id, fmt):
    """Show scan status or list all scans."""
    results_dir = Path.home() / "Hunter" / "results"
    
    if scan_id:
        # Show specific scan
        matches = list(results_dir.rglob(f"*/{scan_id}/state.db"))
        if not matches:
            click.echo(f"  [-] Scan '{scan_id}' not found.")
            return
        state = ScanState(scan_id, str(matches[0].parent))
        summary = state.summary()
        state.close()
        
        if fmt == "json":
            click.echo(json.dumps(summary, indent=2))
        else:
            click.echo(f"\n  Scan: {scan_id}")
            click.echo(f"  Target: {summary['target']}")
            click.echo(f"  Status: {summary['status']}")
            click.echo(f"  Findings: {summary['total_findings']}")
            for sev, cnt in summary['findings'].items():
                click.echo(f"    {sev}: {cnt}")
            click.echo(f"  Phases: {', '.join(summary['completed_phases'])}")
    else:
        # List all scans
        if not results_dir.exists():
            click.echo("  No scans found.")
            return
        dbs = list(results_dir.rglob("state.db"))
        if not dbs:
            click.echo("  No scans found.")
            return
        for db in dbs[-10:]:  # Last 10
            scan_dir = db.parent
            sid = scan_dir.name
            state = ScanState(sid, str(scan_dir))
            s = state.summary()
            state.close()
            status_icon = {"completed": "✓", "running": "●", "interrupted": "✗"}.get(s["status"], "?")
            click.echo(f"  {status_icon} {s['scan_id']:40s} {s['target']:30s} findings={s['total_findings']}")


def _post_webhook(url, summary, findings):
    """POST results to webhook."""
    import subprocess
    payload = json.dumps({"summary": summary, "findings_count": len(findings)})
    try:
        subprocess.run(
            ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
             "-d", payload, url],
            capture_output=True, timeout=10
        )
    except Exception:
        pass


@cli.command()
@click.argument("target")
@click.option("--json-out", is_flag=True, help="JSON output")
def plan(target, json_out):
    """Generate pre-computed attack plan for TARGET."""
    from .agent.api import HunterAgent
    
    agent = HunterAgent()
    click.echo(f"  [hunter] Generating attack plan for {target}...")
    steps = agent.get_attack_plan(target)
    
    if json_out:
        click.echo(json.dumps(steps, indent=2))
    else:
        click.echo(f"\n  Attack Plan: {len(steps)} steps\n")
        for i, step in enumerate(steps[:30], 1):
            sev = step.get('severity', '?')
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(sev, '⚪')
            click.echo(f"  {i:3d}. {icon} {step['action']:25s} {step['target'][:60]}")
            if step.get('param'):
                click.echo(f"       param={step['param']} payloads={len(step.get('payloads', []))}")
        if len(steps) > 30:
            click.echo(f"\n  ... and {len(steps) - 30} more steps")


@cli.command()
@click.argument("vuln_type", required=False)
def payloads(vuln_type):
    """Show pre-built attack payloads."""
    from .core.payloads import Payloads
    
    if vuln_type:
        items = Payloads.get(vuln_type)
        if not items:
            click.echo(f"  Unknown type: {vuln_type}")
            click.echo(f"  Available: {', '.join(Payloads.all_types())}")
            return
        click.echo(f"\n  {vuln_type.upper()} Payloads ({len(items)}):\n")
        for p in items:
            click.echo(f"    {p}")
    else:
        click.echo("\n  Available payload types:\n")
        for t in Payloads.all_types():
            items = Payloads.get(t)
            click.echo(f"    {t:12s} ({len(items)} payloads)")
        click.echo("\n  Usage: hunter payloads sqli")


@cli.command()
@click.argument("target")
@click.option("--compact", is_flag=True, help="Minimal token output")
@click.option("--json-out", is_flag=True, help="JSON output")
def agent(target, compact, json_out):
    """Agent-optimized scan with minimal token output."""
    from .agent.api import HunterAgent
    from .core.token_efficient import TokenEfficient
    
    agent = HunterAgent()
    results = agent.scan(target)
    
    if compact:
        click.echo(results.to_one_line())
    elif json_out:
        click.echo(results.to_json(compact=True))
    else:
        # Show summary + action items
        click.echo(f"\n  Target: {target}")
        click.echo(f"  Findings: {len(results.findings)}")
        click.echo(f"  Critical: {len(results.critical_findings())}")
        click.echo(f"  High: {len(results.high_findings())}")
        
        actions = results.action_items()
        if actions:
            click.echo(f"\n  Action Items ({len(actions)}):\n")
            for a in actions[:20]:
                click.echo(f"    {a}")
