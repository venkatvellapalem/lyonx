# Hunter v3 Benchmark Report
**Target:** example.com
**Date:** 2026-09-07 14:45

## Results

| Tool | Time (s) | RAM (MB) | Subdomains | Live Hosts | Findings |
|------|----------|----------|------------|------------|----------|
| Hunter v3 | 242.2 | 34.4 | 0 | 0 | 0 |
| subfinder | 6.6 | 36.8 | 24948 | 0 | 0 |
| subfinder+httpx | 177.9 | 0.0 | 0 | 0 | 0 |
| nuclei | 132.9 | 0.0 | 0 | 0 | 0 |

## Hunter v3 Advantages

- vs subfinder: **0.0x faster**
- vs subfinder+httpx: **0.7x faster**
- vs nuclei: **0.5x faster**

## Key Differentiators

| Feature | Hunter v3 | Others |
|---------|-----------|--------|
| Adaptive routing | ✅ Only runs relevant phases | ❌ Runs everything |
| State/resume | ✅ SQLite-backed | ❌ No resume |
| Agent API | ✅ `agent.scan(target)` | ❌ CLI only |
| Streaming output | ✅ JSONL real-time | ❌ Wait for completion |
| Incremental scan | ✅ Only new findings | ❌ Full rescan |
| Confidence scoring | ✅ 0-100 per finding | ❌ No scoring |
| Parallel phases | ✅ Independent phases parallel | ❌ Sequential |
| Resource budget | ✅ Auto-throttle | ❌ Fixed concurrency |
| Cross-phase dedup | ✅ URL/host/finding | ❌ None |