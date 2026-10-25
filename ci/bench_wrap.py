"""Measures the per-call latency writ wrap adds to a tools/call round trip.

Usage: bench_wrap.py <path-to-writ> [--calls N]

Runs the same sequential tools/call workload three ways against the fake MCP
server from the test suite:
  direct   client -> server
  allowed  client -> writ wrap -> server (decision recorded, call forwarded)
  denied   client -> writ wrap (decision recorded, answered by writ)
Overhead is reported as the difference between allowed and direct percentiles.
"""

import argparse
import os
import statistics
import sys
import tempfile
import time

from mcp_client import McpClient

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "crates/writ-cli/tests/fixtures/fake_mcp_server.py")
POLICY = """\
version: 1
namespace: bench
capabilities:
  - tool: "postgres.query"
    conditions: ["args.limit <= 100"]
  - tool: "*"
    action: deny
"""
WARMUP = 200


def percentile(samples, p):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))]


def measure(argv, env, tool, calls):
    client = McpClient(argv, env=env)
    client.request("initialize", {}, timeout=30)
    args = {"sql": "select * from invoices where id = $1", "params": [991], "limit": 10}
    samples = []
    for i in range(WARMUP + calls):
        start = time.perf_counter_ns()
        response = client.call_tool(tool, args)
        elapsed = (time.perf_counter_ns() - start) / 1000
        if "result" not in response:
            sys.exit(f"unexpected response: {response}")
        if i >= WARMUP:
            samples.append(elapsed)
    client.close()
    return samples


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("writ")
    parser.add_argument("--calls", type=int, default=5000)
    opts = parser.parse_args()

    work = tempfile.mkdtemp()
    policy = os.path.join(work, "writ.yaml")
    with open(policy, "w") as f:
        f.write(POLICY)
    env = {**os.environ, "FAKE_MCP_LOG": os.devnull}
    server = [sys.executable, "-I", FIXTURE]

    def wrapped(log_name):
        return [opts.writ, "wrap", "--policy", policy, "--log", os.path.join(work, log_name), "--", *server]

    runs = {
        "direct": measure(server, env, "postgres.query", opts.calls),
        "allowed": measure(wrapped("allowed.jsonl"), env, "postgres.query", opts.calls),
        "denied": measure(wrapped("denied.jsonl"), env, "shell.exec", opts.calls),
    }

    print(f"{opts.calls} sequential tools/call round trips per run (after {WARMUP} warm-up), microseconds")
    print(f"{'':10}{'p50':>9}{'p90':>9}{'p99':>9}{'max':>9}{'mean':>9}")
    for name, samples in runs.items():
        row = [percentile(samples, p) for p in (50, 90, 99)] + [max(samples), statistics.fmean(samples)]
        print(f"{name:10}" + "".join(f"{v:9.0f}" for v in row))
    for p in (50, 99):
        overhead = percentile(runs["allowed"], p) - percentile(runs["direct"], p)
        print(f"writ overhead at p{p}: {overhead:.0f} us")


if __name__ == "__main__":
    main()
