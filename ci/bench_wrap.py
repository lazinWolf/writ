"""Measures the per-call latency writ wrap adds to a tools/call round trip.

Usage: bench_wrap.py <path-to-writ> [--calls N]

Runs the same sequential tools/call workload six ways against the fake MCP
server from the test suite:
  direct    client -> server
  standalone client -> writ wrap -> server (decision fsynced, the default)
  nofsync   as standalone, with --no-fsync
  daemon    client -> writ wrap -> writd -> back -> server (writd fsyncs)
  daemon-nofsync  as daemon, writd started with --no-fsync (isolates the socket hop)
  denied    client -> writ wrap (decision recorded, answered by writ)
Overhead is the difference from direct at each percentile.
"""

import argparse
import os
import signal
import statistics
import subprocess
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
    parser.add_argument(
        "--log-dir",
        help="where flight logs go (default: a temp dir). fsync numbers are only meaningful on a "
        "real filesystem: container overlays may be mounted `volatile`, which makes fsync a no-op",
    )
    opts = parser.parse_args()

    work = tempfile.mkdtemp()
    policy = os.path.join(work, "writ.yaml")
    with open(policy, "w") as f:
        f.write(POLICY)
    env = {**os.environ, "FAKE_MCP_LOG": os.devnull}
    server = [sys.executable, "-I", FIXTURE]
    log_dir = opts.log_dir or work
    os.makedirs(log_dir, exist_ok=True)
    fs = subprocess.run(["stat", "-f", "-c", "%T", log_dir], capture_output=True, text=True).stdout.strip()
    print(f"flight logs in {log_dir} ({fs or 'unknown filesystem'})")

    def wrapped(log_name, *flags):
        log = os.path.join(log_dir, log_name)
        if os.path.exists(log):
            os.remove(log)
        return [opts.writ, "wrap", *flags, "--policy", policy, "--log", log, "--", *server]

    writd_bin = os.path.join(os.path.dirname(os.path.abspath(opts.writ)), "writd")

    def via_writd(name, *writd_flags):
        """Runs the workload through a fresh writd with its own socket and log."""
        socket = os.path.join(work, name, "writd.sock")
        log = os.path.join(log_dir, f"{name}.jsonl")
        if os.path.exists(log):
            os.remove(log)
        writd = subprocess.Popen([writd_bin, "--socket", socket, "--log", log, *writd_flags])
        try:
            while not os.path.exists(socket):
                time.sleep(0.01)
            argv = [opts.writ, "wrap", "--daemon", "--policy", policy, "--", *server]
            return measure(argv, {**env, "WRIT_SOCKET": socket}, "postgres.query", opts.calls)
        finally:
            writd.send_signal(signal.SIGTERM)
            writd.wait()

    runs = {
        "direct": measure(server, env, "postgres.query", opts.calls),
        "standalone": measure(wrapped("standalone.jsonl"), env, "postgres.query", opts.calls),
        "nofsync": measure(wrapped("nofsync.jsonl", "--no-fsync"), env, "postgres.query", opts.calls),
        "daemon": via_writd("daemon"),
        "daemon-nofsync": via_writd("daemon-nofsync", "--no-fsync"),
        "denied": measure(wrapped("denied.jsonl"), env, "shell.exec", opts.calls),
    }

    print(f"{opts.calls} sequential tools/call round trips per run (after {WARMUP} warm-up), microseconds")
    print(f"{'':15}{'p50':>9}{'p90':>9}{'p99':>9}{'max':>9}{'mean':>9}")
    for name, samples in runs.items():
        row = [percentile(samples, p) for p in (50, 90, 99)] + [max(samples), statistics.fmean(samples)]
        print(f"{name:15}" + "".join(f"{v:9.0f}" for v in row))
    for variant in ("standalone", "nofsync", "daemon", "daemon-nofsync", "denied"):
        for p in (50, 99):
            overhead = percentile(runs[variant], p) - percentile(runs["direct"], p)
            print(f"writ overhead ({variant}) at p{p}: {overhead:.0f} us")


if __name__ == "__main__":
    main()
