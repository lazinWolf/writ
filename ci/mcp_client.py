"""Minimal newline-delimited JSON-RPC client for driving MCP servers over stdio."""

import json
import queue
import subprocess
import threading
import time


class McpClient:
    def __init__(self, argv, env=None):
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True, bufsize=1
        )
        self.inbox = queue.Queue()
        self.notifications = []
        self._next_id = 1
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            self.inbox.put(json.loads(line))
        self.inbox.put(None)

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method, params=None, timeout=30.0):
        msg_id = self._next_id
        self._next_id += 1
        self.send({"jsonrpc": "2.0", "id": msg_id, "method": method, **({"params": params} if params else {})})
        return self.wait_for(msg_id, timeout)

    def call_tool(self, name, arguments, timeout=30.0):
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout)

    def wait_for(self, msg_id, timeout):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no response to request {msg_id} within {timeout}s")
            try:
                message = self.inbox.get(timeout=remaining)
            except queue.Empty:
                continue
            if message is None:
                raise EOFError(f"server closed stdout before answering request {msg_id}")
            if message.get("id") == msg_id and "method" not in message:
                return message
            # Server-originated notifications and requests are kept for inspection.
            self.notifications.append(message)

    def close(self, timeout=15.0):
        self.proc.stdin.close()
        return self.proc.wait(timeout=timeout)
