//! `writ wrap`: a stdio MCP proxy in cooperative mode.
//!
//! The proxy sits between an MCP client and a server it spawns. Every
//! `tools/call` is decided by the policy and recorded before anything reaches
//! the server; denied calls are answered by the proxy with an MCP tool error
//! so the agent sees why. `tools/list` responses hide tools the policy always
//! denies, which is a usability aid only (D6).
//!
//! Hardening choices:
//! - Client messages are re-serialized from the parsed value instead of
//!   forwarded verbatim, so the server cannot interpret a message differently
//!   from the proxy (duplicate keys, lenient parsers).
//! - Unparseable messages and JSON-RPC batches are rejected, not forwarded.
//! - If the flight recorder cannot record a decision, the call is denied.
//! - Arguments are redacted per policy before they are recorded.
//! - Requests the server sends to the client (sampling, elicitation) are
//!   recorded but not yet governed by policy.
//!
//! Unix only: the server runs in its own process group (see `supervisor`).

mod supervisor;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use writ_policy::{Outcome, Policy};
use writ_recorder::Recorder;

use supervisor::Event;

pub struct WrapConfig {
    pub policy: Policy,
    pub policy_sha256: String,
    pub recorder: Recorder,
    /// Server program followed by its arguments.
    pub command: Vec<String>,
    pub session: String,
    /// How long the server gets to exit after the client closes stdin (or
    /// after it closes its own stdout) before writ terminates it.
    pub shutdown_grace: Duration,
    /// Forward SIGTERM, SIGINT, and SIGHUP received by this process to the
    /// server. Installs process-wide signal handlers.
    pub forward_signals: bool,
}

/// A session id that is unique enough to tell sessions apart in one log.
pub fn new_session_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("ses_{nanos:x}{:x}", std::process::id())
}

struct PendingCall {
    tool: String,
    started: Instant,
}

struct State {
    policy: Policy,
    recorder: Recorder,
    session: String,
    calls_allowed: u64,
    pending_calls: HashMap<String, PendingCall>,
    pending_lists: HashSet<String>,
}

impl State {
    fn record(&mut self, kind: &str, data: Value) -> Result<()> {
        self.recorder.append(&self.session, kind, data)?;
        Ok(())
    }

    /// For entries that gate an action: fsynced when the recorder asks for it.
    fn record_durable(&mut self, kind: &str, data: Value) -> Result<()> {
        self.recorder.append_durable(&self.session, kind, data)?;
        Ok(())
    }

    /// Recording failures on non-decision events are reported but not fatal.
    fn record_or_warn(&mut self, kind: &str, data: Value) {
        if let Err(e) = self.record(kind, data) {
            eprintln!("writ: {e:#}");
        }
    }
}

type Shared<T> = Arc<Mutex<T>>;

/// Runs the proxy until the server has exited and its stdout has closed.
/// Returns the exit code writ should exit with: the server's, `128 + n` if
/// the server died from signal `n`, or `128 + n` if writ itself received
/// signal `n`.
pub fn run<R, W>(config: WrapConfig, client_in: R, client_out: W) -> Result<i32>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (program, args) = config.command.split_first().context("no server command given")?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .with_context(|| format!("failed to start MCP server `{program}`"))?;
    let pid = child.id();
    let server_in = child.stdin.take().expect("stdin is piped");
    let server_out = child.stdout.take().expect("stdout is piped");

    let mut state = State {
        policy: config.policy,
        recorder: config.recorder,
        session: config.session,
        calls_allowed: 0,
        pending_calls: HashMap::new(),
        pending_lists: HashSet::new(),
    };
    if let Err(e) = state.record_durable(
        "session_start",
        json!({
            "command": config.command,
            "server_pid": pid,
            "namespace": state.policy.namespace,
            "enforcement": state.policy.enforcement,
            "policy_sha256": config.policy_sha256,
        }),
    ) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }

    let state = Arc::new(Mutex::new(state));
    let client_out: Shared<W> = Arc::new(Mutex::new(client_out));
    let (events, inbox) = mpsc::channel();

    if config.forward_signals {
        forward_signals(events.clone())?;
    }
    {
        let (state, client_out, events) = (state.clone(), client_out.clone(), events.clone());
        thread::spawn(move || {
            client_to_server(client_in, server_in, &state, &client_out);
            let _ = events.send(Event::ClientClosed);
        });
    }
    {
        let (state, client_out, events) = (state.clone(), client_out.clone(), events.clone());
        thread::spawn(move || {
            for line in BufReader::new(server_out).lines() {
                let Ok(line) = line else { break };
                let line = server_to_client(&line, &state);
                if send(&client_out, &line).is_err() {
                    // Nobody is listening any more; treat it like the client leaving.
                    let _ = events.send(Event::ClientClosed);
                    break;
                }
            }
            let _ = events.send(Event::StdoutClosed);
        });
    }
    thread::spawn(move || {
        if let Ok(status) = child.wait() {
            let _ = events.send(Event::ServerExited(status));
        }
    });

    let outcome = supervisor::supervise(inbox, pid, config.shutdown_grace);

    let code = match (outcome.writ_signal, outcome.status) {
        (Some(sig), _) => 128 + sig,
        (None, Some(status)) => status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        (None, None) => 1,
    };
    let mut state = state.lock().unwrap();
    let unanswered: Vec<&str> = state.pending_calls.values().map(|p| p.tool.as_str()).collect();
    let data = json!({
        "exit_code": outcome.status.and_then(|s| s.code()),
        "server_signal": outcome.status.and_then(|s| s.signal()),
        "termination": outcome.termination,
        "writ_signal": outcome.writ_signal,
        "calls_allowed": state.calls_allowed,
        "unanswered_calls": unanswered,
    });
    state.record_or_warn("session_end", data);
    Ok(code)
}

fn forward_signals(events: Sender<Event>) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals =
        signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]).context("installing signal handlers")?;
    thread::spawn(move || {
        for signal in signals.forever() {
            if events.send(Event::Signal(signal)).is_err() {
                break;
            }
        }
    });
    Ok(())
}

fn client_to_server<R: Read, W: Write>(
    client_in: R,
    mut server_in: ChildStdin,
    state: &Shared<State>,
    client_out: &Shared<W>,
) {
    for line in BufReader::new(client_in).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let forward = match serde_json::from_str::<Value>(&line) {
            Err(e) => {
                state
                    .lock()
                    .unwrap()
                    .record_or_warn("protocol_error", json!({ "error": e.to_string() }));
                let _ = send(
                    client_out,
                    &rpc_error(&Value::Null, -32700, "writ: message is not valid JSON"),
                );
                None
            }
            Ok(Value::Array(batch)) => {
                state
                    .lock()
                    .unwrap()
                    .record_or_warn("protocol_error", json!({ "error": "batch rejected" }));
                for id in batch.iter().filter_map(|m| m.get("id")) {
                    let _ = send(
                        client_out,
                        &rpc_error(id, -32600, "writ: JSON-RPC batches are not supported"),
                    );
                }
                None
            }
            Ok(message) => handle_client_message(message, state, client_out),
        };
        if let Some(message) = forward {
            let bytes = serde_json::to_string(&message).expect("JSON value serializes");
            if writeln!(server_in, "{bytes}").and_then(|()| server_in.flush()).is_err() {
                break;
            }
        }
    }
    // Dropping server_in closes the server's stdin, the MCP stdio shutdown signal.
}

/// Returns the message to forward to the server, or `None` if the proxy
/// answered it itself.
fn handle_client_message<W: Write>(message: Value, state: &Shared<State>, client_out: &Shared<W>) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id").cloned();

    match (method, id) {
        (Some("tools/call"), Some(id)) => {
            let mut state = state.lock().unwrap();
            match decide_call(&message, &id, &mut state) {
                Ok(()) => Some(message),
                Err(reply) => {
                    drop(state);
                    let _ = send(client_out, &reply);
                    None
                }
            }
        }
        (Some("tools/call"), None) => {
            // A notification cannot carry a result, so there is nothing to allow.
            state
                .lock()
                .unwrap()
                .record_or_warn("protocol_error", json!({ "error": "tools/call without id dropped" }));
            None
        }
        (Some("tools/list"), Some(id)) => {
            state.lock().unwrap().pending_lists.insert(id_key(&id));
            Some(message)
        }
        _ => Some(message),
    }
}

/// Decides a `tools/call`. `Ok` means forward it; `Err` carries the reply the
/// proxy sends instead.
fn decide_call(message: &Value, id: &Value, state: &mut State) -> Result<(), String> {
    let params = message.get("params");
    let Some(tool) = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        state.record_or_warn(
            "protocol_error",
            json!({ "error": "tools/call without a string name", "id": id }),
        );
        return Err(rpc_error(id, -32602, "writ: tools/call requires a string `name`"));
    };
    let args = params.and_then(|p| p.get("arguments")).cloned().unwrap_or(json!({}));

    let mut decision = state.policy.evaluate(&tool, &args);
    if decision.outcome == Outcome::Allow
        && let Some(max) = state.policy.limits.max_tool_calls
        && state.calls_allowed >= max
    {
        decision.outcome = Outcome::Deny;
        decision.reason = format!("max_tool_calls limit reached ({max})");
    }

    let mut data = json!({ "id": id, "tool": tool, "decision": decision });
    match state.policy.arguments_for_log(&tool, &args) {
        Some(logged) => data["arguments"] = logged,
        None => data["arguments_omitted"] = json!(true),
    }
    if let Err(e) = state.record_durable("tool_call", data) {
        eprintln!("writ: {e:#}");
        return Err(tool_error(
            id,
            "writ denied this call: the flight recorder is unavailable, so the call cannot be audited",
        ));
    }

    match decision.outcome {
        Outcome::Allow => {
            state.calls_allowed += 1;
            state.pending_calls.insert(
                id_key(id),
                PendingCall {
                    tool,
                    started: Instant::now(),
                },
            );
            Ok(())
        }
        Outcome::RequireSudo => Err(tool_error(
            id,
            &format!(
                "writ: this call requires approval ({}). Approval is not available in this build, so the call was not executed.",
                decision.reason
            ),
        )),
        Outcome::Deny => Err(tool_error(id, &format!("writ denied this call: {}", decision.reason))),
    }
}

/// Inspects one server line and returns what to send to the client.
fn server_to_client(line: &str, state: &Shared<State>) -> String {
    let Ok(mut message) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };
    let Some(id) = message.get("id") else {
        return line.to_string(); // a notification
    };

    if let Some(method) = message.get("method").and_then(Value::as_str) {
        // A request from the server to the client, e.g. sampling/createMessage
        // or elicitation/create. Params may carry prompts, so only the method
        // is recorded.
        let data = json!({ "id": id, "method": method });
        state.lock().unwrap().record_or_warn("server_request", data);
        return line.to_string();
    }

    let key = id_key(id);
    let mut state = state.lock().unwrap();

    if let Some(call) = state.pending_calls.remove(&key) {
        let is_error = message.get("error").is_some()
            || message
                .pointer("/result/isError")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let data = json!({
            "id": id,
            "tool": call.tool,
            "is_error": is_error,
            "duration_ms": call.started.elapsed().as_millis() as u64,
        });
        state.record_or_warn("tool_result", data);
        return line.to_string();
    }

    if state.pending_lists.remove(&key)
        && let Some(Value::Array(tools)) = message.pointer_mut("/result/tools")
    {
        let mut hidden = Vec::new();
        tools.retain(|tool| match tool.get("name").and_then(Value::as_str) {
            Some(name) if state.policy.always_denies(name) => {
                hidden.push(name.to_string());
                false
            }
            _ => true,
        });
        if !hidden.is_empty() {
            state.record_or_warn("tools_hidden", json!({ "tools": hidden }));
            return serde_json::to_string(&message).expect("JSON value serializes");
        }
    }
    line.to_string()
}

fn send<W: Write>(out: &Shared<W>, line: &str) -> std::io::Result<()> {
    let mut out = out.lock().unwrap();
    writeln!(out, "{line}")?;
    out.flush()
}

/// JSON-RPC ids may be numbers or strings; `1` and `"1"` are different ids.
fn id_key(id: &Value) -> String {
    id.to_string()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// A tool-level error result, which MCP clients show to the model.
fn tool_error(id: &Value, text: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [{ "type": "text", "text": text }], "isError": true },
    })
    .to_string()
}
