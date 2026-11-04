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
//! - Policy evaluation, limits, and recording live in a [`Backend`]: the
//!   in-process engine (standalone) or writd (shared task).
//! - Requests the server sends to the client (sampling, elicitation) are
//!   recorded but not yet governed by policy.
//! - A call that needs approval (under writd, with an `approvals:` block)
//!   is *paused*: it waits on a thread of its own while other calls and
//!   results keep flowing, then is forwarded or answered with the decision.
//!   The agent sees only the real result, never a placeholder (D4).
//!
//! Unix only: the server runs in its own process group (see `supervisor`).

mod backend;
mod supervisor;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use writ_policy::{Decision, Outcome};

pub use backend::{ApprovalWaiter, Backend, DaemonBackend, LocalBackend};
use supervisor::Event;

pub struct WrapConfig {
    pub backend: Box<dyn Backend>,
    /// Server program followed by its arguments.
    pub command: Vec<String>,
    /// The server's name; its session is `mcp:<name>`.
    pub name: String,
    /// True when `name` was derived from the command rather than given.
    pub name_derived: bool,
    /// How long the server gets to exit after the client closes stdin (or
    /// after it closes its own stdout) before writ terminates it.
    pub shutdown_grace: Duration,
    /// Forward SIGTERM, SIGINT, and SIGHUP received by this process to the
    /// server. Installs process-wide signal handlers.
    pub forward_signals: bool,
}

struct PendingCall {
    tool: String,
    started: Instant,
}

struct State {
    backend: Box<dyn Backend>,
    pending_calls: HashMap<String, PendingCall>,
    pending_lists: HashSet<String>,
    /// Calls waiting for approval, by id key: the tool name.
    paused: HashMap<String, String>,
}

impl State {
    /// Recording failures on non-decision events are reported but not fatal.
    fn record_or_warn(&mut self, kind: &str, data: Value) {
        if let Err(e) = self.backend.record(kind, data) {
            eprintln!("writ: {e:#}");
        }
    }
}

type Shared<T> = Arc<Mutex<T>>;

/// The server's stdin, shared so an approved call can be forwarded from the
/// thread that waited for it. `None` once the client has gone: dropping it
/// is what tells the server to shut down.
type ServerIn = Shared<Option<ChildStdin>>;

/// Writes one message to the server. False if its stdin is closed or gone.
fn forward(server_in: &ServerIn, message: &Value) -> bool {
    let bytes = serde_json::to_string(message).expect("JSON value serializes");
    let mut guard = server_in.lock().unwrap();
    let Some(stdin) = guard.as_mut() else { return false };
    writeln!(stdin, "{bytes}").and_then(|()| stdin.flush()).is_ok()
}

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
    let server_in: ServerIn = Arc::new(Mutex::new(Some(child.stdin.take().expect("stdin is piped"))));
    let server_out = child.stdout.take().expect("stdout is piped");

    let mut state = State {
        backend: config.backend,
        pending_calls: HashMap::new(),
        pending_lists: HashSet::new(),
        paused: HashMap::new(),
    };
    if let Err(e) = state.backend.open(
        &config.name,
        json!({ "command": config.command, "server_pid": pid, "name_derived": config.name_derived }),
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
    let unanswered: Vec<&str> = state
        .pending_calls
        .values()
        .map(|p| p.tool.as_str())
        .chain(state.paused.values().map(String::as_str))
        .collect();
    let data = json!({
        "exit_code": outcome.status.and_then(|s| s.code()),
        "server_signal": outcome.status.and_then(|s| s.signal()),
        "termination": outcome.termination,
        "writ_signal": outcome.writ_signal,
        "unanswered_calls": unanswered,
    });
    if let Err(e) = state.backend.close(data) {
        eprintln!("writ: {e:#}");
    }
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

fn client_to_server<R: Read, W: Write + Send + 'static>(
    client_in: R,
    server_in: ServerIn,
    state: &Shared<State>,
    client_out: &Shared<W>,
) {
    for line in BufReader::new(client_in).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let outgoing = match serde_json::from_str::<Value>(&line) {
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
            Ok(message) => handle_client_message(message, state, client_out, &server_in),
        };
        if let Some(message) = outgoing
            && !forward(&server_in, &message)
        {
            break;
        }
    }
    // Dropping the server's stdin closes it: the MCP stdio shutdown signal. Calls
    // still waiting for approval then have nowhere to go, and are dropped.
    server_in.lock().unwrap().take();
}

/// Returns the message to forward to the server, or `None` if the proxy
/// answered it itself.
fn handle_client_message<W: Write + Send + 'static>(
    message: Value,
    state: &Shared<State>,
    client_out: &Shared<W>,
    server_in: &ServerIn,
) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id").cloned();

    match (method, id) {
        (Some("tools/call"), Some(id)) => {
            let mut guard = state.lock().unwrap();
            match decide_call(&message, &id, &mut guard) {
                Ok(Fate::Forward) => Some(message),
                Ok(Fate::Paused { approval, waiter }) => {
                    drop(guard);
                    let (state, client_out, server_in) = (state.clone(), client_out.clone(), server_in.clone());
                    thread::spawn(move || {
                        await_approval(&approval, &*waiter, message, &state, &client_out, &server_in)
                    });
                    None
                }
                Err(reply) => {
                    drop(guard);
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

/// What happens to a `tools/call` the policy didn't refuse outright.
enum Fate {
    Forward,
    /// Waiting for a human: `waiter` blocks until `approval` is settled.
    Paused {
        approval: String,
        waiter: Arc<dyn ApprovalWaiter>,
    },
}

/// Waits for a paused call's approval on its own thread, then forwards the
/// call or answers it with the denial. Other calls keep flowing meanwhile.
fn await_approval<W: Write>(
    approval: &str,
    waiter: &dyn ApprovalWaiter,
    message: Value,
    state: &Shared<State>,
    client_out: &Shared<W>,
    server_in: &ServerIn,
) {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let key = id_key(&id);
    // If writd can't be reached, nobody can approve: deny.
    let decision = waiter.wait(approval).unwrap_or_else(|e| {
        Decision::new(
            Outcome::Deny,
            None,
            format!("writ could not wait for approval `{approval}` ({e:#})"),
        )
    });
    let mut guard = state.lock().unwrap();
    let Some(tool) = guard.paused.remove(&key) else { return };
    if decision.outcome == Outcome::Allow {
        // writd recorded the approval durably before answering.
        eprintln!("writ: `{tool}` approved ({approval}); forwarding it");
        guard.pending_calls.insert(
            key.clone(),
            PendingCall {
                tool,
                started: Instant::now(),
            },
        );
        drop(guard);
        if !forward(server_in, &message) {
            // The client left while we waited; there's nobody to answer.
            state.lock().unwrap().pending_calls.remove(&key);
        }
    } else {
        drop(guard);
        let _ = send(
            client_out,
            &tool_error(&id, &format!("writ denied this call: {}", decision.reason)),
        );
    }
}

/// Decides a `tools/call`. `Ok` means forward it or wait; `Err` carries the
/// reply the proxy sends instead.
fn decide_call(message: &Value, id: &Value, state: &mut State) -> Result<Fate, String> {
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

    // The backend records the decision before returning it; if it cannot, deny.
    let decision = match state.backend.decide(id, &tool, &args) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("writ: {e:#}");
            return Err(tool_error(
                id,
                "writ denied this call: the decision could not be made and recorded (writd or the flight recorder is unavailable)",
            ));
        }
    };

    match decision.outcome {
        Outcome::Allow => {
            state.pending_calls.insert(
                id_key(id),
                PendingCall {
                    tool,
                    started: Instant::now(),
                },
            );
            Ok(Fate::Forward)
        }
        Outcome::RequireSudo => match (decision.approval, state.backend.approval_waiter()) {
            (Some(approval), Some(waiter)) => {
                eprintln!(
                    "writ: `{tool}` is waiting for approval ({}). Decide with: writ sudo approve {approval}  (or: writ sudo deny {approval})",
                    decision.reason
                );
                state.paused.insert(id_key(id), tool);
                Ok(Fate::Paused { approval, waiter })
            }
            _ => Err(tool_error(
                id,
                &format!(
                    "writ: this call requires approval ({}), and nobody can be asked: the policy has no \
                     `approvals:` block, or this `writ wrap` runs without writd. The call was not executed.",
                    decision.reason
                ),
            )),
        },
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
        let names: Vec<String> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        // Hiding is a usability aid (D6): on failure, show the list and rely on per-call denial.
        let hidden = state.backend.hidden_tools(&names).unwrap_or_else(|e| {
            eprintln!("writ: {e:#}");
            Vec::new()
        });
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_none_or(|name| !hidden.iter().any(|h| h == name))
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
