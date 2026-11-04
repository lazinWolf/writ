use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::engine::{Authority, Engine, EngineError, LoadedEntitlements, LoadedPolicy, Resolution};
use crate::protocol::{Request, Response};

/// The engine, plus a condition variable signalled whenever a request may
/// have settled an approval, so waiters can sleep without holding the lock.
pub struct Shared {
    pub engine: Mutex<Engine>,
    changed: Condvar,
}

impl Shared {
    pub fn new(engine: Engine) -> Self {
        Shared {
            engine: Mutex::new(engine),
            changed: Condvar::new(),
        }
    }

    /// Blocks until approval `id` is settled (or times out) and returns its
    /// final decision. Holds the engine lock only while checking.
    fn wait_approval(&self, id: &str) -> Result<writ_policy::Decision, EngineError> {
        let mut engine = self.engine.lock().unwrap();
        loop {
            if let Some(decision) = engine.take_resolution(id) {
                return Ok(decision);
            }
            let deadline = engine
                .approval_deadline(id)
                .ok_or_else(|| EngineError::Invalid(format!("unknown approval `{id}`")))?;
            let now = Instant::now();
            if now >= deadline {
                engine.expire_approval(id)?;
                continue;
            }
            engine = self.changed.wait_timeout(engine, deadline - now).unwrap().0;
        }
    }
}

/// Accepts connections forever, one thread per connection.
pub fn serve(listener: UnixListener, shared: Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // The socket directory is 0700, so this is defence in depth.
        let Some(peer_pid) = same_user_peer(&stream) else {
            continue;
        };
        let shared = shared.clone();
        thread::spawn(move || {
            Connection {
                peer_pid,
                ..Connection::default()
            }
            .run(stream, &shared)
        });
    }
}

#[derive(Default)]
struct Connection {
    session: Option<String>,
    tasks: Vec<String>,
    /// The peer's pid, when the platform reports it. Recorded with approvals.
    peer_pid: Option<i32>,
}

impl Connection {
    fn run(mut self, stream: UnixStream, shared: &Shared) {
        let engine = &shared.engine;
        let Ok(read_half) = stream.try_clone() else { return };
        let mut writer = stream;
        for line in BufReader::new(read_half).lines() {
            let Ok(line) = line else { break };
            let request = serde_json::from_str::<Request>(&line);
            if let Ok(Request::Record { kind, data }) = request {
                // One-way: no response. Failures are reported here, not to the peer.
                let recorded = match &self.session {
                    Some(session) => engine.lock().unwrap().record(session, &kind, data),
                    None => Err(no_session()),
                };
                report(recorded);
                continue;
            }
            let response = match request {
                // Waits without holding the engine lock, so this connection must not
                // hold a session: the proxy opens a separate connection to wait.
                Ok(Request::WaitApproval { id }) => match shared.wait_approval(&id) {
                    Ok(decision) => Response::Ok {
                        body: serde_json::to_value(decision).expect("decision serializes"),
                    },
                    Err(e) => Response::Error { message: e.to_string() },
                },
                Ok(request) => {
                    let result = self.handle(request, &mut engine.lock().unwrap());
                    // Any request may have settled an approval (approve, deny, end a task).
                    shared.changed.notify_all();
                    match result {
                        Ok(body) => Response::Ok { body },
                        Err(e) => Response::Error { message: e.to_string() },
                    }
                }
                Err(e) => Response::Error {
                    message: format!("bad request: {e}"),
                },
            };
            let mut bytes = serde_json::to_vec(&response).expect("response serializes");
            bytes.push(b'\n');
            if writer.write_all(&bytes).is_err() {
                break;
            }
        }

        // The peer is gone: whatever it held loses its authority.
        let mut engine = engine.lock().unwrap();
        if let Some(session) = self.session.take() {
            report(engine.close_session(&session, json!({ "termination": "connection_lost" })));
        }
        for task in self.tasks.drain(..) {
            report(engine.end_task(&task, "creator disconnected"));
        }
        drop(engine);
        shared.changed.notify_all();
    }

    fn handle(&mut self, request: Request, engine: &mut Engine) -> Result<Value, EngineError> {
        match request {
            Request::CreateTask {
                policy,
                entitlements,
                principal,
                ttl_secs,
                meta,
            } => {
                let authority = Authority {
                    principal,
                    entitlements: entitlements.as_deref().map(LoadedEntitlements::parse).transpose()?,
                };
                let task = engine.create_task(LoadedPolicy::parse(&policy)?, authority, meta)?;
                if let Some(pid) = self.peer_pid {
                    engine.set_task_process(&task, pid);
                }
                self.tasks.push(task.clone());
                let ttl = ttl_secs.map_or(crate::token::DEFAULT_TTL, Duration::from_secs);
                let token = engine.task_token(&task, ttl)?;
                Ok(json!({ "task": task, "token": token }))
            }
            Request::EndTask { task } => {
                if !self.tasks.contains(&task) {
                    return Err(EngineError::Invalid(format!(
                        "task `{task}` wasn't created on this connection; only its creator can end it"
                    )));
                }
                engine.end_task(&task, "ended by creator")?;
                self.tasks.retain(|t| t != &task);
                Ok(Value::Null)
            }
            Request::OpenSession {
                token,
                task,
                policy,
                name,
                entitlements,
                info,
            } => {
                if self.session.is_some() {
                    return Err(EngineError::Invalid("this connection already has a session".into()));
                }
                if let Some(task) = task {
                    return Err(EngineError::Invalid(format!(
                        "refusing to join task `{task}` by id: task ids carry no authority. \
                         Present the task's writ token (WRIT_TOKEN, set by `writ run`)."
                    )));
                }
                let policy = policy.as_deref().map(LoadedPolicy::parse).transpose()?;
                let entitlements = entitlements.as_deref().map(LoadedEntitlements::parse).transpose()?;
                let session = match token {
                    Some(token) => engine.open_session_with_token(&token, policy, entitlements, &name, info)?,
                    None => engine.open_session(None, policy, entitlements, &name, info)?,
                };
                if let Some(pid) = self.peer_pid {
                    engine.set_session_process(&session, pid);
                }
                self.session = Some(session.clone());
                Ok(json!({ "session": session }))
            }
            Request::Decide { call_id, tool, args } => {
                let decision = engine.decide(self.session()?, &call_id, &tool, &args)?;
                Ok(serde_json::to_value(decision).expect("decision serializes"))
            }
            Request::Record { .. } => unreachable!("handled before dispatch: it has no response"),
            Request::HiddenTools { names } => Ok(json!({ "hidden": engine.hidden_tools(self.session()?, &names)? })),
            Request::CloseSession { data } => {
                let session = self.session.take().ok_or_else(no_session)?;
                engine.close_session(&session, data)?;
                Ok(Value::Null)
            }
            Request::Ps => Ok(json!({ "tasks": engine.tasks() })),
            Request::ListApprovals => Ok(json!({ "approvals": engine.approvals() })),
            Request::ResolveApproval {
                id,
                approve,
                mut approver,
            } => {
                // The agent (a descendant of `writ run`) and the wrapped servers (descendants
                // of their `writ wrap`) must not decide their own task's approvals. A process
                // that detaches from its parent escapes this check: it's a guard, not a
                // boundary against same-user code.
                if let Some(peer) = self.peer_pid
                    && let Some(owner) = engine
                        .approval_processes(&id)
                        .into_iter()
                        .find(|&owner| descends_from(peer, owner))
                {
                    return Err(EngineError::Invalid(format!(
                        "refusing to decide approval `{id}`: the request comes from a process running under \
                         that task (pid {peer} descends from pid {owner}). An agent or its servers must not \
                         decide their own approvals; run `writ sudo` from your own shell."
                    )));
                }
                // Who decided, as the kernel reports it, alongside what the client says.
                if let Value::Object(map) = &mut approver {
                    map.insert("pid".into(), json!(self.peer_pid));
                    // SAFETY: getuid has no preconditions. Peers are checked to share it.
                    map.insert("uid".into(), json!(unsafe { libc::getuid() }));
                }
                let resolution = if approve { Resolution::Approve } else { Resolution::Deny };
                let decision = engine.resolve_approval(&id, resolution, approver)?;
                Ok(serde_json::to_value(decision).expect("decision serializes"))
            }
            Request::WaitApproval { .. } => unreachable!("handled before dispatch: it waits without the lock"),
        }
    }

    fn session(&self) -> Result<&str, EngineError> {
        self.session.as_deref().ok_or_else(no_session)
    }
}

fn no_session() -> EngineError {
    EngineError::Invalid("no session is open on this connection".into())
}

fn report(result: Result<(), EngineError>) {
    if let Err(e) = result {
        eprintln!("writd: {e}");
    }
}

/// `Some(pid)` when the peer runs as this user (the pid is `None` where the
/// platform doesn't report it); `None` to refuse the connection.
#[cfg(target_os = "linux")]
fn same_user_peer(stream: &UnixStream) -> Option<Option<i32>> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    // SAFETY: getuid has no preconditions.
    (rc == 0 && cred.uid == unsafe { libc::getuid() }).then_some(Some(cred.pid))
}

/// True when `pid` is `ancestor` or one of its descendants, following parent
/// pids through `/proc`. A process that was reparented (it detached, or its
/// parent died) no longer descends from its original ancestor.
#[cfg(target_os = "linux")]
fn descends_from(pid: i32, ancestor: i32) -> bool {
    let parent = |pid: i32| -> Option<i32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) state ppid ...`; comm may contain spaces and parentheses.
        let after_comm = &stat[stat.rfind(')')? + 1..];
        after_comm.split_whitespace().nth(1)?.parse().ok()
    };
    let mut current = pid;
    for _ in 0..256 {
        if current == ancestor {
            return true;
        }
        match parent(current) {
            Some(p) if p > 0 && p != current => current = p,
            _ => return false,
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn descends_from(_pid: i32, _ancestor: i32) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn same_user_peer(_stream: &UnixStream) -> Option<Option<i32>> {
    Some(None)
}

/// Runs writd until it receives SIGTERM, SIGINT, or SIGHUP.
///
/// The socket's directory is created 0700 and the socket 0600. A lock file
/// next to the socket guarantees one writd per socket path; a stale socket
/// left by a crashed writd is replaced. The pid is written to `<socket>.pid`.
pub fn run(socket: &Path, log: &Path, fsync: bool) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let dir = socket.parent().context("socket path has no parent directory")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;

    let lock_path = socket.with_extension("lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("cannot open {}", lock_path.display()))?;
    if lock.try_lock().is_err() {
        bail!("writd is already running for {}", socket.display());
    }
    // We hold the lock, so any socket file here is stale.
    if socket.exists() {
        fs::remove_file(socket).with_context(|| format!("cannot remove stale {}", socket.display()))?;
    }
    let listener = UnixListener::bind(socket).with_context(|| format!("cannot bind {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let pid_path = socket.with_extension("pid");
    fs::write(&pid_path, format!("{}\n", std::process::id()))?;

    let mut recorder = writ_recorder::Recorder::open(log)?;
    recorder.set_fsync(fsync);
    let mut engine = Engine::new(recorder);
    engine.enable_approvals();
    let shared = Arc::new(Shared::new(engine));
    shared.engine.lock().unwrap().note(
        "writd_start",
        json!({ "pid": std::process::id(), "socket": socket, "fsync": fsync }),
    );

    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])?;
    {
        let (shared, socket, pid_path) = (shared.clone(), socket.to_path_buf(), pid_path.clone());
        thread::spawn(move || {
            if let Some(signal) = signals.forever().next() {
                let _ = fs::remove_file(&socket);
                let _ = fs::remove_file(&pid_path);
                let mut engine = shared.engine.lock().unwrap();
                let live = engine.tasks().len();
                // Settle waiting calls first, so the log shows how each approval ended.
                engine.cancel_all_approvals("writd stopped");
                engine.note("writd_stop", json!({ "signal": signal, "live_tasks": live }));
                // Exiting drops every connection: sessions lose their decision source and deny.
                std::process::exit(0);
            }
        });
    }

    serve(listener, shared);
    drop(lock);
    Ok(())
}
