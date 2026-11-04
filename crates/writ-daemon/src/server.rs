use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};

use crate::engine::{Authority, Engine, EngineError, LoadedEntitlements, LoadedPolicy};
use crate::protocol::{Request, Response};

/// Accepts connections forever, one thread per connection.
pub fn serve(listener: UnixListener, engine: Arc<Mutex<Engine>>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if !same_user(&stream) {
            // The socket directory is 0700, so this is defence in depth.
            continue;
        }
        let engine = engine.clone();
        thread::spawn(move || Connection::default().run(stream, &engine));
    }
}

#[derive(Default)]
struct Connection {
    session: Option<String>,
    tasks: Vec<String>,
}

impl Connection {
    fn run(mut self, stream: UnixStream, engine: &Mutex<Engine>) {
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
                Ok(request) => match self.handle(request, &mut engine.lock().unwrap()) {
                    Ok(body) => Response::Ok { body },
                    Err(e) => Response::Error { message: e.to_string() },
                },
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
    }

    fn handle(&mut self, request: Request, engine: &mut Engine) -> Result<Value, EngineError> {
        match request {
            Request::CreateTask {
                policy,
                entitlements,
                principal,
                meta,
            } => {
                let authority = Authority {
                    principal,
                    entitlements: entitlements.as_deref().map(LoadedEntitlements::parse).transpose()?,
                };
                let task = engine.create_task(LoadedPolicy::parse(&policy)?, authority, meta)?;
                self.tasks.push(task.clone());
                Ok(json!({ "task": task }))
            }
            Request::EndTask { task } => {
                engine.end_task(&task, "ended by creator")?;
                self.tasks.retain(|t| t != &task);
                Ok(Value::Null)
            }
            Request::OpenSession {
                task,
                policy,
                name,
                entitlements,
                info,
            } => {
                if self.session.is_some() {
                    return Err(EngineError::Invalid("this connection already has a session".into()));
                }
                let policy = policy.as_deref().map(LoadedPolicy::parse).transpose()?;
                let session = engine.open_session(
                    task.as_deref(),
                    policy,
                    entitlements.as_deref().map(LoadedEntitlements::parse).transpose()?,
                    &name,
                    info,
                )?;
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

#[cfg(target_os = "linux")]
fn same_user(stream: &UnixStream) -> bool {
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
    rc == 0 && cred.uid == unsafe { libc::getuid() }
}

#[cfg(not(target_os = "linux"))]
fn same_user(_stream: &UnixStream) -> bool {
    true
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
    let engine = Arc::new(Mutex::new(Engine::new(recorder)));
    engine.lock().unwrap().note(
        "writd_start",
        json!({ "pid": std::process::id(), "socket": socket, "fsync": fsync }),
    );

    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])?;
    {
        let (engine, socket, pid_path) = (engine.clone(), socket.to_path_buf(), pid_path.clone());
        thread::spawn(move || {
            if let Some(signal) = signals.forever().next() {
                let _ = fs::remove_file(&socket);
                let _ = fs::remove_file(&pid_path);
                let mut engine = engine.lock().unwrap();
                let live = engine.tasks().len();
                engine.note("writd_stop", json!({ "signal": signal, "live_tasks": live }));
                // Exiting drops every connection: sessions lose their decision source and deny.
                std::process::exit(0);
            }
        });
    }

    serve(listener, engine);
    drop(lock);
    Ok(())
}
