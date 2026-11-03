use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use writ_policy::Decision;

use crate::engine::TaskSummary;
use crate::protocol::{Request, Response};

/// How long a request may take before the caller treats writd as unavailable.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    pub fn connect(socket: &Path) -> Result<Self> {
        let stream =
            UnixStream::connect(socket).with_context(|| format!("cannot reach writd at {}", socket.display()))?;
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Client { stream, reader })
    }

    /// Connects, starting writd first if nothing is listening.
    pub fn connect_or_start(socket: &Path, log: Option<&Path>) -> Result<Self> {
        if let Ok(client) = Self::connect(socket) {
            return Ok(client);
        }
        let writd = writd_binary();
        let mut cmd = Command::new(&writd);
        cmd.arg("--socket").arg(socket);
        if let Some(log) = log {
            cmd.arg("--log").arg(log);
        }
        // Its own process group: a Ctrl-C meant for the agent must not reach the daemon.
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("cannot start {}", writd.display()))?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match Self::connect(socket) {
                Ok(client) => return Ok(client),
                Err(e) if Instant::now() > deadline => return Err(e.context("writd did not start within 5s")),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    pub fn request(&mut self, request: &Request) -> Result<Value> {
        let mut line = serde_json::to_vec(request)?;
        line.push(b'\n');
        self.stream.write_all(&line).context("writd connection lost")?;
        let mut reply = String::new();
        if self.reader.read_line(&mut reply).context("writd connection lost")? == 0 {
            bail!("writd closed the connection");
        }
        match serde_json::from_str(&reply).context("malformed reply from writd")? {
            Response::Ok { body } => Ok(body),
            Response::Error { message } => Err(anyhow!("writd: {message}")),
        }
    }

    pub fn create_task(&mut self, policy: &str, meta: Value) -> Result<String> {
        let body = self.request(&Request::CreateTask {
            policy: policy.to_string(),
            meta,
        })?;
        string_field(&body, "task")
    }

    pub fn end_task(&mut self, task: &str) -> Result<()> {
        self.request(&Request::EndTask { task: task.to_string() })?;
        Ok(())
    }

    pub fn open_session(
        &mut self,
        task: Option<&str>,
        policy: Option<&str>,
        name: &str,
        info: Value,
    ) -> Result<String> {
        let body = self.request(&Request::OpenSession {
            task: task.map(str::to_string),
            policy: policy.map(str::to_string),
            name: name.to_string(),
            info,
        })?;
        string_field(&body, "session")
    }

    pub fn decide(&mut self, call_id: &Value, tool: &str, args: &Value) -> Result<Decision> {
        let body = self.request(&Request::Decide {
            call_id: call_id.clone(),
            tool: tool.to_string(),
            args: args.clone(),
        })?;
        Ok(serde_json::from_value(body)?)
    }

    /// One-way (see [`Request::Record`]): returns once the event is sent.
    pub fn record(&mut self, kind: &str, data: Value) -> Result<()> {
        let mut line = serde_json::to_vec(&Request::Record {
            kind: kind.to_string(),
            data,
        })?;
        line.push(b'\n');
        self.stream.write_all(&line).context("writd connection lost")
    }

    pub fn hidden_tools(&mut self, names: &[String]) -> Result<Vec<String>> {
        let body = self.request(&Request::HiddenTools { names: names.to_vec() })?;
        Ok(serde_json::from_value(body["hidden"].clone())?)
    }

    pub fn close_session(&mut self, data: Value) -> Result<()> {
        self.request(&Request::CloseSession { data })?;
        Ok(())
    }

    pub fn ps(&mut self) -> Result<Vec<TaskSummary>> {
        let body = self.request(&Request::Ps)?;
        Ok(serde_json::from_value(body["tasks"].clone())?)
    }
}

fn string_field(body: &Value, field: &str) -> Result<String> {
    body[field]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("writd reply is missing `{field}`: {}", json!(body)))
}

/// `writd` next to the running executable if present, else from `$PATH`.
fn writd_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name("writd"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("writd"))
}
