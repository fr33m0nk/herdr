//! End-to-end test for the iroh bridge.
//!
//! Starts a herdr server, bridges it over iroh QUIC, and validates the
//! client handshake through the bridge.
//!
//! The test spawns:
//! 1. `herdr server` — headless server
//! 2. `herdr iroh-bridge serve` — bridges the server's client socket
//! 3. `herdr iroh-bridge connect` — local proxy to the remote bridge
//! 4. Client handshake through the bridge socket

mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use support::{cleanup_test_base, register_runtime_dir, register_spawned_herdr_pid};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    PathBuf::from(format!(
        "/tmp/herdr-iroh-e2e-{}-{nanos}",
        std::process::id()
    ))
}

fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn herdr_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_herdr"))
}

struct SpawnedServer {
    _master: Option<Box<dyn MasterPty + Send>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        let pid = self.child.process_id();
        let _ = self.child.kill();
        drop(self._master.take());
        if let Some(pid) = pid {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                let mut status = 0;
                let result =
                    unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if result == pid as libc::pid_t || result == -1 {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            support::unregister_spawned_herdr_pid(Some(pid));
        }
    }
}

fn spawn_server_headless(
    config_home: &Path,
    runtime_dir: &Path,
    api_socket_path: &Path,
) -> SpawnedServer {
    fs::create_dir_all(config_home.join("herdr")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    register_runtime_dir(runtime_dir);
    fs::write(
        config_home.join("herdr/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();

    let mut cmd = CommandBuilder::new(herdr_binary());
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("HERDR_SOCKET_PATH", api_socket_path);
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env("SHELL", "/bin/sh");
    cmd.env_remove("HERDR_ENV");

    let child = pair.slave.spawn_command(cmd).unwrap();
    register_spawned_herdr_pid(child.process_id());
    drop(pair.slave);

    SpawnedServer {
        _master: Some(pair.master),
        child,
    }
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("socket did not appear at {}", path.display());
}

/// Wait for a socket file to exist (without connecting to it).
/// Connecting would trigger the bridge's accept and cause it to exit.
fn wait_for_socket_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            use std::os::unix::fs::FileTypeExt;
            if let Ok(meta) = path.metadata() {
                if meta.file_type().is_socket() {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("socket file did not appear at {}", path.display());
}

// ---------------------------------------------------------------------------
// Iroh bridge processes
// ---------------------------------------------------------------------------

struct IrohBridgeServe {
    child: Child,
}

impl IrohBridgeServe {
    /// Spawn iroh-bridge serve. Returns the process and endpoint ID.
    fn spawn(server_socket: &Path, config_home: &Path, runtime_dir: &Path) -> (Self, String) {
        let mut cmd = Command::new(herdr_binary());
        cmd.arg("iroh-bridge");
        cmd.arg("serve");
        cmd.arg("--socket");
        cmd.arg(server_socket);
        cmd.env("XDG_CONFIG_HOME", config_home);
        cmd.env("XDG_RUNTIME_DIR", runtime_dir);
        cmd.env_remove("HERDR_ENV");
        cmd.env("HERDR_IROH_KEY_NEW_PASSPHRASE", "e2e-test-pw-1234");
        cmd.env("HERDR_IROH_KEY_PASSPHRASE", "e2e-test-pw-1234");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        // Capture stderr to a temp file for debugging.
        let stderr_path = config_home.join("herdr").join("iroh-serve-stderr.log");
        let stderr_file = fs::File::create(&stderr_path).expect("create serve stderr log");
        cmd.stderr(stderr_file);

        let mut child = cmd.spawn().expect("spawn iroh-bridge serve");

        // Read endpoint ID from first line of stdout.
        let stdout = child.stdout.take().expect("serve stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read endpoint id");
        let endpoint_id = line.trim().to_string();
        assert!(!endpoint_id.is_empty());
        assert_eq!(endpoint_id.len(), 64, "endpoint id length");

        eprintln!("[serve] endpoint = {endpoint_id}");

        // Wait for serve to be listening.
        thread::sleep(Duration::from_secs(1));

        (Self { child }, endpoint_id)
    }
}

impl Drop for IrohBridgeServe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct IrohBridgeConnect {
    child: Child,
    local_socket: PathBuf,
}

impl IrohBridgeConnect {
    /// Spawn iroh-bridge connect. Stdout is inherited to avoid broken pipe
    /// panics during the reconnect loop.
    fn spawn(
        endpoint_id: &str,
        local_socket: &Path,
        config_home: &Path,
        runtime_dir: &Path,
    ) -> Self {
        let _ = fs::remove_file(local_socket);

        let mut cmd = Command::new(herdr_binary());
        cmd.arg("iroh-bridge");
        cmd.arg("connect");
        cmd.arg(endpoint_id);
        cmd.arg("--socket");
        cmd.arg(local_socket);
        cmd.env("XDG_CONFIG_HOME", config_home);
        cmd.env("XDG_RUNTIME_DIR", runtime_dir);
        cmd.env_remove("HERDR_ENV");
        cmd.env("HERDR_IROH_KEY_NEW_PASSPHRASE", "e2e-test-pw-1234");
        cmd.env("HERDR_IROH_KEY_PASSPHRASE", "e2e-test-pw-1234");
        cmd.stdin(Stdio::null());
        // Inherit stdout so reconnect prints are visible in test output.
        cmd.stdout(Stdio::inherit());
        let stderr_path = config_home.join("herdr").join("iroh-connect-stderr.log");
        let stderr_file = fs::File::create(&stderr_path).expect("create connect stderr log");
        cmd.stderr(stderr_file);

        let mut child = cmd.spawn().expect("spawn iroh-bridge connect");

        // Wait for the bridge to bind (check file existence, don't connect).
        wait_for_socket_file(local_socket, Duration::from_secs(15));

        // Stabilize: the bridge may reconnect if the first QUIC attempt fails.
        // Wait for the socket file to remain present for a full second without
        // disappearing (which would indicate a reconnect cycle).
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(200));
            if !local_socket.exists() {
                // Socket was deleted — bridge reconnecting. Wait for it to
                // reappear and restart the stabilization check.
                wait_for_socket_file(local_socket, Duration::from_secs(15));
            }
        }

        // Quick check that the child hasn't already exited.
        if let Ok(Some(status)) = child.try_wait() {
            panic!("iroh-bridge connect exited early with {status}");
        }

        Self {
            child,
            local_socket: local_socket.to_path_buf(),
        }
    }
}

impl Drop for IrohBridgeConnect {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.local_socket);
    }
}

// ---------------------------------------------------------------------------
// Client handshake helpers (bincode v2 wire format)
// ---------------------------------------------------------------------------

fn encode_varint_u32(value: u32) -> Vec<u8> {
    if value < 251 {
        vec![value as u8]
    } else if value <= u16::MAX as u32 {
        let mut buf = vec![251];
        buf.extend_from_slice(&(value as u16).to_le_bytes());
        buf
    } else {
        let mut buf = vec![252];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }
}

fn encode_varint_u16(value: u16) -> Vec<u8> {
    encode_varint_u32(value as u32)
}

fn build_hello_frame(version: u32, cols: u16, rows: u16) -> Vec<u8> {
    // Matches ClientMessage::Hello encoding from server_headless.rs tests.
    let mut payload = Vec::new();
    // ClientMessage::Hello = variant 0
    payload.extend_from_slice(&encode_varint_u32(0));
    payload.extend_from_slice(&encode_varint_u32(version));
    payload.extend_from_slice(&encode_varint_u16(cols));
    payload.extend_from_slice(&encode_varint_u16(rows));
    payload.extend_from_slice(&encode_varint_u32(8)); // cell_width_px
    payload.extend_from_slice(&encode_varint_u32(16)); // cell_height_px
    payload.extend_from_slice(&encode_varint_u32(0)); // RenderEncoding::SemanticFrame
    payload.extend_from_slice(&encode_varint_u32(0)); // ClientKeybindings::Server
    payload.extend_from_slice(&encode_varint_u32(0)); // ClientLaunchMode::App

    let len = payload.len() as u32;
    let mut frame = len.to_le_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

#[derive(Debug)]
#[allow(dead_code)]
struct Welcome {
    version: u32,
    error: Option<String>,
}

fn read_welcome(stream: &mut UnixStream) -> Result<Welcome, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read frame len: {e}"))?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len > 1024 * 1024 {
        return Err(format!("frame too large: {payload_len}"));
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("read payload: {e}"))?;

    decode_welcome(&payload)
}

/// Decode ServerMessage::Welcome: variant 0, version: u32, error: Option<String>.
fn decode_welcome(payload: &[u8]) -> Result<Welcome, String> {
    let (variant, offset) = decode_varint(payload, 0)?;
    if variant != 0 {
        return Err(format!("not Welcome (variant={variant})"));
    }
    let (version, offset) = decode_varint(payload, offset)?;
    let (error, _) = decode_option_string(payload, offset)?;
    Ok(Welcome { version, error })
}

fn decode_varint(payload: &[u8], offset: usize) -> Result<(u32, usize), String> {
    if offset >= payload.len() {
        return Err("eof reading varint".to_string());
    }
    let first = payload[offset];
    match first {
        0..=250 => Ok((first as u32, offset + 1)),
        251 => {
            if offset + 3 > payload.len() {
                return Err("eof reading u16 varint".to_string());
            }
            let v = u16::from_le_bytes([payload[offset + 1], payload[offset + 2]]) as u32;
            Ok((v, offset + 3))
        }
        252 => {
            if offset + 5 > payload.len() {
                return Err("eof reading u32 varint".to_string());
            }
            let v = u32::from_le_bytes([
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
            ]);
            Ok((v, offset + 5))
        }
        _ => Err(format!("bad varint marker: {first}")),
    }
}

fn decode_option_string(payload: &[u8], offset: usize) -> Result<(Option<String>, usize), String> {
    // Option discriminant: 0 = None, 1 = Some
    if offset >= payload.len() {
        return Err("eof reading option".to_string());
    }
    match payload[offset] {
        0 => Ok((None, offset + 1)),
        1 => {
            let (len, offset) = decode_varint(payload, offset + 1)?;
            let end = offset + len as usize;
            if end > payload.len() {
                return Err("eof reading option string".to_string());
            }
            let s = String::from_utf8_lossy(&payload[offset..end]).to_string();
            Ok((Some(s), end))
        }
        _ => Err(format!("bad option discriminant: {}", payload[offset])),
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn iroh_bridge_e2e_handshake() {
    let _lock = test_lock();

    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr").join("api.sock");
    let client_socket = runtime_dir.join("herdr").join("api-client.sock");

    // 1. Start herdr server.
    let _server = spawn_server_headless(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&client_socket, Duration::from_secs(10));

    // 2. Start iroh bridge serve.
    let (_serve, endpoint_id) = IrohBridgeServe::spawn(&client_socket, &config_home, &runtime_dir);

    // 3. Start iroh bridge connect.
    let local_socket = base.join("bridge.sock");
    let _connect =
        IrohBridgeConnect::spawn(&endpoint_id, &local_socket, &config_home, &runtime_dir);

    // 4. Client handshake through the bridge.
    // The bridge connect may retry its QUIC connection on startup, recreating
    // the Unix socket.  Retry the connection + handshake if the bridge resets.
    let hello = build_hello_frame(support::CURRENT_PROTOCOL, 80, 24);
    let mut last_err = String::new();

    for attempt in 1..=5 {
        let mut stream = match UnixStream::connect(&local_socket) {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("connect attempt {attempt}: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        // Give the QUIC tunnel time to establish.
        thread::sleep(Duration::from_secs(3));

        if stream.write_all(&hello).is_err() {
            last_err = format!("write attempt {attempt}: bridge reset");
            thread::sleep(Duration::from_secs(2));
            continue;
        }
        if stream.flush().is_err() {
            last_err = format!("flush attempt {attempt}: bridge reset");
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        match read_welcome(&mut stream) {
            Ok(w) => {
                eprintln!("Welcome: version={}", w.version);
                assert_eq!(w.version, support::CURRENT_PROTOCOL);
                last_err.clear();
                break;
            }
            Err(e) => {
                last_err = format!("read attempt {attempt}: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        }
    }

    if !last_err.is_empty() {
        // Dump bridge process stderr logs for debugging.
        for (name, log) in &[
            (
                "serve",
                config_home.join("herdr").join("iroh-serve-stderr.log"),
            ),
            (
                "connect",
                config_home.join("herdr").join("iroh-connect-stderr.log"),
            ),
        ] {
            if let Ok(contents) = fs::read_to_string(log) {
                if !contents.trim().is_empty() {
                    eprintln!("=== iroh {name} stderr ===\n{contents}");
                }
            }
        }
        panic!("bridge handshake failed after retries: {last_err}");
    }

    drop(_connect);
    drop(_serve);
    drop(_server);
    cleanup_test_base(&base);
}
