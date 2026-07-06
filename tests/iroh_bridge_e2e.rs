//! End-to-end test for the iroh bridge.
//!
//! Starts a herdr server, bridges it over iroh QUIC using the iroh_bridge
//! API in-process (no separate subprocesses for the bridge), and validates
//! the client handshake through the tunnel.
//!
//! Unlike the subprocess-based approach, this uses a shared tokio runtime
//! and in-memory iroh endpoints, avoiding the need for network-layer QUIC
//! connectivity (loopback UDP, relay servers) on restricted CI runners.

mod support;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::{
    endpoint::Connection,
    protocol::{ProtocolHandler, Router},
};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use support::{cleanup_test_base, register_runtime_dir, register_spawned_herdr_pid};

use herdr::iroh_bridge;

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

// ---------------------------------------------------------------------------
// Bincode helpers
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
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_varint_u32(0)); // ClientMessage::Hello
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

#[derive(Debug)]
#[allow(dead_code)]
struct Welcome {
    version: u32,
    error: Option<String>,
}

fn decode_welcome(payload: &[u8]) -> Result<Welcome, String> {
    let (variant, offset) = decode_varint(payload, 0)?;
    if variant != 0 {
        return Err(format!("not Welcome (variant={variant})"));
    }
    let (version, offset) = decode_varint(payload, offset)?;
    let (error, _) = decode_option_string(payload, offset)?;
    Ok(Welcome { version, error })
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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// End-to-end iroh bridge test using the in-process API.
///
/// 1. Start herdr server (headless)
/// 2. Bind iroh endpoints in-process with ephemeral keys
/// 3. Spawn serve side: accept QUIC connection → bridge to server socket
/// 4. Connect side: connect to serve → open bi stream → bridge to Unix pair
/// 5. Send client handshake through the bridged Unix stream
/// 6. Validate Welcome response
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

    // 2. Set up a shared tokio runtime for both iroh endpoints.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        // Bind both endpoints with ephemeral keys — no keyfile needed.
        let (serve_endpoint, serve_id) = iroh_bridge::bind_endpoint(None, vec![]).await.unwrap();
        let (connect_endpoint, _) = iroh_bridge::bind_endpoint(None, vec![]).await.unwrap();

        eprintln!("[serve] endpoint = {serve_id}");

        // 3. Set up the serve side with a Router + ProtocolHandler that
        //    bridges incoming iroh connections to the herdr server socket.
        let serve_socket = client_socket.clone();
        let serve_ep = serve_endpoint.clone();

        #[derive(Debug)]
        struct TestBridgeHandler {
            server_socket: PathBuf,
        }

        impl ProtocolHandler for TestBridgeHandler {
            async fn accept(
                &self,
                connection: Connection,
            ) -> Result<(), iroh::protocol::AcceptError> {
                let (iroh_send, iroh_recv) = match connection.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => return Ok(()),
                };
                let server_stream = match tokio::net::UnixStream::connect(&self.server_socket).await
                {
                    Ok(s) => s,
                    Err(_) => return Ok(()),
                };
                let (mut server_read, mut server_write) = server_stream.into_split();
                let (mut iroh_read, mut iroh_write) =
                    (tokio::io::BufReader::new(iroh_recv), iroh_send);
                let up = async {
                    let _ = tokio::io::copy(&mut server_read, &mut iroh_write).await;
                };
                let down = async {
                    let _ = tokio::io::copy(&mut iroh_read, &mut server_write).await;
                };
                tokio::join!(up, down);
                Ok(())
            }
        }

        let _router = Router::builder(serve_ep)
            .accept(
                iroh_bridge::ALPN,
                TestBridgeHandler {
                    server_socket: serve_socket,
                },
            )
            .spawn();

        // 4. Connect side: connect to the serve endpoint, open a bidirectional
        //    stream, and bridge to a Unix socket pair for the test client.
        let conn = connect_endpoint
            .connect(serve_id, iroh_bridge::ALPN)
            .await
            .expect("connect to serve");

        let (iroh_send, iroh_recv) = conn.open_bi().await.expect("open bidirectional stream");

        // Create a Unix socket pair for the test client.
        let (bridge_stream, test_stream) =
            tokio::net::UnixStream::pair().expect("UnixStream::pair");

        // Bridge the test stream ↔ iroh stream.
        let bridge_task = tokio::spawn(async move {
            let (mut local_read, mut local_write) = bridge_stream.into_split();
            let (mut iroh_read, mut iroh_write) = (tokio::io::BufReader::new(iroh_recv), iroh_send);

            let up = async {
                let _ = tokio::io::copy(&mut local_read, &mut iroh_write).await;
            };
            let down = async {
                let _ = tokio::io::copy(&mut iroh_read, &mut local_write).await;
            };
            tokio::join!(up, down);
        });

        // 5. Send client handshake through the bridged test stream.
        let mut std_stream = test_stream
            .into_std()
            .expect("convert tokio UnixStream to std");
        // into_std may leave the fd non-blocking; force blocking for reads.
        std_stream.set_nonblocking(false).expect("set blocking");

        let hello = build_hello_frame(support::CURRENT_PROTOCOL, 80, 24);
        std_stream.write_all(&hello).expect("write hello");
        std_stream.flush().expect("flush hello");

        let welcome = read_welcome(&mut std_stream).expect("read welcome");
        eprintln!("Welcome: version={}", welcome.version);
        assert_eq!(welcome.version, support::CURRENT_PROTOCOL);

        // Cleanup.
        serve_endpoint.close().await;
        connect_endpoint.close().await;
        bridge_task.abort();
        let _ = bridge_task.await;
    });

    drop(_server);
    cleanup_test_base(&base);
}
