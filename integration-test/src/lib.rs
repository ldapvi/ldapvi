//! Test driver for ldapvi integration tests.
//!
//! Spawns `test-ldapvi` with:
//! - fd 3: a socketpair for structured protocol (CHOOSE/CHOSE, EDIT/EDITED, VIEW/VIEWED)
//! - stdout: a PTY so isatty(1) returns true (ldapvi requires this)
//! - stderr: a pipe, captured for assertions

use nix::pty::openpty;
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// A running test-ldapvi session.
pub struct TestSession {
    child: Child,
    /// Our end of the socketpair (fd 3 in the child).
    control: std::fs::File,
    /// Buffered reader for the control fd.
    control_reader: BufReader<std::fs::File>,
    /// Captured stdout (from PTY master), populated by background thread.
    stdout_capture: Arc<Mutex<Vec<u8>>>,
    /// Captured stderr, populated by background thread.
    stderr_capture: Arc<Mutex<Vec<u8>>>,
    /// Join handle for stdout drain thread.
    _stdout_thread: thread::JoinHandle<()>,
    /// Join handle for stderr drain thread.
    _stderr_thread: thread::JoinHandle<()>,
}

impl TestSession {
    /// Spawn test-ldapvi with the given arguments.
    ///
    /// `binary` is the path to the test-ldapvi binary.
    /// `args` are the command-line arguments.
    /// `env` are additional environment variables to set.
    pub fn spawn(
        binary: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> std::io::Result<TestSession> {
        Self::spawn_in(binary, args, env, None)
    }

    /// Like `spawn`, but with an optional working directory.
    pub fn spawn_in(
        binary: &str,
        args: &[&str],
        env: &[(&str, &str)],
        cwd: Option<&str>,
    ) -> std::io::Result<TestSession> {
        // Create socketpair for control channel (fd 3 in child).
        let (parent_sock, child_sock) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Create PTY for child's stdout.
        let pty = openpty(None, None)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let pty_master_fd = pty.master.into_raw_fd();
        let pty_slave_fd = pty.slave.into_raw_fd();

        let child_sock_fd = child_sock.into_raw_fd();

        let mut cmd = Command::new(binary);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }

        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }

        // stdin and stdout are set up in pre_exec (PTY slave) so
        // isatty(0) and isatty(1) both return true.
        // stderr is piped for capture.
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        // In the child (pre_exec), set up stdin, stdout, and fd 3.
        unsafe {
            cmd.pre_exec(move || {
                // Set up stdin and stdout as PTY slave.
                // Both must be a tty so fixup_streams() in ldapvi.c
                // doesn't try to reopen from /dev/tty.
                if libc::dup2(pty_slave_fd, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(pty_slave_fd, 1) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if pty_slave_fd > 1 {
                    libc::close(pty_slave_fd);
                }

                // Set up fd 3 as control channel.
                if child_sock_fd == 3 {
                    let flags = libc::fcntl(3, libc::F_GETFD);
                    libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                } else {
                    if libc::dup2(child_sock_fd, 3) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(child_sock_fd);
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn()?;

        // Close the child-side fds in the parent.
        unsafe {
            libc::close(child_sock_fd);
            libc::close(pty_slave_fd);
        }

        // Set up control channel: dup the fd so we have separate
        // read and write handles (BufReader and File).
        let parent_fd = parent_sock.into_raw_fd();
        let read_fd = unsafe { libc::dup(parent_fd) };
        let control_write = unsafe { std::fs::File::from_raw_fd(parent_fd) };
        let control_read = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let control_reader = BufReader::new(control_read);

        // Background thread to drain PTY master (prevents child blocking).
        let stdout_capture = Arc::new(Mutex::new(Vec::new()));
        let stdout_cap = Arc::clone(&stdout_capture);
        let stdout_thread = thread::spawn(move || {
            let mut master = unsafe { std::fs::File::from_raw_fd(pty_master_fd) };
            let mut buf = [0u8; 4096];
            loop {
                match master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        stdout_cap.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    Err(e) => {
                        // EIO is expected when the slave side closes.
                        if e.raw_os_error() == Some(libc::EIO) {
                            break;
                        }
                        eprintln!("stdout drain error: {e}");
                        break;
                    }
                }
            }
        });

        // Background thread to capture stderr.
        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
        let stderr_cap = Arc::clone(&stderr_capture);
        let stderr_pipe = child.stderr.take().unwrap();
        let stderr_thread = thread::spawn(move || {
            let mut pipe = stderr_pipe;
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        stderr_cap.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    Err(e) => {
                        eprintln!("stderr drain error: {e}");
                        break;
                    }
                }
            }
        });

        Ok(TestSession {
            child,
            control: control_write,
            control_reader,
            stdout_capture,
            stderr_capture,
            _stdout_thread: stdout_thread,
            _stderr_thread: stderr_thread,
        })
    }

    /// Read one line from the control fd.
    fn read_control_line(&mut self) -> String {
        let mut line = String::new();
        self.control_reader
            .read_line(&mut line)
            .expect("failed to read from control fd");
        line.truncate(line.trim_end_matches('\n').len());
        line
    }

    /// Read a `CHOOSE <charbag>` message from the control fd.
    /// Returns the charbag string.
    pub fn expect_choose(&mut self) -> String {
        let line = self.read_control_line();
        assert!(
            line.starts_with("CHOOSE "),
            "expected 'CHOOSE ...', got '{line}'"
        );
        line["CHOOSE ".len()..].to_string()
    }

    /// Send a `CHOSE <c>` response on the control fd.
    pub fn respond(&mut self, c: char) {
        write!(self.control, "CHOSE {c}\n").expect("failed to write to control fd");
        self.control.flush().expect("failed to flush control fd");
    }

    /// Read an `EDIT <pathname>` message from the control fd.
    /// Calls `editor_fn` with the pathname so the test can modify the file.
    /// Then sends `EDITED` back.
    pub fn expect_edit<F>(&mut self, editor_fn: F) -> String
    where
        F: FnOnce(&str),
    {
        let line = self.read_control_line();
        assert!(
            line.starts_with("EDIT "),
            "expected 'EDIT ...', got '{line}'"
        );
        let pathname = &line["EDIT ".len()..];
        editor_fn(pathname);
        write!(self.control, "EDITED\n").expect("failed to write to control fd");
        self.control.flush().expect("failed to flush control fd");
        pathname.to_string()
    }

    /// Read a `VIEW <pathname>` message from the control fd.
    /// Calls `view_fn` with the pathname so the test can inspect the file.
    /// Then sends `VIEWED` back.
    pub fn expect_view<F>(&mut self, view_fn: F) -> String
    where
        F: FnOnce(&str),
    {
        let line = self.read_control_line();
        assert!(
            line.starts_with("VIEW "),
            "expected 'VIEW ...', got '{line}'"
        );
        let pathname = &line["VIEW ".len()..];
        view_fn(pathname);
        write!(self.control, "VIEWED\n").expect("failed to write to control fd");
        self.control.flush().expect("failed to flush control fd");
        pathname.to_string()
    }

    /// Wait for the child to exit and assert the exit code.
    pub fn wait_exit(mut self, expected_code: i32) -> SessionOutput {
        let status = self.child.wait().expect("failed to wait for child");
        let code = status.code().unwrap_or(-1);

        // Drop control fd to unblock any pending reads in the child
        drop(self.control);

        // Wait for capture threads to finish.
        // (They'll finish once the child's fds close.)
        let _ = self._stdout_thread.join();
        let _ = self._stderr_thread.join();

        let stdout = String::from_utf8_lossy(&self.stdout_capture.lock().unwrap()).to_string();
        let stderr = String::from_utf8_lossy(&self.stderr_capture.lock().unwrap()).to_string();

        assert_eq!(
            code, expected_code,
            "expected exit code {expected_code}, got {code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        SessionOutput { stdout, stderr }
    }
}

/// Output captured from a completed session.
pub struct SessionOutput {
    pub stdout: String,
    pub stderr: String,
}
