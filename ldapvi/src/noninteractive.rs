use std::io::{BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::sync::OnceLock;

const CONTROL_FD: i32 = 3;

struct ControlChannel {
    writer: std::fs::File,
    reader: BufReader<std::fs::File>,
}

impl ControlChannel {
    fn open() -> Self {
        unsafe {
            let write_fd = nix::libc::dup(CONTROL_FD);
            let writer = std::fs::File::from_raw_fd(CONTROL_FD);
            let reader = BufReader::new(std::fs::File::from_raw_fd(write_fd));
            ControlChannel { writer, reader }
        }
    }

    fn send(&mut self, msg: &str) {
        write!(self.writer, "{}\n", msg).expect("failed to write to control fd");
        self.writer.flush().expect("failed to flush control fd");
    }

    fn recv(&mut self) -> String {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .expect("failed to read from control fd");
        line.truncate(line.trim_end_matches('\n').len());
        line
    }
}

static CONTROL: OnceLock<std::sync::Mutex<ControlChannel>> = OnceLock::new();

fn control() -> &'static std::sync::Mutex<ControlChannel> {
    CONTROL.get_or_init(|| std::sync::Mutex::new(ControlChannel::open()))
}

/// Present a single-character menu prompt. Returns the chosen character.
pub fn choose(prompt: &str, charbag: &str, _help: &str) -> char {
    // Echo prompt to stdout for observability
    print!("{}", prompt);
    let _ = std::io::stdout().flush();

    let mut ctrl = control().lock().unwrap();
    ctrl.send(&format!("CHOOSE {}", charbag));
    let response = ctrl.recv();

    if !response.starts_with("CHOSE ") {
        panic!("expected 'CHOSE ...', got '{}'", response);
    }
    let c = response["CHOSE ".len()..].chars().next().unwrap();
    if !charbag.contains(c) {
        panic!("invalid choice '{}', expected one of '{}'", c, charbag);
    }
    c
}

/// Open an external editor on the given file.
pub fn edit(pathname: &str, _line: Option<i64>) {
    let mut ctrl = control().lock().unwrap();
    ctrl.send(&format!("EDIT {}", pathname));
    let response = ctrl.recv();
    if response != "EDITED" {
        panic!("expected 'EDITED', got '{}'", response);
    }
}

/// Open an external pager to view the given file.
pub fn view(pathname: &str) {
    let mut ctrl = control().lock().unwrap();
    ctrl.send(&format!("VIEW {}", pathname));
    let response = ctrl.recv();
    if response != "VIEWED" {
        panic!("expected 'VIEWED', got '{}'", response);
    }
}

/// Prompt for a line of text input from the user.
pub fn read_line(prompt: &str) -> String {
    let mut ctrl = control().lock().unwrap();
    ctrl.send(&format!("READLINE {}", prompt));
    ctrl.recv()
}

/// Prompt for a password (input is not echoed).
pub fn read_password(prompt: &str) -> String {
    read_line(prompt)
}

/// Convert a byte offset in a file to a 1-based line number.
pub fn line_number(pathname: &str, pos: u64) -> Option<i64> {
    let data = std::fs::read(pathname).ok()?;
    if pos as usize > data.len() {
        return None;
    }
    let line = data[..pos as usize].iter().filter(|&&b| b == b'\n').count() + 1;
    Some(line as i64)
}
