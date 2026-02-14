use std::io::{Read, Write};
use std::os::fd::BorrowedFd;
use std::process::Command;

/// Present a single-character menu prompt. Returns the chosen character.
pub fn choose(prompt: &str, charbag: &str, help: &str) -> char {
    use nix::sys::termios;

    let stdin_fd = unsafe { BorrowedFd::borrow_raw(0) };
    let old_term = termios::tcgetattr(stdin_fd).expect("tcgetattr failed");
    let mut raw_term = old_term.clone();

    // Disable canonical mode and echo
    raw_term.local_flags &= !(termios::LocalFlags::ICANON | termios::LocalFlags::ECHO);
    raw_term.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 1;
    raw_term.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 0;
    termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, &raw_term).expect("tcsetattr failed");

    let result;
    loop {
        // Print prompt and valid choices
        eprint!("{} [", prompt);
        for c in charbag.chars() {
            if c > ' ' {
                eprint!("{}", c);
            }
        }
        eprint!("] ");

        let mut buf = [0u8; 1];
        let n = std::io::stdin().lock().read(&mut buf).unwrap_or(0);
        if n == 0 {
            continue;
        }
        let c = buf[0] as char;
        eprintln!("{}", c);

        if charbag.contains(c) {
            result = c;
            break;
        }
        eprintln!("{}", help);
    }

    // Restore terminal
    termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, &old_term)
        .expect("tcsetattr restore failed");
    result
}

/// Open an external editor on the given file.
pub fn edit(pathname: &str, line: Option<i64>) {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    let mut cmd = Command::new("sh");
    cmd.arg("-c");

    if let Some(line) = line {
        if line > 0 {
            cmd.arg(format!("exec \"$0\" +{} \"$1\"", line));
            cmd.arg(&editor);
            cmd.arg(pathname);
        } else {
            cmd.arg("exec \"$0\" \"$1\"");
            cmd.arg(&editor);
            cmd.arg(pathname);
        }
    } else {
        cmd.arg("exec \"$0\" \"$1\"");
        cmd.arg(&editor);
        cmd.arg(pathname);
    }

    let status = cmd.status().expect("failed to spawn editor");
    if !status.success() {
        eprintln!("editor died with status {:?}", status.code());
    }
}

/// Open an external pager to view the given file.
pub fn view(pathname: &str) {
    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".to_string());

    let status = Command::new("sh")
        .arg("-c")
        .arg("exec \"$0\" \"$1\"")
        .arg(&pager)
        .arg(pathname)
        .status()
        .expect("failed to spawn pager");

    if !status.success() {
        eprintln!("pager died with status {:?}", status.code());
    }
}

/// Prompt for a line of text input from the user.
pub fn read_line(prompt: &str) -> String {
    use std::io::BufRead;

    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap_or(0);
    line.truncate(line.trim_end_matches('\n').trim_end_matches('\r').len());
    line
}

/// Prompt for a password (input is not echoed).
pub fn read_password(prompt: &str) -> String {
    use nix::sys::termios;
    use std::io::BufRead;

    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();

    let stdin_fd = unsafe { BorrowedFd::borrow_raw(0) };
    let old_term = termios::tcgetattr(stdin_fd).expect("tcgetattr failed");
    let mut noecho_term = old_term.clone();
    noecho_term.local_flags &= !termios::LocalFlags::ECHO;
    termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, &noecho_term).expect("tcsetattr failed");

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap_or(0);

    termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, &old_term)
        .expect("tcsetattr restore failed");
    eprintln!(); // newline after hidden input

    line.truncate(line.trim_end_matches('\n').trim_end_matches('\r').len());
    line
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
