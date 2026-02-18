use std::{
    io::{self, Write},
    os::{
        fd::RawFd,
        unix::{
            io::{AsRawFd, OwnedFd},
            net::UnixStream,
        },
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::Duration,
};

use crate::script::script_command_from_path;

#[derive(Clone)]
pub enum LoginAction {
    Expect { text: String, timeout: Duration },
    Send(String),
    Script { path: PathBuf, index: usize },
}

pub enum VmInput {
    Bytes(Vec<u8>),
    Shutdown,
}

pub(crate) enum VmOutput {
    LoginActionTimeout { action: String, timeout: Duration },
    GuestLogout,
}

#[derive(PartialEq, Eq)]
pub enum WaitResult {
    Timeout,
    Found,
}

#[derive(Default)]
pub struct OutputMonitor {
    buffer: Mutex<String>,
    condvar: Condvar,
    closed: AtomicBool,
}

impl OutputMonitor {
    pub fn push(&self, bytes: &[u8]) {
        self.buffer
            .lock()
            .unwrap()
            .push_str(&String::from_utf8_lossy(bytes));
        self.condvar.notify_all();
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.condvar.notify_all();
    }

    pub fn wait_for(&self, needle: &str, timeout: Duration) -> WaitResult {
        let (_unused, timeout_result) = self
            .condvar
            .wait_timeout_while(self.buffer.lock().unwrap(), timeout, |buf| {
                if self.closed.load(Ordering::Relaxed) { return false; }
                if let Some((_, remaining)) = buf.split_once(needle) {
                    *buf = remaining.to_string();
                    false
                } else {
                    true
                }
            })
            .unwrap();

        if self.closed.load(Ordering::Relaxed) || timeout_result.timed_out() {
            WaitResult::Timeout
        } else {
            WaitResult::Found
        }
    }

    /// Like `wait_for` but with no timeout. Returns `Found` or `Timeout` (if the
    /// monitor is closed before the needle appears).
    pub fn wait_forever(&self, needle: &str) -> WaitResult {
        let guard = self
            .condvar
            .wait_while(self.buffer.lock().unwrap(), |buf| {
                if self.closed.load(Ordering::Relaxed) { return false; }
                if let Some((_, remaining)) = buf.split_once(needle) {
                    *buf = remaining.to_string();
                    false
                } else {
                    true
                }
            })
            .unwrap();
        drop(guard);

        if self.closed.load(Ordering::Relaxed) {
            WaitResult::Timeout
        } else {
            WaitResult::Found
        }
    }
}

pub struct IoContext {
    pub input_tx: Sender<VmInput>,
    pub(crate) wakeup_write: OwnedFd,
    stdin_thread: thread::JoinHandle<()>,
    mux_thread: thread::JoinHandle<()>,
    stdout_thread: thread::JoinHandle<()>,
}

pub fn create_pipe() -> (OwnedFd, OwnedFd) {
    let (read_stream, write_stream) = UnixStream::pair().expect("Failed to create socket pair");
    (read_stream.into(), write_stream.into())
}

pub fn spawn_vm_io(
    output_monitor: Arc<OutputMonitor>,
    vm_output_fd: OwnedFd,
    vm_input_fd: OwnedFd,
) -> IoContext {
    let (input_tx, input_rx): (Sender<VmInput>, Receiver<VmInput>) = mpsc::channel();

    let raw_guard = Arc::new(Mutex::new(None));
    let (wakeup_read, wakeup_write) = create_pipe();

    enum PollResult<'a> {
        Ready(&'a [u8]),
        Spurious,
        Shutdown,
        Error,
    }

    fn poll_with_wakeup<'a>(main_fd: RawFd, wakeup_fd: RawFd, buf: &'a mut [u8]) -> PollResult<'a> {
        let mut fds = [
            libc::pollfd { fd: main_fd,   events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wakeup_fd, events: libc::POLLIN, revents: 0 },
        ];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ret <= 0 || fds[1].revents & libc::POLLIN != 0 {
            PollResult::Shutdown
        } else if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(main_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 { PollResult::Error }
            else if n == 0 { PollResult::Shutdown }
            else { PollResult::Ready(&buf[..(n as usize)]) }
        } else {
            PollResult::Spurious
        }
    }

    let stdin_thread = thread::spawn({
        let input_tx = input_tx.clone();
        let raw_guard = raw_guard.clone();
        let wakeup_read = wakeup_read.try_clone().unwrap();
        move || {
            let mut buf = [0u8; 1024];
            loop {
                match poll_with_wakeup(libc::STDIN_FILENO, wakeup_read.as_raw_fd(), &mut buf) {
                    PollResult::Shutdown | PollResult::Error => break,
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        if raw_guard.lock().unwrap().is_none() { continue; }
                        if input_tx.send(VmInput::Bytes(bytes.to_vec())).is_err() { break; }
                    }
                }
            }
        }
    });

    let stdout_thread = thread::spawn({
        let raw_guard = raw_guard.clone();
        let wakeup_read = wakeup_read.try_clone().unwrap();
        move || {
            let mut stdout = std::io::stdout().lock();
            let mut buf = [0u8; 1024];
            loop {
                match poll_with_wakeup(vm_output_fd.as_raw_fd(), wakeup_read.as_raw_fd(), &mut buf) {
                    PollResult::Shutdown | PollResult::Error => break,
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        let mut guard = raw_guard.lock().unwrap();
                        if guard.is_none()
                            && let Ok(g) = enable_raw_mode(libc::STDIN_FILENO)
                        {
                            *guard = Some(g);
                        }
                        if let Err(e) = stdout.write_all(bytes) {
                            eprintln!("[stdout_thread] write failed: {e:?}");
                            break;
                        }
                        let _ = stdout.flush();
                        output_monitor.push(bytes);
                    }
                }
            }
            // Signal any threads blocked in wait_forever that the VM output has closed.
            output_monitor.close();
        }
    });

    let mux_thread = thread::spawn(move || {
        let mut vm_writer = std::fs::File::from(vm_input_fd);
        loop {
            match input_rx.recv() {
                Ok(VmInput::Bytes(data)) => {
                    if let Err(e) = vm_writer.write_all(&data) {
                        eprintln!("[mux] write failed: {e:?}");
                        break;
                    }
                }
                Ok(VmInput::Shutdown) | Err(_) => break,
            }
        }
    });

    IoContext { input_tx, wakeup_write, stdin_thread, mux_thread, stdout_thread }
}

impl IoContext {
    pub fn shutdown(self) {
        let _ = self.input_tx.send(VmInput::Shutdown);
        unsafe { libc::write(self.wakeup_write.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        let _ = self.stdin_thread.join();
        let _ = self.stdout_thread.join();
        let _ = self.mux_thread.join();
    }
}

pub fn spawn_login_actions_thread(
    login_actions: Vec<LoginAction>,
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<VmInput>,
    vm_output_tx: mpsc::Sender<VmOutput>,
) -> thread::JoinHandle<()> {
    use LoginAction::*;
    thread::spawn(move || {
        for a in login_actions {
            match a {
                Expect { text, timeout } => {
                    if WaitResult::Timeout == output_monitor.wait_for(&text, timeout) {
                        let _ = vm_output_tx.send(VmOutput::LoginActionTimeout {
                            action: format!("expect '{}'", text),
                            timeout,
                        });
                        return;
                    }
                }
                Send(mut text) => {
                    text.push('\n');
                    input_tx.send(VmInput::Bytes(text.into_bytes())).unwrap();
                }
                Script { path, index } => {
                    let command = match script_command_from_path(&path, index) {
                        Ok(c) => c,
                        Err(err) => { eprintln!("{err}"); return; }
                    };
                    let mut text = command;
                    text.push('\n');
                    input_tx.send(VmInput::Bytes(text.into_bytes())).unwrap();
                }
            }
        }

        // All login actions completed — now watch for the user logging out.
        // When the shell exits, the guest will print the login prompt again.
        if WaitResult::Found == output_monitor.wait_forever("login: ") {
            let _ = vm_output_tx.send(VmOutput::GuestLogout);
        }
    })
}

pub fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let original = attributes;
    attributes.c_iflag &= !(libc::ICRNL);
    attributes.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    attributes.c_cc[libc::VMIN] = 0;
    attributes.c_cc[libc::VTIME] = 1;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(RawModeGuard { fd, original })
}

pub struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original); }
    }
}
