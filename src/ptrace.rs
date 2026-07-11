use std::os::raw::{c_int, c_void};
use std::process::Child;

pub type Pid = libc::pid_t;

// macOS ptrace requests
pub const PT_TRACE_ME: c_int = 0;
pub const PT_CONTINUE: c_int = 7;
pub const PT_KILL: c_int = 8;
pub const PT_STEP: c_int = 9;
#[allow(dead_code)]
pub const PT_DETACH: c_int = 10;
#[allow(unused)]
pub const PT_ATTACHEXC: c_int = 14;

extern "C" {
    fn ptrace(request: c_int, pid: Pid, addr: *mut c_void, data: c_int) -> c_int;
}

fn check(ret: c_int, msg: &str) -> std::io::Result<()> {
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        eprintln!("{}: {}", msg, err);
        Err(err)
    } else {
        Ok(())
    }
}

/// 指定子プロセスを ptrace の対象にします（子プロセス内から呼びます）。
pub fn trace_me() -> std::io::Result<()> {
    unsafe { check(ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0), "PT_TRACE_ME") }
}

/// 子プロセスの実行を再開します。
pub fn cont(pid: Pid) -> std::io::Result<()> {
    unsafe { check(ptrace(PT_CONTINUE, pid, 1usize as *mut c_void, 0), "PT_CONTINUE") }
}

/// 子プロセスを 1 命令だけ実行します。
pub fn step(pid: Pid) -> std::io::Result<()> {
    unsafe { check(ptrace(PT_STEP, pid, 1usize as *mut c_void, 0), "PT_STEP") }
}

/// 子プロセスを終了します。
pub fn kill(pid: Pid) -> std::io::Result<()> {
    unsafe { check(ptrace(PT_KILL, pid, std::ptr::null_mut(), 0), "PT_KILL") }
}

/// 子プロセスをデタッチします。
#[allow(dead_code)]
pub fn detach(pid: Pid) -> std::io::Result<()> {
    unsafe { check(ptrace(PT_DETACH, pid, 1usize as *mut c_void, 0), "PT_DETACH") }
}

/// アタッチします（既存プロセスをデバッグする場合）。
#[allow(dead_code)]
pub fn attach(pid: Pid) -> std::io::Result<()> {
    unsafe { check(ptrace(PT_ATTACHEXC, pid, std::ptr::null_mut(), 0), "PT_ATTACHEXC") }
}

/// 子プロセスの pid を取得します。
pub fn pid_of(child: &Child) -> Pid {
    child.id() as Pid
}

