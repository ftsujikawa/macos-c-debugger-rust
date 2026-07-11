use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::breakpoint::Breakpoint;
use crate::mach;
use crate::ptrace::{self, Pid};
use crate::register::ThreadState64;

#[derive(Debug, Clone, Copy)]
pub enum WaitStatus {
    Stopped { signal: i32, pc: u64 },
    Exited { code: i32 },
    Signaled { signal: i32 },
    Unknown { status: i32 },
}

pub struct Debugger {
    pub pid: Pid,
    _child: Child,
    breakpoints: HashMap<usize, Breakpoint>,
    last_status: Option<WaitStatus>,
    /// 直前の停止がブレークポイントヒットによるものならそのアドレス
    at_breakpoint: Option<usize>,
}

impl Debugger {
    /// 指定したプログラムを子プロセスとして起動し、最初の SIGTRAP まで待ちます。
    pub fn new(program: &str, args: &[String]) -> io::Result<Self> {
        let mut cmd = Command::new(program);
        for a in args {
            cmd.arg(a);
        }

        unsafe {
            cmd.pre_exec(|| ptrace::trace_me());
        }

        let child = cmd.spawn()?;
        let pid = ptrace::pid_of(&child);

        let mut me = Self {
            pid,
            _child: child,
            breakpoints: HashMap::new(),
            last_status: None,
            at_breakpoint: None,
        };

        let status = me.wait()?;
        me.last_status = Some(status);
        Ok(me)
    }

    /// 子プロセスを 1 ステップ実行します。
    pub fn step(&mut self) -> io::Result<WaitStatus> {
        if let Some(addr) = self.at_breakpoint.take() {
            self.step_over_breakpoint(addr)?;
        } else {
            ptrace::step(self.pid)?;
            let status = self.wait()?;
            self.last_status = Some(status);
        }
        // ステップ先がブレークポイントの先頭に着地した場合を記録
        if let Ok(pc) = self.pc() {
            let pc = pc as usize;
            if self.breakpoints.get(&pc).map_or(false, |b| b.is_enabled()) {
                self.at_breakpoint = Some(pc);
            }
        }
        Ok(self.last_status.unwrap())
    }

    /// 子プロセスの実行を再開します。
    pub fn cont(&mut self) -> io::Result<WaitStatus> {
        if let Some(addr) = self.at_breakpoint.take() {
            self.step_over_breakpoint(addr)?;
            if !matches!(self.last_status, Some(WaitStatus::Stopped { .. })) {
                return Ok(self.last_status.unwrap());
            }
        }
        ptrace::cont(self.pid)?;
        let status = self.wait()?;
        self.last_status = Some(status);
        self.handle_breakpoint_hit()?;
        Ok(self.last_status.unwrap())
    }

    /// リターンアドレスを取得します。
    /// プロローグの実行状態（rbp/fp と rsp/sp の大小関係）に応じて取得先を切り替えます。
    fn return_address(&self) -> io::Result<usize> {
        let regs = self.registers()?;

        #[cfg(target_arch = "x86_64")]
        {
            let rbp = regs.__rbp as usize;
            let rsp = regs.__rsp as usize;
            if rbp > rsp {
                // プロローグ前: [rsp] の値が rbp と等しければ push rbp 済み → [rsp+8]
                //               そうでなければ [rsp] がリターンアドレス
                let buf = self.read_memory(rsp, 8)?;
                let at_rsp = u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize;
                if at_rsp == rbp {
                    let buf = self.read_memory(rsp + 8, 8)?;
                    Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
                } else {
                    Ok(at_rsp)
                }
            } else {
                // プロローグ後: [rbp+8] がリターンアドレス
                let buf = self.read_memory(rbp + 8, 8)?;
                Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            let fp = regs.__fp as usize;
            let sp = regs.__sp as usize;
            if fp == 0 || fp > sp {
                // プロローグ前: lr レジスタがリターンアドレス
                Ok(regs.__lr as usize)
            } else {
                // プロローグ後: [fp+8] がリターンアドレス
                let buf = self.read_memory(fp + 8, 8)?;
                Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
            }
        }
    }

    /// 現在の関数から復帰するまで実行します。
    /// リターンアドレスに一時ブレークポイントを張って continue します。
    pub fn finish(&mut self) -> io::Result<WaitStatus> {
        let ret_addr = self.return_address()?;

        let existing = self.breakpoints.contains_key(&ret_addr);
        if !existing {
            self.set_breakpoint(ret_addr)?;
        }
        let status = self.cont()?;
        if !existing {
            if matches!(status, WaitStatus::Stopped { .. }) {
                self.remove_breakpoint(ret_addr)?;
            } else {
                // プロセスが終了している場合はメモリ復元せず削除のみ
                self.breakpoints.remove(&ret_addr);
            }
        }
        Ok(status)
    }

    /// ブレークポイントを設定します。
    pub fn set_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        let mut bp = Breakpoint::new(addr);
        bp.enable(self.pid)?;
        self.breakpoints.insert(addr, bp);
        Ok(())
    }

    /// ブレークポイントを削除します。
    pub fn remove_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        if let Some(mut bp) = self.breakpoints.remove(&addr) {
            bp.disable(self.pid)?;
        }
        if self.at_breakpoint == Some(addr) {
            self.at_breakpoint = None;
        }
        Ok(())
    }

    /// 汎用レジスタを取得します。
    pub fn registers(&self) -> io::Result<ThreadState64> {
        mach::get_registers(self.pid)
    }

    /// 汎用レジスタを設定します。
    pub fn set_registers(&self, regs: &ThreadState64) -> io::Result<()> {
        mach::set_registers(self.pid, regs)
    }

    /// プログラムカウンタを取得します。
    pub fn pc(&self) -> io::Result<u64> {
        self.registers().map(|r| r.pc())
    }

    /// 指定アドレスから 4 バイトを読みます。
    pub fn read_word(&self, addr: usize) -> io::Result<u32> {
        mach::read_word(self.pid, addr)
    }

    /// 指定アドレスに任意バイト列を書きます。
    pub fn write_memory(&self, addr: usize, data: &[u8]) -> io::Result<()> {
        mach::write_memory(self.pid, addr, data)
    }

    /// 指定アドレスからメモリを読みます。
    /// ブレークポイントの int3 (0xCC) は元のバイトに置き換えて返します。
    pub fn read_memory(&self, addr: usize, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = mach::read_memory(self.pid, addr, len)?;
        for (bp_addr, bp) in &self.breakpoints {
            if bp.is_enabled() && *bp_addr >= addr && *bp_addr < addr + buf.len() {
                buf[*bp_addr - addr] = bp.saved_byte();
            }
        }
        Ok(buf)
    }

    /// 指定アドレスから 1 バイトを読みます。
    #[allow(dead_code)]
    pub fn read_byte(&self, addr: usize) -> io::Result<u8> {
        mach::read_byte(self.pid, addr)
    }

    /// 指定アドレスに 1 バイトを書きます。
    #[allow(dead_code)]
    pub fn write_byte(&self, addr: usize, value: u8) -> io::Result<()> {
        mach::write_byte(self.pid, addr, value)
    }

    /// メイン実行ファイルの実行時ベースアドレスを取得します。
    pub fn image_base(&self) -> io::Result<u64> {
        mach::get_text_base(self.pid)
    }

    /// 子プロセスをキルします。
    pub fn kill(&self) -> io::Result<()> {
        ptrace::kill(self.pid)
    }

    /// 子プロセスをデタッチします。
    #[allow(dead_code)]
    pub fn detach(&self) -> io::Result<()> {
        ptrace::detach(self.pid)
    }

    /// 現在の停止状態を取得します。
    pub fn last_status(&self) -> Option<WaitStatus> {
        self.last_status
    }

    /// PT_CONTINUE 後の停止がブレークポイントヒットか判定し、
    /// ヒットしていたら PC を BP 先頭に巻き戻して記録します。
    /// (int3 は 1 バイトなので、ヒット直後の PC は BP アドレス + 1)
    fn handle_breakpoint_hit(&mut self) -> io::Result<()> {
        if let Some(WaitStatus::Stopped { signal, pc }) = self.last_status {
            if signal != libc::SIGTRAP {
                return Ok(());
            }
            let bp_addr = (pc as usize).wrapping_sub(1);
            if self.breakpoints.get(&bp_addr).map_or(false, |b| b.is_enabled()) {
                let mut regs = self.registers()?;
                regs.set_pc(bp_addr as u64);
                mach::set_registers(self.pid, &regs)?;
                self.at_breakpoint = Some(bp_addr);
                self.last_status = Some(WaitStatus::Stopped {
                    signal,
                    pc: bp_addr as u64,
                });
            }
        }
        Ok(())
    }

    /// ブレークポイントを「踏み越え」て 1 命令実行し、BP を再設定します。
    fn step_over_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        let mut bp = self
            .breakpoints
            .remove(&addr)
            .expect("missing breakpoint");

        bp.disable(self.pid)?;

        // PC を BP 先頭に戻してステップ実行
        let mut regs = self.registers()?;
        regs.set_pc(addr as u64);
        mach::set_registers(self.pid, &regs)?;

        ptrace::step(self.pid)?;
        let status = self.wait()?;
        self.last_status = Some(status);

        bp.re_enable(self.pid)?;
        self.breakpoints.insert(addr, bp);
        Ok(())
    }

    /// waitpid し、停止/終了/シグナル状態を判定します。
    fn wait(&mut self) -> io::Result<WaitStatus> {
        let mut status: i32 = 0;
        loop {
            let ret = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if ret == -1 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // シグナルで割り込まれた場合は再試行
                    continue;
                }
                return Err(err);
            }
            break;
        }

        let pc = self.pc().unwrap_or(0);

        let s = if (status & 0x7f) == 0x7f {
            WaitStatus::Stopped {
                signal: (status >> 8) & 0xff,
                pc,
            }
        } else if (status & 0x7f) == 0 {
            WaitStatus::Exited {
                code: (status >> 8) & 0xff,
            }
        } else if (status & 0x7f) != 0x7f {
            WaitStatus::Signaled {
                signal: status & 0x7f,
            }
        } else {
            WaitStatus::Unknown { status }
        };

        Ok(s)
    }
}
