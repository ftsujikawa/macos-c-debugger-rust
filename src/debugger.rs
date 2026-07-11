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
    /// 現在の命令バイトを読んでプロローグの実行段階を正確に判定します。
    fn return_address(&self) -> io::Result<usize> {
        let regs = self.registers()?;
        let pc = regs.pc() as usize;

        #[cfg(target_arch = "x86_64")]
        {
            let rbp = regs.__rbp as usize;
            let rsp = regs.__rsp as usize;

            // 現在の命令バイトでプロローグ段階を判定
            let instr = self.read_memory(pc, 3).unwrap_or_default();
            let ret_addr = if instr.first().copied() == Some(0x55) {
                // push rbp の直前:
                //   rsp → [return_address]
                let buf = self.read_memory(rsp, 8)?;
                u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize
            } else if instr.starts_with(&[0x48, 0x89, 0xe5]) {
                // push rbp 完了・mov rbp, rsp の直前:
                //   rsp → [saved_rbp], rsp+8 → [return_address]
                let buf = self.read_memory(rsp + 8, 8)?;
                u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize
            } else {
                // プロローグ完了後の通常フレーム:
                //   rbp → [saved_rbp], rbp+8 → [return_address]
                let buf = self.read_memory(rbp + 8, 8)?;
                u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize
            };
            Ok(ret_addr)
        }

        #[cfg(target_arch = "aarch64")]
        {
            let fp = regs.__fp as usize;
            let sp = regs.__sp as usize;

            // 現在の命令バイトでプロローグ段階を判定
            // stp x29, x30, [sp, #-16]! = 0xFD 0x7B 0xBF 0xA9
            let instr = self.read_memory(pc, 4).unwrap_or_default();
            if instr.starts_with(&[0xfd, 0x7b, 0xbf, 0xa9]) || fp == 0 {
                // stp 命令の直前 (lr がまだスタックに保存されていない):
                // lr レジスタがリターンアドレス
                Ok(regs.__lr as usize)
            } else {
                // プロローグ完了後: [fp+8] がリターンアドレス (保存済み lr)
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

    /// 関数先頭アドレスからプロローグ命令をスキップした最初の本体命令のアドレスを返します。
    /// プロセスのメモリを直接読んで判定するため、DWARF 情報がなくても動作します。
    ///
    /// x86_64: push rbp / mov rbp, rsp / [sub rsp, N] をスキップ
    /// aarch64: stp x29, x30, [sp, #-16]! / mov x29, sp / [sub sp, sp, N] をスキップ
    pub fn skip_prologue_insns(&self, addr: usize) -> usize {
        let Ok(code) = self.read_memory(addr, 16) else {
            return addr;
        };

        #[cfg(target_arch = "x86_64")]
        {
            let mut off = 0usize;
            // push rbp (55)
            if code.get(off) != Some(&0x55) {
                return addr;
            }
            off += 1;
            // mov rbp, rsp (48 89 e5)
            if code.get(off..off + 3) != Some(&[0x48, 0x89, 0xe5]) {
                return addr + off;
            }
            off += 3;
            // optional: sub rsp, imm8  (48 83 ec XX)
            //        or  sub rsp, imm32 (48 81 ec XX XX XX XX)
            if code.get(off..off + 3) == Some(&[0x48, 0x83, 0xec]) {
                off += 4;
            } else if code.get(off..off + 3) == Some(&[0x48, 0x81, 0xec]) {
                off += 7;
            }
            addr + off
        }

        #[cfg(target_arch = "aarch64")]
        {
            let mut off = 0usize;
            // stp x29, x30, [sp, #-16]!  (fd 7b bf a9)
            if code.get(off..off + 4) != Some(&[0xfd, 0x7b, 0xbf, 0xa9]) {
                return addr;
            }
            off += 4;
            // mov x29, sp  (fd 03 00 91)
            if code.get(off..off + 4) != Some(&[0xfd, 0x03, 0x00, 0x91]) {
                return addr + off;
            }
            off += 4;
            // optional: sub sp, sp, #N  (ff XX XX d1)
            if code.get(off + 3) == Some(&0xd1)
                && code.get(off..off + 2) == Some(&[0xff, 0xff])
            {
                off += 4;
            }
            addr + off
        }
    }

    /// ブレークポイントを設定します。
    pub fn set_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        let mut bp = Breakpoint::new(addr);
        bp.enable(self.pid)?;
        self.breakpoints.insert(addr, bp);
        Ok(())
    }

    /// 設定済みブレークポイントのアドレス一覧をソートして返します。
    pub fn breakpoint_addrs(&self) -> Vec<usize> {
        let mut addrs: Vec<usize> = self.breakpoints.keys().cloned().collect();
        addrs.sort();
        addrs
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
