use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::arch::Arch;
use crate::breakpoint::Breakpoint;
use crate::mach;
use crate::ptrace::{self, Pid};
use crate::register::ThreadState64;
#[cfg(target_arch = "x86_64")]
use crate::register::FloatState64;

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
    /// デバッグ対象のアーキテクチャ
    arch: Arch,
    /// ARM64 HW BP スロット管理 (slot → addr)
    #[cfg(target_arch = "aarch64")]
    hw_bp_slots: [Option<usize>; 16],
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
            arch: Arch::X86_64, // 仮初期値、exec 停止後に上書き
            #[cfg(target_arch = "aarch64")]
            hw_bp_slots: [None; 16],
        };

        let status = me.wait()?;
        me.last_status = Some(status);

        // exec 停止後に対象バイナリの Mach-O ヘッダからアーキテクチャを検出する
        me.arch = mach::detect_arch(pid)?;

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

            // 現在の命令がプロローグ先頭 (stp x29, x30, [sp, #-16]!) かチェック
            let instr = self.read_memory(pc, 4).unwrap_or_default();
            if instr.starts_with(&[0xfd, 0x7b, 0xbf, 0xa9]) || fp == 0 {
                // stp 直前: フレーム未設定なので lr がリターンアドレス
                return Ok(regs.__lr as usize);
            }

            // ブレークポイントアドレスを関数先頭ヒントとして使う。
            // `b func` で止まっているとき at_breakpoint には BP 設定アドレス
            // (= 関数エントリ付近) が入っている。
            // この範囲だけをスキャンすることで、Mach-O ヘッダなど
            // コード外領域への誤スキャンを防ぐ。
            //
            // STP x29, x30, [sp, offset] エンコード:
            //   byte[0]=0xfd, byte[1]=0x7b, byte[3]=0xa9  (byte[2] はオフセット依存)
            if let Some(func_start) = self.at_breakpoint {
                if pc >= func_start {
                    // 関数先頭 (BP位置) から現在 PC まで stp を探す
                    let scan_len = pc - func_start;
                    let code = self.read_memory(func_start, scan_len).unwrap_or_default();
                    let has_frame_save = code.windows(4).any(|w| {
                        w[0] == 0xfd && w[1] == 0x7b && w[3] == 0xa9
                    });
                    return if has_frame_save {
                        // 非リーフ: フレーム設定済み → [fp+8] = 保存済み lr
                        let buf = self.read_memory(fp + 8, 8)?;
                        Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
                    } else {
                        // リーフ or フレーム未設定: lr がリターンアドレス
                        Ok(regs.__lr as usize)
                    };
                }
            }

            // at_breakpoint なし (ステップ実行中など): フォールバック
            // プロローグ完了後と仮定して [fp+8] を使う
            let buf = self.read_memory(fp + 8, 8)?;
            Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
        }
    }

    /// 現在の関数から復帰するまで実行します。
    /// x86_64: リターンアドレスにソフトウェア BP を一時設定して continue。
    /// aarch64: コードページ書き込み制限のためハードウェア BP (BVR/BCR) を使用。
    pub fn finish(&mut self) -> io::Result<WaitStatus> {
        let ret_addr = self.return_address()?;

        #[cfg(target_arch = "aarch64")]
        return self.finish_with_hw_bp(ret_addr);

        #[cfg(target_arch = "x86_64")]
        {
            let existing = self.breakpoints.contains_key(&ret_addr);
            if !existing {
                self.set_breakpoint(ret_addr)?;
            }
            let status = self.cont()?;
            if !existing {
                if matches!(status, WaitStatus::Stopped { .. }) {
                    self.remove_breakpoint(ret_addr)?;
                } else {
                    self.breakpoints.remove(&ret_addr);
                }
            }
            Ok(status)
        }
    }

    /// ARM64 専用: ハードウェア BP を使って finish を実装します。
    /// コードページへの書き込みが不要なため、mid-execution でも動作します。
    /// 空きスロットを動的に割り当てて一時 BP を設定します。
    #[cfg(target_arch = "aarch64")]
    fn finish_with_hw_bp(&mut self, ret_addr: usize) -> io::Result<WaitStatus> {
        // 空きスロットに一時 HW BP を設定
        let finish_slot = self.alloc_hw_slot(ret_addr)?;
        mach::set_hw_breakpoint_slot(self.pid, finish_slot, ret_addr)?;

        // ユーザー HW BP に止まっている場合はステップオーバーしてから continue
        if let Some(addr) = self.at_breakpoint.take() {
            self.step_over_breakpoint(addr)?;
            if !matches!(self.last_status, Some(WaitStatus::Stopped { .. })) {
                // ステップ中にプロセスが終了
                let _ = mach::clear_hw_breakpoint_slot(self.pid, finish_slot);
                self.release_hw_slot(finish_slot);
                return Ok(self.last_status.unwrap());
            }
        }

        // finish HW BP が発火するまで実行を続ける
        ptrace::cont(self.pid)?;
        let status = self.wait()?;
        self.last_status = Some(status);

        // finish HW BP をクリアしてスロットを解放
        let _ = mach::clear_hw_breakpoint_slot(self.pid, finish_slot);
        self.release_hw_slot(finish_slot);

        // ユーザー HW BP ヒット判定
        self.handle_breakpoint_hit()?;

        Ok(self.last_status.unwrap())
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
    /// ARM64: コードを書かずにハードウェア BP (BVR/BCR) を使用します。
    /// x86_64: int3 をコードに書き込みます。
    pub fn set_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let slot = self.alloc_hw_slot(addr)?;
            mach::set_hw_breakpoint_slot(self.pid, slot, addr)?;
            let bp = Breakpoint::new_hw_enabled(addr, self.arch);
            self.breakpoints.insert(addr, bp);
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        {
            let mut bp = Breakpoint::new(addr, self.arch);
            bp.enable(self.pid)?;
            self.breakpoints.insert(addr, bp);
            Ok(())
        }
    }

    /// ARM64: 空きスロットを割り当て、スロット番号を返します。
    /// ユーザー BP と finish() 一時 BP が同じプールを共有します。
    /// チップ上の実際の BP 数 (M1=6, M2=8 等) の範囲内で割り当てられます。
    #[cfg(target_arch = "aarch64")]
    fn alloc_hw_slot(&mut self, addr: usize) -> io::Result<usize> {
        for slot in 0..16 {
            if self.hw_bp_slots[slot].is_none() {
                self.hw_bp_slots[slot] = Some(addr);
                return Ok(slot);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "hardware breakpoint slots exhausted (max 16 breakpoints on ARM64)",
        ))
    }

    /// ARM64: スロットを解放します。
    #[cfg(target_arch = "aarch64")]
    fn release_hw_slot(&mut self, slot: usize) {
        self.hw_bp_slots[slot] = None;
    }

    /// ARM64: アドレスに対応するスロット番号を返します。
    #[cfg(target_arch = "aarch64")]
    fn find_hw_slot(&self, addr: usize) -> Option<usize> {
        self.hw_bp_slots.iter().position(|s| *s == Some(addr))
    }

    /// 設定済みブレークポイントのアドレス一覧をソートして返します。
    pub fn breakpoint_addrs(&self) -> Vec<usize> {
        let mut addrs: Vec<usize> = self.breakpoints.keys().cloned().collect();
        addrs.sort();
        addrs
    }

    /// ブレークポイントを削除します。
    pub fn remove_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(slot) = self.find_hw_slot(addr) {
                mach::clear_hw_breakpoint_slot(self.pid, slot)?;
                self.hw_bp_slots[slot] = None;
            }
            self.breakpoints.remove(&addr);
            if self.at_breakpoint == Some(addr) {
                self.at_breakpoint = None;
            }
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        {
            if let Some(mut bp) = self.breakpoints.remove(&addr) {
                bp.disable(self.pid)?;
            }
            if self.at_breakpoint == Some(addr) {
                self.at_breakpoint = None;
            }
            Ok(())
        }
    }

    /// 汎用レジスタを取得します。
    pub fn registers(&self) -> io::Result<ThreadState64> {
        mach::get_registers(self.pid)
    }

    /// 浮動小数点レジスタを取得します (x86_64 のみ)。
    #[cfg(target_arch = "x86_64")]
    pub fn float_registers(&self) -> io::Result<FloatState64> {
        mach::get_float_registers(self.pid)
    }

    /// 浮動小数点レジスタを設定します (x86_64 のみ)。
    #[cfg(target_arch = "x86_64")]
    pub fn set_float_registers(&self, state: &FloatState64) -> io::Result<()> {
        mach::set_float_registers(self.pid, state)
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
    /// ブレークポイント命令は元のバイト列に置き換えて返します。
    /// (x86: int3 1バイト, ARM64: brk #0 4バイト)
    pub fn read_memory(&self, addr: usize, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = mach::read_memory(self.pid, addr, len)?;
        for (bp_addr, bp) in &self.breakpoints {
            if bp.is_enabled() {
                for (i, &byte) in bp.saved_bytes().iter().enumerate() {
                    let patch_addr = bp_addr + i;
                    if patch_addr >= addr && patch_addr < addr + buf.len() {
                        buf[patch_addr - addr] = byte;
                    }
                }
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
    /// x86_64: int3 実行後 PC は BP アドレス + 1 → 1 引く
    /// aarch64: brk #0 後 PC は BP アドレスのまま → 補正不要
    fn handle_breakpoint_hit(&mut self) -> io::Result<()> {
        if let Some(WaitStatus::Stopped { signal, pc }) = self.last_status {
            if signal != libc::SIGTRAP {
                return Ok(());
            }
            let bp_addr = (pc as usize).wrapping_sub(self.arch.bp_pc_offset());
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
    /// ARM64: HW BP を一時無効化 → ステップ → 再有効化 (コード書き込み不要)
    /// x86_64: SW BP を無効化 → ステップ → 再有効化
    fn step_over_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let slot = self.find_hw_slot(addr).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("no HW BP slot for {:#x}", addr),
                )
            })?;
            // HW BP を一時的に無効化
            mach::clear_hw_breakpoint_slot(self.pid, slot)?;
            // PC は ARM64 では補正不要 (bp_pc_offset = 0)
            ptrace::step(self.pid)?;
            let status = self.wait()?;
            self.last_status = Some(status);
            // HW BP を再有効化
            mach::set_hw_breakpoint_slot(self.pid, slot, addr)?;
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        {
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
