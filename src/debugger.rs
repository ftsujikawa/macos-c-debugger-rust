use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::arch::Arch;
use crate::breakpoint::Breakpoint;
use crate::mach::{self, MachPort};
use crate::ptrace::{self, Pid};
use crate::register::ThreadState64;
#[cfg(target_arch = "x86_64")]
use crate::register::FloatState64;
#[cfg(target_arch = "aarch64")]
use crate::register::ArmNeonState64;
use crate::register::{WatchCondition, WatchLen};

#[derive(Debug, Clone, Copy)]
pub enum WaitStatus {
    Stopped { signal: i32, pc: u64 },
    Exited { code: i32 },
    Signaled { signal: i32 },
    Unknown { status: i32 },
}

/// プロセスの起動経緯。子として spawn したのか、既存プロセスに attach したのか。
enum Origin {
    Spawned(#[allow(dead_code)] Child),
    Attached,
}

/// タスク内の1スレッドのポートと表示用情報。
struct ThreadEntry {
    port: MachPort,
    tid: u64,
    /// `suspend_thread`/`resume_thread` によるユーザー指定の一時停止状態。
    suspended: bool,
}

/// `threads()` で外部に返すスレッドのスナップショット情報。
#[derive(Debug, Clone)]
pub struct ThreadSummary {
    pub index: usize,
    pub tid: u64,
    pub pc: Option<u64>,
    pub suspended: bool,
    pub current: bool,
}

/// ウォッチポイント情報 (x86_64)
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug)]
pub struct WatchpointInfo {
    pub addr: usize,
    pub cond: WatchCondition,
    pub len: WatchLen,
}

/// ウォッチポイント情報 (ARM64)
/// ARM64 には DR6 相当のヒットスロット通知がないため、
/// ヒット判定用に前回読み取った値を保持します。
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug)]
pub struct WatchpointInfo {
    pub addr: usize,
    pub cond: WatchCondition,
    pub len: WatchLen,
    pub prev_value: Vec<u8>,
}

pub struct Debugger {
    pub pid: Pid,
    origin: Origin,
    /// デバッグ対象タスクの Mach タスクポート。
    task: MachPort,
    /// タスク内の全スレッド (毎停止時に `refresh_threads` で更新)。
    threads: Vec<ThreadEntry>,
    /// レジスタ操作・ステップ実行の対象となる現在選択中スレッドのインデックス。
    current_thread: usize,
    breakpoints: HashMap<usize, Breakpoint>,
    last_status: Option<WaitStatus>,
    /// 直前の停止がブレークポイントヒットによるものならそのアドレス
    at_breakpoint: Option<usize>,
    /// デバッグ対象のアーキテクチャ
    arch: Arch,
    /// ARM64 HW BP スロット管理 (slot → addr)
    #[cfg(target_arch = "aarch64")]
    hw_bp_slots: [Option<usize>; 16],
    /// ウォッチポイントスロット管理 (slot 0〜3 → info)
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    wp_slots: [Option<WatchpointInfo>; 4],
    /// 直前の停止がウォッチポイントヒットかどうか
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    at_watchpoint: Option<usize>, // ヒットしたアドレス
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

        Self::new_internal(pid, Origin::Spawned(child))
    }

    /// 既存プロセスに attach し、最初の停止まで待ちます。
    pub fn attach(pid: Pid) -> io::Result<Self> {
        ptrace::attach(pid)?;
        Self::new_internal(pid, Origin::Attached)
    }

    fn new_internal(pid: Pid, origin: Origin) -> io::Result<Self> {
        let mut me = Self {
            pid,
            origin,
            task: 0,
            threads: Vec::new(),
            current_thread: 0,
            breakpoints: HashMap::new(),
            last_status: None,
            at_breakpoint: None,
            arch: Arch::X86_64, // 仮初期値、exec 停止後に上書き
            #[cfg(target_arch = "aarch64")]
            hw_bp_slots: [None; 16],
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            wp_slots: [const { None }; 4],
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            at_watchpoint: None,
        };

        // task が未取得の段階では refresh_threads を呼べないので wait() 側でスキップされる
        let status = me.wait()?;
        me.last_status = Some(status);

        // exec 停止後に対象バイナリの Mach-O ヘッダからアーキテクチャを検出する
        me.arch = mach::detect_arch(pid)?;
        me.task = mach::get_task(pid)?;
        me.refresh_threads()?;

        Ok(me)
    }

    /// 現在選択中スレッドのポートを返します。
    fn current_thread_port(&self) -> io::Result<MachPort> {
        self.threads
            .get(self.current_thread)
            .map(|t| t.port)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no threads available"))
    }

    /// タスク内のスレッド一覧を最新化します。
    /// 新規に見つかったスレッドには既存の HW ブレークポイント/ウォッチポイントを適用し、
    /// いなくなったスレッドのポートは解放します。tid をキーに `suspended` 状態と
    /// 現在選択中スレッドを引き継ぎます。
    fn refresh_threads(&mut self) -> io::Result<()> {
        let new_ports = mach::list_threads(self.task)?;
        let old_threads = std::mem::take(&mut self.threads);
        let current_tid = old_threads.get(self.current_thread).map(|t| t.tid);

        let mut new_entries = Vec::with_capacity(new_ports.len());
        for port in new_ports {
            let tid = mach::thread_unique_id(port).unwrap_or(0);
            let is_new = !old_threads.iter().any(|t| t.tid == tid);
            let suspended = old_threads
                .iter()
                .find(|t| t.tid == tid)
                .map_or(false, |t| t.suspended);
            if is_new {
                self.apply_existing_bp_wp_to_thread(port)?;
            }
            new_entries.push(ThreadEntry { port, tid, suspended });
        }

        for old in old_threads {
            mach::deallocate_port(old.port);
        }

        self.current_thread = current_tid
            .and_then(|tid| new_entries.iter().position(|t| t.tid == tid))
            .unwrap_or(0);
        self.threads = new_entries;
        Ok(())
    }

    /// 新規発見スレッドに、既存の HW BP / WP スロットを反映します。
    #[cfg(target_arch = "aarch64")]
    fn apply_existing_bp_wp_to_thread(&self, port: MachPort) -> io::Result<()> {
        for (slot, addr) in self.hw_bp_slots.iter().enumerate() {
            if let Some(addr) = addr {
                mach::set_hw_breakpoint_slot(port, slot, *addr)?;
            }
        }
        for (slot, info) in self.wp_slots.iter().enumerate() {
            if let Some(info) = info {
                mach::set_hw_watchpoint_slot(port, slot, info.addr, info.cond, info.len)?;
            }
        }
        Ok(())
    }

    /// 新規発見スレッドに、既存の HW WP スロットを反映します (x86_64 SW BP はコード側で共有済み)。
    #[cfg(target_arch = "x86_64")]
    fn apply_existing_bp_wp_to_thread(&self, port: MachPort) -> io::Result<()> {
        for (slot, info) in self.wp_slots.iter().enumerate() {
            if let Some(info) = info {
                mach::set_watchpoint_slot(port, slot, info.addr, info.cond, info.len)?;
            }
        }
        Ok(())
    }

    /// 現在選択中スレッドの (インデックス, tid) を返します。
    pub fn current_thread(&self) -> Option<(usize, u64)> {
        self.threads.get(self.current_thread).map(|t| (self.current_thread, t.tid))
    }

    /// 現在のスレッド一覧のスナップショットを返します(表示用)。
    pub fn threads(&self) -> Vec<ThreadSummary> {
        self.threads
            .iter()
            .enumerate()
            .map(|(i, t)| ThreadSummary {
                index: i,
                tid: t.tid,
                pc: mach::get_registers(t.port).ok().map(|r| r.pc()),
                suspended: t.suspended,
                current: i == self.current_thread,
            })
            .collect()
    }

    /// レジスタ操作・ステップ実行の対象スレッドを切り替えます。
    pub fn select_thread(&mut self, idx: usize) -> io::Result<()> {
        if idx >= self.threads.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid thread index"));
        }
        self.current_thread = idx;
        Ok(())
    }

    /// 指定スレッドを Mach レベルで一時停止します。
    /// `cont()`/`step()` でプロセス全体を再開しても、このスレッドだけは止まったままになります。
    pub fn suspend_thread(&mut self, idx: usize) -> io::Result<()> {
        let port = self
            .threads
            .get(idx)
            .map(|t| t.port)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid thread index"))?;
        mach::suspend_thread(port)?;
        self.threads[idx].suspended = true;
        Ok(())
    }

    /// `suspend_thread` で止めたスレッドを再開します。
    pub fn resume_thread(&mut self, idx: usize) -> io::Result<()> {
        let port = self
            .threads
            .get(idx)
            .map(|t| t.port)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid thread index"))?;
        mach::resume_thread(port)?;
        self.threads[idx].suspended = false;
        Ok(())
    }

    /// 現在選択中スレッドだけを1命令進めます。
    ///
    /// macOS の `ptrace(PT_STEP)` はマルチスレッドプロセスでは SIGTRAP を返さず
    /// `wait()` が無期限にブロックすることを確認した (他スレッドを Mach レベルで
    /// suspend しても解消しない既知の ptrace 実装上の制約)。そのため実績のある
    /// 「ブレークポイント + PT_CONTINUE」の仕組みを再利用し、次に実行されうる
    /// アドレスに一時ブレークポイントを置いて1命令だけ進める。
    /// (x86_64: `disasm::step_targets` で jmp/call/jcc の分岐先も候補に含める。
    ///  aarch64: 命令長が固定 4 バイトなので pc+4 のみを候補とする — ただし
    ///  分岐命令をまたぐ場合は直後アドレスに到達しないことがある既知の制限。)
    fn step_current_thread(&mut self) -> io::Result<WaitStatus> {
        let keep_port = self.current_thread_port()?;
        let pc = mach::get_registers(keep_port)?.pc() as usize;
        let code = self.read_memory(pc, 16).unwrap_or_default();

        #[cfg(target_arch = "x86_64")]
        let candidates: Vec<usize> = crate::disasm::step_targets(&code, pc as u64);
        #[cfg(target_arch = "aarch64")]
        let candidates: Vec<usize> = {
            let _ = &code;
            vec![pc + 4]
        };

        // 既存のユーザーブレークポイントと重複しない候補にだけ一時 BP を置く
        let mut installed = Vec::new();
        for &addr in &candidates {
            let already_armed = self.breakpoints.get(&addr).map_or(false, |b| b.is_enabled());
            if !already_armed && self.set_breakpoint(addr).is_ok() {
                installed.push(addr);
            }
        }

        ptrace::cont(self.pid)?;
        let status = self.wait()?;
        self.last_status = Some(status);
        self.handle_breakpoint_hit()?;

        for addr in installed {
            let _ = self.remove_breakpoint(addr);
        }

        Ok(self.last_status.unwrap())
    }

    /// 子プロセスを 1 ステップ実行します。
    pub fn step(&mut self) -> io::Result<WaitStatus> {
        if let Some(addr) = self.at_breakpoint.take() {
            self.step_over_breakpoint(addr)?;
        } else {
            self.step_current_thread()?;
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
        self.handle_watchpoint_hit()?;
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
        // 空きスロットに一時 HW BP を設定 (全スレッドに反映)
        let finish_slot = self.alloc_hw_slot(ret_addr)?;
        for t in &self.threads {
            mach::set_hw_breakpoint_slot(t.port, finish_slot, ret_addr)?;
        }

        // ユーザー HW BP に止まっている場合はステップオーバーしてから continue
        if let Some(addr) = self.at_breakpoint.take() {
            self.step_over_breakpoint(addr)?;
            if !matches!(self.last_status, Some(WaitStatus::Stopped { .. })) {
                // ステップ中にプロセスが終了
                for t in &self.threads {
                    let _ = mach::clear_hw_breakpoint_slot(t.port, finish_slot);
                }
                self.release_hw_slot(finish_slot);
                return Ok(self.last_status.unwrap());
            }
        }

        // finish HW BP が発火するまで実行を続ける
        ptrace::cont(self.pid)?;
        let status = self.wait()?;
        self.last_status = Some(status);

        // finish HW BP をクリアしてスロットを解放 (refresh_threads 後の最新スレッド集合に対して)
        for t in &self.threads {
            let _ = mach::clear_hw_breakpoint_slot(t.port, finish_slot);
        }
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
    /// ARM64: コードを書かずにハードウェア BP (BVR/BCR) を全スレッドに使用します。
    /// x86_64: int3 をコードに書き込みます (アドレス空間共有のため全スレッドに自動適用)。
    pub fn set_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let slot = self.alloc_hw_slot(addr)?;
            for t in &self.threads {
                mach::set_hw_breakpoint_slot(t.port, slot, addr)?;
            }
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

    /// ウォッチポイントを設定します (x86_64 のみ、スロット 0〜3、全スレッドに適用)。
    #[cfg(target_arch = "x86_64")]
    pub fn set_watchpoint(
        &mut self,
        addr: usize,
        cond: WatchCondition,
        len: WatchLen,
    ) -> io::Result<usize> {
        // 同じアドレスが既に登録されていればそのスロットを返す
        for (slot, entry) in self.wp_slots.iter().enumerate() {
            if entry.as_ref().map_or(false, |e| e.addr == addr) {
                return Ok(slot);
            }
        }
        // 空きスロットを探す
        let slot = self
            .wp_slots
            .iter()
            .position(|e| e.is_none())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "watchpoint slots exhausted (max 4 on x86_64)",
                )
            })?;
        for t in &self.threads {
            mach::set_watchpoint_slot(t.port, slot, addr, cond, len)?;
        }
        self.wp_slots[slot] = Some(WatchpointInfo { addr, cond, len });
        Ok(slot)
    }

    /// ウォッチポイントをスロット番号で削除します (x86_64 のみ)。
    #[cfg(target_arch = "x86_64")]
    pub fn remove_watchpoint_slot(&mut self, slot: usize) -> io::Result<()> {
        if slot >= 4 {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid watchpoint slot"));
        }
        for t in &self.threads {
            mach::clear_watchpoint_slot(t.port, slot)?;
        }
        self.wp_slots[slot] = None;
        Ok(())
    }

    /// 設定済みウォッチポイントの一覧を返します (slot, info) (x86_64 のみ)。
    #[cfg(target_arch = "x86_64")]
    pub fn watchpoint_slots(&self) -> Vec<(usize, &WatchpointInfo)> {
        self.wp_slots
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|info| (i, info)))
            .collect()
    }

    /// 直前の停止がウォッチポイントヒットかどうか (x86_64 のみ)。
    #[cfg(target_arch = "x86_64")]
    pub fn at_watchpoint(&self) -> Option<usize> {
        self.at_watchpoint
    }

    /// ウォッチポイントを設定します (ARM64 のみ、スロット 0〜3、WVR/WCR ベース、全スレッドに適用)。
    #[cfg(target_arch = "aarch64")]
    pub fn set_watchpoint(
        &mut self,
        addr: usize,
        cond: WatchCondition,
        len: WatchLen,
    ) -> io::Result<usize> {
        // 同じアドレスが既に登録されていればそのスロットを返す
        for (slot, entry) in self.wp_slots.iter().enumerate() {
            if entry.as_ref().map_or(false, |e| e.addr == addr) {
                return Ok(slot);
            }
        }
        // 空きスロットを探す
        let slot = self
            .wp_slots
            .iter()
            .position(|e| e.is_none())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "watchpoint slots exhausted (max 4 on ARM64)",
                )
            })?;
        let prev = self.read_memory(addr, len.as_bytes()).unwrap_or_default();
        for t in &self.threads {
            mach::set_hw_watchpoint_slot(t.port, slot, addr, cond, len)?;
        }
        self.wp_slots[slot] = Some(WatchpointInfo { addr, cond, len, prev_value: prev });
        Ok(slot)
    }

    /// ウォッチポイントをスロット番号で削除します (ARM64 のみ)。
    #[cfg(target_arch = "aarch64")]
    pub fn remove_watchpoint_slot(&mut self, slot: usize) -> io::Result<()> {
        if slot >= 4 {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid watchpoint slot"));
        }
        for t in &self.threads {
            mach::clear_hw_watchpoint_slot(t.port, slot)?;
        }
        self.wp_slots[slot] = None;
        Ok(())
    }

    /// 設定済みウォッチポイントの一覧を返します (slot, info) (ARM64 のみ)。
    #[cfg(target_arch = "aarch64")]
    pub fn watchpoint_slots(&self) -> Vec<(usize, &WatchpointInfo)> {
        self.wp_slots
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|info| (i, info)))
            .collect()
    }

    /// 直前の停止がウォッチポイントヒットかどうか (ARM64 のみ)。
    #[cfg(target_arch = "aarch64")]
    pub fn at_watchpoint(&self) -> Option<usize> {
        self.at_watchpoint
    }

    /// ブレークポイントを削除します。
    pub fn remove_breakpoint(&mut self, addr: usize) -> io::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(slot) = self.find_hw_slot(addr) {
                for t in &self.threads {
                    mach::clear_hw_breakpoint_slot(t.port, slot)?;
                }
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

    /// 汎用レジスタを取得します (現在選択中スレッド)。
    pub fn registers(&self) -> io::Result<ThreadState64> {
        mach::get_registers(self.current_thread_port()?)
    }

    /// 浮動小数点レジスタを取得します (x86_64 のみ、現在選択中スレッド)。
    #[cfg(target_arch = "x86_64")]
    pub fn float_registers(&self) -> io::Result<FloatState64> {
        mach::get_float_registers(self.current_thread_port()?)
    }

    /// 浮動小数点レジスタを設定します (x86_64 のみ、現在選択中スレッド)。
    #[cfg(target_arch = "x86_64")]
    pub fn set_float_registers(&self, state: &FloatState64) -> io::Result<()> {
        mach::set_float_registers(self.current_thread_port()?, state)
    }

    /// NEON/FP レジスタを取得します (ARM64 のみ、現在選択中スレッド)。
    #[cfg(target_arch = "aarch64")]
    pub fn float_registers(&self) -> io::Result<ArmNeonState64> {
        mach::get_float_registers(self.current_thread_port()?)
    }

    /// NEON/FP レジスタを設定します (ARM64 のみ、現在選択中スレッド)。
    #[cfg(target_arch = "aarch64")]
    pub fn set_float_registers(&self, state: &ArmNeonState64) -> io::Result<()> {
        mach::set_float_registers(self.current_thread_port()?, state)
    }

    /// 汎用レジスタを設定します (現在選択中スレッド)。
    pub fn set_registers(&self, regs: &ThreadState64) -> io::Result<()> {
        mach::set_registers(self.current_thread_port()?, regs)
    }

    /// プログラムカウンタを取得します (現在選択中スレッド)。
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

    /// 子プロセスをデタッチします (プロセス自体は動作を継続します)。
    pub fn detach(&self) -> io::Result<()> {
        ptrace::detach(self.pid)?;
        // detach 成功後は task/スレッドポートへの送信権を解放する
        // (失敗時は保持したままにして、セッションを引き続き操作可能にする)
        for t in &self.threads {
            mach::deallocate_port(t.port);
        }
        mach::deallocate_port(self.task);
        Ok(())
    }

    /// 起動経緯に応じて後始末します: spawn したプロセスは kill、attach したプロセスは detach。
    pub fn shutdown(&self) -> io::Result<()> {
        match self.origin {
            Origin::Spawned(_) => self.kill(),
            Origin::Attached => self.detach(),
        }
    }

    /// 現在の停止状態を取得します。
    pub fn last_status(&self) -> Option<WaitStatus> {
        self.last_status
    }

    /// 現在の停止がブレークポイントヒットかどうかを返します。
    pub fn is_at_breakpoint(&self) -> bool {
        self.at_breakpoint.is_some()
    }

    /// PT_CONTINUE 後の停止がブレークポイントヒットか判定します。
    /// 全スレッドの PC を走査してヒットしたスレッドを特定し、そのスレッドを
    /// 自動的に current にした上で PC を BP 先頭に巻き戻します。
    /// x86_64: int3 実行後 PC は BP アドレス + 1 → 1 引く
    /// aarch64: brk #0 後 PC は BP アドレスのまま → 補正不要
    /// x86_64 では複数スレッドが同じ int3 に同時にトラップすることがある。
    /// 補正されないまま残った thread は元命令の途中 (bp_addr+1) から実行を
    /// 再開してしまい、命令ストリームが破損する。そのため見つかった最初の
    /// 1 本を current/at_breakpoint として選ぶだけでなく、該当する全スレッドの
    /// PC を bp_addr まで巻き戻す。
    fn handle_breakpoint_hit(&mut self) -> io::Result<()> {
        if let Some(WaitStatus::Stopped { signal, .. }) = self.last_status {
            if signal != libc::SIGTRAP {
                return Ok(());
            }
            let mut hit: Option<(usize, usize)> = None; // (thread index, bp_addr)
            for i in 0..self.threads.len() {
                let port = self.threads[i].port;
                let Ok(mut regs) = mach::get_registers(port) else { continue };
                let pc = regs.pc() as usize;
                let bp_addr = pc.wrapping_sub(self.arch.bp_pc_offset());
                if self.breakpoints.get(&bp_addr).map_or(false, |b| b.is_enabled()) {
                    regs.set_pc(bp_addr as u64);
                    mach::set_registers(port, &regs)?;
                    if hit.is_none() {
                        hit = Some((i, bp_addr));
                    }
                }
            }
            if let Some((i, bp_addr)) = hit {
                self.at_breakpoint = Some(bp_addr);
                self.current_thread = i;
                self.last_status = Some(WaitStatus::Stopped {
                    signal,
                    pc: bp_addr as u64,
                });
            }
        }
        Ok(())
    }

    /// DR6 を読んでウォッチポイントヒットを記録します (x86_64 のみ)。
    /// DR6 はスレッドごとのレジスタなので全スレッドを走査します。
    #[cfg(target_arch = "x86_64")]
    fn handle_watchpoint_hit(&mut self) -> io::Result<()> {
        self.at_watchpoint = None;
        if let Some(WaitStatus::Stopped { signal, .. }) = self.last_status {
            // ウォッチポイントも SIGTRAP で停止する
            if signal != libc::SIGTRAP {
                return Ok(());
            }
            // ブレークポイントヒットでない場合のみウォッチポイントを確認
            if self.at_breakpoint.is_some() {
                return Ok(());
            }
            for i in 0..self.threads.len() {
                let port = self.threads[i].port;
                let hits = mach::watchpoint_hit_slots(port)?;
                if let Some(&slot) = hits.first() {
                    if let Some(info) = &self.wp_slots[slot] {
                        self.at_watchpoint = Some(info.addr);
                        self.current_thread = i;
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    /// ウォッチポイントヒットを記録します (ARM64 のみ)。
    /// ARM64 には DR6 相当のヒットスロット通知 (ESR_EL1) がユーザ空間 (ptrace) から
    /// 取得できないため、各スロットの監視先メモリを前回値と比較して変化した
    /// スロットをヒットとみなします(プロセス共有メモリなのでスレッドに依存しません)。
    #[cfg(target_arch = "aarch64")]
    fn handle_watchpoint_hit(&mut self) -> io::Result<()> {
        self.at_watchpoint = None;
        if let Some(WaitStatus::Stopped { signal, .. }) = self.last_status {
            // ウォッチポイントも SIGTRAP で停止する
            if signal != libc::SIGTRAP {
                return Ok(());
            }
            // ブレークポイントヒットでない場合のみウォッチポイントを確認
            if self.at_breakpoint.is_some() {
                return Ok(());
            }
            for slot in 0..self.wp_slots.len() {
                let Some(info) = self.wp_slots[slot].clone() else { continue };
                let cur = self.read_memory(info.addr, info.len.as_bytes()).unwrap_or_default();
                if cur != info.prev_value {
                    self.at_watchpoint = Some(info.addr);
                    if let Some(entry) = self.wp_slots[slot].as_mut() {
                        entry.prev_value = cur;
                    }
                    return Ok(());
                }
            }
            // 値が変化していなくても HW ウォッチポイントが設定済みなら、
            // その SIGTRAP はウォッチポイント由来とみなす (取りこぼし防止)
            if let Some(info) = self.wp_slots.iter().flatten().next() {
                self.at_watchpoint = Some(info.addr);
            }
        }
        Ok(())
    }

    /// ブレークポイントを「踏み越え」て 1 命令実行し、BP を再設定します。
    /// ARM64: HW BP を一時無効化 (全スレッド) → ステップ → 再有効化 (コード書き込み不要)
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
            // HW BP を一時的に無効化 (全スレッド)
            for t in &self.threads {
                mach::clear_hw_breakpoint_slot(t.port, slot)?;
            }
            self.step_current_thread()?;
            // HW BP を再有効化 (refresh_threads 後の最新スレッド集合に対して)
            for t in &self.threads {
                mach::set_hw_breakpoint_slot(t.port, slot, addr)?;
            }
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
            let keep_port = self.current_thread_port()?;
            mach::set_registers(keep_port, &regs)?;

            self.step_current_thread()?;

            bp.re_enable(self.pid)?;
            self.breakpoints.insert(addr, bp);
            Ok(())
        }
    }

    /// waitpid し、停止/終了/シグナル状態を判定します。
    /// プロセスが停止した場合は `refresh_threads` でスレッド一覧を最新化します
    /// (構築直後で task が未取得の間はスキップされます)。
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

        let stopped = (status & 0x7f) == 0x7f;
        if stopped && self.task != 0 {
            let _ = self.refresh_threads();
        }

        let pc = self.pc().unwrap_or(0);

        let s = if stopped {
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
