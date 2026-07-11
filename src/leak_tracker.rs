/// malloc/calloc/realloc/free にブレークポイントを設置し、
/// 解放されていないヒープアロケーションを追跡します。
use std::collections::HashMap;
use std::io;

use crate::debugger::{Debugger, WaitStatus};
use crate::register::ThreadState64;
use crate::symbols::Symbols;

/// ヒープアロケーション情報。
pub struct AllocInfo {
    pub size: usize,
    /// malloc を呼び出した側の戻りアドレス (call_site)
    pub call_site: usize,
}

/// malloc/calloc/realloc 呼び出し中の保留エントリ。
struct PendingAlloc {
    size: usize,
    call_site: usize,
}

/// ヒープリークトラッカー。
pub struct LeakTracker {
    pub enabled: bool,
    /// 生存中のアロケーション: 返された ptr → 情報
    live: HashMap<usize, AllocInfo>,
    /// malloc/calloc/realloc/free のスタブアドレス (runtime)
    malloc_addr: Option<usize>,
    calloc_addr: Option<usize>,
    realloc_addr: Option<usize>,
    free_addr: Option<usize>,
    /// malloc/calloc/realloc の返値を捕捉するための一時 BP: ret_addr → 保留スタック
    pending_returns: HashMap<usize, Vec<PendingAlloc>>,
}

impl LeakTracker {
    pub fn new() -> Self {
        Self {
            enabled: false,
            live: HashMap::new(),
            malloc_addr: None,
            calloc_addr: None,
            realloc_addr: None,
            free_addr: None,
            pending_returns: HashMap::new(),
        }
    }

    /// トラッカーを有効にし、指定アドレスにブレークポイントを設定します。
    /// いずれかのアドレスが None の場合はそのシンボルを追跡しません。
    pub fn enable(
        &mut self,
        dbg: &mut Debugger,
        malloc: Option<usize>,
        calloc: Option<usize>,
        realloc: Option<usize>,
        free: Option<usize>,
    ) -> io::Result<()> {
        for addr in [malloc, calloc, realloc, free].into_iter().flatten() {
            dbg.set_breakpoint(addr)?;
        }
        self.malloc_addr = malloc;
        self.calloc_addr = calloc;
        self.realloc_addr = realloc;
        self.free_addr = free;
        self.live.clear();
        self.pending_returns.clear();
        self.enabled = true;
        Ok(())
    }

    /// トラッカーを無効にし、設定したブレークポイントをすべて削除します。
    pub fn disable(&mut self, dbg: &mut Debugger) -> io::Result<()> {
        for addr in [self.malloc_addr, self.calloc_addr, self.realloc_addr, self.free_addr]
            .into_iter()
            .flatten()
        {
            let _ = dbg.remove_breakpoint(addr);
        }
        for addr in self.pending_returns.keys().cloned().collect::<Vec<_>>() {
            let _ = dbg.remove_breakpoint(addr);
        }
        self.pending_returns.clear();
        self.enabled = false;
        Ok(())
    }

    /// 停止ポイントがトラッカーの BP かどうかを判定し、処理します。
    /// 返値が `true` のとき呼び出し側は自動的に `cont` を再発行してください。
    pub fn handle_stop(&mut self, dbg: &mut Debugger) -> io::Result<bool> {
        if !self.enabled {
            return Ok(false);
        }

        let pc = dbg.pc()? as usize;
        let regs = dbg.registers()?;

        // ── malloc エントリ ──────────────────────────────────────────────
        if Some(pc) == self.malloc_addr {
            let size = Self::arg0(&regs) as usize;
            self.push_pending(dbg, &regs, size)?;
            return Ok(true);
        }

        // ── calloc エントリ ──────────────────────────────────────────────
        if Some(pc) == self.calloc_addr {
            let nelem = Self::arg0(&regs) as usize;
            let esz = Self::arg1(&regs) as usize;
            self.push_pending(dbg, &regs, nelem.saturating_mul(esz))?;
            return Ok(true);
        }

        // ── realloc エントリ ─────────────────────────────────────────────
        if Some(pc) == self.realloc_addr {
            let old_ptr = Self::arg0(&regs) as usize;
            let new_size = Self::arg1(&regs) as usize;
            if old_ptr != 0 {
                self.live.remove(&old_ptr);
            }
            self.push_pending(dbg, &regs, new_size)?;
            return Ok(true);
        }

        // ── free エントリ ────────────────────────────────────────────────
        if Some(pc) == self.free_addr {
            let ptr = Self::arg0(&regs) as usize;
            if ptr != 0 {
                self.live.remove(&ptr);
            }
            return Ok(true);
        }

        // ── malloc/calloc/realloc からの返値 BP ─────────────────────────
        if let Some(pending_list) = self.pending_returns.get_mut(&pc) {
            if let Some(pending) = pending_list.pop() {
                let ptr = Self::retval(&regs) as usize;
                if ptr != 0 {
                    self.live.insert(
                        ptr,
                        AllocInfo {
                            size: pending.size,
                            call_site: pending.call_site,
                        },
                    );
                }
            }
            let is_empty = self.pending_returns[&pc].is_empty();
            if is_empty {
                self.pending_returns.remove(&pc);
                // 一時 BP は使い捨て: 使い終わったら削除
                let _ = dbg.remove_breakpoint(pc);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// 生存アロケーションをリーク候補として一覧表示します。
    /// `syms` と `runtime_base` が指定されていればコールサイトのソース位置も表示します。
    pub fn show_leaks(&self, syms: Option<&Symbols>, runtime_base: Option<u64>) {
        if self.live.is_empty() {
            println!("No leaks detected.");
            return;
        }
        println!("{} live allocation(s) (possible leaks):", self.live.len());
        let mut entries: Vec<_> = self.live.iter().collect();
        entries.sort_by_key(|(addr, _)| *addr);
        for (ptr, info) in &entries {
            // call_site はリターンアドレスなので、直前の命令 (call/bl) を含む行を得るため -1
            let loc = syms.zip(runtime_base).and_then(|(s, base)| {
                let slide = s.slide(base);
                let vaddr = (info.call_site as u64).wrapping_sub(slide).wrapping_sub(1);
                s.find_location(vaddr)
            });
            match loc {
                Some((ref path, line)) => {
                    // パスは長くなりがちなのでファイル名のみ表示
                    let fname = std::path::Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(path.as_str());
                    println!(
                        "  {:#018x}  size={:<6}  caller={:#018x}  ({}:{})",
                        ptr, info.size, info.call_site, fname, line
                    );
                }
                None => {
                    println!(
                        "  {:#018x}  size={:<6}  caller={:#018x}",
                        ptr, info.size, info.call_site
                    );
                }
            }
        }
    }

    /// 現在の生存アロケーション数を返します。
    #[allow(dead_code)]
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// malloc/calloc/realloc エントリで保留エントリを積み、返値 BP を設定します。
    fn push_pending(
        &mut self,
        dbg: &mut Debugger,
        regs: &ThreadState64,
        size: usize,
    ) -> io::Result<()> {
        let call_site = Self::return_addr(dbg, regs)?;

        // 同じ返値アドレスに対して初回のみ BP を設定
        if !self.pending_returns.contains_key(&call_site) {
            dbg.set_breakpoint(call_site)?;
        }
        self.pending_returns
            .entry(call_site)
            .or_default()
            .push(PendingAlloc { size, call_site });
        Ok(())
    }

    // ── ABI 依存のレジスタアクセス ──────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    fn arg0(regs: &ThreadState64) -> u64 {
        regs.__rdi
    }
    #[cfg(target_arch = "x86_64")]
    fn arg1(regs: &ThreadState64) -> u64 {
        regs.__rsi
    }
    #[cfg(target_arch = "x86_64")]
    fn retval(regs: &ThreadState64) -> u64 {
        regs.__rax
    }
    #[cfg(target_arch = "x86_64")]
    fn return_addr(dbg: &Debugger, regs: &ThreadState64) -> io::Result<usize> {
        let rsp = regs.__rsp as usize;
        let buf = dbg.read_memory(rsp, 8)?;
        Ok(u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize)
    }

    #[cfg(target_arch = "aarch64")]
    fn arg0(regs: &ThreadState64) -> u64 {
        regs.__x[0]
    }
    #[cfg(target_arch = "aarch64")]
    fn arg1(regs: &ThreadState64) -> u64 {
        regs.__x[1]
    }
    #[cfg(target_arch = "aarch64")]
    fn retval(regs: &ThreadState64) -> u64 {
        regs.__x[0]
    }
    #[cfg(target_arch = "aarch64")]
    fn return_addr(_dbg: &Debugger, regs: &ThreadState64) -> io::Result<usize> {
        Ok(regs.__lr as usize)
    }
}

/// `cont` / `step` 後の停止がリークトラッカーの BP であれば自動的に継続します。
/// ユーザー BP または停止理由が別の場合は即座に返します。
pub fn auto_cont(
    dbg: &mut Debugger,
    tracker: &mut Option<LeakTracker>,
    initial_status: WaitStatus,
) -> io::Result<WaitStatus> {
    let mut status = initial_status;
    loop {
        if let (Some(tr), WaitStatus::Stopped { .. }) = (tracker.as_mut(), status) {
            if tr.handle_stop(dbg)? {
                status = dbg.cont()?;
                continue;
            }
        }
        return Ok(status);
    }
}
