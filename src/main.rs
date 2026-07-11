mod breakpoint;
mod debugger;
mod disasm;
mod expr;
mod mach;
mod ptrace;
mod register;
mod symbols;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use debugger::{Debugger, WaitStatus};
use symbols::{Symbols, VarLocation};

/// SIGINTを転送する先の子プロセスPID (0 = 未設定)
static CHILD_PID: AtomicI32 = AtomicI32::new(0);
/// 子プロセスが実行中のとき true
static CHILD_RUNNING: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn sigint_handler(_: libc::c_int) {
    // 実行中のときだけ転送し、フラグを下ろす（多重転送を防ぐ）
    if CHILD_RUNNING.swap(false, Ordering::SeqCst) {
        let pid = CHILD_PID.load(Ordering::Relaxed);
        if pid > 0 {
            libc::kill(pid, libc::SIGINT);
        }
    }
}

fn setup_sigint_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigint_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        // SA_RESTART: read_line などの遅いシスコールを自動再開させる
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

fn parse_addr(s: &str, base: Option<u64>) -> Option<usize> {
    if let Some(rest) = s.strip_prefix("base+") {
        let offset = if let Some(hex) = rest.strip_prefix("0x") {
            usize::from_str_radix(hex, 16).ok()?
        } else {
            rest.parse().ok()?
        };
        let base = base? as usize;
        return Some(base + offset);
    }
    if let Some(hex) = s.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// b コマンドの引数を実行時アドレスに解決します。
/// アドレス / base+オフセット / ソースファイル:行番号 / シンボル名 をサポートします。
/// 失敗時は原因を示すメッセージを返します。
fn resolve_location(
    arg: &str,
    base: Option<u64>,
    syms: Option<&Symbols>,
    current_file: Option<&str>,
) -> Result<usize, String> {
    // "file:line" 形式
    if let Some((file, line_str)) = arg.rsplit_once(':') {
        if let Ok(line) = line_str.parse::<u32>() {
            let syms = syms.ok_or("no symbol/debug info loaded")?;
            let vaddr = syms
                .find_line(file, line)
                .ok_or_else(|| format!("no line info for {} (try dsymutil)", arg))?;
            let base = base.ok_or("image base unknown (task_for_pid failed?)")?;
            return Ok(vaddr.wrapping_add(syms.slide(base)) as usize);
        }
    }
    // 純粋な整数 → 現在のソースファイルの行番号
    if let Ok(line) = arg.parse::<u32>() {
        let syms = syms.ok_or("no symbol/debug info loaded")?;
        let file = current_file
            .ok_or_else(|| "no current source file; use file:line format".to_string())?;
        let vaddr = syms
            .find_line(file, line)
            .ok_or_else(|| format!("no line info for {}:{} (try dsymutil)", file, line))?;
        let base = base.ok_or("image base unknown (task_for_pid failed?)")?;
        return Ok(vaddr.wrapping_add(syms.slide(base)) as usize);
    }
    // 0x... / base+... などのアドレス表記
    if let Some(addr) = parse_addr(arg, base) {
        return Ok(addr);
    }
    // シンボル名
    let syms = syms.ok_or("no symbol/debug info loaded")?;
    let vaddr = syms
        .find_symbol(arg)
        .ok_or_else(|| format!("symbol not found: {}", arg))?;
    let vaddr = syms.skip_prologue(vaddr);
    let base = base.ok_or(
        "image base unknown (task_for_pid failed; is the target codesigned with get-task-allow?)",
    )?;
    Ok(vaddr.wrapping_add(syms.slide(base)) as usize)
}

/// 現在の PC に対応する (ソースファイル名, 行番号) を取得します。
fn eval_expression(
    dbg: &Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
    expr_str: &str,
) -> Result<u64, String> {
    let expr = expr::parse(expr_str)?;
    let regs = dbg.registers().map_err(|e| e.to_string())?;
    let read = |addr: usize| dbg.read_memory(addr, 8);
    let resolve = |name: &str| resolve_variable(dbg, base, syms, name);
    let mut ctx = expr::EvalContext::new(
        &regs,
        base,
        Some(&read as &dyn Fn(usize) -> io::Result<Vec<u8>>),
    );
    ctx.resolve_var = Some(&resolve as &dyn Fn(&str) -> Result<(u64, u8), String>);
    expr::eval(&expr, &ctx)
}

/// 変数名を実行時の (アドレス, バイト数) に解決します。
fn resolve_variable(
    dbg: &Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
    name: &str,
) -> Result<(u64, u8), String> {
    let syms = syms.ok_or("no debug info loaded")?;
    let base = base.ok_or("image base unknown")?;
    let slide = syms.slide(base);
    let pc = dbg.pc().map_err(|e| e.to_string())?;
    let var = syms
        .find_variable(name, pc.wrapping_sub(slide))
        .ok_or_else(|| format!("variable not found: {}", name))?;
    let addr = match var.location {
        VarLocation::FrameOffset(off) => {
            let regs = dbg.registers().map_err(|e| e.to_string())?;
            (regs.bp() as i64).wrapping_add(off) as u64
        }
        VarLocation::Addr(a) => a.wrapping_add(slide),
    };
    Ok((addr, var.byte_size))
}

/// 単純な識別子（変数名）かどうか判定します。
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

fn current_line(dbg: &Debugger, base: Option<u64>, syms: Option<&Symbols>) -> Option<(String, u32)> {
    let syms = syms?;
    let slide = syms.slide(base?);
    let pc = dbg.pc().ok()?;
    syms.find_location(pc.wrapping_sub(slide))
}

/// ソースコード 1 行分を実行します。
/// 行情報が変わるまで命令単位ステップを繰り返します。
fn step_line(
    dbg: &mut Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
) -> io::Result<WaitStatus> {
    const MAX_STEPS: usize = 100_000;

    let start = current_line(dbg, base, syms);
    let mut status = dbg.step()?;
    // 行情報がない場合は 1 命令ステップと同じ振る舞い
    if start.is_none() {
        return Ok(status);
    }
    for _ in 0..MAX_STEPS {
        if !matches!(status, WaitStatus::Stopped { .. }) {
            return Ok(status);
        }
        let now = current_line(dbg, base, syms);
        if now != start {
            return Ok(status);
        }
        status = dbg.step()?;
    }
    eprintln!("warning: too many steps; stopping");
    Ok(status)
}

/// ソースコードの次の行まで実行します（関数呼び出しはステップオーバー）。
/// - フレームポインタが下がった（サブ関数に入った）場合は finish() で戻る
/// - 行情報が None（PLT スタブ等）の場合は有効な行に到達するまで進み続ける
fn next_line(
    dbg: &mut Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
) -> io::Result<WaitStatus> {
    const MAX_STEPS: usize = 100_000;

    let start = current_line(dbg, base, syms);
    let start_fp = dbg.registers().map(|r| r.bp()).unwrap_or(0);

    let mut status = dbg.step()?;

    for _ in 0..MAX_STEPS {
        if !matches!(status, WaitStatus::Stopped { .. }) {
            return Ok(status);
        }
        let now_fp = dbg.registers().map(|r| r.bp()).unwrap_or(0);
        if now_fp < start_fp {
            // サブ関数内に入った → finish で呼び出し元に戻る
            status = match dbg.finish() {
                Ok(s) => s,
                Err(_) => return Ok(status),
            };
            continue;
        }
        // 有効なソース行情報があり、開始行と異なれば完了
        let now = current_line(dbg, base, syms);
        if now.is_some() && now != start {
            return Ok(status);
        }
        // 行情報なし (PLT スタブ等) または同じ行 → さらにステップ
        status = dbg.step()?;
    }

    eprintln!("warning: too many steps; stopping");
    Ok(status)
}

/// フレームポインタチェーンをたどってバックトレースを表示します。
fn print_backtrace(dbg: &Debugger, base: Option<u64>, syms: Option<&Symbols>) {
    const MAX_FRAMES: usize = 64;

    let regs = match dbg.registers() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to read registers: {}", e);
            return;
        }
    };
    let slide = match (base, syms) {
        (Some(b), Some(s)) => Some(s.slide(b)),
        _ => None,
    };

    let mut pc = regs.pc();
    let mut fp = regs.bp();
    for i in 0..MAX_FRAMES {
        let mut sym_name: Option<&str> = None;
        let mut desc = String::new();
        if let (Some(slide), Some(syms)) = (slide, syms) {
            let vaddr = pc.wrapping_sub(slide);
            if let Some((name, off)) = syms.find_symbol_for_addr(vaddr) {
                sym_name = Some(name);
                desc.push_str(&format!("  {} + {:#x}", name, off));
            }
            if let Some((path, line)) = syms.find_location(vaddr) {
                desc.push_str(&format!("  ({}:{})", path, line));
            }
        }
        println!("#{:<2} {:#018x}{}", i, pc, desc);

        // main まで表示したら終了
        if matches!(sym_name, Some("_main") | Some("main")) {
            break;
        }
        if fp == 0 {
            break;
        }
        // [fp] = 保存されたフレームポインタ, [fp+8] = リターンアドレス
        let buf = match dbg.read_memory(fp as usize, 16) {
            Ok(b) if b.len() >= 16 => b,
            _ => break,
        };
        let saved_fp = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let ret = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        // チェーンが壊れていたら終了 (fp は単調増加のはず)
        if ret == 0 || saved_fp <= fp {
            break;
        }
        pc = ret;
        fp = saved_fp;
    }
}

/// リスト引数を解析し (file, line) を返します。
/// 行番号のみの場合は current_file を使います。
fn resolve_list_target(
    arg: &str,
    current_file: Option<&str>,
    syms: Option<&Symbols>,
) -> Result<(String, u32), String> {
    if let Some((file, line)) = arg.rsplit_once(':') {
        let line = line
            .parse::<u32>()
            .map_err(|_| format!("invalid line number: {}", line))?;
        if let Some(syms) = syms {
            if let Some(vaddr) = syms.find_line(file, line) {
                if let Some((full_path, _)) = syms.find_location(vaddr) {
                    return Ok((full_path, line));
                }
            }
            // DWARF から解決できなかったら、入力したパスをそのまま試す
            if fs::metadata(file).is_ok() {
                return Ok((file.to_string(), line));
            }
        }
        return Err(format!("no source info for {} (try full path or dsymutil)", arg));
    }
    if let Ok(line) = arg.parse::<u32>() {
        let file = current_file
            .map(|s| s.to_string())
            .ok_or("no current source file; use list file:line or list symbol")?;
        return Ok((file, line));
    }
    // シンボル名とみなす
    let syms = syms.ok_or("no symbol/debug info loaded")?;
    let vaddr = syms
        .find_symbol(arg)
        .ok_or_else(|| format!("symbol not found: {}", arg))?;
    syms.find_location(vaddr)
        .ok_or_else(|| format!("no source info for symbol: {}", arg))
}

/// リスト引数がなければ現在位置、あれば指定位置のソースを表示します。
fn show_list(
    parts: &[&str],
    dbg: &Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
) {
    let current = current_line(dbg, base, syms);

    let (file, line) = if parts.len() >= 2 {
        let current_file = current.as_ref().map(|(p, _)| p.as_str());
        match resolve_list_target(parts[1], current_file, syms) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("list: {}", e);
                return;
            }
        }
    } else {
        match current {
            Some(v) => v,
            None => {
                eprintln!("list: no current source location");
                return;
            }
        }
    };

    if !list_source(&file, line, 3) {
        eprintln!("list: failed to read {}", file);
    }
}

/// 停止位置のコンテキストを表示します。
/// ソースコードが見つかればソースを、なければ逆アセンブルを表示します。
fn show_context(dbg: &Debugger, base: Option<u64>, syms: Option<&Symbols>) {
    if let Some((path, line)) = current_line(dbg, base, syms) {
        if print_source(&path, line) {
            return;
        }
    }
    print_disasm(dbg);
}

/// 指定行の前後 2 行を含めてソースコードを表示します。
/// ファイルが読めない場合は false を返します。
fn list_source(path: &str, line: u32, context: usize) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let lines: Vec<&str> = text.lines().collect();
    let cur = line as usize;
    if cur == 0 || cur > lines.len() {
        return false;
    }
    println!("{}:{}", path, line);
    let start = cur.saturating_sub(context).max(1);
    let end = (cur + context).min(lines.len());
    let width = end.to_string().len();
    for n in start..=end {
        let marker = if n == cur { "=>" } else { "  " };
        println!("{} {:width$}  {}", marker, n, lines[n - 1], width = width);
    }
    true
}

/// 指定行の前後 2 行を含めてソースコードを表示します。
/// ファイルが読めない場合は false を返します。
fn print_source(path: &str, line: u32) -> bool {
    list_source(path, line, 2)
}

/// PC 以降の数命令を逆アセンブルして表示します。
fn print_disasm(dbg: &Debugger) {
    let Ok(pc) = dbg.pc() else {
        return;
    };
    match dbg.read_memory(pc as usize, 32) {
        Ok(code) => disasm::print(&code, pc, 4),
        Err(e) => eprintln!("failed to read memory for disasm: {}", e),
    }
}

/// dis コマンドの実装。指定アドレス (またはPC) から count 命令を逆アセンブル表示します。
fn show_disasm(
    parts: &[&str],
    dbg: &Debugger,
    base: Option<u64>,
    syms: Option<&Symbols>,
) {
    const DEFAULT_COUNT: usize = 10;
    // 命令数の引数を探す（最後の引数が純粋な整数なら count とみなす）
    let (loc_arg, count) = match parts {
        [_, loc, n] => {
            if let Ok(c) = n.parse::<usize>() {
                (Some(*loc), c)
            } else {
                (Some(*loc), DEFAULT_COUNT)
            }
        }
        [_, loc] => {
            if let Ok(c) = loc.parse::<usize>() {
                (None, c)
            } else {
                (Some(*loc), DEFAULT_COUNT)
            }
        }
        _ => (None, DEFAULT_COUNT),
    };

    let addr = if let Some(loc) = loc_arg {
        let cur_file = current_line(dbg, base, syms).map(|(f, _)| f);
        match resolve_location(loc, base, syms, cur_file.as_deref()) {
            Ok(a) => a as u64,
            Err(e) => {
                eprintln!("dis: {}", e);
                return;
            }
        }
    } else {
        match dbg.pc() {
            Ok(pc) => pc,
            Err(e) => {
                eprintln!("dis: failed to get PC: {}", e);
                return;
            }
        }
    };

    // シンボル情報があれば関数名ヘッダを表示
    if let (Some(syms), Some(base)) = (syms, base) {
        let slide = syms.slide(base);
        let vaddr = addr.wrapping_sub(slide);
        if let Some((name, _)) = syms.find_symbol_for_addr(vaddr) {
            println!("Dump of assembler code for function {}:", name);
        }
    }

    // x86_64 の最大命令長は 15 バイト
    let byte_len = count * 15;
    match dbg.read_memory(addr as usize, byte_len) {
        Ok(code) => disasm::print(&code, addr, count),
        Err(e) => eprintln!("dis: failed to read memory: {}", e),
    }
}

fn print_status(status: WaitStatus) {
    match status {
        WaitStatus::Stopped { signal, pc } => {
            println!("Stopped: signal={} pc={:#018x}", signal, pc);
        }
        WaitStatus::Exited { code } => {
            println!("Exited: code={}", code);
        }
        WaitStatus::Signaled { signal } => {
            println!("Signaled: signal={}", signal);
        }
        WaitStatus::Unknown { status } => {
            println!("Unknown status: {}", status);
        }
    }
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("Usage: macos-c-debugger <program> [args...]");
        std::process::exit(1);
    }

    let program = args.remove(0);
    let dbg_args = args;

    println!("Starting: {} {:?}", program, dbg_args);
    let mut dbg = Debugger::new(&program, &dbg_args)?;
    println!("Process started. pid={}", dbg.pid);
    print_status(dbg.last_status().unwrap());

    // SIGINTを子プロセスへ転送するハンドラを設定
    CHILD_PID.store(dbg.pid, Ordering::Relaxed);
    setup_sigint_handler();

    let base = dbg.image_base().ok();
    let syms = match Symbols::load(&program) {
        Ok(s) => {
            println!(
                "Loaded {} symbols, {} line table entries",
                s.symbol_count(),
                s.line_row_count()
            );
            if s.line_row_count() == 0 {
                eprintln!(
                    "warning: no line info; run `dsymutil {}` to generate a dSYM",
                    program
                );
            }
            Some(s)
        }
        Err(e) => {
            eprintln!("warning: failed to load symbols: {}", e);
            None
        }
    };

    let stdin = io::stdin();
    let mut line = String::new();

    loop {
        print!("(dbg) ");
        io::stdout().flush()?;
        line.clear();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "h" | "help" => {
                println!("commands:");
                println!("  h, help                      show this help");
                println!("  b, break <loc>               set breakpoint (addr | base+off | symbol | file:line)");
                println!("  c, continue, cont            continue execution");
                println!("  s, step                      step one source line (step into)");
                println!("  n, next                      step one source line (step over)");
                println!("  si, stepi                    step one instruction");
                println!("  up, finish                   run until current function returns");
                println!("  tb, bt, backtrace            show backtrace");
                println!("  list, l [loc]                show source code (loc: line | file:line | symbol)");
                println!("  syms, symbols [pat]          show loaded symbols (optional name filter)");
                println!("  lines [pat]                  show line number table (optional file filter)");
                println!("  dbg, info                    show debug info (symbols, line numbers, types)");
                println!("  p[/FMT], print[/FMT] <expr> evaluate and print (FMT: x X d u o t c a s)");
                println!("  set <lvalue> = <expr>        set register, variable, or memory");
                println!("                               (e.g. $rax = 1, myvar = 42, 0x1000 = 0xab)");
                println!("  r, regs, registers           show registers");
                println!("  m, mem, memory <addr>        read 4 bytes at address");
                println!("  dis [loc] [count]            disassemble instructions (default: PC, 10 insns)");
                println!("  base                         show main executable load address");
                println!("  q, quit, exit                quit");
            }
            "b" | "break" => {
                if parts.len() < 2 {
                    eprintln!("usage: b <addr | base+off | symbol | file:line>");
                    continue;
                }
                let cur_file = current_line(&dbg, base, syms.as_ref()).map(|(f, _)| f);
                match resolve_location(parts[1], base, syms.as_ref(), cur_file.as_deref()) {
                    Ok(addr) => {
                        dbg.set_breakpoint(addr)?;
                        println!("Breakpoint set at {:#018x}", addr);
                    }
                    Err(e) => {
                        eprintln!("could not resolve location {}: {}", parts[1], e);
                    }
                }
            }
            "c" | "continue" | "cont" => {
                CHILD_RUNNING.store(true, Ordering::SeqCst);
                let status = dbg.cont()?;
                CHILD_RUNNING.store(false, Ordering::SeqCst);
                print_status(status);
                if matches!(status, WaitStatus::Exited { .. }) {
                    break;
                }
                show_context(&dbg, base, syms.as_ref());
            }
            "s" | "step" => {
                CHILD_RUNNING.store(true, Ordering::SeqCst);
                let status = step_line(&mut dbg, base, syms.as_ref())?;
                CHILD_RUNNING.store(false, Ordering::SeqCst);
                print_status(status);
                if matches!(status, WaitStatus::Exited { .. }) {
                    break;
                }
                show_context(&dbg, base, syms.as_ref());
            }
            "n" | "next" => {
                CHILD_RUNNING.store(true, Ordering::SeqCst);
                let status = next_line(&mut dbg, base, syms.as_ref())?;
                CHILD_RUNNING.store(false, Ordering::SeqCst);
                print_status(status);
                if matches!(status, WaitStatus::Exited { .. }) {
                    break;
                }
                show_context(&dbg, base, syms.as_ref());
            }
            "si" | "stepi" => {
                CHILD_RUNNING.store(true, Ordering::SeqCst);
                let status = dbg.step()?;
                CHILD_RUNNING.store(false, Ordering::SeqCst);
                print_status(status);
                if matches!(status, WaitStatus::Exited { .. }) {
                    break;
                }
                show_context(&dbg, base, syms.as_ref());
            }
            "up" | "finish" => {
                CHILD_RUNNING.store(true, Ordering::SeqCst);
                let result = dbg.finish();
                CHILD_RUNNING.store(false, Ordering::SeqCst);
                match result {
                    Ok(status) => {
                        print_status(status);
                        if matches!(status, WaitStatus::Exited { .. }) {
                            break;
                        }
                        show_context(&dbg, base, syms.as_ref());
                    }
                    Err(e) => eprintln!("failed to finish: {}", e),
                }
            }
            "tb" | "bt" | "backtrace" => {
                print_backtrace(&dbg, base, syms.as_ref());
            }
            "list" | "l" => {
                show_list(&parts, &dbg, base, syms.as_ref());
            }
            "syms" | "symbols" => {
                if let Some(syms) = syms.as_ref() {
                    let filter = if parts.len() >= 2 { Some(parts[1]) } else { None };
                    syms.print_symbols(filter);
                } else {
                    eprintln!("no symbol information loaded");
                }
            }
            "lines" => {
                if let Some(syms) = syms.as_ref() {
                    let filter = if parts.len() >= 2 { Some(parts[1]) } else { None };
                    syms.print_lines(filter);
                } else {
                    eprintln!("no line information loaded");
                }
            }
            "dbg" | "info" => {
                println!("pid: {}", dbg.pid);
                println!("program: {}", program);
                if let Some(syms) = syms.as_ref() {
                    syms.print_debug_info(base);
                } else {
                    eprintln!("no symbol information loaded");
                }
            }
            "r" | "regs" | "registers" => {
                match dbg.registers() {
                    Ok(regs) => regs.display(),
                    Err(e) => eprintln!("failed to read registers: {}", e),
                }
            }
            cmd if cmd == "p" || cmd == "print"
                || cmd.starts_with("p/") || cmd.starts_with("print/") =>
            {
                let fmt_from_cmd = cmd.find('/').and_then(|i| cmd[i + 1..].chars().next());
                let rest = line.trim().splitn(2, char::is_whitespace).nth(1).unwrap_or("").trim();
                // "p /x expr" 形式 (コマンドと/FMTの間にスペース) にも対応
                let (fmt, expr_str) = if fmt_from_cmd.is_none() && rest.starts_with('/') {
                    let after_slash = &rest[1..];
                    let fmt_char = after_slash.chars().next().filter(|c| c.is_alphabetic());
                    if let Some(f) = fmt_char {
                        (Some(f), after_slash[f.len_utf8()..].trim())
                    } else {
                        (None, rest)
                    }
                } else {
                    (fmt_from_cmd, rest)
                };
                if expr_str.is_empty() {
                    eprintln!("usage: p[/FMT] <expr>  (FMT: x X d u o t c a s)");
                    continue;
                }
                match eval_expression(&dbg, base, syms.as_ref(), expr_str) {
                    Ok(v) => match fmt {
                        Some('x') => println!("{:#018x}", v),
                        Some('X') => println!("{:#018X}", v),
                        Some('d') => println!("{}", v as i64),
                        Some('u') => println!("{}", v),
                        Some('o') => println!("{:#o}", v),
                        Some('t') => println!("{:#b}", v),
                        Some('c') => {
                            let ch = char::from_u32(v as u32).unwrap_or('?');
                            if ch.is_ascii_graphic() || ch == ' ' {
                                println!("{} '{}'", v as i64, ch);
                            } else {
                                println!("{} '\\x{:02x}'", v as i64, v as u8);
                            }
                        }
                        Some('a') => println!("{:#018x}", v),
                        Some('s') => {
                            // vをポインタとしてnull終端文字列を読む
                            let mut addr = v as usize;
                            let mut s = String::new();
                            'read: loop {
                                match dbg.read_memory(addr, 64) {
                                    Ok(chunk) => {
                                        for &b in &chunk {
                                            if b == 0 {
                                                break 'read;
                                            }
                                            if b.is_ascii_graphic() || b == b' ' {
                                                s.push(b as char);
                                            } else {
                                                s.push_str(&format!("\\x{:02x}", b));
                                            }
                                        }
                                        addr += chunk.len();
                                    }
                                    Err(e) => {
                                        eprintln!("print: failed to read string at {:#x}: {}", v, e);
                                        break;
                                    }
                                }
                            }
                            println!("{:#018x}  \"{}\"", v, s);
                        }
                        Some(f) => eprintln!("print: unknown format '{}'", f),
                        None => {
                            if is_identifier(expr_str) {
                                println!("{}  ({:#x})", v as i64, v);
                            } else {
                                println!("{:#018x}  ({})", v, v);
                            }
                        }
                    },
                    Err(e) => eprintln!("print: {}", e),
                }
            }
            "set" => {
                let rest = line.trim().splitn(2, char::is_whitespace).nth(1).unwrap_or("").trim();
                if rest.is_empty() {
                    eprintln!("usage: set <lvalue> = <expr>");
                    continue;
                }
                let Some((target, value_expr)) = rest.split_once('=') else {
                    eprintln!("usage: set <lvalue> = <expr>");
                    continue;
                };
                let target = target.trim();
                let value_expr = value_expr.trim();
                if target.is_empty() || value_expr.is_empty() {
                    eprintln!("usage: set <lvalue> = <expr>");
                    continue;
                }
                let value = match eval_expression(&dbg, base, syms.as_ref(), value_expr) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("set: {}", e);
                        continue;
                    }
                };

                if target.starts_with('$')
                    && target.len() > 1
                    && target.chars().skip(1).all(|c| c.is_alphanumeric() || c == '_')
                {
                    let reg = &target[1..];
                    let mut regs = match dbg.registers() {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("failed to read registers: {}", e);
                            continue;
                        }
                    };
                    if regs.set(reg, value).is_none() {
                        eprintln!("unknown register: {}", target);
                        continue;
                    }
                    if let Err(e) = dbg.set_registers(&regs) {
                        eprintln!("failed to set registers: {}", e);
                        continue;
                    }
                    println!("set {} = {:#018x}", target, value);
                } else {
                    // 変数名なら値ではなくアドレスとサイズを取得する
                    let (addr, byte_size) = if is_identifier(target) {
                        match resolve_variable(&dbg, base, syms.as_ref(), target) {
                            Ok((a, sz)) => (a, sz as usize),
                            Err(e) => {
                                eprintln!("set: {}", e);
                                continue;
                            }
                        }
                    } else {
                        match eval_expression(&dbg, base, syms.as_ref(), target) {
                            Ok(v) => (v, 8),
                            Err(e) => {
                                eprintln!("set: {}", e);
                                continue;
                            }
                        }
                    };
                    let write_size = byte_size.clamp(1, 8);
                    let bytes = &value.to_le_bytes()[..write_size];
                    if let Err(e) = dbg.write_memory(addr as usize, bytes) {
                        eprintln!("failed to write memory: {}", e);
                        continue;
                    }
                    println!("[{:#018x}] = {}", addr, value as i64);
                }
            }
            "m" | "mem" | "memory" => {
                if parts.len() < 2 {
                    eprintln!("usage: m <addr>");
                    continue;
                }
                if let Some(addr) = parse_addr(parts[1], base) {
                    match dbg.read_word(addr) {
                        Ok(v) => println!("[{:#018x}] = {:#010x}", addr, v),
                        Err(e) => eprintln!("failed to read memory: {}", e),
                    }
                } else {
                    eprintln!("invalid address");
                }
            }
            "dis" | "disasm" | "disassemble" => {
                show_disasm(&parts, &dbg, base, syms.as_ref());
            }
            "base" => {
                match dbg.image_base() {
                    Ok(base) => println!("image base: {:#018x}", base),
                    Err(e) => eprintln!("failed to get image base: {}", e),
                }
            }
            "q" | "quit" | "exit" => {
                let _ = dbg.kill();
                break;
            }
            _ => {
                eprintln!("unknown command: {}", parts[0]);
            }
        }
    }

    Ok(())
}
