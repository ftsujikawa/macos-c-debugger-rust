use capstone::prelude::*;

/// 指定バイト列を逆アセンブルして表示します。
pub fn print(code: &[u8], pc: u64, count: usize) {
    let cs = match build_capstone() {
        Ok(cs) => cs,
        Err(e) => {
            eprintln!("failed to initialize capstone: {}", e);
            return;
        }
    };
    let insns = match cs.disasm_count(code, pc, count) {
        Ok(insns) => insns,
        Err(e) => {
            eprintln!("disasm error: {}", e);
            return;
        }
    };
    for insn in insns.iter() {
        let marker = if insn.address() == pc { "=>" } else { "  " };
        println!(
            "{} {:#018x}: {:8} {}",
            marker,
            insn.address(),
            insn.mnemonic().unwrap_or("?"),
            insn.op_str().unwrap_or(""),
        );
    }
}

/// 指定バイト列の先頭にある1命令を実行した後に PC が取りうるアドレス候補を返します。
/// (x86_64 のみ。可変長命令かつ jmp/call/jcc で直後アドレスに進まない場合があるため)
///
/// macOS の `ptrace(PT_STEP)` はマルチスレッドプロセスで SIGTRAP を返さず
/// ハングすることが確認できたため、このプロジェクトでは「次に実行されうる
/// アドレスに一時ブレークポイントを置いて PT_CONTINUE する」方式で1命令ステップを
/// 実現している。直接分岐 (即値オペランドを持つ jmp/call/jcc) は逆アセンブル結果
/// から分岐先を読み取って候補に加えるが、`ret` やレジスタ/メモリ経由の間接分岐は
/// 実行時までターゲットが分からないため直後アドレスにフォールバックする
/// (= その場合は正しく1命令で止まれないことがある既知の制限)。
#[cfg(target_arch = "x86_64")]
pub fn step_targets(code: &[u8], pc: u64) -> Vec<usize> {
    let fallback = vec![pc as usize + 1];
    let Ok(cs) = build_capstone() else { return fallback };
    let Ok(insns) = cs.disasm_count(code, pc, 1) else { return fallback };
    let Some(insn) = insns.iter().next() else { return fallback };

    let len = insn.bytes().len().max(1);
    let fallthrough = pc as usize + len;
    let mnemonic = insn.mnemonic().unwrap_or("");
    let op_str = insn.op_str().unwrap_or("").trim();
    let is_branch = mnemonic == "call" || mnemonic.starts_with('j') || mnemonic.starts_with("loop");
    let is_unconditional = mnemonic == "jmp" || mnemonic == "call";

    let mut targets = Vec::new();
    if is_branch {
        let parsed = op_str
            .strip_prefix("0x")
            .and_then(|h| usize::from_str_radix(h, 16).ok())
            .or_else(|| op_str.parse::<usize>().ok());
        if let Some(target) = parsed {
            targets.push(target);
        }
    }
    // 分岐先を特定できない場合 (間接分岐・ret) や条件分岐が不成立の場合に備えて
    // 直後の命令アドレスも常に候補に含める。
    if !is_unconditional || targets.is_empty() {
        targets.push(fallthrough);
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

#[cfg(target_arch = "x86_64")]
fn build_capstone() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()
}

#[cfg(target_arch = "aarch64")]
fn build_capstone() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build()
}
