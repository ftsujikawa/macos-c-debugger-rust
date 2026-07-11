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
