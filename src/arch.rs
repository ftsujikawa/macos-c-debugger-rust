/// デバッグ対象プログラムのアーキテクチャ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// ブレークポイント命令のバイト列 (x86_64 SW BP 用)
    #[allow(dead_code)]
    pub fn bp_bytes(self) -> &'static [u8] {
        match self {
            // int3
            Arch::X86_64 => &[0xCC],
            // brk #0  (LE: 0xD4200000)
            Arch::Aarch64 => &[0x00, 0x00, 0x20, 0xD4],
        }
    }

    /// ブレークポイント命令のバイト数
    pub fn bp_size(self) -> usize {
        self.bp_bytes().len()
    }

    /// ブレークポイントヒット直後に PC が BP アドレスから何バイト先を指しているか
    /// x86: int3 実行後 PC は次の命令 (BP アドレス + 1)
    /// ARM64: brk はトラップ後も PC が brk 命令を指したまま (オフセット 0)
    pub fn bp_pc_offset(self) -> usize {
        match self {
            Arch::X86_64 => 1,
            Arch::Aarch64 => 0,
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "aarch64"),
        }
    }
}
