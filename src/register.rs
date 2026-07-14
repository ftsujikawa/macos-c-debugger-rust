#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct ThreadState64 {
    pub __rax: u64,
    pub __rbx: u64,
    pub __rcx: u64,
    pub __rdx: u64,
    pub __rdi: u64,
    pub __rsi: u64,
    pub __rbp: u64,
    pub __rsp: u64,
    pub __r8: u64,
    pub __r9: u64,
    pub __r10: u64,
    pub __r11: u64,
    pub __r12: u64,
    pub __r13: u64,
    pub __r14: u64,
    pub __r15: u64,
    pub __rip: u64,
    pub __rflags: u64,
    pub __cs: u64,
    pub __fs: u64,
    pub __gs: u64,
}

#[cfg(target_arch = "x86_64")]
impl ThreadState64 {
    pub fn pc(&self) -> u64 {
        self.__rip
    }
    pub fn set_pc(&mut self, pc: u64) {
        self.__rip = pc;
    }
    #[allow(dead_code)]
    pub fn sp(&self) -> u64 {
        self.__rsp
    }
    pub fn bp(&self) -> u64 {
        self.__rbp
    }

    /// レジスタ名から値を取得します。pc/rip や rsp などのエイリアスも対応します。
    pub fn get(&self, name: &str) -> Option<u64> {
        Some(match name.to_lowercase().as_str() {
            "pc" | "rip" => self.__rip,
            "sp" | "rsp" => self.__rsp,
            "bp" | "rbp" => self.__rbp,
            "rax" => self.__rax,
            "rbx" => self.__rbx,
            "rcx" => self.__rcx,
            "rdx" => self.__rdx,
            "rdi" => self.__rdi,
            "rsi" => self.__rsi,
            "r8" => self.__r8,
            "r9" => self.__r9,
            "r10" => self.__r10,
            "r11" => self.__r11,
            "r12" => self.__r12,
            "r13" => self.__r13,
            "r14" => self.__r14,
            "r15" => self.__r15,
            "rflags" => self.__rflags,
            "cs" => self.__cs,
            "fs" => self.__fs,
            "gs" => self.__gs,
            _ => return None,
        })
    }

    /// レジスタ名に値を設定します。pc/rip などのエイリアスも対応します。
    pub fn set(&mut self, name: &str, value: u64) -> Option<()> {
        match name.to_lowercase().as_str() {
            "pc" | "rip" => self.__rip = value,
            "sp" | "rsp" => self.__rsp = value,
            "bp" | "rbp" => self.__rbp = value,
            "rax" => self.__rax = value,
            "rbx" => self.__rbx = value,
            "rcx" => self.__rcx = value,
            "rdx" => self.__rdx = value,
            "rdi" => self.__rdi = value,
            "rsi" => self.__rsi = value,
            "r8" => self.__r8 = value,
            "r9" => self.__r9 = value,
            "r10" => self.__r10 = value,
            "r11" => self.__r11 = value,
            "r12" => self.__r12 = value,
            "r13" => self.__r13 = value,
            "r14" => self.__r14 = value,
            "r15" => self.__r15 = value,
            "rflags" => self.__rflags = value,
            "cs" => self.__cs = value,
            "fs" => self.__fs = value,
            "gs" => self.__gs = value,
            _ => return None,
        }
        Some(())
    }

    pub fn display(&self) {
        println!("  RIP: {:#018x}  RSP: {:#018x}  RBP: {:#018x}", self.__rip, self.__rsp, self.__rbp);
        println!("  RAX: {:#018x}  RBX: {:#018x}  RCX: {:#018x}  RDX: {:#018x}", self.__rax, self.__rbx, self.__rcx, self.__rdx);
        println!("  RSI: {:#018x}  RDI: {:#018x}  R08: {:#018x}  R09: {:#018x}", self.__rsi, self.__rdi, self.__r8, self.__r9);
        println!("  R10: {:#018x}  R11: {:#018x}  R12: {:#018x}  R13: {:#018x}", self.__r10, self.__r11, self.__r12, self.__r13);
        println!("  R14: {:#018x}  R15: {:#018x}  RFLAGS: {:#018x}", self.__r14, self.__r15, self.__rflags);
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct ThreadState64 {
    pub __x: [u64; 29],
    pub __fp: u64,
    pub __lr: u64,
    pub __sp: u64,
    pub __pc: u64,
    pub __cpsr: u32,
    pub __pad: u32,
}

#[cfg(target_arch = "aarch64")]
impl ThreadState64 {
    pub fn pc(&self) -> u64 {
        self.__pc
    }
    pub fn set_pc(&mut self, pc: u64) {
        self.__pc = pc;
    }
    #[allow(dead_code)]
    pub fn sp(&self) -> u64 {
        self.__sp
    }
    pub fn bp(&self) -> u64 {
        self.__fp
    }

    /// レジスタ名から値を取得します。pc や x0 などのエイリアスも対応します。
    pub fn get(&self, name: &str) -> Option<u64> {
        let name = name.to_lowercase();
        Some(match name.as_str() {
            "pc" => self.__pc,
            "sp" => self.__sp,
            "fp" | "bp" => self.__fp,
            "lr" => self.__lr,
            "cpsr" => self.__cpsr as u64,
            _ => {
                if let Some(rest) = name.strip_prefix('x') {
                    let n: usize = rest.parse().ok()?;
                    if n < 29 {
                        self.__x[n]
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        })
    }

    /// レジスタ名に値を設定します。pc や x0 などのエイリアスも対応します。
    pub fn set(&mut self, name: &str, value: u64) -> Option<()> {
        let name = name.to_lowercase();
        match name.as_str() {
            "pc" => self.__pc = value,
            "sp" => self.__sp = value,
            "fp" | "bp" => self.__fp = value,
            "lr" => self.__lr = value,
            "cpsr" => self.__cpsr = value as u32,
            _ => {
                if let Some(rest) = name.strip_prefix('x') {
                    let n: usize = rest.parse().ok()?;
                    if n < 29 {
                        self.__x[n] = value;
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        }
        Some(())
    }

    pub fn display(&self) {
        println!("  PC:  {:#018x}  SP: {:#018x}  FP: {:#018x}  LR: {:#018x}", self.__pc, self.__sp, self.__fp, self.__lr);
        for (i, v) in self.__x.iter().enumerate() {
            print!(" X{:02}: {:#018x} ", i, v);
            if (i + 1) % 4 == 0 {
                println!();
            }
        }
        println!("  CPSR: {:#010x}", self.__cpsr);
    }
}

/// x86_64 FPU 浮動小数点状態 (x86_FLOAT_STATE64)。
/// ST0-ST7 (x87 80ビット) / MM0-MM7 (MMX 64ビット) / MXCSR を保持します。
/// ST と MM は同じ物理レジスタのエイリアスです。
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Debug)]
pub struct FloatState64 {
    pub __fpu_reserved:   [i32; 2],
    pub __fpu_fcw:        u16,   // x87 FPU 制御ワード
    pub __fpu_fsw:        u16,   // x87 FPU ステータスワード
    pub __fpu_ftw:        u8,    // x87 FPU タグワード (abridged)
    pub __fpu_rsrv1:      u8,
    pub __fpu_fop:        u16,
    pub __fpu_ip:         u32,
    pub __fpu_cs:         u16,
    pub __fpu_rsrv2:      u16,
    pub __fpu_dp:         u32,
    pub __fpu_ds:         u16,
    pub __fpu_rsrv3:      u16,
    pub __fpu_mxcsr:      u32,
    pub __fpu_mxcsrmask:  u32,
    /// ST0-ST7 / MM0-MM7: 各 10 バイト値 + 6 バイトパディング = 16 バイト
    pub __fpu_stmm:       [[u8; 16]; 8],
    /// XMM0-XMM15: 各 16 バイト
    pub __fpu_xmm:        [[u8; 16]; 16],
    pub __fpu_rsrv4:      [u8; 96],
    pub __fpu_reserved1:  i32,
}

#[cfg(target_arch = "x86_64")]
impl Default for FloatState64 {
    fn default() -> Self {
        // Safety: 全フィールドが数値型 or バイト配列なのでゼロ初期化で有効
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_arch = "x86_64")]
impl FloatState64 {
    /// x87 80ビット拡張精度レジスタを f64 に変換します。
    /// 精度は落ちますが符号・指数・大まかな値は正確に保ちます。
    fn st_to_f64(reg: &[u8; 16]) -> f64 {
        let mant = u64::from_le_bytes(reg[0..8].try_into().unwrap());
        let exp_sign = u16::from_le_bytes([reg[8], reg[9]]);
        let sign = (exp_sign >> 15) as u64;
        let exp80 = (exp_sign & 0x7fff) as i32;

        // 特殊値処理
        if exp80 == 0x7fff {
            if mant & 0x7fff_ffff_ffff_ffff == 0 {
                let bits = (sign << 63) | 0x7ff0_0000_0000_0000;
                return f64::from_bits(bits); // ±Inf
            }
            return f64::NAN;
        }
        if exp80 == 0 && mant == 0 {
            return if sign != 0 { -0.0 } else { 0.0 };
        }

        // 通常値: 80ビットバイアス 16383 → 64ビットバイアス 1023
        // 80ビットは整数ビット明示。64ビットは暗黙。
        let exp64 = exp80 - 16383 + 1023;
        if exp64 >= 0x7ff {
            let bits = (sign << 63) | 0x7ff0_0000_0000_0000;
            return f64::from_bits(bits);
        }
        if exp64 <= 0 {
            return if sign != 0 { -0.0 } else { 0.0 };
        }
        // 64ビット仮数: 80ビット仮数の下位 63 ビットから上位 52 ビットを取る
        let frac = (mant >> 11) & 0x000f_ffff_ffff_ffff;
        f64::from_bits((sign << 63) | ((exp64 as u64) << 52) | frac)
    }

    /// レジスタ名に値を設定します。
    /// ST/MM: 下位 64 ビット (MMX 整数値) に書き込みます。
    /// XMM:   下位 64 ビットに書き込み、上位 64 ビットはゼロにします。
    pub fn set(&mut self, name: &str, value: u64) -> Option<()> {
        let name = name.to_lowercase();
        let bytes = value.to_le_bytes();
        // st0-st7 / mm0-mm7
        let st_idx: Option<usize> = if let Some(rest) = name.strip_prefix("st") {
            rest.parse().ok()
        } else if let Some(rest) = name.strip_prefix("mm") {
            rest.parse().ok()
        } else {
            None
        };
        if let Some(n) = st_idx {
            if n >= 8 { return None; }
            self.__fpu_stmm[n][..8].copy_from_slice(&bytes);
            self.__fpu_stmm[n][8..].fill(0);
            return Some(());
        }
        // xmm0-xmm15
        if let Some(rest) = name.strip_prefix("xmm") {
            let n: usize = rest.parse().ok()?;
            if n >= 16 { return None; }
            self.__fpu_xmm[n][..8].copy_from_slice(&bytes);
            self.__fpu_xmm[n][8..].fill(0);
            return Some(());
        }
        match name.as_str() {
            "mxcsr" => self.__fpu_mxcsr = value as u32,
            "fcw"   => self.__fpu_fcw   = value as u16,
            "fsw"   => self.__fpu_fsw   = value as u16,
            _ => return None,
        }
        Some(())
    }

    /// MMX / ST / XMM レジスタを表示します。
    pub fn display(&self) {
        println!(
            "  FCW: {:#06x}  FSW: {:#06x}  FTW: {:#04x}  MXCSR: {:#010x}",
            self.__fpu_fcw, self.__fpu_fsw, self.__fpu_ftw, self.__fpu_mxcsr
        );
        for i in 0..8 {
            let reg = &self.__fpu_stmm[i];
            let mant = u64::from_le_bytes(reg[0..8].try_into().unwrap());
            let exp_sign = u16::from_le_bytes([reg[8], reg[9]]);
            let fval = Self::st_to_f64(reg);
            println!(
                "  ST{i}/MM{i}: {exp_sign:04x} {mant:016x}  ({fval:e})"
            );
        }
        for i in 0..16 {
            let reg = &self.__fpu_xmm[i];
            let lo = u64::from_le_bytes(reg[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(reg[8..16].try_into().unwrap());
            print!(" XMM{i:02}: {hi:016x}_{lo:016x}");
            if (i + 1) % 2 == 0 {
                println!();
            }
        }
    }
}

/// ARM64 NEON/FP レジスタ状態 (ARM_NEON_STATE64)。
/// V0-V31 (128ビット) と FPSR/FPCR を保持します。
/// V レジスタは Q (128bit) / D (64bit) / S (32bit) / H (16bit) / B (8bit) で
/// 下位ビットをエイリアスします。
/// C 側は `__uint128_t v[32]` (16バイトアライン) を持つため、
/// 構造体全体のサイズも 16 の倍数にパディングされる (520→528 バイト)。
/// これが ARM_NEON_STATE64_COUNT の計算に影響するため align(16) で揃える。
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
#[derive(Clone, Debug)]
pub struct ArmNeonState64 {
    pub v: [[u8; 16]; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

#[cfg(target_arch = "aarch64")]
impl Default for ArmNeonState64 {
    fn default() -> Self {
        // Safety: 全フィールドが数値型 or バイト配列なのでゼロ初期化で有効
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_arch = "aarch64")]
impl ArmNeonState64 {
    /// レジスタ名に値を設定します。
    /// v/q: 下位 64 ビットに書き込み、上位 64 ビットはゼロにします。
    /// d/s/h/b: 該当バイト幅のみ書き込みます (残りは変更しません)。
    pub fn set(&mut self, name: &str, value: u64) -> Option<()> {
        let name = name.to_lowercase();
        let bytes = value.to_le_bytes();

        let (prefix, rest) = if let Some(r) = name.strip_prefix('v') {
            ('v', r)
        } else if let Some(r) = name.strip_prefix('q') {
            ('q', r)
        } else if let Some(r) = name.strip_prefix('d') {
            ('d', r)
        } else if let Some(r) = name.strip_prefix('s') {
            ('s', r)
        } else if let Some(r) = name.strip_prefix('h') {
            ('h', r)
        } else if let Some(r) = name.strip_prefix('b') {
            ('b', r)
        } else {
            return match name.as_str() {
                "fpsr" => { self.fpsr = value as u32; Some(()) }
                "fpcr" => { self.fpcr = value as u32; Some(()) }
                _ => None,
            };
        };
        let n: usize = rest.parse().ok()?;
        if n >= 32 {
            return None;
        }
        match prefix {
            'v' | 'q' => {
                self.v[n][..8].copy_from_slice(&bytes);
                self.v[n][8..].fill(0);
            }
            'd' => self.v[n][..8].copy_from_slice(&bytes),
            's' => self.v[n][..4].copy_from_slice(&bytes[..4]),
            'h' => self.v[n][..2].copy_from_slice(&bytes[..2]),
            'b' => self.v[n][..1].copy_from_slice(&bytes[..1]),
            _ => unreachable!(),
        }
        Some(())
    }

    /// V0-V31 / FPSR / FPCR を表示します。
    pub fn display(&self) {
        println!("  FPSR: {:#010x}  FPCR: {:#010x}", self.fpsr, self.fpcr);
        for i in 0..32 {
            let reg = &self.v[i];
            let lo = u64::from_le_bytes(reg[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(reg[8..16].try_into().unwrap());
            print!(" V{i:02}: {hi:016x}_{lo:016x}");
            if (i + 1) % 2 == 0 {
                println!();
            }
        }
    }
}

/// ARM64 デバッグ状態 (ARM_DEBUG_STATE64)
/// ハードウェアブレークポイント / ウォッチポイントレジスタを保持する。
///
/// AArch64 デバッグアーキテクチャ:
///   BVR[n] = ブレークポイントアドレス
///   BCR[n] = ブレークポイント制御
///   WVR[n] = ウォッチポイントアドレス
///   WCR[n] = ウォッチポイント制御
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct ArmDebugState64 {
    pub bvr: [u64; 16],
    pub bcr: [u64; 16],
    pub wvr: [u64; 16],
    pub wcr: [u64; 16],
    pub mdscr_el1: u64,
}

/// BCR の基本制御値 (ユーザ空間アドレスブレークポイント)
///   E   bit[0]   = 1  (有効)
///   PMC bit[2:1] = 10 (EL0 のみ)
///   BAS bit[8:5] = 1111 (4 バイト命令全バイトマッチ)
#[cfg(target_arch = "aarch64")]
pub const HW_BP_BCR_ENABLE: u64 = 0x1E5;

/// ARM64 ウォッチポイント用 WVR (監視アドレス) と WCR (制御値) を組み立てます。
///
/// AArch64 デバッグアーキテクチャ:
///   WVR.VA bits[63:3] = ウォッチアドレス (8バイト境界にアライン、下位3ビットは RES0)
///   WCR: E bit[0]=1(有効), PAC bits[2:1]=10(EL0のみ), LSC bits[4:3]=Load/Store制御,
///        BAS bits[12:5]=アライン済みアドレスからのバイトマスク
#[cfg(target_arch = "aarch64")]
pub fn wcr_encode(addr: usize, cond: WatchCondition, len: WatchLen) -> (u64, u64) {
    let size = len.as_bytes();
    let offset = addr & 0x7;
    let bas: u64 = (((1u64 << size) - 1) << offset) & 0xff;
    let lsc: u64 = match cond {
        WatchCondition::Write => 0b10,
        _ => 0b11, // ReadWrite など (Load/Store 両方)
    };
    let wcr = 1u64            // E: 有効
        | (0b10u64 << 1)      // PAC: EL0 のみ
        | (lsc << 3)          // LSC
        | (bas << 5);         // BAS
    let wvr = (addr as u64) & !0x7;
    (wvr, wcr)
}

/// x86_64 デバッグ状態 (x86_DEBUG_STATE64, flavor = 12)
/// DR0〜DR3 がウォッチポイント / ブレークポイントアドレス。
/// DR6 = ステータス、DR7 = 制御。
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct X86DebugState64 {
    pub __dr0: u64,
    pub __dr1: u64,
    pub __dr2: u64,
    pub __dr3: u64,
    pub __dr4: u64,
    pub __dr5: u64,
    pub __dr6: u64,
    pub __dr7: u64,
}

/// DR7 制御レジスタのフィールドを組み立てます。
///
/// slot: 0〜3、condition: WatchCondition
#[cfg(target_arch = "x86_64")]
pub fn dr7_set_slot(dr7: u64, slot: usize, cond: WatchCondition, len: WatchLen) -> u64 {
    // 各スロットの有効ビット: L0=bit0, L1=bit2, L2=bit4, L3=bit6
    let enable_bit = slot * 2;
    // R/W フィールド: bits [17+slot*4 .. 18+slot*4]
    let rw_shift = 16 + slot * 4;
    // LEN フィールド: bits [19+slot*4 .. 20+slot*4]
    let len_shift = 18 + slot * 4;

    let rw_bits = cond as u64;
    let len_bits = len as u64;

    // 対象スロットの既存ビットをクリア
    let mask = (0b11u64 << rw_shift) | (0b11u64 << len_shift) | (0b11u64 << enable_bit);
    let cleared = dr7 & !mask;

    cleared
        | (1u64 << enable_bit)           // Local enable
        | (rw_bits << rw_shift)
        | (len_bits << len_shift)
}

#[cfg(target_arch = "x86_64")]
pub fn dr7_clear_slot(dr7: u64, slot: usize) -> u64 {
    let enable_bit = slot * 2;
    let rw_shift = 16 + slot * 4;
    let len_shift = 18 + slot * 4;
    let mask = (0b11u64 << rw_shift) | (0b11u64 << len_shift) | (0b11u64 << enable_bit);
    dr7 & !mask
}

/// ウォッチポイントのトリガー条件 (x86_64: DR7 R/W フィールド、ARM64: WCR LSC フィールド)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchCondition {
    /// 実行 (ブレークポイント)
    #[allow(dead_code)]
    Execute = 0b00,
    /// 書き込み
    Write    = 0b01,
    /// 読み書き（I/O アドレス空間、x86_64 のみ）
    #[allow(dead_code)]
    IoRW     = 0b10,
    /// 読み書き（データアドレス空間）
    ReadWrite = 0b11,
}

/// ウォッチポイントの監視バイト幅 (x86_64: DR7 LEN フィールド、ARM64: WCR BAS 幅)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchLen {
    Byte1  = 0b00,
    Word2  = 0b01,
    QWord8 = 0b10,
    Dword4 = 0b11,
}

impl WatchLen {
    pub fn from_bytes(n: usize) -> Self {
        match n {
            2 => Self::Word2,
            4 => Self::Dword4,
            8 => Self::QWord8,
            _ => Self::Byte1,
        }
    }
    pub fn as_bytes(self) -> usize {
        match self {
            Self::Byte1  => 1,
            Self::Word2  => 2,
            Self::Dword4 => 4,
            Self::QWord8 => 8,
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture: this debugger base is only for x86_64 or aarch64 macOS");
