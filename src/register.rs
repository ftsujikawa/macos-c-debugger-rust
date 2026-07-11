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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture: this debugger base is only for x86_64 or aarch64 macOS");
