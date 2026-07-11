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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture: this debugger base is only for x86_64 or aarch64 macOS");
