use crate::arch::Arch;
use crate::mach;
use crate::ptrace::Pid;

#[derive(Debug, Clone)]
pub struct Breakpoint {
    addr: usize,
    enabled: bool,
    /// 上書き前の元バイト列 (x86: 1 バイト, ARM64 SW: 4 バイト, ARM64 HW: 空)
    saved_bytes: Vec<u8>,
    #[allow(dead_code)]
    arch: Arch,
}

impl Breakpoint {
    #[allow(dead_code)]
    pub fn new(addr: usize, arch: Arch) -> Self {
        Self {
            addr,
            enabled: false,
            saved_bytes: Vec::new(),
            arch,
        }
    }

    /// ARM64 ハードウェア BP 用: コードを書かずに有効済みとしてマークします。
    #[cfg(target_arch = "aarch64")]
    pub fn new_hw_enabled(addr: usize, arch: Arch) -> Self {
        Self {
            addr,
            enabled: true,
            saved_bytes: Vec::new(),
            arch,
        }
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// ブレークポイント設定前の元バイト列を返します。
    pub fn saved_bytes(&self) -> &[u8] {
        &self.saved_bytes
    }

    /// ブレークポイントを有効化します。
    /// x86_64: int3 (0xCC) を 1 バイト書き込みます。
    #[allow(dead_code)]
    pub fn enable(&mut self, pid: Pid) -> std::io::Result<()> {
        if self.enabled {
            return Ok(());
        }
        self.saved_bytes = mach::read_memory(pid, self.addr, self.arch.bp_size())?;
        mach::write_memory(pid, self.addr, self.arch.bp_bytes())?;
        self.enabled = true;
        Ok(())
    }

    /// 元のバイト列を復元し、ブレークポイントを無効化します。
    #[allow(dead_code)]
    pub fn disable(&mut self, pid: Pid) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        mach::write_memory(pid, self.addr, &self.saved_bytes.clone())?;
        self.enabled = false;
        Ok(())
    }

    /// ブレークポイントを通過後に再設定します。
    #[allow(dead_code)]
    pub fn re_enable(&mut self, pid: Pid) -> std::io::Result<()> {
        if !self.enabled {
            self.enable(pid)?;
        }
        Ok(())
    }
}
