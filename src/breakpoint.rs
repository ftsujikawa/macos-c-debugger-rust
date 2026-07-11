use crate::mach;
use crate::ptrace::Pid;

#[derive(Debug, Clone)]
pub struct Breakpoint {
    addr: usize,
    enabled: bool,
    saved_byte: u8,
}

impl Breakpoint {
    pub fn new(addr: usize) -> Self {
        Self {
            addr,
            enabled: false,
            saved_byte: 0,
        }
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// ブレークポイント設定前の元の 1 バイトを返します。
    pub fn saved_byte(&self) -> u8 {
        self.saved_byte
    }

    /// ブレークポイントを有効化します。int3 (0xCC) を 1 バイト書き込みます。
    pub fn enable(&mut self, pid: Pid) -> std::io::Result<()> {
        if self.enabled {
            return Ok(());
        }
        self.saved_byte = read_byte(pid, self.addr)?;
        write_byte(pid, self.addr, 0xCC)?;
        self.enabled = true;
        Ok(())
    }

    /// 元の 1 バイトを復元し、ブレークポイントを無効化します。
    pub fn disable(&mut self, pid: Pid) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        write_byte(pid, self.addr, self.saved_byte)?;
        self.enabled = false;
        Ok(())
    }

    /// ブレークポイントを通過後に再設定します。
    pub fn re_enable(&mut self, pid: Pid) -> std::io::Result<()> {
        if !self.enabled {
            self.enable(pid)?;
        }
        Ok(())
    }
}

/// 指定アドレスから 1 バイト読みます。
fn read_byte(pid: Pid, addr: usize) -> std::io::Result<u8> {
    mach::read_byte(pid, addr)
}

/// 指定アドレスに 1 バイト書きます。
fn write_byte(pid: Pid, addr: usize, byte: u8) -> std::io::Result<()> {
    mach::write_byte(pid, addr, byte)
}
