use std::os::raw::c_int;

use crate::arch::Arch;
use crate::ptrace::Pid;
#[cfg(target_arch = "aarch64")]
use crate::ptrace;
use crate::register::ThreadState64;
#[cfg(target_arch = "x86_64")]
use crate::register::{FloatState64, X86DebugState64, WatchCondition, WatchLen, dr7_set_slot, dr7_clear_slot};
#[cfg(target_arch = "aarch64")]
use crate::register::{ArmDebugState64, HW_BP_BCR_ENABLE, WatchCondition, WatchLen, wcr_encode};

pub type MachPort = u32;
pub type KernReturn = c_int;

#[cfg(target_arch = "x86_64")]
const THREAD_STATE64_FLAVOR: i32 = 4; // x86_THREAD_STATE64
#[cfg(target_arch = "x86_64")]
const FLOAT_STATE64_FLAVOR: i32 = 5; // x86_FLOAT_STATE64
#[cfg(target_arch = "x86_64")]
const FLOAT_STATE64_COUNT: u32 = 131; // x86_FLOAT_STATE64_COUNT (524 bytes / 4)
#[cfg(target_arch = "x86_64")]
const DEBUG_STATE64_FLAVOR: i32 = 12; // x86_DEBUG_STATE64
// x86_DEBUG_STATE64_COUNT = sizeof(x86_debug_state64_t) / sizeof(int) = 64 / 4 = 16
#[cfg(target_arch = "x86_64")]
const DEBUG_STATE64_COUNT: u32 = (std::mem::size_of::<crate::register::X86DebugState64>() / 4) as u32;

#[cfg(target_arch = "aarch64")]
const THREAD_STATE64_FLAVOR: i32 = 6; // ARM_THREAD_STATE64
#[cfg(target_arch = "aarch64")]
const ARM_DEBUG_STATE64_FLAVOR: i32 = 15; // ARM_DEBUG_STATE64
#[cfg(target_arch = "aarch64")]
const ARM_DEBUG_STATE64_COUNT: u32 = 130; // 520 bytes / 4 (bvr[16]+bcr[16]+wvr[16]+wcr[16]+mdscr_el1)

#[allow(dead_code)]
const VM_PROT_NONE: i32 = 0x00;
const VM_PROT_READ: i32 = 0x01;
const VM_PROT_WRITE: i32 = 0x02;
#[allow(dead_code)]
const VM_PROT_EXECUTE: i32 = 0x04;
const VM_PROT_COPY: i32 = 0x10;

const VM_REGION_BASIC_INFO_64: i32 = 9;
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

#[cfg(target_arch = "aarch64")]
const PAGE_SIZE: usize = 16384;
#[cfg(not(target_arch = "aarch64"))]
const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = PAGE_SIZE - 1;

extern "C" {
    static mut mach_task_self_: MachPort;

    fn task_for_pid(target_tport: MachPort, pid: c_int, t: *mut MachPort) -> KernReturn;
    fn task_threads(
        target_task: MachPort,
        act_list: *mut *mut MachPort,
        act_listCnt: *mut u32,
    ) -> KernReturn;
    fn thread_get_state(
        target_act: MachPort,
        flavor: i32,
        old_state: *mut u32,
        old_stateCnt: *mut u32,
    ) -> KernReturn;
    fn thread_set_state(
        target_act: MachPort,
        flavor: i32,
        new_state: *const u32,
        new_stateCnt: u32,
    ) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn vm_deallocate(target_task: MachPort, address: usize, size: usize) -> KernReturn;

    fn mach_vm_region(
        target_task: MachPort,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        infoCnt: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;
    fn mach_vm_read(
        target_task: MachPort,
        address: u64,
        size: u64,
        data: *mut usize,
        dataCnt: *mut u32,
    ) -> KernReturn;
    fn mach_vm_write(
        target_task: MachPort,
        address: u64,
        data: usize,
        dataCnt: u32,
    ) -> KernReturn;
    fn mach_vm_protect(
        target_task: MachPort,
        address: u64,
        size: u64,
        set_maximum: i32,
        new_protection: i32,
    ) -> KernReturn;
}

fn mach_err(ret: KernReturn, msg: &str) -> std::io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{}: mach error {}", msg, ret),
        ))
    }
}

fn task_self() -> MachPort {
    unsafe { mach_task_self_ }
}

/// 指定 PID のタスクポートを取得します。
/// 対象プロセスには `com.apple.security.get-task-allow` エンタイトルメントが必要です。
pub fn get_task(pid: Pid) -> std::io::Result<MachPort> {
    let mut task: MachPort = 0;
    unsafe {
        let ret = task_for_pid(task_self(), pid as c_int, &mut task);
        mach_err(ret, "task_for_pid")?;
    }
    Ok(task)
}

/// タスク内の先頭スレッド番号を取得します。
pub fn get_main_thread(task: MachPort) -> std::io::Result<MachPort> {
    unsafe {
        let mut list: *mut MachPort = std::ptr::null_mut();
        let mut count: u32 = 0;
        let ret = task_threads(task, &mut list, &mut count);
        if ret != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("task_threads: mach error {}", ret),
            ));
        }
        if list.is_null() || count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "task_threads returned no threads",
            ));
        }
        let thread = *list;
        // MIG から返された配列を解放
        let _ = vm_deallocate(task_self(), list as usize, count as usize * std::mem::size_of::<MachPort>());
        Ok(thread)
    }
}

/// レジスタ状態を取得します。
pub fn get_registers(pid: Pid) -> std::io::Result<ThreadState64> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let mut state = ThreadState64::default();
        let mut count = (std::mem::size_of::<ThreadState64>() / std::mem::size_of::<u32>()) as u32;
        let ret = thread_get_state(
            thread,
            THREAD_STATE64_FLAVOR,
            &mut state as *mut ThreadState64 as *mut u32,
            &mut count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_get_state")?;
        Ok(state)
    }
}

/// 浮動小数点レジスタ状態を取得します (x86_64 のみ)。
#[cfg(target_arch = "x86_64")]
pub fn get_float_registers(pid: Pid) -> std::io::Result<FloatState64> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let mut state = FloatState64::default();
        let mut count = FLOAT_STATE64_COUNT;
        let ret = thread_get_state(
            thread,
            FLOAT_STATE64_FLAVOR,
            &mut state as *mut FloatState64 as *mut u32,
            &mut count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_get_state (float)")?;
        Ok(state)
    }
}

/// 浮動小数点レジスタ状態を設定します (x86_64 のみ)。
#[cfg(target_arch = "x86_64")]
pub fn set_float_registers(pid: Pid, state: &FloatState64) -> std::io::Result<()> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let count = FLOAT_STATE64_COUNT;
        let ret = thread_set_state(
            thread,
            FLOAT_STATE64_FLAVOR,
            state as *const FloatState64 as *const u32,
            count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_set_state (float)")?;
        Ok(())
    }
}

/// レジスタ状態を設定します。
pub fn set_registers(pid: Pid, state: &ThreadState64) -> std::io::Result<()> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let count = (std::mem::size_of::<ThreadState64>() / std::mem::size_of::<u32>()) as u32;
        let ret = thread_set_state(
            thread,
            THREAD_STATE64_FLAVOR,
            state as *const ThreadState64 as *const u32,
            count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_set_state")?;
        Ok(())
    }
}

/// ARM64 ハードウェアデバッグ状態を取得します。
#[cfg(target_arch = "aarch64")]
pub fn get_debug_state(pid: Pid) -> std::io::Result<ArmDebugState64> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let mut state = ArmDebugState64::default();
        let mut count = ARM_DEBUG_STATE64_COUNT;
        let ret = thread_get_state(
            thread,
            ARM_DEBUG_STATE64_FLAVOR,
            &mut state as *mut ArmDebugState64 as *mut u32,
            &mut count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_get_state (debug)")?;
        Ok(state)
    }
}

/// ARM64 ハードウェアデバッグ状態を設定します。
#[cfg(target_arch = "aarch64")]
pub fn set_debug_state(pid: Pid, state: &ArmDebugState64) -> std::io::Result<()> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let count = ARM_DEBUG_STATE64_COUNT;
        let ret = thread_set_state(
            thread,
            ARM_DEBUG_STATE64_FLAVOR,
            state as *const ArmDebugState64 as *const u32,
            count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_set_state (debug)")?;
        Ok(())
    }
}

/// 指定スロットにハードウェアブレークポイントを設定します。
/// slot は 0..16 の範囲。
#[cfg(target_arch = "aarch64")]
pub fn set_hw_breakpoint_slot(pid: Pid, slot: usize, addr: usize) -> std::io::Result<()> {
    assert!(slot < 16, "HW BP slot must be 0..15");
    let mut state = get_debug_state(pid)?;
    state.bvr[slot] = addr as u64;
    state.bcr[slot] = HW_BP_BCR_ENABLE;
    set_debug_state(pid, &state)
}

/// 指定スロットのハードウェアブレークポイントをクリアします。
#[cfg(target_arch = "aarch64")]
pub fn clear_hw_breakpoint_slot(pid: Pid, slot: usize) -> std::io::Result<()> {
    assert!(slot < 16, "HW BP slot must be 0..15");
    let mut state = get_debug_state(pid)?;
    state.bvr[slot] = 0;
    state.bcr[slot] = 0;
    set_debug_state(pid, &state)
}

/// 指定スロットにハードウェアウォッチポイントを設定します。
/// slot は 0..4 の範囲。
#[cfg(target_arch = "aarch64")]
pub fn set_hw_watchpoint_slot(
    pid: Pid,
    slot: usize,
    addr: usize,
    cond: WatchCondition,
    len: WatchLen,
) -> std::io::Result<()> {
    assert!(slot < 4, "HW watchpoint slot must be 0..3");
    let mut state = get_debug_state(pid)?;
    let (wvr, wcr) = wcr_encode(addr, cond, len);
    state.wvr[slot] = wvr;
    state.wcr[slot] = wcr;
    set_debug_state(pid, &state)
}

/// 指定スロットのハードウェアウォッチポイントをクリアします。
#[cfg(target_arch = "aarch64")]
pub fn clear_hw_watchpoint_slot(pid: Pid, slot: usize) -> std::io::Result<()> {
    assert!(slot < 4, "HW watchpoint slot must be 0..3");
    let mut state = get_debug_state(pid)?;
    state.wvr[slot] = 0;
    state.wcr[slot] = 0;
    set_debug_state(pid, &state)
}

/// 指定アドレスから `size` バイトを読みます。
pub fn read_memory(pid: Pid, addr: usize, size: usize) -> std::io::Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let task = get_task(pid)?;
    unsafe {
        let mut data: usize = 0;
        let mut cnt: u32 = 0;
        let ret = mach_vm_read(task, addr as u64, size as u64, &mut data, &mut cnt);
        if ret != 0 {
            let _ = mach_port_deallocate(task_self(), task);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mach_vm_read: error {}", ret),
            ));
        }
        if data == 0 || cnt == 0 {
            let _ = mach_port_deallocate(task_self(), task);
            return Ok(Vec::new());
        }
        let slice = std::slice::from_raw_parts(data as *const u8, cnt as usize);
        let result = slice.to_vec();
        let _ = vm_deallocate(task_self(), data, cnt as usize);
        let _ = mach_port_deallocate(task_self(), task);
        Ok(result)
    }
}

/// 指定アドレスに `data` を書き込みます。
///
/// コードページへの書き込み戦略 (ARM64 Apple Silicon 対応):
///
/// exec 直後の最初の停止では max_prot=rwx なので VM_PROT_COPY が使える。
/// プロセスが一度実行を開始するとコードサイニングにより max_prot が r-x に固定され、
/// VM_PROT_COPY は KERN_PROTECTION_FAILURE を返すようになる。
///
/// 戦略1: VM_PROT_COPY で CoW 書き込み (exec 直後に成功)
/// 戦略2: mach_vm_write 直接 (cs.debugger + get-task-allow 環境では
///         カーネルがデバッガの書き込みを特別許可することがある)
/// 戦略3: 戦略1 と 2 が両方失敗した場合はエラーを返す
pub fn write_memory(pid: Pid, addr: usize, data: &[u8]) -> std::io::Result<()> {
    let task = get_task(pid)?;
    unsafe {
        let mut region_addr: u64 = addr as u64;
        let mut region_size: u64 = 0;
        let mut info: [i32; 9] = [0; 9];
        let mut info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object_name: MachPort = 0;
        let ret = mach_vm_region(
            task,
            &mut region_addr,
            &mut region_size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut info_cnt,
            &mut object_name,
        );
        if ret != 0 {
            let _ = mach_port_deallocate(task_self(), task);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mach_vm_region: error {}", ret),
            ));
        }
        let _ = mach_port_deallocate(task_self(), object_name);

        let original_prot = info[0];
        let max_prot = info[1];
        let page = (addr as u64) & !(PAGE_MASK as u64);
        let page_size = PAGE_SIZE as u64;

        let needs_protect = original_prot & VM_PROT_WRITE == 0;
        let mut protection_changed = false;
        let mut protect_err = 0i32;

        if needs_protect {
            // 戦略1: VM_PROT_COPY で CoW 書き込み (exec 直後の max_prot=rwx 時に成功)
            let write_prot = if max_prot & VM_PROT_WRITE != 0 {
                original_prot | VM_PROT_WRITE
            } else {
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
            };
            let ret = mach_vm_protect(task, page, page_size, 0, write_prot);
            if ret == 0 {
                protection_changed = true;
            } else {
                // 戦略1 失敗: protect エラーを記録しておく
                // 戦略2 (直接書き込み) を次に試みる
                protect_err = ret;
            }
        }

        // 書き込みを試みる (戦略1 で保護変更済みか、戦略2 として直接試みる)
        let ret = mach_vm_write(task, addr as u64, data.as_ptr() as usize, data.len() as u32);

        if needs_protect && protection_changed {
            let _ = mach_vm_protect(task, page, page_size, 0, original_prot);
        }

        if ret != 0 {
            // 戦略3 (ARM64 のみ): ptrace(PT_WRITE_I) でコードページに書き込む
            // mach_vm_write が KERN_INVALID_ADDRESS を返す場合の代替手段
            #[cfg(target_arch = "aarch64")]
            if data.len() == 4 && addr % 4 == 0 {
                let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                if ptrace::write_code_word(pid, addr, word).is_ok() {
                    let _ = mach_port_deallocate(task_self(), task);
                    return Ok(());
                }
            }

            let _ = mach_port_deallocate(task_self(), task);
            let msg = if needs_protect && !protection_changed {
                format!("mach_vm_protect: error {} (write also failed: {})", protect_err, ret)
            } else {
                format!("mach_vm_write: error {}", ret)
            };
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }

        let _ = mach_port_deallocate(task_self(), task);
        Ok(())
    }
}

/// 4 バイトを読みます。
pub fn read_word(pid: Pid, addr: usize) -> std::io::Result<u32> {
    let buf = read_memory(pid, addr, 4)?;
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// 4 バイトを書きます。
#[allow(dead_code)]
pub fn write_word(pid: Pid, addr: usize, value: u32) -> std::io::Result<()> {
    write_memory(pid, addr, &value.to_le_bytes())
}

/// 1 バイトを読みます。
pub fn read_byte(pid: Pid, addr: usize) -> std::io::Result<u8> {
    let buf = read_memory(pid, addr, 1)?;
    Ok(buf[0])
}

/// 1 バイトを書きます。
pub fn write_byte(pid: Pid, addr: usize, value: u8) -> std::io::Result<()> {
    write_memory(pid, addr, &[value])
}

/// メイン実行ファイルの実行時ベースアドレスを取得します。
/// 0x100000000 以降のメモリ領域を走査し、Mach-O 64 ビットマジック
/// 0xfeedfacf を含む領域を探します。
pub fn get_text_base(pid: Pid) -> std::io::Result<u64> {
    let task = get_task(pid)?;
    unsafe {
        let mut addr: u64 = 0x100000000;
        let mut size: u64 = 0;
        let mut info: [i32; 9] = [0; 9];
        let mut info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object_name: MachPort = 0;

        for _ in 0..32 {
            let ret = mach_vm_region(
                task,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut info_cnt,
                &mut object_name,
            );
            if ret != 0 {
                break;
            }
            let _ = mach_port_deallocate(task_self(), object_name);
            object_name = 0;

            let magic = read_memory(pid, addr as usize, 4);
            if let Ok(magic) = magic {
                if magic.len() == 4
                    && magic[0] == 0xcf
                    && magic[1] == 0xfa
                    && magic[2] == 0xed
                    && magic[3] == 0xfe
                {
                    let _ = mach_port_deallocate(task_self(), task);
                    return Ok(addr);
                }
            }

            if size == 0 {
                break;
            }
            addr += size;
        }

        let _ = mach_port_deallocate(task_self(), task);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "main executable base not found",
        ))
    }
}

/// 子プロセスの Mach-O ヘッダを読み、CPU アーキテクチャを返します。
/// Mach-O 64 ヘッダ: [magic:4][cpu_type:4][cpu_subtype:4]...
/// CPU_TYPE_X86_64  = 0x01000007
/// CPU_TYPE_ARM64   = 0x0100000C
pub fn detect_arch(pid: Pid) -> std::io::Result<Arch> {
    let base = get_text_base(pid)?;
    // magic の直後 4 バイトが cpu_type
    let buf = read_memory(pid, base as usize + 4, 4)?;
    let cpu_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    match cpu_type {
        0x01000007 => Ok(Arch::X86_64),
        0x0100000C => Ok(Arch::Aarch64),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unknown cpu_type in Mach-O header: {:#010x}", cpu_type),
        )),
    }
}

/// x86_64 デバッグレジスタ状態を取得します。
#[cfg(target_arch = "x86_64")]
pub fn get_debug_state(pid: Pid) -> std::io::Result<X86DebugState64> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let mut state = X86DebugState64::default();
        let mut count = DEBUG_STATE64_COUNT;
        let ret = thread_get_state(
            thread,
            DEBUG_STATE64_FLAVOR,
            &mut state as *mut X86DebugState64 as *mut u32,
            &mut count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        if ret != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "thread_get_state (x86_DEBUG_STATE64): mach error {} \
                     — デバッグレジスタへのアクセスには cs.debugger エンタイトルメントが必要です。\
                     `make sign` を実行してデバッガーに署名してください。\
                     Apple Silicon + Rosetta 2 環境では x86 デバッグレジスタは使用できません。",
                    ret
                ),
            ));
        }
        Ok(state)
    }
}

/// x86_64 デバッグレジスタ状態を設定します。
#[cfg(target_arch = "x86_64")]
pub fn set_debug_state(pid: Pid, state: &X86DebugState64) -> std::io::Result<()> {
    let task = get_task(pid)?;
    unsafe {
        let thread = get_main_thread(task)?;
        let count = DEBUG_STATE64_COUNT;
        let ret = thread_set_state(
            thread,
            DEBUG_STATE64_FLAVOR,
            state as *const X86DebugState64 as *const u32,
            count,
        );
        let _ = mach_port_deallocate(task_self(), thread);
        let _ = mach_port_deallocate(task_self(), task);
        mach_err(ret, "thread_set_state (debug)")?;
        Ok(())
    }
}

/// 指定スロット (0〜3) にウォッチポイントを設定します。
#[cfg(target_arch = "x86_64")]
pub fn set_watchpoint_slot(
    pid: Pid,
    slot: usize,
    addr: usize,
    cond: WatchCondition,
    len: WatchLen,
) -> std::io::Result<()> {
    assert!(slot < 4, "watchpoint slot must be 0..3");
    let mut state = get_debug_state(pid)?;
    // DRn にアドレスを設定
    match slot {
        0 => state.__dr0 = addr as u64,
        1 => state.__dr1 = addr as u64,
        2 => state.__dr2 = addr as u64,
        3 => state.__dr3 = addr as u64,
        _ => unreachable!(),
    }
    state.__dr7 = dr7_set_slot(state.__dr7, slot, cond, len);
    set_debug_state(pid, &state)
}

/// 指定スロットのウォッチポイントをクリアします。
#[cfg(target_arch = "x86_64")]
pub fn clear_watchpoint_slot(pid: Pid, slot: usize) -> std::io::Result<()> {
    assert!(slot < 4, "watchpoint slot must be 0..3");
    let mut state = get_debug_state(pid)?;
    match slot {
        0 => state.__dr0 = 0,
        1 => state.__dr1 = 0,
        2 => state.__dr2 = 0,
        3 => state.__dr3 = 0,
        _ => unreachable!(),
    }
    state.__dr7 = dr7_clear_slot(state.__dr7, slot);
    set_debug_state(pid, &state)
}

/// ヒットしたウォッチポイントスロット番号を DR6 から読み取ります。
/// 戻り値: ヒットしたスロット番号のリスト (0〜3)
#[cfg(target_arch = "x86_64")]
pub fn watchpoint_hit_slots(pid: Pid) -> std::io::Result<Vec<usize>> {
    let state = get_debug_state(pid)?;
    let dr6 = state.__dr6;
    let mut hits = Vec::new();
    for slot in 0..4 {
        if dr6 & (1u64 << slot) != 0 {
            hits.push(slot);
        }
    }
    // DR6 をクリア（次回判定のため）
    let mut cleared = state;
    cleared.__dr6 = 0;
    let _ = set_debug_state(pid, &cleared);
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_get_self_task() {
        let task = get_task(std::process::id() as Pid);
        assert!(task.is_ok());
    }
}
