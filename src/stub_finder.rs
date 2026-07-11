/// Mach-O バイナリから外部関数スタブのアドレスを取得します。
/// ファット/シン両バイナリに対応します。
use std::collections::HashMap;

// Mach-O マジック定数
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const FAT_MAGIC_BE: u32 = 0xCAFEBABE; // fat_header.magic はビッグエンディアン
const FAT_MAGIC_64_BE: u32 = 0xCAFEBABF;

// ロードコマンド種別
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_SEGMENT_64: u32 = 0x19;

// CPU タイプ (fat_arch.cputype はビッグエンディアン)
#[cfg(target_arch = "aarch64")]
const TARGET_CPUTYPE_BE: u32 = 0x0000010C_u32.swap_bytes(); // CPU_TYPE_ARM64 = 0x0100000C
#[cfg(target_arch = "x86_64")]
const TARGET_CPUTYPE_BE: u32 = 0x00000107_u32.swap_bytes(); // CPU_TYPE_X86_64 = 0x01000007

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let s = data.get(off..off + 4)?;
    Some(u32::from_le_bytes(s.try_into().unwrap()))
}
fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    let s = data.get(off..off + 8)?;
    Some(u64::from_le_bytes(s.try_into().unwrap()))
}
fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    let s = data.get(off..off + 4)?;
    Some(u32::from_be_bytes(s.try_into().unwrap()))
}

/// ファットバイナリから現在のアーキテクチャに対応するスライスを取得します。
fn get_thin_slice(data: &[u8]) -> &[u8] {
    if data.len() < 8 {
        return data;
    }
    let magic_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic_be != FAT_MAGIC_BE && magic_be != FAT_MAGIC_64_BE {
        return data;
    }

    let is_fat64 = magic_be == FAT_MAGIC_64_BE;
    let nfat_arch = match read_u32_be(data, 4) {
        Some(n) => n as usize,
        None => return data,
    };

    // fat_arch (32ビット版): cputype(4)+cpusubtype(4)+offset(4)+size(4)+align(4) = 20 bytes
    // fat_arch_64:           cputype(4)+cpusubtype(4)+offset(8)+size(8)+align(4)+reserved(4) = 32 bytes
    let arch_size = if is_fat64 { 32usize } else { 20usize };
    let arch_base = 8usize;

    for i in 0..nfat_arch {
        let off = arch_base + i * arch_size;
        let cputype = match read_u32_be(data, off) {
            Some(v) => v,
            None => break,
        };
        if cputype == TARGET_CPUTYPE_BE {
            let maybe = if is_fat64 {
                let ob = data.get(off + 8..off + 16).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                let sb = data.get(off + 16..off + 24).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                ob.zip(sb).map(|(o, s)| (o as usize, s as usize))
            } else {
                read_u32_be(data, off + 8).zip(read_u32_be(data, off + 12))
                    .map(|(o, s)| (o as usize, s as usize))
            };
            if let Some((slice_off, slice_size)) = maybe {
                if let Some(slice) = data.get(slice_off..slice_off + slice_size) {
                    return slice;
                }
            }
        }
    }
    data
}

/// 64 ビット LE Mach-O スリムバイナリから指定シンボルのスタブアドレスを取得します。
fn parse_thin_macho64(data: &[u8], want: &[&str]) -> HashMap<String, u64> {
    let mut result = HashMap::new();

    // マジックチェック
    if read_u32_le(data, 0) != Some(MH_MAGIC_64) {
        return result;
    }

    let ncmds = match read_u32_le(data, 16) {
        Some(n) => n as usize,
        None => return result,
    };

    let mut symoff = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut indirectsymoff = 0u32;
    // __TEXT,__stubs セクション情報
    let mut stubs_addr = 0u64;
    let mut stubs_size = 0u64;
    let mut stubs_entry_size = 0u32;
    let mut stubs_indirect_start = 0u32;

    let mut lc_off = 32usize; // mach_header_64 = 32 bytes
    for _ in 0..ncmds {
        let cmd = match read_u32_le(data, lc_off) {
            Some(v) => v,
            None => break,
        };
        let cmdsize = match read_u32_le(data, lc_off + 4) {
            Some(v) => v as usize,
            None => break,
        };
        if cmdsize == 0 {
            break;
        }

        match cmd {
            LC_SYMTAB => {
                // symtab_command: cmd(4)+cmdsize(4)+symoff(4)+nsyms(4)+stroff(4)+strsize(4)
                if let (Some(so), Some(ns), Some(stro)) = (
                    read_u32_le(data, lc_off + 8),
                    read_u32_le(data, lc_off + 12),
                    read_u32_le(data, lc_off + 16),
                ) {
                    symoff = so;
                    nsyms = ns;
                    stroff = stro;
                }
            }
            LC_DYSYMTAB => {
                // dysymtab_command: cmd(4)+cmdsize(4)+ilocalsym(4)+nlocalsym(4)+iextdefsym(4)
                //   +nextdefsym(4)+iundefsym(4)+nundefsym(4)+tocoff(4)+ntoc(4)+modtaboff(4)
                //   +nmodtab(4)+extrefsymoff(4)+nextrefsyms(4)+indirectsymoff(4)+...
                // indirectsymoff はオフセット 56
                if let Some(iso) = read_u32_le(data, lc_off + 56) {
                    indirectsymoff = iso;
                }
            }
            LC_SEGMENT_64 => {
                // segment_command_64: cmd(4)+cmdsize(4)+segname(16)+vmaddr(8)+vmsize(8)
                //   +fileoff(8)+filesize(8)+maxprot(4)+initprot(4)+nsects(4)+flags(4) = 72 bytes
                let nsects = match read_u32_le(data, lc_off + 64) {
                    Some(n) => n as usize,
                    None => {
                        lc_off += cmdsize;
                        continue;
                    }
                };
                let seg_segname = data.get(lc_off + 8..lc_off + 24).unwrap_or(&[]);

                let mut sec_off = lc_off + 72;
                for _ in 0..nsects {
                    // section_64: sectname(16)+segname(16)+addr(8)+size(8)+offset(4)
                    //   +align(4)+reloff(4)+nreloc(4)+flags(4)+reserved1(4)+reserved2(4)+reserved3(4) = 80 bytes
                    if sec_off + 80 > data.len() {
                        break;
                    }
                    let sectname = &data[sec_off..sec_off + 16];
                    let sec_segname = &data[sec_off + 16..sec_off + 32];

                    let in_text = seg_segname.starts_with(b"__TEXT\0")
                        || sec_segname.starts_with(b"__TEXT\0");

                    if in_text && sectname.starts_with(b"__stubs\0") {
                        stubs_addr = read_u64_le(data, sec_off + 32).unwrap_or(0);
                        stubs_size = read_u64_le(data, sec_off + 40).unwrap_or(0);
                        stubs_indirect_start = read_u32_le(data, sec_off + 68).unwrap_or(0); // reserved1
                        stubs_entry_size = read_u32_le(data, sec_off + 72).unwrap_or(0); // reserved2
                    }

                    sec_off += 80;
                }
            }
            _ => {}
        }

        lc_off += cmdsize;
    }

    if stubs_addr == 0 || stubs_entry_size == 0 || indirectsymoff == 0 || nsyms == 0 {
        return result;
    }

    let stub_count = (stubs_size / stubs_entry_size as u64) as usize;
    // nlist_64: n_strx(4)+n_type(1)+n_sect(1)+n_desc(2)+n_value(8) = 16 bytes
    let nlist_size = 16usize;

    for i in 0..stub_count {
        let ind_off = indirectsymoff as usize + (stubs_indirect_start as usize + i) * 4;
        let sym_idx = match read_u32_le(data, ind_off) {
            Some(v) => v as usize,
            None => break,
        };
        if sym_idx >= nsyms as usize {
            continue;
        }

        let nlist_off = symoff as usize + sym_idx * nlist_size;
        let n_strx = match read_u32_le(data, nlist_off) {
            Some(v) => v as usize,
            None => continue,
        };

        let str_start = stroff as usize + n_strx;
        if str_start >= data.len() {
            continue;
        }
        let name_bytes = &data[str_start..];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(0);
        let raw_name = match std::str::from_utf8(&name_bytes[..name_end]) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // macOS C シンボルは _ プレフィックスを持つ
        let name = raw_name.strip_prefix('_').unwrap_or(raw_name);

        if want.contains(&name) {
            let stub_addr = stubs_addr + (i as u64) * stubs_entry_size as u64;
            result.insert(name.to_string(), stub_addr);
        }
    }

    result
}

/// 実行ファイルから指定シンボルのスタブ静的アドレスを取得します。
pub fn find_stubs(data: &[u8], want: &[&str]) -> HashMap<String, u64> {
    let thin = get_thin_slice(data);
    parse_thin_macho64(thin, want)
}
