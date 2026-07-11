use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSegment, ObjectSymbol};

/// 実行ファイルのシンボル情報と DWARF 行番号情報を保持します。
/// 起動時にすべて読み込んでメモリにキャッシュします。
pub struct Symbols {
    /// (シンボル名, ファイル上の仮想アドレス)
    symbols: Vec<(String, u64)>,
    /// __TEXT セグメントの仮想アドレス(スライド計算用)
    text_vmaddr: u64,
    /// DWARF 行番号テーブル(アドレス順のシーケンス列)
    line_rows: Vec<LineRow>,
    /// 実際に読み込んだデバッグ情報ファイル（dSYM または実行ファイル）
    debug_file: PathBuf,
    /// コンパイルディレクトリ一覧
    comp_dirs: BTreeSet<String>,
    /// 読み込んだ型名一覧
    type_names: BTreeSet<String>,
    /// 読み込んだ変数情報（ローカル変数・引数・グローバル）
    variables: Vec<Variable>,
}

/// DWARF から読み取った変数 1 つ分の情報。
#[derive(Debug, Clone)]
pub struct Variable {
    /// 変数名
    pub name: String,
    /// スコープの範囲（ファイル上の仮想アドレス）。None ならグローバル。
    pub scope: Option<(u64, u64)>,
    /// 変数の場所
    pub location: VarLocation,
    /// 型のバイト数（1・2・4・8 など）
    pub byte_size: u8,
}

/// 変数の場所。
#[derive(Debug, Clone, Copy)]
pub enum VarLocation {
    /// フレームベース (rbp/fp) からのオフセット (DW_OP_fbreg)
    FrameOffset(i64),
    /// 静的アドレス (DW_OP_addr、ファイル上の仮想アドレス)
    Addr(u64),
}

impl Symbols {
    /// 実行ファイルからシンボルテーブルと DWARF 行番号情報を読み込みます。
    pub fn load(exe: &str) -> io::Result<Self> {
        let data = fs::read(exe)?;
        let obj = object::File::parse(&*data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut symbols = Vec::new();
        for sym in obj.symbols() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    symbols.push((name.to_string(), sym.address()));
                }
            }
        }

        let text_vmaddr = obj
            .segments()
            .find(|s| matches!(s.name(), Ok(Some("__TEXT"))))
            .map(|s| s.address())
            .unwrap_or(0);

        // デバッグ情報 (DWARF) を読み込み。dSYM があれば優先。
        let debug_file = find_debug_file(exe);
        let (line_rows, comp_dirs, type_names, variables) =
            load_line_rows(&debug_file).unwrap_or_default();

        Ok(Self {
            symbols,
            text_vmaddr,
            line_rows,
            debug_file,
            comp_dirs,
            type_names,
            variables,
        })
    }

    /// 読み込んだシンボル数を返します。
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// 読み込んだ行番号テーブルのエントリ数を返します。
    pub fn line_row_count(&self) -> usize {
        self.line_rows.len()
    }

    /// 読み込んだ型名の数を返します。
    pub fn type_count(&self) -> usize {
        self.type_names.len()
    }

    /// 変数名と PC（ファイル上の仮想アドレス）から変数を検索します。
    /// スコープ内の変数を優先し、最も内側のスコープを選びます。
    pub fn find_variable(&self, name: &str, pc_vaddr: u64) -> Option<&Variable> {
        // スコープ内の変数（最も狭いスコープを優先）
        let local = self
            .variables
            .iter()
            .filter(|v| v.name == name)
            .filter_map(|v| match v.scope {
                Some((low, high)) if low <= pc_vaddr && pc_vaddr < high => {
                    Some((high - low, v))
                }
                _ => None,
            })
            .min_by_key(|(range, _)| *range)
            .map(|(_, v)| v);
        if local.is_some() {
            return local;
        }
        // グローバル変数
        self.variables
            .iter()
            .find(|v| v.name == name && v.scope.is_none())
    }

    /// 実行時のロードアドレスからスライド量を計算します。
    pub fn slide(&self, runtime_base: u64) -> u64 {
        runtime_base.wrapping_sub(self.text_vmaddr)
    }

    /// シンボル名からファイル上の仮想アドレスを検索します。
    /// Mach-O では C のシンボルに '_' が前置されるため、両方を試します。
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        let underscored = format!("_{}", name);
        self.symbols
            .iter()
            .find(|(n, _)| n == name || n == &underscored)
            .map(|(_, addr)| *addr)
    }

    /// 読み込んだすべてのシンボル情報を表示します。
    /// オプションでシンボル名に部分一致するフィルタを指定できます。
    pub fn print_symbols(&self, filter: Option<&str>) {
        for (name, addr) in &self.symbols {
            if addr == &0 {
                continue;
            }
            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    continue;
                }
            }
            if let Some((path, line)) = self.find_location(*addr) {
                println!("{:#018x}  {}  ({}:{})", addr, name, path, line);
            } else {
                println!("{:#018x}  {}", addr, name);
            }
        }
    }

    /// ファイル上の仮想アドレスから、それを含むシンボルを逆引きします。
    /// (シンボル名, シンボル先頭からのオフセット) を返します。
    pub fn find_symbol_for_addr(&self, vaddr: u64) -> Option<(&str, u64)> {
        self.symbols
            .iter()
            .filter(|(n, a)| *a <= vaddr && *a != 0 && n != "__mh_execute_header")
            .max_by_key(|(_, a)| *a)
            .map(|(n, a)| (n.as_str(), vaddr - a))
    }

    /// ソースファイル名と行番号からファイル上の仮想アドレスを検索します。
    /// 指定行が見つからない場合は、指定行以降で最も近い行を採用します。
    pub fn find_line(&self, file: &str, line: u32) -> Option<u64> {
        let want = Path::new(file).file_name()?.to_str()?.to_string();

        // (行番号の差, アドレス) が最小のものを選びます。
        let mut best: Option<(u32, u64)> = None;
        for row in &self.line_rows {
            let LineRow::Row {
                file,
                line: l,
                addr,
                ..
            } = row
            else {
                continue;
            };
            if file != &want || *l < line {
                continue;
            }
            let delta = *l - line;
            match best {
                Some((d, a)) if (d, a) <= (delta, *addr) => {}
                _ => best = Some((delta, *addr)),
            }
        }

        best.map(|(_, addr)| addr)
    }

    /// 関数先頭アドレスからプロローグ終了後のアドレスを求めます。
    /// DWARF の prologue_end フラグを優先し、なければ関数先頭の
    /// 次の行テーブルエントリを使います。求められない場合は
    /// 関数先頭をそのまま返します。
    pub fn skip_prologue(&self, func_vaddr: u64) -> u64 {
        // 次のシンボルの先頭を超えたら別の関数とみなす
        let bound = self
            .symbols
            .iter()
            .map(|(_, a)| *a)
            .filter(|a| *a > func_vaddr)
            .min();

        let mut in_func = false;
        for row in &self.line_rows {
            match row {
                LineRow::Row {
                    addr,
                    prologue_end,
                    ..
                } => {
                    if *addr == func_vaddr {
                        in_func = true;
                        if *prologue_end {
                            return *addr;
                        }
                        continue;
                    }
                    if in_func && *addr > func_vaddr {
                        if bound.map_or(true, |b| *addr < b) {
                            return *addr;
                        }
                        // 次の行が別関数 → スキップ断念
                        return func_vaddr;
                    }
                }
                LineRow::EndSequence { .. } => {
                    in_func = false;
                }
            }
        }
        func_vaddr
    }

    /// 読み込んだ行番号テーブルのエントリを表示します。
    /// オプションでファイル名に部分一致するフィルタを指定できます。
    pub fn print_lines(&self, filter: Option<&str>) {
        for row in &self.line_rows {
            let LineRow::Row {
                file,
                path,
                line,
                addr,
                prologue_end,
            } = row
            else {
                continue;
            };
            if let Some(f) = filter {
                if !file.to_lowercase().contains(&f.to_lowercase())
                    && !path.to_lowercase().contains(&f.to_lowercase())
                {
                    continue;
                }
            }
            let marker = if *prologue_end { " (prologue_end)" } else { "" };
            println!("{:#018x}  {}:{}  [{}]{}", addr, path, line, file, marker);
        }
    }

    /// 読み込んだデバッグ情報のサマリを表示します。
    pub fn print_debug_info(&self, runtime_base: Option<u64>) {
        println!("debug file: {}", self.debug_file.display());
        println!("text vmaddr: {:#018x}", self.text_vmaddr);
        if let Some(base) = runtime_base {
            println!("image base: {:#018x}", base);
            println!("slide: {:#018x}", self.slide(base));
        }
        println!("symbols: {}", self.symbol_count());
        println!("line rows: {}", self.line_row_count());
        println!("types: {}", self.type_count());
        if !self.comp_dirs.is_empty() {
            println!("compilation directories:");
            for d in &self.comp_dirs {
                println!("  {}", d);
            }
        }
        if !self.type_names.is_empty() {
            println!("types:");
            for t in &self.type_names {
                println!("  {}", t);
            }
        }
    }

    /// ファイル上の仮想アドレスから (ソースファイルのフルパス, 行番号) を逆引きします。
    pub fn find_location(&self, vaddr: u64) -> Option<(String, u32)> {
        let mut prev: Option<(&str, u32, u64)> = None;
        for row in &self.line_rows {
            let addr = match row {
                LineRow::Row { addr, .. } => *addr,
                LineRow::EndSequence { addr } => *addr,
            };
            if let Some((ppath, pline, paddr)) = prev {
                if paddr <= vaddr && vaddr < addr {
                    return Some((ppath.to_string(), pline));
                }
            }
            prev = match row {
                LineRow::Row {
                    path, line, addr, ..
                } => Some((path, *line, *addr)),
                LineRow::EndSequence { .. } => None,
            };
        }
        None
    }
}

/// DWARF 行番号テーブルの全行を読み込みます。
/// 同時にコンパイルディレクトリ一覧・型名一覧・変数情報も返します。
type DebugInfo = (
    Vec<LineRow>,
    BTreeSet<String>,
    BTreeSet<String>,
    Vec<Variable>,
);

fn load_line_rows(debug_file: &Path) -> Option<DebugInfo> {
    let data = fs::read(debug_file).ok()?;
    let obj = object::File::parse(&*data).ok()?;

    let load_section = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        use object::ObjectSection;
        Ok(obj
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    };
    let sections = gimli::DwarfSections::load(load_section).ok()?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, gimli::LittleEndian));

    let mut result = Vec::new();
    let mut comp_dirs = BTreeSet::new();
    let mut type_names = BTreeSet::new();
    let mut variables = Vec::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if let Some(comp_dir) = &unit.comp_dir {
            comp_dirs.insert(String::from_utf8_lossy(comp_dir.slice()).into_owned());
        }

        collect_type_names(&dwarf, &unit, &mut type_names);
        collect_variables(&dwarf, &unit, &mut variables);

        let program = match unit.line_program.clone() {
            Some(p) => p,
            None => continue,
        };
        let mut rows = program.rows();
        while let Ok(Some((header, row))) = rows.next_row() {
            if row.end_sequence() {
                result.push(LineRow::EndSequence {
                    addr: row.address(),
                });
                continue;
            }
            let line = match row.line() {
                Some(l) => l.get() as u32,
                None => continue,
            };
            let file_entry = match row.file(header) {
                Some(f) => f,
                None => continue,
            };
            let name = match dwarf.attr_string(&unit, file_entry.path_name()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let name = String::from_utf8_lossy(name.slice()).into_owned();
            let basename = Path::new(&name)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| name.clone());

            // フルパスを組み立て: comp_dir / ディレクトリ / ファイル名
            let mut full = PathBuf::new();
            if let Some(comp_dir) = &unit.comp_dir {
                full.push(String::from_utf8_lossy(comp_dir.slice()).as_ref());
            }
            if let Some(dir) = file_entry.directory(header) {
                if let Ok(d) = dwarf.attr_string(&unit, dir) {
                    let d = String::from_utf8_lossy(d.slice());
                    if d.starts_with('/') {
                        full = PathBuf::from(d.as_ref());
                    } else {
                        full.push(d.as_ref());
                    }
                }
            }
            if name.starts_with('/') {
                full = PathBuf::from(&name);
            } else {
                full.push(&name);
            }

            result.push(LineRow::Row {
                file: basename,
                path: full.to_string_lossy().into_owned(),
                line,
                addr: row.address(),
                prologue_end: row.prologue_end(),
            });
        }
    }
    Some((result, comp_dirs, type_names, variables))
}

/// ユニットの DIE から変数情報を収集します。
/// スコープ（関数・レキシカルブロック）の PC 範囲を追跡します。
fn collect_variables<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    variables: &mut Vec<Variable>,
) {
    // (ネスト深度, スコープ範囲)
    let mut scope_stack: Vec<(isize, (u64, u64))> = Vec::new();
    let mut depth: isize = 0;

    let mut entries = unit.entries();
    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        depth += delta;
        // 現在の深度より深いスコープを取り除く
        while scope_stack.last().map_or(false, |(d, _)| *d >= depth) {
            scope_stack.pop();
        }

        match entry.tag() {
            gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block => {
                if let Some(range) = entry_pc_range(entry) {
                    scope_stack.push((depth, range));
                }
            }
            gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                let Some(name) = attr_to_string(dwarf, unit, entry, gimli::DW_AT_name) else {
                    continue;
                };
                let Some(location) = parse_var_location(entry) else {
                    continue;
                };
                let (byte_size, _) = resolve_type_info(dwarf, unit, entry);
                let scope = scope_stack.last().map(|(_, r)| *r);
                variables.push(Variable {
                    name,
                    scope,
                    location,
                    byte_size,
                });
            }
            _ => {}
        }
    }
}

/// DIE の DW_AT_low_pc / DW_AT_high_pc から PC 範囲を取得します。
fn entry_pc_range<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<(u64, u64)> {
    let low = match entry.attr_value(gimli::DW_AT_low_pc).ok()?? {
        gimli::AttributeValue::Addr(a) => a,
        _ => return None,
    };
    let high = match entry.attr_value(gimli::DW_AT_high_pc).ok()?? {
        gimli::AttributeValue::Addr(a) => a,
        gimli::AttributeValue::Udata(off) => low + off,
        gimli::AttributeValue::Data1(off) => low + off as u64,
        gimli::AttributeValue::Data2(off) => low + off as u64,
        gimli::AttributeValue::Data4(off) => low + off as u64,
        gimli::AttributeValue::Data8(off) => low + off,
        _ => return None,
    };
    Some((low, high))
}

/// DIE の文字列属性を String に変換します。
fn attr_to_string<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
    attr: gimli::DwAt,
) -> Option<String> {
    let value = entry.attr_value(attr).ok()??;
    let s = dwarf.attr_string(unit, value).ok()?;
    let bytes = s.to_slice().ok()?;
    Some(String::from_utf8_lossy(bytes.as_ref()).into_owned())
}

/// DW_AT_location の DWARF 式を解析します。
/// DW_OP_fbreg (0x91) と DW_OP_addr (0x03) のみサポートします。
fn parse_var_location<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<VarLocation> {
    let value = entry.attr_value(gimli::DW_AT_location).ok()??;
    let gimli::AttributeValue::Exprloc(expr) = value else {
        return None;
    };
    let bytes = expr.0.to_slice().ok()?;
    let bytes = bytes.as_ref();
    match bytes.first()? {
        0x91 => {
            // DW_OP_fbreg: SLEB128 オフセット
            let (off, _) = decode_sleb128(&bytes[1..])?;
            Some(VarLocation::FrameOffset(off))
        }
        0x03 => {
            // DW_OP_addr: 8 バイトのアドレス
            if bytes.len() < 9 {
                return None;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[1..9]);
            Some(VarLocation::Addr(u64::from_le_bytes(buf)))
        }
        _ => None,
    }
}

/// SLEB128 をデコードします。(値, 消費バイト数) を返します。
fn decode_sleb128(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            // 符号拡張
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            return Some((result, i + 1));
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// DW_AT_type をたどって型のバイト数と型名を取得します。
/// typedef などを最大 8 回まで追跡します。不明な場合は (8, "") を返します。
fn resolve_type_info<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> (u8, String) {
    let mut type_name = String::new();
    let mut offset = match entry.attr_value(gimli::DW_AT_type) {
        Ok(Some(gimli::AttributeValue::UnitRef(o))) => o,
        _ => return (8, type_name),
    };
    for _ in 0..8 {
        let Ok(die) = unit.entry(offset) else {
            break;
        };
        if type_name.is_empty() {
            if let Some(name) = attr_to_string(dwarf, unit, &die, gimli::DW_AT_name) {
                type_name = name;
            }
        }
        if let Ok(Some(gimli::AttributeValue::Udata(size))) =
            die.attr_value(gimli::DW_AT_byte_size)
        {
            return (size.min(8) as u8, type_name);
        }
        // ポインタ型は 8 バイト
        if die.tag() == gimli::DW_TAG_pointer_type {
            return (8, type_name);
        }
        match die.attr_value(gimli::DW_AT_type) {
            Ok(Some(gimli::AttributeValue::UnitRef(o))) => offset = o,
            _ => break,
        }
    }
    (8, type_name)
}

/// ユニットの DIE から型名を収集します。
fn collect_type_names<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    type_names: &mut BTreeSet<String>,
) {
    let mut entries = unit.entries();
    while let Ok(Some((_, entry))) = entries.next_dfs() {
        let name = match entry.attr_value(gimli::DW_AT_name) {
            Ok(Some(v)) => match dwarf.attr_string(unit, v) {
                Ok(s) => match s.to_slice() {
                    Ok(bytes) => String::from_utf8_lossy(bytes.as_ref()).into_owned(),
                    Err(_) => continue,
                },
                Err(_) => continue,
            },
            _ => continue,
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if let Some(formatted) = format_type_name(entry.tag(), name) {
            type_names.insert(formatted);
        }
    }
}

/// DWARF タグに応じた型名を組み立てます。
fn format_type_name(tag: gimli::constants::DwTag, name: &str) -> Option<String> {
    let prefix = match tag {
        gimli::DW_TAG_base_type => "",
        gimli::DW_TAG_typedef => "typedef ",
        gimli::DW_TAG_structure_type => "struct ",
        gimli::DW_TAG_union_type => "union ",
        gimli::DW_TAG_class_type => "class ",
        gimli::DW_TAG_enumeration_type => "enum ",
        gimli::DW_TAG_interface_type => "interface ",
        _ => return None,
    };
    Some(format!("{}{}", prefix, name))
}

/// DWARF 行番号テーブルの 1 行分の情報。
enum LineRow {
    /// 通常の行: (ソースファイル名, フルパス, 行番号, アドレス, プロローグ終了)
    Row {
        file: String,
        path: String,
        line: u32,
        addr: u64,
        prologue_end: bool,
    },
    /// シーケンス終端 (アドレスは範囲の終わり)
    EndSequence { addr: u64 },
}

/// dSYM バンドルがあればその DWARF ファイルを、なければ実行ファイル自身を返します。
fn find_debug_file(exe: &str) -> PathBuf {
    let exe_path = Path::new(exe);
    if let Some(file_name) = exe_path.file_name() {
        let dsym = PathBuf::from(format!("{}.dSYM", exe))
            .join("Contents/Resources/DWARF")
            .join(file_name);
        if dsym.exists() {
            return dsym;
        }
    }
    exe_path.to_path_buf()
}
