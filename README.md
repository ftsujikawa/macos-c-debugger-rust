# macOS C デバッガー（Rust）

macOS の `ptrace` と Mach 64 ビット API を使って実装した、C プログラム向けデバッガーです。x86_64 / Apple Silicon (aarch64) の両アーキテクチャに対応しています。

## 機能

- **プロセス制御** — 起動、実行再開、シングルステップ（命令レベル・ソースレベル）、ステップオーバー、関数終了まで実行
- **ブレークポイント** — アドレス・シンボル名・ソースファイル行番号で設定、番号・アドレス・一括での削除
- **レジスタ** — 汎用レジスタの表示・変更（x86_64: RAX〜R15/RIP/RFLAGS、aarch64: X0〜X28/FP/LR/SP/PC）
- **FPU/SIMD レジスタ** （x86_64）— ST0〜ST7（x87）/ MM0〜MM7（MMX）/ XMM0〜XMM15 の表示・変更
- **メモリアクセス** — 任意アドレスの読み書き、式で計算したアドレス指定
- **DWARF デバッグ情報** — シンボル名解決、ソースファイル・行番号のマッピング、ローカル変数・引数・グローバル変数の表示
- **ディスアセンブル** — 任意アドレス・シンボル・ソース行からの逆アセンブル表示
- **バックトレース** — スタックフレームをシンボル名・ソース位置付きで表示
- **式評価** — `$rax + 0x10`、`*0x1000`、変数名などの式を評価して表示・設定
- **ヒープリーク検出** — `malloc`/`calloc`/`realloc`/`free` にブレークポイントを設置し、解放されていないアロケーションを追跡

## ファイル構成

| ファイル | 役割 |
|---|---|
| `src/main.rs` | CLI エントリーポイント・コマンドループ |
| `src/debugger.rs` | 子プロセス制御（ステップ、continue、finish、BP 管理） |
| `src/mach.rs` | Mach API FFI ラッパー（task_for_pid、thread_get_state、vm_read/write 等） |
| `src/ptrace.rs` | `ptrace` FFI ラッパー |
| `src/breakpoint.rs` | `int3` / `brk` によるブレークポイント実装 |
| `src/register.rs` | x86_64 / aarch64 汎用レジスタ・FPU レジスタ構造体 |
| `src/symbols.rs` | DWARF 解析（シンボル・行番号・変数・型情報） |
| `src/disasm.rs` | Capstone を用いた逆アセンブラ |
| `src/expr.rs` | デバッガー式パーサー・評価器 |
| `src/stub_finder.rs` | Mach-O `__stubs` セクション解析（malloc 等のスタブアドレス取得） |
| `src/leak_tracker.rs` | ヒープリークトラッカー |

## 必要な環境

- macOS（x86_64 または Apple Silicon）
- Rust ツールチェーン
- Xcode Command Line Tools（`dsymutil`、`clang`）
- クレート: `libc`, `object`, `gimli`, `capstone`

## ビルド

```bash
# デバッガーのビルド・署名とサンプルのコンパイルをまとめて実行
make

# デバッガーのみビルド
cargo build
```

`make` は以下を実行します。
1. `cargo build` でデバッガーをビルド
2. デバッガーバイナリに `cs.debugger` エンタイトルメントを付与（ad-hoc 署名）
3. `samples/hello.c`、`samples/sleep.c` をコンパイル・`dsymutil` で dSYM 生成・署名

## 使い方

```bash
./target/debug/macos-c-debugger <target> [args...]
```

### CLI コマンド一覧

#### 実行制御

| コマンド | 説明 |
|---|---|
| `c`, `cont` | 実行再開（次のブレークポイントまで） |
| `s`, `step` | ソース 1 行ステップ実行（ステップイン） |
| `n`, `next` | ソース 1 行ステップ実行（ステップオーバー） |
| `si`, `stepi` | 命令 1 つステップ実行 |
| `up`, `finish` | 現在の関数から戻るまで実行 |

#### ブレークポイント

| コマンド | 説明 |
|---|---|
| `b <loc>` | ブレークポイント設定（例: `0x1000`、`base+0x470`、`main`、`hello.c:10`） |
| `del <N>` | 番号指定で削除（`show bp` の番号） |
| `del <addr>` | アドレス指定で削除 |
| `del all` | 全ブレークポイントを削除 |
| `show bp` | ブレークポイント一覧 |

#### レジスタ・メモリ

| コマンド | 説明 |
|---|---|
| `r`, `regs` | レジスタ表示（汎用 + FPU/SIMD） |
| `set $rax = 1` | レジスタに値を設定（`$` なしも可） |
| `set xmm0 = 0xff` | FPU/SIMD レジスタへの設定 |
| `m <addr>` | 指定アドレスから 4 バイト読み出し |
| `set 0x1000 = 0xab` | 指定アドレスへの書き込み |

#### シンボル・変数

| コマンド | 説明 |
|---|---|
| `show locals` | 現在の PC に対応するローカル変数を表示 |
| `show args` | 現在の関数の引数を表示 |
| `show globals` | グローバル変数を表示 |
| `p <expr>` | 式を評価して表示（例: `p $rax`, `p myvar`, `p *0x1000`） |
| `p/x <expr>` | 16 進数表示（`/d` 10 進、`/o` 8 進、`/t` 2 進、`/c` 文字、`/s` 文字列） |
| `set <var> = <expr>` | 変数に値を設定 |
| `syms [pat]` | シンボル一覧（パターンフィルタ可） |
| `lines [pat]` | 行番号テーブル一覧（ファイル名フィルタ可） |

#### ソース・逆アセンブル

| コマンド | 説明 |
|---|---|
| `list [loc]` | ソースコード表示（`loc`: 行番号・`file:line`・シンボル名） |
| `dis [loc] [count]` | 逆アセンブル表示（デフォルト: PC から 10 命令） |
| `tb`, `bt` | バックトレース |

#### ヒープリーク検出

| コマンド | 説明 |
|---|---|
| `leaks on` | リーク追跡を有効化（malloc/calloc/realloc/free にフック） |
| `leaks off` | リーク追跡を無効化 |
| `leaks show` / `show leaks` | 解放されていないアロケーションを一覧表示 |

`leaks show` の出力例:

```
3 live allocation(s) (possible leaks):
  0x00007f8a00600000  size=128     caller=0x000000010000abcd  (hello.c:42)
  0x00007f8a00601000  size=64      caller=0x000000010000cd10  (hello.c:57)
  0x00007f8a00602000  size=32      caller=0x000000010000de20
```

#### その他

| コマンド | 説明 |
|---|---|
| `base` | メイン実行ファイルの実行時ロードアドレス表示 |
| `dbg`, `info` | デバッグ情報の概要表示 |
| `h`, `help` | ヘルプ表示 |
| `q`, `quit` | 終了 |

## 式の文法

`p`・`set` で使える式:

```
expr  := number | $register | variable | *expr | expr op expr | (expr)
op    := + - * / % & | ^ ~ << >>
number := 0x... (16進) | 0b... (2進) | 0o... (8進) | 10進
```

例:
```
p $rsp + 8
p *($rbp - 16)
p base + 0x3f20
set $rip = 0x100003f20
set myvar = $rax * 2
```

## サンプルプログラム

```c
// samples/hello.c
#include <stdio.h>

int main() {
    for (int i = 0; i < 3; i++) {
        printf("hello %d\n", i);
    }
    return 0;
}
```

```bash
make samples        # コンパイル・署名
./target/debug/macos-c-debugger samples/hello
(dbg) b main        # main にブレークポイント
(dbg) c             # 実行開始
(dbg) show args     # 引数表示
(dbg) show locals   # ローカル変数表示
(dbg) n             # 次の行へ
(dbg) leaks on      # リーク追跡開始
(dbg) c             # 実行継続
(dbg) show leaks    # リーク確認
```

## macOS のセキュリティについて

macOS では Mach API によるタスクポート・メモリ・レジスタアクセスに制限があります。

- **デバッグ対象プロセス**には `com.apple.security.get-task-allow` エンタイトルメントが必要です
- デバッガー自身には `cs.debugger` エンタイトルメントが必要です
- `make sign` でデバッガーへの署名、`make samples` でサンプルへの署名を行います

`debugger-entitlements.plist`（デバッガー用）:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.debugger</key><true/>
</dict></plist>
```

`samples/entitlements.xml`（デバッグ対象用）:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
```

## 制限事項

- マルチスレッドプログラムでは最初のスレッドのみ制御します
- DWARF 5 形式のデバッグ情報に対応（Apple clang 生成バイナリ）
- ヒープリーク検出はメインバイナリが `malloc`/`free` スタブを持つ場合のみ動作します
- C++ / Swift / Objective-C の名前マングリング解除は未対応です

## ライセンス

MIT
