# macOS C デバッガー ベース（Rust）

macOS の `ptrace` と Mach 64 ビット API を使った、C プログラム向けデバッガーの最小実装サンプルです。子プロセスの起動、ブレークポイント、シングルステップ、レジスタ表示、メモリ読み出しなどの基本機能を含みます。

- プロセス制御（実行再開、ステップ、キル）は `ptrace` を使用
- レジスタ取得・設定、メモリ読み書き、タスクポート取得は `mach64` API を使用

## 主なファイル

- `src/main.rs` — 簡易 CLI エントリーポイント
- `src/debugger.rs` — 子プロセス制御とデバッグループ
- `src/mach.rs` — Mach API FFI ラッパー（task_for_pid、thread_get_state、vm_read/write/protect 等）
- `src/ptrace.rs` — `ptrace` FFI ラッパー
- `src/breakpoint.rs` — `int3` (0xCC) によるブレークポイント
- `src/register.rs` — x86_64 / Apple Silicon (aarch64) 用レジスタ構造体

## 必要な環境

- macOS（x86_64 または Apple Silicon）
- Rust ツールチェーン
- `libc` クレート

## ビルド

```bash
cd /Users/tsu/Documents/src/rust/macos-c-debugger
cargo build --release
```

## 使い方

```bash
cargo run -- <target> [args...]
# または
./target/release/macos-c-debugger <target> [args...]
```

### CLI コマンド

| コマンド | 説明 |
|---|---|
| `b <addr>` | 指定アドレスにブレークポイントを設定（例: `b 0x100003f20`、または `b base+0x470`） |
| `c` | 実行再開 |
| `s` | 1 命令実行 |
| `r` | レジスタ表示 |
| `m <addr>` | 指定アドレスから 4 バイト読み出し |
| `base` | メイン実行ファイルの実行時ロードアドレスを表示 |
| `q` | 終了 |
| `h` | ヘルプ |

## 動作確認サンプル

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
clang -g -O0 samples/hello.c -o samples/hello
codesign --sign - --force --entitlements samples/entitlements.xml samples/hello
./target/release/macos-c-debugger samples/hello
```

## 注意点 / macOS のセキュリティ

macOS では `ptrace` だけでなく、Mach API によるタスクポート・メモリ・レジスタアクセスにも制限があります。

- **デバッグ対象のプロセス**（子プロセス含む）には `com.apple.security.get-task-allow` エンタイトルメントが必要です。
- 上記のサンプルでは `samples/hello` を ad-hoc 署名し、`samples/entitlements.xml` で `get-task-allow` を有効にしています。
- デバッガー自身に `get-task-allow` を付与する必要はありませんが、タスクポート取得のためにはターゲット側のエンタイトルメントが不可欠です。

`samples/entitlements.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
```

## 制限事項

- シンボル解決、DWARF 解析、ソースレベルデバッグは含まれていません。
- `int3` ブレークポイントは、対象アドレスに対して 1 バイト書き換えを行います。
- 実行時アドレスは ASLR の影響を受けるため、ブレークポイントには `base` コマンドで取得したロードアドレスにオフセットを加えた値を使用してください。
- ベース実装なので、スレッド切り替えや動的ロード等には未対応です。

## ライセンス

MIT / または好みのライセンスを自由に設定してください。
