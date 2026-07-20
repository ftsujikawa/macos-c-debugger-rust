DEBUGGER     := target/debug/macos-c-debugger
DBG_ENT      := debugger-entitlements.plist
SAMPLE_ENT   := samples/entitlements.xml
SAMPLES      := samples/hello samples/sleep samples/threads
CC           := clang
ARCH         := $(shell uname -m)
CFLAGS       := -g -O0 -arch $(ARCH)

.PHONY: all build sign samples clean

# デフォルト: ビルド → 署名
all: build sign samples

# Rust デバッガをビルド
build:
	cargo build

# デバッガに cs.debugger エンタイトルメントを付与
# (task_for_pid を get-task-allow 付きターゲットに対して使えるようにする)
sign: build
	codesign -s - --entitlements $(DBG_ENT) -f $(DEBUGGER)

# サンプルをコンパイル → 署名 → dsymutil
samples: $(SAMPLES)

samples/hello: samples/hello.c
	$(CC) $(CFLAGS) -c -o samples/hello.o $<
	$(CC) $(CFLAGS) -o $@ samples/hello.o
	dsymutil $@
	rm -f samples/hello.o
	codesign -s - --entitlements $(SAMPLE_ENT) -f $@

samples/sleep: samples/sleep.c
	$(CC) $(CFLAGS) -c -o samples/sleep.o $<
	$(CC) $(CFLAGS) -o $@ samples/sleep.o
	dsymutil $@
	rm -f samples/sleep.o
	codesign -s - --entitlements $(SAMPLE_ENT) -f $@

samples/threads: samples/threads.c
	$(CC) $(CFLAGS) -c -o samples/threads.o $<
	$(CC) $(CFLAGS) -o $@ samples/threads.o
	dsymutil $@
	rm -f samples/threads.o
	codesign -s - --entitlements $(SAMPLE_ENT) -f $@

clean:
	cargo clean
	rm -f $(SAMPLES)
	rm -rf samples/*.dSYM
