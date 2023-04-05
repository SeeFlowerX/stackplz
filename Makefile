CMD_CLANG ?= clang
CMD_GO ?= go
CMD_RM ?= rm

DEBUG_PRINT ?=
LINUX_ARCH = arm64
ifeq ($(DEBUG),1)
DEBUG_PRINT := -DDEBUG_PRINT
endif

.PHONY: all
all: ebpf assets build
	@echo $(shell date)


.PHONY: clean
clean:
	$(CMD_RM) -f user/bytecode/*.d
	$(CMD_RM) -f user/bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/stackplz

.PHONY: ebpf
ebpf:
	clang \
	-D__aarch64__ \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	$(DEBUG_PRINT)	\
	-isystem external/bionic/libc/include \
	-isystem external/bionic/libc/kernel/uapi \
	-isystem external/bionic/libc/kernel/uapi/asm-arm64 \
	-isystem external/bionic/libc/kernel/android/uapi \
	-I       external/system/core/libcutils/include \
	-I       external/libbpf/src \
	-I       src \
	-g \
	-MD -MF user/bytecode/stack.d \
	-o user/bytecode/stack.o \
	src/stack.c

.PHONY: assets
assets:
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o ./preload_libs/*.so ./user/config/*.json)

.PHONY: build
build:
	GOARCH=arm64 GOOS=android CGO_ENABLED=1 CC=aarch64-linux-android29-clang $(CMD_GO) build -ldflags "-w -s -extldflags '-Wl,--hash-style=sysv'" -o bin/stackplz .